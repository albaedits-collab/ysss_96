import os
import hmac
import hashlib
import base64
from typing import Optional, List, Dict
from urllib.parse import urlparse, parse_qs, unquote

import requests
from bs4 import BeautifulSoup
from fastapi import FastAPI, Header, HTTPException


# =========================
# Domain policy
# =========================
ALLOW = {
    "alifta.gov.sa",
    "alifta.net",
    "binbaz.org.sa",
    "binothaimeen.net",
    "alfawzan.af.org.sa",
    "alalbani.info",
    "sualruhaily.com",
    "rabee.net",
    "miraath.net",
    "al-badr.net",
    "alnajmi.net",
    "muqbel.net",
    "lohaidan.af.org.sa",
    "home.ajurry.com",
}

DENY = {
    "islamqa.org",
    "islamqa.info",
    "islamweb.net",
    "sajidine.com",
    "ecolemalikite.com",
    "doctrine-malikite.fr",
    "at-tawhid.net",
    "ecolehanafite.com",
    "al-hanz.org",
    "islametinfo.fr",
    "katibin.fr",
    "alnas.fr",
    "oumma.com",
    "islamophile.org",
    "dourous.net",
    "dammaj-fr.com",
    "aloloom-fr.com",
    "islamsunnite.net",
    "sunnisme.com",
    "apbif.fr",
    "yabiladi.com",
    "youtube.com",
    "facebook.com",
}


def _normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return ""
    p = urlparse(url)
    if not p.scheme:
        return "https://" + url
    return url


def _domain(url: str) -> str:
    url = _normalize_url(url)
    if not url:
        return ""
    p = urlparse(url)
    return (p.netloc or "").lower().lstrip("www.")


def domain_ok(url: str) -> bool:
    d = _domain(url)
    if not d:
        return False
    if any(d == x or d.endswith("." + x) for x in DENY):
        return False
    return any(d == x or d.endswith("." + x) for x in ALLOW)


# =========================
# Auth + signing
# =========================
APP_KEY = os.environ.get("APP_KEY", "").strip()

app = FastAPI(title="Salafi Source Gate", version="1.2.0")


def require_key(x_api_key: Optional[str]) -> None:
    if not APP_KEY:
        raise HTTPException(status_code=500, detail="Server misconfigured: APP_KEY missing")
    if not x_api_key or x_api_key != APP_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")


def sign_url(u: str) -> str:
    key = APP_KEY.encode("utf-8")
    msg = u.encode("utf-8")
    digest = hmac.new(key, msg, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")


def token_ok(u: str, token: str) -> bool:
    if not token:
        return False
    expected = sign_url(u)
    return hmac.compare_digest(expected, token)


# =========================
# HTTP session
# =========================
SESSION = requests.Session()
DEFAULT_HEADERS = {"User-Agent": "Mozilla/5.0"}
TIMEOUT_SECONDS = 20
MAX_TEXT_CHARS = 200000


def clean_html(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    return " ".join(soup.get_text(separator=" ").split())


# =========================
# Endpoints
# =========================
@app.get("/health")
def health():
    return {"ok": True}


@app.get("/fetch")
def fetch(
    url: str,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
):
    require_key(x_api_key)

    url = _normalize_url(url)
    if not url:
        raise HTTPException(status_code=422, detail="Missing or empty url")

    d = _domain(url)
    if not domain_ok(url):
        raise HTTPException(status_code=403, detail=f"Forbidden domain: {d or 'unknown'}")

    r = SESSION.get(
        url,
        timeout=TIMEOUT_SECONDS,
        allow_redirects=True,
        headers=DEFAULT_HEADERS,
    )

    final_url = r.url
    final_domain = _domain(final_url)
    if not domain_ok(final_url):
        raise HTTPException(status_code=403, detail=f"Redirected to forbidden domain: {final_domain or 'unknown'}")

    r.raise_for_status()

    content_type = (r.headers.get("content-type") or "").lower()
    body = r.text if hasattr(r, "text") else ""
    text = clean_html(body) if "html" in content_type else body

    token = sign_url(final_url)

    return {
        "url": final_url,
        "status": int(r.status_code),
        "text": (text or "")[:MAX_TEXT_CHARS],
        "token": token,
    }


@app.get("/verify")
def verify(
    url: str,
    token: str,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
):
    require_key(x_api_key)

    url = _normalize_url(url)
    if not url:
        return {"ok": False}
    if not domain_ok(url):
        return {"ok": False}

    return {"ok": token_ok(url, token)}


def _ddg_extract_real_url(href: str) -> str:
    """
    DuckDuckGo sometimes returns redirect links like:
    https://duckduckgo.com/l/?uddg=<ENCODED_URL>
    """
    href = (href or "").strip()
    if not href:
        return ""

    p = urlparse(href)

    # absolute ddg redirect
    if p.netloc.endswith("duckduckgo.com") and p.path.startswith("/l/"):
        qs = parse_qs(p.query or "")
        if "uddg" in qs and qs["uddg"]:
            return unquote(qs["uddg"][0])

    # relative ddg redirect
    if p.netloc == "" and href.startswith("/l/?"):
        qs = parse_qs(urlparse("https://duckduckgo.com" + href).query or "")
        if "uddg" in qs and qs["uddg"]:
            return unquote(qs["uddg"][0])

    return href


@app.get("/search")
def search(
    q: str,
    site: Optional[str] = None,
    limit: int = 8,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
):
    """
    Returns allowlisted URLs only.
    Uses DuckDuckGo HTML as a discovery layer, then filters to ALLOW.
    """
    require_key(x_api_key)

    q = (q or "").strip()
    if not q:
        raise HTTPException(status_code=422, detail="Missing or empty q")
    if limit < 1:
        limit = 1
    if limit > 12:
        limit = 12

    if site:
        site = site.strip().lower().lstrip("www.")
        if site not in ALLOW:
            raise HTTPException(status_code=403, detail=f"Site not allowlisted: {site}")
        scoped = f"site:{site} {q}"
    else:
        scoped_sites = " OR ".join([f"site:{d}" for d in sorted(ALLOW)])
        scoped = f"({scoped_sites}) {q}"

    # DuckDuckGo HTML endpoint
    ddg_url = "https://duckduckgo.com/html/"
    try:
        r = SESSION.get(
            ddg_url,
            params={"q": scoped},
            timeout=TIMEOUT_SECONDS,
            headers=DEFAULT_HEADERS,
        )
        r.raise_for_status()
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Search provider error: {type(e).__name__}")

    soup = BeautifulSoup(r.text, "html.parser")
    out: List[Dict[str, str]] = []
    seen = set()

    for a in soup.select("a.result__a"):
        href = a.get("href") or ""
        real = _ddg_extract_real_url(href)
        real = _normalize_url(real)

        if not real:
            continue
        if not domain_ok(real):
            continue
        if real in seen:
            continue

        seen.add(real)
        title = " ".join((a.get_text(" ") or "").split())
        out.append({"url": real, "title": title})
        if len(out) >= limit:
            break

    return {"query": q, "scoped_query": scoped, "results": out}
