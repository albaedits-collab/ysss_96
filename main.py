import os
import re
import hmac
import hashlib
import base64
import ipaddress
from typing import Optional, List
from urllib.parse import urlparse, urljoin

import requests
from bs4 import BeautifulSoup
from fastapi import FastAPI, Header, HTTPException, Query


# =========================
# Domain policy
# =========================
ALLOW = {
    "alifta.gov.sa",
    "binbaz.org.sa",
    "binothaimeen.net",
    "alfawzan.af.org.sa",
    "sualruhaily.com",
    "rabee.net",
    "al-badr.net",
    "alnajmi.net",
    "lohaidan.af.org.sa",
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

ASSET_EXT = (".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".css", ".js", ".ico", ".pdf", ".zip")


def _normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return ""
    p = urlparse(url)
    if not p.scheme:
        url = "https://" + url
        p = urlparse(url)
    if p.scheme not in {"http", "https"}:
        return ""
    return url


def _host(url: str) -> str:
    url = _normalize_url(url)
    if not url:
        return ""
    p = urlparse(url)
    return (p.hostname or "").lower().lstrip("www.")


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except Exception:
        return False


def domain_ok(url: str) -> bool:
    url = _normalize_url(url)
    if not url:
        return False

    host = _host(url)
    if not host:
        return False

    # block IPs + localhost-like
    if _is_ip(host) or host in {"localhost"} or host.endswith(".local"):
        return False

    # DENY first (including subdomains)
    if any(host == x or host.endswith("." + x) for x in DENY):
        return False

    # ALLOW then (including subdomains)
    return any(host == x or host.endswith("." + x) for x in ALLOW)


# =========================
# Auth + signing
# =========================
APP_KEY = os.environ.get("APP_KEY", "").strip()

app = FastAPI(title="Salafi Source Gate", version="1.2.1")


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
# HTTP / extraction
# =========================
SESSION = requests.Session()
DEFAULT_HEADERS = {"User-Agent": "Mozilla/5.0"}
TIMEOUT_SECONDS = 25
MAX_TEXT_CHARS = 200000


def clean_html(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    return " ".join(soup.get_text(separator=" ").split())


def _clean_query(q: str) -> str:
    q = (q or "").strip()
    # enlève les opérateurs type: site:domain
    q = re.sub(r"\bsite:[^\s]+\b", "", q, flags=re.IGNORECASE).strip()
    q = re.sub(r"\s{2,}", " ", q)
    return q[:200]


def _valid_internal_link(full_url: str, site: str) -> bool:
    if not full_url:
        return False
    u = _normalize_url(full_url)
    if not u:
        return False
    if not domain_ok(u):
        return False
    if _host(u) != site:
        return False

    path = (urlparse(u).path or "").lower()
    if any(path.endswith(ext) for ext in ASSET_EXT):
        return False

    # chemins utiles (binbaz + général)
    good_prefixes = (
        "/fatwas/",
        "/fatwa/",
        "/majmou-fatawa/",
        "/noor-ala-darb/",
        "/articles/",
        "/categories/",
        "/node/",
    )
    if path.startswith(good_prefixes):
        return True

    # fallback: accepte aussi des pages “contenu” avec chiffres (souvent des articles/entrées)
    if re.search(r"/\d+", path):
        return True

    return False


# =========================
# Endpoints
# =========================
@app.get("/health")
def health():
    return {"ok": True, "version": "1.2.1"}


@app.get("/fetch")
def fetch(
    url: str,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
):
    require_key(x_api_key)

    url = _normalize_url(url)
    if not url:
        raise HTTPException(status_code=422, detail="Missing or empty url")

    if not domain_ok(url):
        raise HTTPException(status_code=403, detail=f"Forbidden domain: {_host(url) or 'unknown'}")

    try:
        r = SESSION.get(url, timeout=TIMEOUT_SECONDS, allow_redirects=True, headers=DEFAULT_HEADERS)
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=503, detail=f"External request failed: {str(e)}")

    final_url = r.url
    if not domain_ok(final_url):
        raise HTTPException(status_code=403, detail=f"Redirected to forbidden domain: {_host(final_url) or 'unknown'}")

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
    if not url or not domain_ok(url):
        return {"ok": False}

    return {"ok": token_ok(url, token)}


@app.get("/search")
def search(
    q: str = Query(..., description="Query string to search for (NO site: operator)."),
    limit: int = Query(5, ge=1, le=10),
    site: str = Query("binbaz.org.sa", description="Target site (must be in ALLOW)."),
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
):
    require_key(x_api_key)

    if site not in ALLOW:
        raise HTTPException(status_code=403, detail="Site not allowed")

    q2 = _clean_query(q)
    if not q2:
        raise HTTPException(status_code=422, detail="Missing q after cleaning")

    # stratégie simple: /search?q=... (marche pour binbaz)
    base = f"https://{site}"
    candidates = [
        (f"{base}/search", {"q": q2}),
        (f"{base}/search", {"query": q2}),
    ]

    out: List[str] = []
    seen = set()

    for search_url, params in candidates:
        try:
            r = SESSION.get(search_url, params=params, timeout=TIMEOUT_SECONDS, allow_redirects=True, headers=DEFAULT_HEADERS)
            if r.status_code >= 400:
                continue
        except requests.exceptions.RequestException:
            continue

        soup = BeautifulSoup(r.text, "html.parser")
        for a in soup.find_all("a", href=True):
            href = (a.get("href") or "").strip()
            if not href:
                continue

            # construit une URL absolue
            if href.startswith("http://") or href.startswith("https://"):
                full = href
            else:
                full = urljoin(search_url, href)

            # filtre
            if not _valid_internal_link(full, site):
                continue

            if full not in seen:
                seen.add(full)
                out.append(full)
                if len(out) >= limit:
                    break

        if len(out) >= limit:
            break

    return {"site": site, "q": q2, "results": out}
