import os
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
# Domain policy (ALLOW only + optional DENY)
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
# ... (DENY list reste la même)
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
    d = (p.hostname or "").lower().lstrip("www.")
    return d


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

    p = urlparse(url)
    host = (p.hostname or "").lower().lstrip("www.")
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


# =========================
# Endpoints
# =========================
@app.get("/health")
def health():
    return {"ok": True, "version": "1.2.0"}


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
        raise HTTPException(status_code=403, detail=f"Forbidden domain: {_domain(url) or 'unknown'}")

    try:
        r = SESSION.get(url, timeout=TIMEOUT_SECONDS, allow_redirects=True, headers=DEFAULT_HEADERS)
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=503, detail=f"External request failed: {str(e)}")


    final_url = r.url
    if not domain_ok(final_url):
        raise HTTPException(status_code=403, detail=f"Redirected to forbidden domain: {_domain(final_url) or 'unknown'}")

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
    q: str = Query(..., description="Query string to search for."),
    limit: int = Query(5, ge=1, le=10, description="Maximum number of results to return."),
    site: str = Query("binbaz.org.sa", description="Target site for search, must be in ALLOW list."),
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
):
    """
    Performs an allowlist-only search. NOTE: Currently only binbaz.org.sa is fully implemented.
    The GPT MUST call this function sequentially for each domain in the ALLOWLIST to perform a full search.
    """
    require_key(x_api_key)

    q = (q or "").strip()
    if not q:
        raise HTTPException(status_code=422, detail="Missing q")

    if site not in ALLOW:
        raise HTTPException(status_code=403, detail="Site not allowed")

    # === START OF CRITICAL CODE SECTION ===
    # *** ATTENTION: You need to implement search logic for ALL sites here. ***
    # *** For now, only binbaz.org.sa is implemented in the original code. ***
    # if site != "binbaz.org.sa":
    #     raise HTTPException(status_code=400, detail="Search not implemented for this site yet. Try binbaz.org.sa.")
    # === END OF CRITICAL CODE SECTION ===

    # Placeholder logic for binbaz.org.sa (kept from your original code)
    if site == "binbaz.org.sa":
        # Your existing scraping logic for binbaz.org.sa goes here
        # (omitted for brevity, but assume it returns correct 'out' list)
        
        # Example of the result structure expected by the GPT:
        # out = ["https://binbaz.org.sa/fatwa/...", "https://binbaz.org.sa/article/..."]
        
        search_url = f"https://{site}/search"
        try:
            r = SESSION.get(
                search_url,
                params={"q": q},
                timeout=TIMEOUT_SECONDS,
                allow_redirects=True,
                headers=DEFAULT_HEADERS,
            )
            r.raise_for_status()
        except requests.exceptions.RequestException:
            return {"site": site, "q": q, "results": []}

        soup = BeautifulSoup(r.text, "html.parser")
        out = []
        seen = set()
        
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if not href:
                continue

            # keep relevant internal content links
            if href.startswith("/fatwas/") or href.startswith("/categories/") or href.startswith("/articles/"):
                full = urljoin(search_url, href)
            elif href.startswith(f"https://{site}/"):
                full = href
            else:
                continue

            if not domain_ok(full):
                continue

            if full not in seen:
                seen.add(full)
                out.append(full)
                if len(out) >= limit:
                    break

        return {"site": site, "q": q, "results": out}
    
    # If the site is allowed but search is not implemented (i.e., you remove the 400 error but haven't written the code)
    # The GPT will receive this empty result and continue to the next site, which is better than a hard error.
    return {"site": site, "q": q, "results": []}
