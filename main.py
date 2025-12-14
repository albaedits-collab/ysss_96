import os
import hmac
import hashlib
import base64
from typing import Optional
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from fastapi import FastAPI, Header, HTTPException


# =========================
# Domain policy
# =========================
ALLOW = {
    "alifta.gov.sa",
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
    """Accepts 'example.com/path' and turns it into 'https://example.com/path'."""
    url = (url or "").strip()
    if not url:
        return url
    p = urlparse(url)
    if not p.scheme:
        return "https://" + url
    return url


def _domain(url: str) -> str:
    url = _normalize_url(url)
    p = urlparse(url)
    d = (p.netloc or "").lower().lstrip("www.")
    return d


def domain_ok(url: str) -> bool:
    d = _domain(url)
    if not d:
        return False
    # BAN first (including subdomains)
    if any(d == x or d.endswith("." + x) for x in DENY):
        return False
    # then ALLOW (including subdomains)
    return any(d == x or d.endswith("." + x) for x in ALLOW)


# =========================
# Auth + signing
# =========================
APP_KEY = os.environ.get("APP_KEY", "").strip()

app = FastAPI(title="Salafi Source Gate", version="1.1.0")


def require_key(x_api_key: Optional[str]) -> None:
    if not APP_KEY:
        raise HTTPException(500, "Server misconfigured: APP_KEY missing")
    if not x_api_key or x_api_key != APP_KEY:
        raise HTTPException(401, "Unauthorized")


def sign_url(u: str) -> str:
    """
    Returns a stable HMAC token for the exact URL.
    Used to prove the URL was produced by /fetch.
    """
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
# Content extraction
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
    if not domain_ok(url):
        raise HTTPException(403, "Forbidden domain")

    r = SESSION.get(
        url,
        timeout=TIMEOUT_SECONDS,
        allow_redirects=True,
        headers=DEFAULT_HEADERS,
    )

    final_url = r.url
    if not domain_ok(final_url):
        raise HTTPException(403, "Redirected to forbidden domain")

    r.raise_for_status()

    # If it looks like HTML, clean it. Otherwise return raw text (still clipped).
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
    if not domain_ok(url):
        return {"ok": False}

    return {"ok": token_ok(url, token)}
