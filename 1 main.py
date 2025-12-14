import os
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
from fastapi import FastAPI, Header, HTTPException

ALLOW = {
  "alifta.gov.sa","binbaz.org.sa","binothaimeen.net","alfawzan.af.org.sa",
  "alalbani.info","sualruhaily.com","rabee.net","miraath.net","al-badr.net",
  "alnajmi.net","muqbel.net","lohaidan.af.org.sa","home.ajurry.com"
}
DENY = {
  "islamqa.org","islamweb.net","sajidine.com","ecolemalikite.com","doctrine-malikite.fr",
  "at-tawhid.net","ecolehanafite.com","al-hanz.org","islametinfo.fr","katibin.fr","alnas.fr",
  "oumma.com","islamophile.org","dourous.net","dammaj-fr.com","aloloom-fr.com","islamsunnite.net",
  "sunnisme.com","apbif.fr","yabiladi.com","youtube.com","facebook.com"
}

def domain_ok(url: str) -> bool:
    d = urlparse(url).netloc.lower().lstrip("www.")
    if any(d == x or d.endswith("." + x) for x in DENY):
        return False
    return any(d == x or d.endswith("." + x) for x in ALLOW)

APP_KEY = os.environ.get("APP_KEY", "")

app = FastAPI(title="Salafi Source Gate", version="1.0.0")

def require_key(x_api_key: str | None):
    if not APP_KEY:
        raise HTTPException(500, "Server misconfigured: APP_KEY missing")
    if not x_api_key or x_api_key != APP_KEY:
        raise HTTPException(401, "Unauthorized")

def clean_html(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script","style","noscript"]):
        tag.decompose()
    return " ".join(soup.get_text(separator=" ").split())

@app.get("/health")
def health():
    return {"ok": True}

@app.get("/fetch")
def fetch(url: str, x_api_key: str | None = Header(default=None)):
    require_key(x_api_key)

    if not domain_ok(url):
        raise HTTPException(403, "Forbidden domain")

    r = requests.get(url, timeout=20, allow_redirects=True, headers={"User-Agent": "Mozilla/5.0"})
    final_url = r.url
    if not domain_ok(final_url):
        raise HTTPException(403, "Redirected to forbidden domain")

    r.raise_for_status()
    return {"url": final_url, "status": r.status_code, "text": clean_html(r.text)[:200000]}
