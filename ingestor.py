#!/usr/bin/env python3

import requests
import urllib3
import re
from datetime import datetime
from bs4 import BeautifulSoup
from pymisp import PyMISP, MISPEvent

# Import credentials from our local config
try:
    import config
    MISP_URL = config.MISP_URL
    MISP_KEY = config.MISP_KEY
    VERIFY_SSL = config.VERIFY_SSL
except ImportError:
    print("[ERROR] config.py not found. Please copy config.py.example to config.py")
    exit(1)

urllib3.disable_warnings()

misp = PyMISP(MISP_URL, MISP_KEY, ssl=VERIFY_SSL)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) MISP-AusCERT-Ingestor/1.0"
}

# ================= UTIL =================

def log(msg):
    print(f"[{datetime.now()}] {msg}")

def safe_request(url):
    try:
        r = requests.get(url, headers=HEADERS, timeout=20, verify=False)
        if r.status_code != 200:
            log(f"[ERROR] {url} → {r.status_code}")
            return None
        return r
    except Exception as e:
        log(f"[ERROR] {url} → {e}")
        return None

# ================= IOC EXTRACTION =================

def extract_iocs(text):
    results = []

    # IP
    ips = re.findall(r'(?:\d{1,3}\.){3}\d{1,3}', text)

    # Domain
    domains = re.findall(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b', text)

    # Hash
    hashes = re.findall(r'\b[a-fA-F0-9]{32,64}\b', text)

    for ip in ips:
        results.append(("ip-dst", ip))

    for d in domains:
        if not d.endswith((".png", ".jpg", ".css", ".js", ".html", ".php")):
            results.append(("domain", d))

    for h in hashes:
        if len(h) == 32:
            results.append(("md5", h))
        elif len(h) == 40:
            results.append(("sha1", h))
        elif len(h) == 64:
            results.append(("sha256", h))

    return results

# ================= DEDUP =================

local_seen = set()

def is_new_ioc(value):
    if value in local_seen:
        return False

    try:
        res = misp.search(controller="attributes", value=value)
        if res.get("Attribute"):
            return False
    except Exception as e:
        log(f"[WARN] Dedup failed: {value} → {e}")

    local_seen.add(value)
    return True

# ================= SCORING =================

def score_intel(text):
    score = 0
    t = text.lower()

    if "critical" in t: score += 50
    if "ransomware" in t: score += 40
    if "malware" in t: score += 30
    if "exploit" in t: score += 20

    return score

# ================= EVENT =================

def create_event(title, attributes):
    if not attributes:
        log(f"[SKIPPED] No new IOCs for {title}")
        return

    event = MISPEvent()
    event.info = title
    event.distribution = 3 # All communities
    event.threat_level_id = 2 # Medium
    event.analysis = 0 # Initial

    try:
        event = misp.add_event(event, pythonify=True)
    except Exception as e:
        log(f"[ERROR] Event create failed: {e}")
        return

    for attr_type, value, comment in attributes:
        try:
            event.add_attribute(attr_type, value, comment=comment)
        except Exception as e:
            log(f"[ERROR] Attribute fail: {value} → {e}")

    try:
        misp.update_event(event)
    except Exception as e:
        log(f"[ERROR] Event update failed: {e}")

    # Tagging
    for tag in ["osint", "source:auscert", "country:AU", "tlp:white"]:
        try:
            misp.tag(event.uuid, tag)
        except:
            log(f"[TAG FAIL] {tag}")

    log(f"[+] Event {event.id} created/updated with {len(attributes)} IOCs")

# ================= FETCH AUSCERT =================

def fetch_auscert():
    log("[*] Fetching AusCERT data")
    base_url = "https://www.auscert.org.au/advisories/"
    r = safe_request(base_url)

    if not r:
        log("[*] Fallback → Homepage scraping")
        r = safe_request("https://www.auscert.org.au/")
        if not r: return

    soup = BeautifulSoup(r.text, "html.parser")
    seen_links = set()
    final_attributes = []

    for link in soup.find_all("a", href=True):
        href = link["href"]
        if not href.startswith("http") or "auscert.org.au" not in href:
            continue

        if href in seen_links:
            continue
        seen_links.add(href)

        page = safe_request(href)
        if not page: continue

        text = page.text
        iocs = extract_iocs(text)
        score = score_intel(text)

        for ioc_type, value in iocs:
            if not is_new_ioc(value):
                continue

            final_attributes.append((
                ioc_type,
                value,
                f"AusCERT | {href} | Score:{score}"
            ))

    create_event(f"AusCERT IOC Feed - {datetime.now().strftime('%Y-%m-%d')}", final_attributes)

# ================= MAIN =================

def main():
    log("===== START AUSCERT IOC PIPELINE =====")
    fetch_auscert()
    log("===== END =====")

if __name__ == "__main__":
    main()
