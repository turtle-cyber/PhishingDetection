# utils.py
import re
import tldextract

def detect_url_column(df):
    candidates = [c for c in df.columns if re.search(r"url|link|domain|website|site", c, re.I)]
    if candidates:
        return candidates[0]
    return df.columns[0]

def normalize_url(raw):
    raw = raw.strip()
    if not raw:
        return ""
    if not re.match(r"^https?://", raw):
        raw = "http://" + raw
    return raw
from playwright.sync_api import sync_playwright
import imagehash
from PIL import Image
import io

def screenshot_and_phash(url, timeout=10):
    res = {}
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, timeout=timeout*1000)
            screenshot_bytes = page.screenshot(full_page=True)
            img = Image.open(io.BytesIO(screenshot_bytes)).convert("RGB")
            ph = str(imagehash.phash(img))
            res["screenshot_phash"] = ph
            browser.close()
    except Exception as e:
        res["screenshot_error"] = str(e)
    return res
