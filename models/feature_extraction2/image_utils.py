# image_utils.py
import requests
from urllib.parse import urljoin, urlparse
from PIL import Image
import io, imagehash
from bs4 import BeautifulSoup

# image_utils.py
import os
import re
import io
import base64
import hashlib
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from PIL import Image, ImageStat
import imagehash
from collections import Counter

# Optional: convert SVG->PNG
try:
    import cairosvg
    CAIROSVG_AVAILABLE = True
except Exception:
    CAIROSVG_AVAILABLE = False

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117 Safari/537.36"

def _safe_requests_get(url, timeout=8):
    headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    return requests.get(url, headers=headers, timeout=timeout, stream=True)

def _is_data_uri(href):
    return isinstance(href, str) and href.strip().startswith("data:")

def _decode_data_uri(data_uri):
    # returns bytes and content-type
    m = re.match(r"data:([^;]+)(;base64)?,(.*)$", data_uri, flags=re.I)
    if not m:
        return None, None
    content_type = m.group(1)
    is_base64 = bool(m.group(2))
    data = m.group(3)
    if is_base64:
        raw = base64.b64decode(data)
    else:
        raw = data.encode("utf-8")
    return raw, content_type

def _make_safe_filename(s):
    return re.sub(r"[^A-Za-z0-9_.-]", "_", s)[:200]

def _compute_image_hashes_from_bytes(img_bytes):
    try:
        img = Image.open(io.BytesIO(img_bytes)).convert("RGB")
        ph = str(imagehash.phash(img))
        ah = str(imagehash.average_hash(img))
        dh = str(imagehash.dhash(img))
        w,h = img.size
        return {"phash": ph, "ahash": ah, "dhash": dh, "width": w, "height": h}
    except Exception:
        return {"phash": "", "ahash": "", "dhash": "", "width": 0, "height": 0}

def _compute_color_stats(img_bytes, top_n=3):
    try:
        img = Image.open(io.BytesIO(img_bytes)).convert("RGB")
        # resize small for color quantization
        small = img.resize((64,64))
        pixels = list(small.getdata())
        counts = Counter(pixels)
        top = counts.most_common(top_n)
        top_hex = [f"#{r:02x}{g:02x}{b:02x}" for (r,g,b),_ in top]
        dominant = top_hex[0] if top_hex else ""
        color_count = len(counts)
        return {"top_colors": ",".join(top_hex), "dominant_color": dominant, "color_count": color_count}
    except Exception:
        return {"top_colors": "", "dominant_color": "", "color_count": 0}

def _entropy_bytes(bts):
    if not bts:
        return 0.0
    probs = [n/len(bts) for n in Counter(bts).values()]
    import math
    return -sum(p * math.log2(p) for p in probs)

def _fetch_and_normalize_svg(svg_bytes):
    # If cairosvg available, convert to PNG bytes to compute phash; otherwise fallback to hashing svg bytes.
    if CAIROSVG_AVAILABLE:
        try:
            png_bytes = cairosvg.svg2png(bytestring=svg_bytes)
            return png_bytes, "image/png"
        except Exception:
            return svg_bytes, "image/svg+xml"
    else:
        return svg_bytes, "image/svg+xml"

def discover_favicon_candidates(page_url, html_content=None):
    """
    Returns a list of candidate hrefs (may include data: URIs). If html_content provided,
    parse link tags. Always include root /favicon.ico as fallback.
    """
    candidates = []
    parsed = urlparse(page_url)
    root = f"{parsed.scheme}://{parsed.netloc}"
    # if html provided, parse <link rel> tags
    if html_content:
        soup = BeautifulSoup(html_content, "lxml")
        for tag in soup.find_all("link", href=True):
            rels = " ".join(tag.get("rel", []) or [])
            if "icon" in rels or "shortcut" in rels or "apple-touch-icon" in rels or "mask-icon" in rels:
                href = tag.get("href")
                candidates.append(href)
    # fallback root
    candidates.append(urljoin(root, "/favicon.ico"))
    return candidates

def fetch_favicon_hash(page_url, html_content=None, out_dir="Phishing_Evidences/favicons", timeout=8, ephemeral_patterns=None, attempt_playwright=False):
    """
    Tries multiple favicon candidates, returns dict of fields and saves files where possible.
    """
    os.makedirs(out_dir, exist_ok=True)
    result = {
        "favicon_present": False,
        "favicon_source_type": "none",
        "favicon_candidate_url": "",
        "favicon_fetch_http_status": None,
        "favicon_content_type": "",
        "favicon_file_size_bytes": 0,
        "favicon_md5": "",
        "favicon_sha256": "",
        "favicon_is_data_uri": False,
        "favicon_is_svg": False,
        "favicon_width": 0,
        "favicon_height": 0,
        "favicon_phash": "",
        "favicon_ahash": "",
        "favicon_dhash": "",
        "favicon_entropy": 0.0,
        "favicon_top_colors": "",
        "favicon_dominant_color": "",
        "favicon_color_count": 0,
        "favicon_from_cdn": False,
        "favicon_same_host_as_page": False,
        "favicon_saved_path_raw": "",
        "favicon_saved_path_png": "",
        "favicon_similarity_to_target_phash": "",
        "favicon_similarity_binary": False,
        "favicon_detection_method": "",
        "favicon_error": ""
    }
    try:
        candidates = discover_favicon_candidates(page_url, html_content)
        parsed_page = urlparse(page_url)
        page_host = parsed_page.netloc.lower()
        # iterate candidates
        tried = set()
        for cand in candidates:
            if not cand:
                continue
            # normalize cand to absolute url if not data URI
            if _is_data_uri(cand):
                raw, ctype = _decode_data_uri(cand)
                if not raw:
                    continue
                # save raw
                filename_raw = _make_safe_filename(f"{page_host}_datafavicon")
                raw_path = os.path.join(out_dir, filename_raw + ".bin")
                with open(raw_path, "wb") as f:
                    f.write(raw)
                md5 = hashlib.md5(raw).hexdigest()
                sha256 = hashlib.sha256(raw).hexdigest()
                # if svg
                is_svg = (ctype and 'svg' in ctype.lower())
                if is_svg:
                    png_bytes, ct = _fetch_and_normalize_svg(raw)
                    hashes = _compute_image_hashes_from_bytes(png_bytes)
                    colors = _compute_color_stats(png_bytes)
                else:
                    hashes = _compute_image_hashes_from_bytes(raw)
                    colors = _compute_color_stats(raw)
                result.update({
                    "favicon_present": True,
                    "favicon_source_type": "data_uri",
                    "favicon_candidate_url": "data:",
                    "favicon_fetch_http_status": None,
                    "favicon_content_type": ctype or "",
                    "favicon_file_size_bytes": len(raw),
                    "favicon_md5": md5,
                    "favicon_sha256": sha256,
                    "favicon_is_data_uri": True,
                    "favicon_is_svg": is_svg,
                    "favicon_width": hashes.get("width",0),
                    "favicon_height": hashes.get("height",0),
                    "favicon_phash": hashes.get("phash",""),
                    "favicon_ahash": hashes.get("ahash",""),
                    "favicon_dhash": hashes.get("dhash",""),
                    "favicon_entropy": _entropy_bytes(raw),
                    "favicon_top_colors": colors.get("top_colors",""),
                    "favicon_dominant_color": colors.get("dominant_color",""),
                    "favicon_color_count": colors.get("color_count",0),
                    "favicon_from_cdn": False,
                    "favicon_same_host_as_page": True,
                    "favicon_saved_path_raw": raw_path,
                    "favicon_saved_path_png": ""
                })
                result["favicon_detection_method"] = "data_uri"
                return result

            # make absolute url
            cand_abs = urljoin(page_url, cand)
            if cand_abs in tried:
                continue
            tried.add(cand_abs)
            # fetch
            try:
                r = _safe_requests_get(cand_abs, timeout=timeout)
                status = r.status_code
                result["favicon_fetch_http_status"] = status
                if status != 200:
                    # try next candidate
                    r.close()
                    continue
                raw = r.content
                content_type = r.headers.get("Content-Type","").split(";")[0].lower()
                md5 = hashlib.md5(raw).hexdigest()
                sha256 = hashlib.sha256(raw).hexdigest()
                is_svg = 'svg' in content_type or cand_abs.lower().endswith(".svg")
                if is_svg:
                    raw_norm, ct = _fetch_and_normalize_svg(raw)
                    hashes = _compute_image_hashes_from_bytes(raw_norm)
                    colors = _compute_color_stats(raw_norm)
                    # save normalized png if possible
                    filename_raw = _make_safe_filename(f"{page_host}_favicon")
                    raw_path = os.path.join(out_dir, filename_raw + os.path.splitext(cand_abs)[1] if os.path.splitext(cand_abs)[1] else ".svg")
                    with open(raw_path, "wb") as f:
                        f.write(raw)  # save original svg raw
                    png_path = None
                    if CAIROSVG_AVAILABLE:
                        try:
                            png_bytes = cairosvg.svg2png(bytestring=raw)
                            png_path = os.path.join(out_dir, filename_raw + ".png")
                            with open(png_path, "wb") as f:
                                f.write(png_bytes)
                        except Exception:
                            png_path = None
                else:
                    hashes = _compute_image_hashes_from_bytes(raw)
                    colors = _compute_color_stats(raw)
                    filename_raw = _make_safe_filename(f"{page_host}_favicon")
                    ext = ""
                    # choose extension from content_type
                    if "png" in content_type:
                        ext = ".png"
                    elif "jpeg" in content_type or "jpg" in content_type:
                        ext = ".jpg"
                    elif "gif" in content_type:
                        ext = ".gif"
                    elif "x-icon" in content_type or ".ico" in cand_abs.lower():
                        ext = ".ico"
                    else:
                        ext = os.path.splitext(cand_abs)[1] or ".bin"
                    raw_path = os.path.join(out_dir, filename_raw + ext)
                    with open(raw_path, "wb") as f:
                        f.write(raw)
                    png_path = raw_path if ext.lower() in [".png",".jpg",".jpeg",".gif"] else ""
                # heuristics
                cand_host = urlparse(cand_abs).netloc.lower()
                from_cdn = False
                if ephemeral_patterns:
                    for p in ephemeral_patterns:
                        if p in cand_host:
                            from_cdn = True
                            break
                same_host = (page_host == cand_host)
                # update result
                result.update({
                    "favicon_present": True,
                    "favicon_source_type": "link" if cand_abs else "root",
                    "favicon_candidate_url": cand_abs,
                    "favicon_fetch_http_status": status,
                    "favicon_content_type": content_type,
                    "favicon_file_size_bytes": len(raw),
                    "favicon_md5": md5,
                    "favicon_sha256": sha256,
                    "favicon_is_data_uri": False,
                    "favicon_is_svg": is_svg,
                    "favicon_width": hashes.get("width",0),
                    "favicon_height": hashes.get("height",0),
                    "favicon_phash": hashes.get("phash",""),
                    "favicon_ahash": hashes.get("ahash",""),
                    "favicon_dhash": hashes.get("dhash",""),
                    "favicon_entropy": _entropy_bytes(raw),
                    "favicon_top_colors": colors.get("top_colors",""),
                    "favicon_dominant_color": colors.get("dominant_color",""),
                    "favicon_color_count": colors.get("color_count",0),
                    "favicon_from_cdn": from_cdn,
                    "favicon_same_host_as_page": same_host,
                    "favicon_saved_path_raw": raw_path,
                    "favicon_saved_path_png": png_path or ""
                })
                result["favicon_detection_method"] = "html_link"
                # done (first successful candidate)
                return result
            except Exception as e:
                # try next candidate
                result["favicon_error"] = str(e)
                continue

        # no candidate hit: if attempt_playwright True, try render mode (heavy)
        if attempt_playwright:
            # lightweight attempt: use Playwright to get document icons after JS
            try:
                from playwright.sync_api import sync_playwright
                with sync_playwright() as p:
                    browser = p.chromium.launch(headless=True)
                    page = browser.new_page()
                    page.goto(page_url, timeout=10000, wait_until="domcontentloaded")
                    # query favicons
                    vals = page.eval_on_selector_all("link[rel]", "els => els.map(e => ({rel: e.rel, href: e.href}))")
                    for v in vals:
                        href = v.get("href")
                        if href:
                            # attempt fetch (re-using logic)
                            res_play = fetch_favicon_hash(page_url, html_content=None, out_dir=out_dir, timeout=timeout, ephemeral_patterns=ephemeral_patterns, attempt_playwright=False)
                            if res_play.get("favicon_present"):
                                res_play["favicon_detection_method"] = "playwright"
                                return res_play
                    browser.close()
            except Exception as e:
                result["favicon_error"] = "playwright_err:" + str(e)
        # final result (no favicon found)
        return result
    except Exception as e:
        result["favicon_error"] = str(e)
        return result

from playwright.sync_api import sync_playwright
import imagehash
from PIL import Image
import io

def screenshot_and_phash(url, target_org="Unknown", serial_no=1, out_dir="Phishing_Evidences", timeout=15):
    """
    Render a page, capture full screenshot, save PNG + PDF, return pHash + file paths.
    """
    res = {}
    try:
        os.makedirs(out_dir, exist_ok=True)
        safe_domain = url.replace("http://","").replace("https://","").split("/")[0]
        base_name = f"{target_org}_{safe_domain}_{serial_no}"
        png_path = os.path.join(out_dir, f"{base_name}.png")
        pdf_path = os.path.join(out_dir, f"{base_name}.pdf")

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=["--disable-web-security"])
            page = browser.new_page()
            page.set_default_timeout(timeout * 1000)
            page.goto(url, wait_until="load")

            # Save PNG + PDF
            screenshot_bytes = page.screenshot(full_page=True, path=png_path)
            page.pdf(path=pdf_path, format="A4")

            # Compute perceptual hash
            img = Image.open(io.BytesIO(screenshot_bytes)).convert("RGB")
            ph = str(imagehash.phash(img))

            res["screenshot_phash"] = ph
            res["evidence_png"] = png_path
            res["evidence_pdf"] = pdf_path
            browser.close()
    except Exception as e:
        res["screenshot_error"] = str(e)
    return res

# For screenshot_and_phash: recommended to implement using Playwright (heavy).
