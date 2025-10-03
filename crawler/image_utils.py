#======== The following code is commented out. This is for static url only. ========#

# # image_utils.py
# import os, io
# from urllib.parse import urljoin, urlparse
# import requests
# from PIL import Image
# import imagehash
# from bs4 import BeautifulSoup
# from playwright.sync_api import sync_playwright


# def fetch_favicon(url, timeout=8, out_dir="Phishing_Evidences"):
#     """
#     Download favicon, compute hash, and also save it locally.
#     Returns dict with presence, hashes, and file path.
#     """
#     res = {
#         "favicon_present": False,
#         "favicon_md5": "",
#         "favicon_phash": "",
#         "favicon_path": "",
#         "favicon_error": ""
#     }
#     try:
#         import hashlib
#         r = requests.get(url, timeout=timeout)
#         soup = BeautifulSoup(r.content, "lxml")
#         icon_link = None
#         # find common link rels
#         for tag in soup.find_all("link", rel=True):
#             rel = " ".join(tag.get("rel", []))
#             if "icon" in rel or "shortcut icon" in rel:
#                 icon_link = tag.get("href")
#                 break
#         if not icon_link:
#             parsed = urlparse(r.url)
#             icon_link = f"{parsed.scheme}://{parsed.netloc}/favicon.ico"

#         icon_url = urljoin(r.url, icon_link)
#         ir = requests.get(icon_url, timeout=timeout)
#         if ir.status_code == 200 and ir.content:
#             os.makedirs(out_dir, exist_ok=True)
#             safe_domain = urlparse(url).netloc.replace(":", "_")
#             fav_path = os.path.abspath(os.path.join(out_dir, f"{safe_domain}_favicon.ico"))

#             # Save favicon to disk
#             with open(fav_path, "wb") as f:
#                 f.write(ir.content)

#             # Compute hashes
#             img = Image.open(io.BytesIO(ir.content)).convert("RGB")
#             ph = str(imagehash.phash(img))
#             res["favicon_present"] = True
#             res["favicon_phash"] = ph
#             res["favicon_md5"] = hashlib.md5(ir.content).hexdigest()
#             res["favicon_path"] = fav_path

#             print(f"[+] Favicon saved: {fav_path}")

#     except Exception as e:
#         res["favicon_error"] = str(e)
#         print(f"[!] Favicon fetch failed for {url}: {e}")

#     return res


# def render_screenshot_and_pdf(url, out_dir="Phishing_Evidences", base_name=None, timeout=20, page=None):
#     """
#     Capture screenshot + PDF. If a Playwright `page` is provided (from crawler),
#     reuse it. Otherwise launch a temporary browser.
#     """
#     out = {"evidence_png": "", "evidence_pdf": "", "screenshot_phash": "", "screenshot_error": ""}
#     os.makedirs(out_dir, exist_ok=True)

#     from urllib.parse import urlparse
#     import imagehash, io
#     from PIL import Image

#     if base_name is None:
#         parsed = urlparse(url)
#         base_name = parsed.netloc.replace(":", "_")

#     png_path = os.path.abspath(os.path.join(out_dir, base_name + ".png"))
#     pdf_path = os.path.abspath(os.path.join(out_dir, base_name + ".pdf"))

#     try:
#         if page:  # ✅ reuse crawler's Playwright page
#             img_bytes = page.screenshot(full_page=True, path=png_path)
#             page.pdf(path=pdf_path, format="A4")
#         else:     # fallback: launch temporary browser
#             from playwright.sync_api import sync_playwright
#             with sync_playwright() as p:
#                 browser = p.chromium.launch(headless=True, args=["--no-sandbox"])
#                 context = browser.new_context()
#                 page = context.new_page()
#                 page.set_default_timeout(timeout * 1000)
#                 page.goto(url, wait_until="networkidle")
#                 img_bytes = page.screenshot(full_page=True, path=png_path)
#                 page.pdf(path=pdf_path, format="A4")
#                 context.close()
#                 browser.close()

#         # compute perceptual hash
#         img = Image.open(io.BytesIO(img_bytes)).convert("RGB")
#         out["screenshot_phash"] = str(imagehash.phash(img))
#         out["evidence_png"] = png_path
#         out["evidence_pdf"] = pdf_path

#         print(f"[+] Evidence saved: {png_path}, {pdf_path}")

#     except Exception as e:
#         out["screenshot_error"] = str(e)
#         print(f"[!] Screenshot failed for {url}: {e}")

#     return out

# crawler/image_utils.py
import os, io, time
from urllib.parse import urlparse
from PIL import Image
import imagehash

RUN_EVIDENCE_DIR = os.environ.get("PHISHING_EVIDENCE_DIR", "Phishing_Evidences")

def safe_mkdir(d):
    os.makedirs(d, exist_ok=True)
    return d

def _abs_path(out_dir, fname):
    return os.path.abspath(os.path.join(out_dir, fname))

def render_screenshot_and_pdf(url, out_dir=None, base_name=None, page=None, timeout=20):
    """
    If `page` (Playwright page object) is provided, reuse it; otherwise
    spawn a short-lived browser (fallback).
    Returns dict with evidence_png, evidence_pdf, screenshot_phash, screenshot_error.
    """
    out_dir = out_dir or RUN_EVIDENCE_DIR
    safe_mkdir(out_dir)
    parsed = urlparse(url)
    base = base_name or parsed.netloc.replace(":", "_")
    png_path = _abs_path(out_dir, f"{base}.png")
    pdf_path = _abs_path(out_dir, f"{base}.pdf")
    res = {"evidence_png": "", "evidence_pdf": "", "screenshot_phash": "", "screenshot_error": ""}
    try:
        if page:
            # use existing Playwright page
            img_bytes = page.screenshot(full_page=True, path=png_path)
            try:
                page.pdf(path=pdf_path, format="A4")
            except Exception:
                # some contexts may not support pdf on all platforms
                pass
        else:
            # fallback: launch temporary browser
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True, args=["--no-sandbox"])
                ctx = browser.new_context()
                pg = ctx.new_page()
                pg.goto(url, wait_until="networkidle", timeout=timeout*1000)
                img_bytes = pg.screenshot(full_page=True, path=png_path)
                try:
                    pg.pdf(path=pdf_path, format="A4")
                except Exception:
                    pass
                ctx.close()
                browser.close()
        # compute phash
        if isinstance(img_bytes, (bytes, bytearray)):
            img = Image.open(io.BytesIO(img_bytes)).convert("RGB")
        else:
            img = Image.open(png_path).convert("RGB")
        res["screenshot_phash"] = str(imagehash.phash(img))
        res["evidence_png"] = png_path if os.path.exists(png_path) else ""
        res["evidence_pdf"] = pdf_path if os.path.exists(pdf_path) else ""
    except Exception as e:
        res["screenshot_error"] = str(e)
    return res

# Favicon fetch that also saves the file
def fetch_favicon(url, out_dir=None, timeout=8):
    from bs4 import BeautifulSoup
    import requests, hashlib
    out_dir = out_dir or RUN_EVIDENCE_DIR
    safe_mkdir(out_dir)
    res = {"favicon_present": False, "favicon_md5": "", "favicon_phash": "", "favicon_path": "", "favicon_error": ""}
    try:
        r = requests.get(url, timeout=timeout)
        soup = BeautifulSoup(r.content, "lxml")
        icon_link = None
        for tag in soup.find_all("link", rel=True):
            rel = " ".join(tag.get("rel", []))
            if "icon" in rel:
                icon_link = tag.get("href")
                break
        if not icon_link:
            parsed = urlparse(r.url)
            icon_link = f"{parsed.scheme}://{parsed.netloc}/favicon.ico"
        icon_url = requests.compat.urljoin(r.url, icon_link)
        ir = requests.get(icon_url, timeout=timeout)
        if ir.status_code == 200 and ir.content:
            safe_mkdir(out_dir)
            safe_domain = urlparse(url).netloc.replace(":", "_")
            fav_path = _abs_path(out_dir, f"{safe_domain}_favicon")
            # guess extension from content-type
            ct = ir.headers.get("Content-Type","").lower()
            if "png" in ct:
                fav_path += ".png"
            else:
                fav_path += ".ico"
            with open(fav_path, "wb") as f:
                f.write(ir.content)
            # compute hashes
            img = Image.open(io.BytesIO(ir.content)).convert("RGB")
            res["favicon_present"] = True
            res["favicon_phash"] = str(imagehash.phash(img))
            res["favicon_md5"] = hashlib.md5(ir.content).hexdigest()
            res["favicon_path"] = fav_path
    except Exception as e:
        res["favicon_error"] = str(e)
    return res
def compute_phash(path_or_bytes):
    """Return perceptual hash string for an image path or bytes."""
    if isinstance(path_or_bytes, (bytes, bytearray)):
        from io import BytesIO
        img = Image.open(BytesIO(path_or_bytes)).convert("RGB")
    else:
        img = Image.open(path_or_bytes).convert("RGB")
    return str(imagehash.phash(img))    
