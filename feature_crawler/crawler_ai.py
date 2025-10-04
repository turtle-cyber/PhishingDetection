import os
import argparse
import pandas as pd
import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import asyncio
import datetime
from crawl4ai import AsyncWebCrawler
from crawl4ai.async_configs import BrowserConfig, CrawlerRunConfig
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from feature_crawler.extractor import FeatureExtractor
from feature_crawler.utils import normalize_url, detect_url_column, safe_name_for_file
from PIL import Image
import io, imagehash, hashlib


def save_favicon(url, html, out_dir, base_name):
    """Extract favicon link, download it, compute hashes, and save locally."""
    fav_info = {
        "favicon_present": False,
        "favicon_md5": "",
        "favicon_phash": "",
        "favicon_path": "",
        "favicon_error": ""
    }
    try:
        soup = BeautifulSoup(html or "", "lxml")
        icon_link = None
        for tag in soup.find_all("link", rel=True):
            rel = " ".join(tag.get("rel", [])).lower()
            if "icon" in rel:
                icon_link = tag.get("href")
                break
        if not icon_link:
            parsed = urlparse(url)
            icon_link = f"{parsed.scheme}://{parsed.netloc}/favicon.ico"

        icon_url = urljoin(url, icon_link)
        r = requests.get(icon_url, timeout=8)
        if r.status_code == 200 and r.content:
            os.makedirs(out_dir, exist_ok=True)
            ext = ".ico" if icon_url.endswith(".ico") else ".png"
            fav_path = os.path.join(out_dir, f"{base_name}_favicon{ext}")
            with open(fav_path, "wb") as f:
                f.write(r.content)

            img = Image.open(io.BytesIO(r.content)).convert("RGB")
            ph = str(imagehash.phash(img))
            fav_info["favicon_present"] = True
            fav_info["favicon_phash"] = ph
            fav_info["favicon_md5"] = hashlib.md5(r.content).hexdigest()
            fav_info["favicon_path"] = os.path.abspath(fav_path)
            print(f"[+] Favicon saved: {fav_path}")
    except Exception as e:
        fav_info["favicon_error"] = str(e)
        print(f"[!] Favicon fetch failed for {url}: {e}")
    return fav_info


async def crawl_single_url(url, device_name, browser_config, run_config, fe, out_dir, i):
    """Crawl a single URL with given configuration."""
    try:
        async with AsyncWebCrawler(config=browser_config) as crawler:
            result = await crawler.arun(url=url, config=run_config)

            # Base name for evidence files
            domain_safe = safe_name_for_file(urlparse(url).netloc)
            base_name = f"{domain_safe}_{device_name}_{i+1}"

            # Save screenshot, PDF, HAR
            screenshot_path, pdf_path, har_path = "", "", ""
            if result.screenshot:
                screenshot_path = os.path.join(out_dir, base_name + ".png")
                with open(screenshot_path, "wb") as f:
                    f.write(result.screenshot)

            if hasattr(result, "pdf") and result.pdf:
                pdf_path = os.path.join(out_dir, base_name + ".pdf")
                with open(pdf_path, "wb") as f:
                    f.write(result.pdf)

            if hasattr(result, "har") and result.har:
                har_path = os.path.join(out_dir, base_name + ".har")
                with open(har_path, "w", encoding="utf-8") as f:
                    f.write(result.har)

            # Save favicon
            favicon_info = save_favicon(url, result.html or "", out_dir, base_name)

            # Run phishing feature extractor
            feat = fe.process(url, meta={"row_id": i+1}, render=False)
            feat["device"] = device_name
            feat["crawled_url"] = url
            feat["evidence_png"] = screenshot_path
            feat["evidence_pdf"] = pdf_path
            feat["har_file"] = har_path
            feat["page_text"] = result.html or ""
            feat.update(favicon_info)

            return feat

    except Exception as e:
        return {
            "crawled_url": url,
            "device": device_name,
            "error": str(e)
        }


async def crawl_urls_async(input_file, output_csv, url_col=None, both=False, limit=None, out_dir="Phishing_Evidences"):
    # Timestamped evidence folder
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    out_dir = os.path.join(out_dir, timestamp)
    os.makedirs(out_dir, exist_ok=True)

    df = pd.read_excel(input_file) if input_file.lower().endswith(".xlsx") else pd.read_csv(input_file)
    if url_col is None:
        url_col = detect_url_column(df)
    urls = df[url_col].dropna().astype(str).tolist()
    if limit:
        urls = urls[:limit]

    fe = FeatureExtractor()

    configs = []
    # Mobile configuration
    mobile_browser_cfg = BrowserConfig(
        headless=True,
        viewport_width=393,
        viewport_height=851,
        user_agent="Mozilla/5.0 (Linux; Android 12; Pixel 5) AppleWebKit/537.36"
    )
    mobile_run_cfg = CrawlerRunConfig(
        screenshot=True,
        pdf=False,
        #record_har=True,
        wait_until="networkidle"
    )
    configs.append(("mobile", mobile_browser_cfg, mobile_run_cfg))

    if both:
        desktop_browser_cfg = BrowserConfig(
            headless=True,
            viewport_width=1920,
            viewport_height=1080
        )
        desktop_run_cfg = CrawlerRunConfig(
            screenshot=True,
            pdf=False,
            #record_har=True,
            wait_until="networkidle"
        )
        configs.append(("desktop", desktop_browser_cfg, desktop_run_cfg))

    all_rows = []
    for i, u in enumerate(urls):
        url = normalize_url(u)
        print(f"[{i+1}/{len(urls)}] Crawling {url}")

        for device_name, browser_cfg, run_cfg in configs:
            result = await crawl_single_url(url, device_name, browser_cfg, run_cfg, fe, out_dir, i)
            all_rows.append(result)

    out_df = pd.DataFrame(all_rows)
    out_df.to_csv(output_csv, index=False)
    print(f"✅ Saved {len(out_df)} rows → {output_csv}")
    print(f"📂 Evidence folder: {out_dir}")


def crawl_urls(input_file, output_csv, url_col=None, both=False, limit=None, out_dir="Phishing_Evidences"):
    """Wrapper to run async function."""
    asyncio.run(crawl_urls_async(input_file, output_csv, url_col, both, limit, out_dir))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("input", help="Input Excel/CSV of URLs")
    parser.add_argument("output", help="Output CSV")
    parser.add_argument("--url-col", default=None)
    parser.add_argument("--both", action="store_true", help="Capture both mobile & desktop")
    parser.add_argument("--limit", type=int, default=None, help="Limit number of URLs (for demo)")
    args = parser.parse_args()

    crawl_urls(args.input, args.output, url_col=args.url_col, both=args.both, limit=args.limit)
