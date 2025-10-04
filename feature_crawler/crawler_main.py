# # crawler.py
# import os
# import argparse
# import pandas as pd
# from urllib.parse import urljoin, urlparse
# from bs4 import BeautifulSoup
# from playwright.sync_api import sync_playwright
# from feature_extraction.extractor import FeatureExtractor
# from feature_extraction.utils import normalize_url, safe_name_for_file, detect_url_column

# class Crawler:
#     def __init__(self, max_depth=2, max_pages=5, out_dir="Phishing_Evidences",
#                  render=True, targets=None, both=False):
#         self.max_depth = max_depth
#         self.max_pages = max_pages
#         self.out_dir = out_dir
#         self.render = render
#         self.both = both  # capture both mobile + desktop
#         self.fe = FeatureExtractor(targets=targets)

#     def crawl_domain(self, start_url, target_org="Unknown"):
#         visited = set()
#         to_visit = [(start_url, 0)]
#         results = []

#         with sync_playwright() as p:
#             browser = p.chromium.launch(headless=True, args=["--no-sandbox"])

#             while to_visit and len(results) < self.max_pages:
#                 url, depth = to_visit.pop(0)
#                 if url in visited or depth > self.max_depth:
#                     continue
#                 visited.add(url)

#                 try:
#                     # Default: mobile emulation
#                     mobile_device = p.devices["Pixel 5"]
#                     context = browser.new_context(**mobile_device)
#                     page = context.new_page()
#                     page.goto(url, wait_until="networkidle", timeout=20000)

#                     # Save HAR
#                     har_path = os.path.join(self.out_dir, safe_name_for_file(urlparse(url).netloc) + ".har")
#                     context.tracing.start(title="har", screenshots=True, snapshots=True)
#                     html = page.content()
#                     context.tracing.stop(path=har_path)

#                     # Example JS interaction: try clicking login buttons if present
#                     try:
#                         page.click("button[type='submit']")
#                         page.wait_for_load_state("networkidle", timeout=5000)
#                     except Exception:
#                         pass

#                     # Run extractor (mobile)
#                     feat_mobile = self.fe.process(
#                         url, meta={"row_id": len(results)+1, "target_org": target_org}, render=self.render
#                     )
#                     feat_mobile["target_org"] = target_org
#                     feat_mobile["crawled_url"] = url
#                     feat_mobile["device"] = "mobile"
#                     feat_mobile["har_file"] = har_path
#                     results.append(feat_mobile)
#                     context.close()

#                     # If both requested: run desktop too
#                     if self.both:
#                         context_d = browser.new_context()  # desktop default
#                         page_d = context_d.new_page()
#                         page_d.goto(url, wait_until="networkidle", timeout=20000)
#                         from feature_extraction.image_utils import render_screenshot_and_pdf


                        

#                         feat_desk = self.fe.process(
#                             url, meta={"row_id": len(results)+1, "target_org": target_org}, render=self.render
#                         )
#                         feat_desk["target_org"] = target_org
#                         feat_desk["crawled_url"] = url
#                         feat_desk["device"] = "desktop"
#                         results.append(feat_desk)
#                         context_d.close()

#                     # Parse links for further crawling
#                     soup = BeautifulSoup(html, "lxml")
#                     for a in soup.find_all("a", href=True):
#                         new_url = urljoin(url, a["href"])
#                         if urlparse(new_url).netloc == urlparse(start_url).netloc:
#                             to_visit.append((new_url, depth+1))

#                 except Exception as e:
#                     results.append({"crawled_url": url, "error": str(e)})

#             browser.close()
#         return results

# def crawl_from_file(input_path, output_csv, max_depth=2, max_pages=5, render=True,
#                     url_col=None, targets=None, both=False, limit=None):
#     df = pd.read_excel(input_path) if input_path.lower().endswith(".xlsx") else pd.read_csv(input_path)
#     if url_col is None:
#         url_col = detect_url_column(df)
#     urls = df[url_col].dropna().astype(str).tolist()
#     if limit:
#         urls = urls[:limit]

#     all_rows = []
#     crawler = Crawler(max_depth=max_depth, max_pages=max_pages,
#                       render=render, targets=targets, both=both)
#     for i, u in enumerate(urls):
#         print(f"[{i+1}/{len(urls)}] Crawling {u}")
#         rows = crawler.crawl_domain(normalize_url(u), target_org="Unknown")
#         all_rows.extend(rows)
#     out_df = pd.DataFrame(all_rows)
#     out_df.to_csv(output_csv, index=False)
#     print("Saved:", output_csv)

# if __name__ == "__main__":
#     parser = argparse.ArgumentParser()
#     parser.add_argument("input", help="Input URL or CSV/XLSX of URLs")
#     parser.add_argument("output_csv", help="Output CSV file")
#     parser.add_argument("--max-depth", type=int, default=2)
#     parser.add_argument("--max-pages", type=int, default=5)
#     parser.add_argument("--no-render", action="store_true")
#     parser.add_argument("--both", action="store_true", help="Capture both desktop and mobile")
#     parser.add_argument("--url-col", default=None)
#     parser.add_argument("--limit", type=int, default=None, help="Limit number of input URLs (demo/testing)")
#     args = parser.parse_args()

#     if args.input.lower().startswith("http"):
#         c = Crawler(max_depth=args.max_depth, max_pages=args.max_pages,
#                     render=not args.no_render, both=args.both)
#         rows = c.crawl_domain(args.input)
#         pd.DataFrame(rows).to_csv(args.output_csv, index=False)
#         print("Saved", args.output_csv)
#     else:
#         crawl_from_file(args.input, args.output_csv,
#                         max_depth=args.max_depth, max_pages=args.max_pages,
#                         render=not args.no_render, url_col=args.url_col,
#                         both=args.both, limit=args.limit)
import os
import argparse
import pandas as pd
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright
#from crawler.extractor import FeatureExtractor
from feature_crawler.utils import normalize_url, safe_name_for_file, detect_url_column
from feature_crawler.image_utils import render_screenshot_and_pdf
from feature_crawler.persistence import ensure_db
from feature_crawler.extractor2 import FeatureExtractor


class Crawler:
    def __init__(self, max_depth=2, max_pages=5, out_dir="Phishing_Evidences",
                 render=True, targets=None, both=False):
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.out_dir = out_dir
        self.render = render
        self.both = both  # capture both desktop + mobile
        ensure_db()  # Ensure DB is set up
        self.fe = FeatureExtractor(targets=targets, evidence_dir= self.out_dir)
    def _har_path(self, url, device, idx):
        fname = f"{safe_name_for_file(urlparse(url).netloc)}_{device}_{idx}.zip"
        return os.path.join(self.out_dir, fname)
    def crawl_domain(self, start_url, target_org="Unknown"):
        visited = set()
        to_visit = [(start_url, 0)]
        results = []

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=["--no-sandbox"])

            while to_visit and len(results) < self.max_pages:
                url, depth = to_visit.pop(0)
                if url in visited or depth > self.max_depth:
                    continue
                visited.add(url)

                try:
                    # --- Mobile context ---
                    mobile_device = p.devices["Pixel 5"]
                    context = browser.new_context(**mobile_device)

                    har_path = self._har_path(url, "mobile", len(results)+1)
                    context.tracing.start(title="har", screenshots=True, snapshots=True)

                    page = context.new_page()
                    page.goto(url, wait_until="networkidle", timeout=20000)
                    
                    # Stop trace & save HAR
                    context.tracing.stop(path=har_path)

                    # Capture mobile screenshot + PDF
                    screenshot_info = {}
                    if self.render:
                        screenshot_info = render_screenshot_and_pdf(
                            url,
                            out_dir=self.out_dir,
                            base_name=safe_name_for_file(urlparse(url).netloc) + f"_mobile_{len(results)+1}",
                            page=page
                        )

                    feat_mobile = self.fe.process(
                        url, meta={"row_id": len(results)+1, "target_org": target_org},
                        page = page,
                        render=False
                    )
                    feat_mobile.update(screenshot_info)
                    feat_mobile["target_org"] = target_org
                    feat_mobile["crawled_url"] = url
                    feat_mobile["device"] = "mobile"
                    feat_mobile["har_file"] = har_path
                    results.append(feat_mobile)
                    context.close()

                    # --- Desktop context (if --both) ---
                    if self.both:
                        context_d = browser.new_context()  # default = desktop
                        har_path_d = self._har_path(url, "desktop", len(results)+1)
                        context_d.tracing.start(title="har", screenshots=True, snapshots=True)

                        page_d = context_d.new_page()
                        page_d.goto(url, wait_until="networkidle", timeout=20000)

                        context_d.tracing.stop(path=har_path_d)

                        screenshot_info_d = {}
                        if self.render:
                            screenshot_info_d = render_screenshot_and_pdf(
                                url,
                                out_dir=self.out_dir,
                                base_name=safe_name_for_file(urlparse(url).netloc) + f"_desktop_{len(results)+1}",
                                page=page_d
                            )

                        feat_desk = self.fe.process(
                            url, meta={"row_id": len(results)+1, "target_org": target_org}, page= page_d, render=False
                        )
                        feat_desk.update(screenshot_info_d)
                        feat_desk["target_org"] = target_org
                        feat_desk["crawled_url"] = url
                        feat_desk["device"] = "desktop"
                        feat_desk["har_file"] = har_path_d
                        results.append(feat_desk)
                        context_d.close()

                    # Parse links for further crawling
                    soup = BeautifulSoup(page.content(), "lxml")
                    for a in soup.find_all("a", href=True):
                        new_url = urljoin(url, a["href"])
                        if urlparse(new_url).netloc == urlparse(start_url).netloc:
                            to_visit.append((new_url, depth+1))

                except Exception as e:
                    results.append({"crawled_url": url, "error": str(e)})

            browser.close()
        return results


def crawl_from_file(input_path, output_csv, max_depth=2, max_pages=5, render=True,
                    url_col=None, targets=None, both=False, limit=None):
    df = pd.read_excel(input_path) if input_path.lower().endswith(".xlsx") else pd.read_csv(input_path)
    if url_col is None:
        url_col = detect_url_column(df)
    urls = df[url_col].dropna().astype(str).tolist()
    if limit:
        urls = urls[:limit]

    all_rows = []
    crawler = Crawler(max_depth=max_depth, max_pages=max_pages,
                      render=render, targets=targets, both=both)
    for i, u in enumerate(urls):
        print(f"[{i+1}/{len(urls)}] Crawling {u}")
        rows = crawler.crawl_domain(normalize_url(u), target_org="Unknown")
        all_rows.extend(rows)
    out_df = pd.DataFrame(all_rows)
    out_df.to_csv(output_csv, index=False)
    print("Saved:", output_csv)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("input", help="Input URL or CSV/XLSX of URLs")
    parser.add_argument("output_csv", help="Output CSV file")
    parser.add_argument("--max-depth", type=int, default=2)
    parser.add_argument("--max-pages", type=int, default=5)
    parser.add_argument("--no-render", action="store_true")
    parser.add_argument("--both", action="store_true", help="Capture both desktop and mobile")
    parser.add_argument("--url-col", default=None)
    parser.add_argument("--limit", type=int, default=None, help="Limit number of input URLs (demo/testing)")
    args = parser.parse_args()

    if args.input.lower().startswith("http"):
        c = Crawler(max_depth=args.max_depth, max_pages=args.max_pages,
                    render=not args.no_render, both=args.both)
        rows = c.crawl_domain(args.input)
        pd.DataFrame(rows).to_csv(args.output_csv, index=False)
        print("Saved", args.output_csv)
    else:
        crawl_from_file(args.input, args.output_csv,
                        max_depth=args.max_depth, max_pages=args.max_pages,
                        render=not args.no_render, url_col=args.url_col,
                        both=args.both, limit=args.limit)
