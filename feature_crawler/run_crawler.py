# # run_crawler.py
# # Example usage:
# # python run_crawler.py input_urls.xlsx output_all.csv --max-depth 2 --max-pages 5

# import argparse
# from feature_extraction.crawler import crawl_from_file

# if __name__ == "__main__":
#     parser = argparse.ArgumentParser()
#     parser.add_argument("input")
#     parser.add_argument("output")
#     parser.add_argument("--max-depth", type=int, default=2)
#     parser.add_argument("--max-pages", type=int, default=5)
#     parser.add_argument("--no-render", action="store_true")
#     parser.add_argument("--url-col", default=None)
#     args = parser.parse_args()
#     crawl_from_file(args.input, args.output, max_depth=args.max_depth, max_pages=args.max_pages, render=not args.no_render, url_col=args.url_col)
# run_crawler.py
# Usage example:
# python -m feature_extraction.run_crawler input.xlsx output.csv --max-depth 2 --max-pages 3 --both

import argparse
from feature_crawler.crawler_main import crawl_from_file
import sys
from pathlib import Path

# # Add project root to path
# project_root = Path(__file__).parent.parent
# sys.path.insert(0, str(project_root))
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("input", help="Input file (Excel/CSV with URLs)")
    parser.add_argument("output", help="Output CSV file")
    parser.add_argument("--max-depth", type=int, default=2, help="Maximum crawl depth")
    parser.add_argument("--max-pages", type=int, default=5, help="Maximum pages per domain")
    parser.add_argument("--no-render", action="store_true", help="Skip screenshots and PDFs")
    parser.add_argument("--url-col", default=None, help="Column name for URLs (if not auto-detected)")
    parser.add_argument("--both", action="store_true", help="Capture both mobile and desktop")
    parser.add_argument("--limit", type=int, default=None, help="Limit number of input URLs (demo/testing)")
    args = parser.parse_args()

    crawl_from_file(
        args.input,
        args.output,
        max_depth=args.max_depth,
        max_pages=args.max_pages,
        render=not args.no_render,
        url_col=args.url_col,
        both=args.both,
        limit=args.limit,
    )
