# run_extract.py
import os
import argparse
import pandas as pd
from extractor import FeatureExtractor
from utils import detect_url_column

def main(input_xlsx, output_csv, sheet_name=0, url_col=None, workers=8):
    df = pd.read_excel(input_xlsx, sheet_name=sheet_name, dtype=str)
    if url_col is None:
        url_col = detect_url_column(df)
    urls = df[url_col].fillna("").astype(str).tolist()
    
    fe = FeatureExtractor(workers=workers)
    rows = []
    # if your sheet has a column with authorized CSE domains
    if "AuthorizedDomain" in df.columns:
        cse_domains = df["AuthorizedDomain"].dropna().unique().tolist()
    else:
        cse_domains = []

    for i, url in enumerate(urls):
        try:
            row = fe.process_url(url.strip(), meta={"row_id": i, "source_filename": os.path.basename(input_xlsx), "cse_domains": cse_domains})
            row["original_row_idx"] = i
            rows.append(row)
        except Exception as e:
            rows.append({"original_url": url, "error": str(e), "original_row_idx": i})
    out_df = pd.DataFrame(rows)
    out_df.to_csv(output_csv, index=False)
    print("Saved:", output_csv)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("input_xlsx")
    parser.add_argument("output_csv")
    parser.add_argument("--sheet", default=0)
    parser.add_argument("--url-col", default=None)
    parser.add_argument("--workers", type=int, default=8)
    args = parser.parse_args()
    main(args.input_xlsx, args.output_csv, sheet_name=args.sheet, url_col=args.url_col, workers=args.workers)
