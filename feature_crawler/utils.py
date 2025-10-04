# utils.py
import re
import os
import string
from urllib.parse import urlparse, urlunparse, unquote
import tldextract

def detect_url_column(df):
    candidates = [c for c in df.columns if re.search(r"url|link|domain|website|site", c, re.I)]
    return candidates[0] if candidates else df.columns[0]

def normalize_url(raw):
    if not raw:
        return ""
    u = raw.strip()
    if not re.match(r"^https?://", u, re.I):
        u = "http://" + u
    return u

def safe_name_for_file(s):
    # make filesystem safe string from domain or url
    allowed = "-_.() %s%s" % (string.ascii_letters, string.digits)
    return "".join(c if c in allowed else "_" for c in s)[:240]

def extract_registered_domain(hostname):
    te = tldextract.extract(hostname or "")
    if te.suffix:
        return te.domain + "." + te.suffix
    return te.domain or hostname

import zipfile, shutil
def package_evidence(run_dir):
    zip_name = run_dir.rstrip("/\\") + ".zip"
    shutil.make_archive(run_dir, 'zip', run_dir)
    return zip_name
