# detections.py
import re
from rapidfuzz.distance import Levenshtein
import unicodedata
import json
import os

# Load provider + parked phrase lists
CONFIG_FILE = os.path.join(os.path.dirname(__file__), "config_providers.json")
with open(CONFIG_FILE, "r") as f:
    CONFIG = json.load(f)

TUNNELING_PROVIDERS = CONFIG["tunneling_providers"]
PARKING_PHRASES = [p.lower() for p in CONFIG["parking_phrases"]]

def detect_tunneling(domain, cname_chain="", tls_san_list=None):
    """
    Detect tunneling/CDN domains by matching hostnames, CNAMEs, and TLS SANs.
    """
    domain = domain.lower()
    if any(domain.endswith(p) for p in TUNNELING_PROVIDERS):
        return True
    if cname_chain:
        if any(p in cname_chain.lower() for p in TUNNELING_PROVIDERS):
            return True
    if tls_san_list:
        if any(any(p in san.lower() for p in TUNNELING_PROVIDERS) for san in tls_san_list):
            return True
    return False

def detect_parked(page_text, html_length, domain_age_days=None):
    """
    Detect parked domains using heuristics:
    - very short content
    - presence of parking phrases
    - newly registered domains
    """
    if not page_text:
        return True
    text = page_text.lower()
    if any(p in text for p in PARKING_PHRASES):
        return True
    if html_length < 500:  # small HTML size
        return True
    if domain_age_days is not None and domain_age_days <= 7:
        return True
    return False

def normalize_unicode(domain):
    """
    Normalize Unicode domain to detect homoglyphs (IDN).
    """
    return unicodedata.normalize("NFKC", domain)

def detect_lookalike(domain, cse_domains, max_edit_distance=2):
    """
    Detect lookalike domains using edit distance and homoglyph normalization.
    """
    domain_norm = normalize_unicode(domain)
    for legit in cse_domains:
        legit_norm = normalize_unicode(legit)
        dist = Levenshtein.distance(domain_norm, legit_norm)
        if dist <= max_edit_distance:
            return True
        if legit_norm in domain_norm:  # contains brand token
            return True
    return False
