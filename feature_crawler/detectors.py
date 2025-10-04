# detectors.py
import os, yaml, time
from datetime import datetime
from urllib.parse import urlparse
from rapidfuzz.distance import Levenshtein
import math

BASE_DIR = os.path.dirname(__file__)
CFG_PROV = yaml.safe_load(open(os.path.join(BASE_DIR, "config", "providers.yml")))
CFG_TH = yaml.safe_load(open(os.path.join(BASE_DIR, "config", "thresholds.yml")))

EPHEMERAL_PATTERNS = [p for prov in CFG_PROV.get("ephemeral_providers", []) for p in prov.get("patterns", [])]

def is_ephemeral_host(hostname, cname_chain=None, cert_sans=None, asn=None):
    """Detect tunneling/ephemeral hosting via simple pattern match on host & CNAMEs."""
    h = (hostname or "").lower()
    for p in EPHEMERAL_PATTERNS:
        if p in h:
            return True, p
    if cname_chain:
        for c in cname_chain:
            for p in EPHEMERAL_PATTERNS:
                if p in c.lower():
                    return True, p
    if cert_sans:
        for s in cert_sans:
            for p in EPHEMERAL_PATTERNS:
                if p in s.lower():
                    return True, p
    # ASN checks or IP ranges can be added if offline DB available
    return False, None

def detect_parked(html_text, content_length, whois_creation_date):
    phrases = CFG_TH.get("parked", {}).get("parking_phrases", [])
    min_text = CFG_TH.get("parked", {}).get("min_text_length", 200)
    max_content = CFG_TH.get("parked", {}).get("max_content_length", 600)
    recent_days = CFG_TH.get("parked", {}).get("recent_domain_days", 30)
    text = (html_text or "").lower()
    for p in phrases:
        if p in text:
            return True, f"parking_phrase:{p}"
    if content_length and content_length < max_content:
        return True, "small_content"
    if len(text) < min_text:
        return True, "short_text"
    if whois_creation_date:
        try:
            if isinstance(whois_creation_date, str):
                whois_creation_date = datetime.fromisoformat(whois_creation_date)
            days = (datetime.utcnow() - whois_creation_date).days
            if days <= recent_days:
                return True, "recent_registration"
        except Exception:
            pass
    return False, None

def lexical_lookalike(candidate_domain, target_domains):
    """Return best target and normalized edit distance."""
    best = {"target": None, "dist": 9999, "rel": 1.0}
    for t in target_domains:
        d = Levenshtein.distance(candidate_domain, t)
        rel = d / max(1, len(t))
        if d < best["dist"]:
            best = {"target": t, "dist": d, "rel": rel}
    th_abs = CFG_TH.get("lookalike", {}).get("edit_distance_threshold_absolute", 3)
    th_rel = CFG_TH.get("lookalike", {}).get("edit_distance_threshold_rel", 0.25)
    flagged = (best["dist"] <= th_abs) or (best["rel"] <= th_rel)
    return flagged, best
