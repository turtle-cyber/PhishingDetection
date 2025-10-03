# # extractor.py
# import re, socket, ssl, json, math, idna
# from urllib.parse import urlparse, unquote
# import tldextract
# import dns.resolver
# import whois
# import requests
# from ipwhois import IPWhois
# from bs4 import BeautifulSoup
# from datetime import datetime
# from collections import Counter
# from .utils import normalize_url, extract_registered_domain, safe_name_for_file
# from .image_utils import fetch_favicon, render_screenshot_and_pdf
# from .detectors import is_ephemeral_host, detect_parked, lexical_lookalike

# # List of suspicious substrings
# SUSPICIOUS_SUBSTRINGS = ["login", "secure", "account", "update", "verify", "banking", "auth", "signin", "password"]

# # Common suspicious JS functions
# SUSPICIOUS_JS = ["eval", "document.write", "atob", "unescape", "fromCharCode", "window.open"]

# # Sensitive file extensions
# SUSPICIOUS_EXTS = [".exe", ".scr", ".zip", ".rar", ".php", ".js", ".apk"]

# # Risky TLDs (can be expanded from OSINT feeds)
# RISKY_TLDS = ["xyz", "top", "click", "work", "loan", "gq", "tk", "cf"]

# def ngram_features(s, n=3):
#     """Return counts of n-grams in a string."""
#     s = re.sub(r"[^a-z0-9]", "", s.lower())
#     grams = [s[i:i+n] for i in range(len(s)-n+1)]
#     return Counter(grams)


# def idn_homoglyph_flag(domain):
#     """Detect if domain is IDN/punycode with possible homoglyphs."""
#     try:
#         decoded = idna.decode(domain)
#         if decoded != domain:
#             return True
#     except Exception:
#         pass
#     return False


# def file_extension_flag(path):
#     for ext in SUSPICIOUS_EXTS:
#         if path.lower().endswith(ext):
#             return ext
#     return ""


# def percent_encoding_ratio(path_or_query):
#     if not path_or_query:
#         return 0.0
#     encoded = path_or_query.count("%")
#     return encoded / max(1, len(path_or_query))


# def contains_sensitive_keywords(path_or_query):
#     text = path_or_query.lower()
#     return any(kw in text for kw in SUSPICIOUS_SUBSTRINGS)


# def js_keyword_counts(html_text):
#     counts = {}
#     text = html_text or ""
#     for kw in SUSPICIOUS_JS:
#         counts[f"js_{kw}"] = text.count(kw)
#     return counts


# def tld_reputation(tld):
#     if not tld:
#         return "unknown"
#     if tld.lower() in RISKY_TLDS:
#         return "risky"
#     return "normal"


# def ttl_features(hostname):
#     out = {}
#     try:
#         resolver = dns.resolver.Resolver()
#         answers = resolver.resolve(hostname, "A")
#         ttls = [r.ttl for r in answers.response.answer if hasattr(r, "ttl")]
#         if ttls:
#             out["ttl_min"] = min(ttls)
#             out["ttl_max"] = max(ttls)
#             out["ttl_avg"] = sum(ttls) / len(ttls)
#     except Exception:
#         out["ttl_min"] = out["ttl_max"] = out["ttl_avg"] = None
#     return out

# def shannon_entropy(s):
#     if not s:
#         return 0.0
#     from collections import Counter
#     probs = [n/len(s) for n in Counter(s).values()]
#     import math
#     return -sum(p*math.log2(p) for p in probs)
# def asn_geo_lookup(ip):
#     """
#     Lookup ASN and Geo for a given IP using ipwhois.
#     Returns dict with ASN number, ASN org, country code.
#     """
#     res = {"asn_number": None, "asn_org": "", "hosting_country": ""}
#     try:
#         obj = IPWhois(ip)
#         details = obj.lookup_rdap(asn_methods=["whois", "http"])
#         res["asn_number"] = details.get("asn")
#         res["asn_org"] = details.get("asn_description", "")
#         res["hosting_country"] = details.get("asn_country_code", "")
#     except Exception as e:
#         res["asn_error"] = str(e)
#     return res
# class FeatureExtractor:
#     def __init__(self, targets=None):
#         """
#         targets: list of legitimate target domains (strings) for lookalike checks and visual comparisons
#         """
#         self.targets = targets or []

#     ##########################
#     # Top-level processor
#     ##########################
#     def process(self, raw_url, meta=None, render=True):
#         meta = meta or {}
#         out = {}
#         out["original_url"] = raw_url
#         url = normalize_url(raw_url)
#         out["url_norm"] = url
#         parsed = urlparse(url)
#         out["hostname"] = parsed.hostname or ""
#         out["registered_domain"] = extract_registered_domain(out["hostname"])
#         out.update(self.url_lexical_features(url, parsed))
#         # DNS + WHOIS + TLS + HTTP
#         out.update(self.dns_features(out["hostname"]))
        
#         out.update(ttl_features(out["hostname"]))
#         out.update(self.whois_features(out["hostname"]))
#         out.update(self.tls_features(out["hostname"]))
#         out.update(self.http_head_features(url))
#         # Light HTML parse if available
#         if out.get("http_status_code") == 200 and out.get("content_type","").startswith("text/html"):
#             out.update(self.html_dom_features(out.get("final_url_after_redirects") or url))
#         if out.get("page_text"):
#             out.update(js_keyword_counts(out.get("page_text")))
#         else:
#             for kw in SUSPICIOUS_JS:
#                 out[f"js_{kw}"] = 0
#         # Favicon
#         try:
#             f = fetch_favicon(url)
#             out.update(f)
#         except Exception as e:
#             out["favicon_error"] = str(e)
#         # Render screenshot + PDF (heavy)
#         if render:
#             try:
#                 base = safe_name_for_file(out["registered_domain"] + "_" + str(meta.get("row_id","0")))
#                 s = render_screenshot_and_pdf(url, base_name=base)
#                 out.update(s)
#             except Exception as e:
#                 out["screenshot_error"] = str(e)
#         # detectors
#         try:
#             cname_chain = out.get("cname_chain", "").split(",") if out.get("cname_chain") else None
#             cert_sans = out.get("tls_san_list", None)
#             ephemeral_flag, ephemeral_provider = is_ephemeral_host(out["hostname"], cname_chain=cname_chain, cert_sans=cert_sans)
#             out["is_ephemeral_host_flag"] = ephemeral_flag
#             out["ephemeral_provider"] = ephemeral_provider or ""
#         except Exception:
#             out["is_ephemeral_host_flag"] = False
#             out["ephemeral_provider"] = ""
#         parked_flag, parked_reason = detect_parked(out.get("page_text"), out.get("content_length") or 0, out.get("whois_creation_date"))
#         out["parked_flag"] = parked_flag
#         out["parked_reason"] = parked_reason or ""
#         # lookalike lexical
#         try:
#             lk_flag, lk_info = lexical_lookalike(out["registered_domain"], self.targets)
#             out["lookalike_flag"] = lk_flag
#             out["lookalike_target"] = lk_info.get("target")
#             out["lookalike_edit_distance"] = lk_info.get("dist")
#             out["lookalike_edit_distance_rel"] = lk_info.get("rel")
#         except Exception:
#             out["lookalike_flag"] = False
#         # placeholders for AI features
#         out.update(self.semantic_features_placeholder(out))
#         out.update(self.visual_ai_features_placeholder(out))
#         # scoring (simple rule based)
#         out["rule_score"] = self.compute_rule_score(out)
#         out["label"] = self.assign_label(out)
#         out["processed_at"] = datetime.utcnow().isoformat()
#         out["semantic_brand_score"] = None
#         #out["semantic_summary"] = ""
#         out["ocr_text"] = ""
#         out["asn_number"] = None
#         out["asn_org"] = ""
#         out["hosting_country"] = ""
#         out["blocklist_hit"] = None
#         out["ct_mentions"] = None
        
#         return out

#     ##########################
#     # Deterministic feature methods
#     ##########################

#     def url_lexical_features(self, url, parsed):
#         out = {}
#         out["url_length"] = len(url)
#         out["domain"] = parsed.hostname or ""
#         out["tld"] = tldextract.extract(url).suffix or ""
#         out["subdomain"] = tldextract.extract(url).subdomain or ""
#         out["num_subdomains"] = len(out["subdomain"].split(".")) if out["subdomain"] else 0
#         out["domain_length"] = len(out["domain"])
#         out["num_dots"] = url.count(".")
#         out["num_slashes"] = url.count("/")
#         out["num_hyphens"] = url.count("-")
#         out["num_underscores"] = url.count("_")
#         out["num_digits"] = sum(c.isdigit() for c in url)
#         out["num_uppercase"] = sum(c.isupper() for c in url)
#         out["num_lowercase"] = sum(c.islower() for c in url)
#         out["num_special_chars"] = sum(1 for c in url if not c.isalnum() and c not in "/:?&=#.%+-_")
#         out["has_query"] = bool(parsed.query)
#         out["has_fragment"] = bool(parsed.fragment)
#         out["path_length"] = len(parsed.path or "")
#         out["path_depth"] = len([p for p in (parsed.path or "").split("/") if p])
#         out["query_length"] = len(parsed.query or "")
#         out["num_query_params"] = parsed.query.count("&") + 1 if parsed.query else 0
#         out["entropy_domain"] = shannon_entropy(out["domain"])
#         out["entropy_subdomain"] = shannon_entropy(out["subdomain"])
#         out["entropy_path"] = shannon_entropy(parsed.path or "")
#         out["has_idn_homoglyph"] = idn_homoglyph_flag(out["domain"])
#         out["tld_reputation"] = tld_reputation(out["tld"])
#         out["suspicious_file_ext"] = file_extension_flag(parsed.path)
#         out["percent_encoding_ratio"] = percent_encoding_ratio(parsed.path + parsed.query)
#         out["sensitive_kw_in_pathquery"] = contains_sensitive_keywords(parsed.path + parsed.query)
#         # N-gram counts
#         grams = ngram_features(out["domain"], 3)
#         out["num_unique_trigrams"] = len(grams)
#         out["top_trigram"] = max(grams, key=grams.get) if grams else ""
#         return out

#     def dns_features(self, hostname):
#         out = {}
#         try:
#             resolver = dns.resolver.Resolver()
#             a = []
#             try:
#                 answers = resolver.resolve(hostname, "A", lifetime=5)
#                 a = [r.to_text() for r in answers]
#             except Exception:
#                 a = []
#             out["resolved_ips"] = ",".join(a)
#             out["num_resolved_ips"] = len(a)
#             # NS
#             try:
#                 ns = resolver.resolve(hostname, "NS", lifetime=5)
#                 out["nameservers"] = ",".join([r.to_text() for r in ns])
#             except Exception:
#                 out["nameservers"] = ""
#             # MX
#             try:
#                 mx = resolver.resolve(hostname, "MX", lifetime=5)
#                 out["mx_records"] = ",".join([r.exchange.to_text() for r in mx])
#             except Exception:
#                 out["mx_records"] = ""
#             # CNAME chain
#             try:
#                 cname = resolver.resolve(hostname, "CNAME", lifetime=3)
#                 out["cname_chain"] = ",".join([r.to_text() for r in cname])
#             except Exception:
#                 out["cname_chain"] = ""
#         except Exception as e:
#             out["dns_error"] = str(e)
#         return out

#     def whois_features(self, hostname):
#         out = {}
#         try:
#             w = whois.whois(hostname)
#             out["registrar"] = w.registrar if hasattr(w, "registrar") else ""
#             out["registrant_name"] = w.name if hasattr(w, "name") else ""
#             out["registrant_org"] = w.org if hasattr(w, "org") else ""
#             out["registrant_country"] = w.country if hasattr(w, "country") else ""
#             try:
#                 created = w.creation_date
#                 if isinstance(created, list):
#                     created = created[0]
#                 out["whois_creation_date"] = created.isoformat() if created else ""
#                 if created:
#                     delta = (datetime.utcnow() - created).days
#                     out["domain_age_days"] = delta
#             except Exception:
#                 out["whois_creation_date"] = ""
#         except Exception as e:
#             out["whois_error"] = str(e)
#         return out

#     def tls_features(self, hostname):
#         out = {"https": False}
#         try:
#             context = ssl.create_default_context()
#             with socket.create_connection((hostname, 443), timeout=5) as sock:
#                 with context.wrap_socket(sock, server_hostname=hostname) as ssock:
#                     cert = ssock.getpeercert()
#                     out["https"] = True
#                     out["tls_subject_cn"] = dict(x[0] for x in cert.get("subject", ())).get("commonName","")
#                     out["tls_issuer"] = dict(x[0] for x in cert.get("issuer", ())).get("organizationName","")
#                     out["tls_valid_from"] = cert.get("notBefore")
#                     out["tls_valid_to"] = cert.get("notAfter")
#                     # SANs
#                     sans = cert.get("subjectAltName", ())
#                     out["tls_san_list"] = [s[1] for s in sans] if sans else []
#         except Exception:
#             pass
#         return out

#     def http_head_features(self, url):
#         out = {}
#         try:
#             r = requests.head(url, allow_redirects=True, timeout=7)
#             out["http_status_code"] = r.status_code
#             out["final_url_after_redirects"] = r.url
#             out["num_redirects"] = len(r.history)
#             out["server_header"] = r.headers.get("Server","")
#             out["content_type"] = r.headers.get("Content-Type","")
#             out["content_length"] = int(r.headers.get("Content-Length") or 0)
#         except Exception as e:
#             out["http_error"] = str(e)
#         return out

#     def html_dom_features(self, url):
#         out = {}
#         try:
#             r = requests.get(url, timeout=10)
#             out["page_text"] = BeautifulSoup(r.content, "lxml").get_text(" ", strip=True)
#             soup = BeautifulSoup(r.content, "lxml")
#             out["num_forms"] = len(soup.find_all("form"))
#             inputs = soup.find_all("input")
#             out["num_inputs_total"] = len(inputs)
#             out["num_password_fields"] = len([i for i in inputs if i.get("type","").lower()=="password"])
#             out["num_iframes"] = len(soup.find_all("iframe"))
#             scripts = soup.find_all("script")
#             out["num_external_scripts"] = len([s for s in scripts if s.get("src")])
#             out["meta_refresh_present"] = bool(soup.find("meta", attrs={"http-equiv":"refresh"}))
#         except Exception as e:
#             out["html_error"] = str(e)
#         return out

#     ##########################
#     # AI stubs (no-op by default)
#     ##########################
#     def semantic_features_placeholder(self, out):
#         """Stub: integrate LLM/NLP here to compute semantic signals:
#            - suspicious substring semantic score
#            - brand token overlap using embeddings
#            - narrative summary explanation
#         """
#         return {
#             "semantic_score": None,
#             "semantic_summary": ""
#         }

#     def visual_ai_features_placeholder(self, out):
#         """Stub: integrate VLM/advanced CV here:
#            - logo detection with CNN
#            - image embeddings similarity
#            - OCR + LLM interpretation
#         """
#         return {
#             "visual_ai_score": None,
#             "visual_ai_notes": ""
#         }

#     ##########################
#     # Simple scoring & labeling
#     ##########################
#     def compute_rule_score(self, out):
#         score = 0
#         if out.get("domain_age_days") is not None and out.get("domain_age_days") < 30:
#             score += 20
#         if out.get("num_password_fields",0) > 0:
#             score += 15
#         if out.get("is_ephemeral_host_flag"):
#             score += 25
#         if out.get("num_hyphens",0) > 2:
#             score += 5
#         if out.get("lookalike_flag"):
#             score += 20
#         if out.get("parked_flag"):
#             score += 10
#         return min(100, score)

#     def assign_label(self, out):
#         s = out.get("rule_score", 0)
#         if s >= 60:
#             return "Phishing"
#         if s >= 30:
#             return "Suspected"
#         return "Benign"

import re, socket, ssl, json, math, idna, os, base64
from urllib.parse import urlparse, unquote
import tldextract
import dns.resolver
import whois
import requests
from ipwhois import IPWhois
from bs4 import BeautifulSoup
from datetime import datetime
from collections import Counter
# GEOIP (maxmind)
try:
    import geoip2.database
    _GEOIP_AVAILABLE = True
    _GEOIP_ASN_DB = "data/GeoLite2-ASN.mmdb"
    _GEOIP_COUNTRY_DB = "data/GeoLite2-Country.mmdb"
except Exception:
    _GEOIP_AVAILABLE = False

# ipwhois fallback
try:
    from ipwhois import IPWhois
    _IPWHOIS_AVAILABLE = True
except Exception:
    _IPWHOIS_AVAILABLE = False

from simhash import Simhash
from .utils import normalize_url, extract_registered_domain, safe_name_for_file
from .image_utils import fetch_favicon, render_screenshot_and_pdf
from .detectors import is_ephemeral_host, detect_parked, lexical_lookalike
from .visuals import compute_phash, compute_ssim, orb_logo_matches, ocr_image
from .persistence import upsert_page, ensure_db


# Suspicious patterns
SUSPICIOUS_SUBSTRINGS = ["login", "secure", "account", "update", "verify", "banking", "auth", "signin", "password"]
SUSPICIOUS_JS = ["eval", "document.write", "atob", "unescape", "fromCharCode", "window.open"]
SUSPICIOUS_EXTS = [".exe", ".scr", ".zip", ".rar", ".php", ".js", ".apk"]
RISKY_TLDS = ["xyz", "top", "click", "work", "loan", "gq", "tk", "cf"]


### --- Helpers --- ###


def shannon_entropy(s):
    if not s:
        return 0.0
    probs = [n/len(s) for n in Counter(s).values()]
    return -sum(p*math.log2(p) for p in probs)

def asn_geo_maxmind(ip):
    res = {"asn_number": None, "asn_org": "", "hosting_country": ""}
    try:
        if _GEOIP_AVAILABLE and os.path.exists(_GEOIP_ASN_DB):
            with geoip2.database.Reader(_GEOIP_ASN_DB) as r:
                asn = r.asn(ip)
                if asn and getattr(asn, "autonomous_system_number", None):
                    res["asn_number"] = "AS" + str(asn.autonomous_system_number)
                    res["asn_org"] = asn.autonomous_system_organization or ""
        if _GEOIP_AVAILABLE and os.path.exists(_GEOIP_COUNTRY_DB):
            with geoip2.database.Reader(_GEOIP_COUNTRY_DB) as rc:
                c = rc.country(ip)
                res["hosting_country"] = c.country.iso_code or ""
    except Exception as e:
        res["asn_error"] = str(e)
    return res

def asn_geo_ipwhois(ip):
    res = {"asn_number": None, "asn_org": "", "hosting_country": ""}
    if not _IPWHOIS_AVAILABLE:
        return res
    try:
        obj = IPWhois(ip)
        details = obj.lookup_rdap(asn_methods=["whois", "http"])
        res["asn_number"] = details.get("asn")
        res["asn_org"] = details.get("asn_description", "")
        res["hosting_country"] = details.get("asn_country_code", "")
    except Exception as e:
        res["asn_error"] = str(e)
    return res

def asn_geo_lookup(ip):
    # prefer maxmind local DB
    if _GEOIP_AVAILABLE and os.path.exists("data/GeoLite2-ASN.mmdb"):
        r = asn_geo_maxmind(ip)
        if r.get("asn_number") or r.get("hosting_country"):
            return r
    # fallback
    return asn_geo_ipwhois(ip)


def ngram_features(s, n=3):
    s = re.sub(r"[^a-z0-9]", "", s.lower())
    return [s[i:i+n] for i in range(len(s)-n+1)]

def idn_homoglyph_flag(domain):
    try:
        decoded = idna.decode(domain)
        if decoded != domain:
            return True
    except Exception:
        pass
    return False

def file_extension_flag(path):
    for ext in SUSPICIOUS_EXTS:
        if path.lower().endswith(ext):
            return ext
    return ""

def percent_encoding_ratio(path_or_query):
    if not path_or_query:
        return 0.0
    return path_or_query.count("%") / max(1, len(path_or_query))

def contains_sensitive_keywords(path_or_query):
    text = path_or_query.lower()
    return any(kw in text for kw in SUSPICIOUS_SUBSTRINGS)

def js_keyword_counts(html_text):
    counts = {}
    text = html_text or ""
    for kw in SUSPICIOUS_JS:
        counts[f"js_{kw}"] = text.count(kw)
    return counts

def tld_reputation(tld):
    if not tld:
        return "unknown"
    return "risky" if tld.lower() in RISKY_TLDS else "normal"

def ttl_features(hostname):
    out = {}
    try:
        resolver = dns.resolver.Resolver()
        answers = resolver.resolve(hostname, "A")
        ttls = [r.ttl for r in answers.response.answer if hasattr(r, "ttl")]
        if ttls:
            out["ttl_min"] = min(ttls)
            out["ttl_max"] = max(ttls)
            out["ttl_avg"] = sum(ttls) / len(ttls)
    except Exception:
        out["ttl_min"] = out["ttl_max"] = out["ttl_avg"] = None
    return out


def is_base64(s):
    try:
        return base64.b64encode(base64.b64decode(s)).decode() == s
    except Exception:
        return False


### --- Feature Extractor --- ###

class FeatureExtractor:
    def __init__(self, targets=None):
        self.targets = targets or []

    def process(self, raw_url, meta=None, render=True):
        meta = meta or {}
        out = {}
        out["original_url"] = raw_url
        url = normalize_url(raw_url)
        out["url_norm"] = url
        parsed = urlparse(url)
        out["hostname"] = parsed.hostname or ""
        out["registered_domain"] = extract_registered_domain(out["hostname"])
        out.update(self.url_lexical_features(url, parsed))

        # DNS + TTL + ASN/Geo
        out.update(self.dns_features(out["hostname"]))
        out.update(ttl_features(out["hostname"]))
        if out.get("resolved_ips"):
            out.update(asn_geo_lookup(out["resolved_ips"].split(",")[0]))

        # WHOIS
        out.update(self.whois_features(out["hostname"]))

        # TLS
        out.update(self.tls_features(out["hostname"]))

        # HTTP HEAD
        out.update(self.http_head_features(url))

        # Path/Query analysis
        out["file_extension"] = os.path.splitext(parsed.path)[1] if parsed.path else ""
        out["long_query_string"] = int(len(parsed.query) > 100)
        out["num_query_names"] = parsed.query.count("=")
        out["query_value_entropy"] = shannon_entropy(parsed.query)
        out["encoded_param_flag"] = int(any(is_base64(v) or "%" in v for v in parsed.query.split("&") if "=" in v for v in v.split("=")[1:]))
        out["sensitive_kw_in_path"] = int(any(kw in parsed.path.lower() for kw in SUSPICIOUS_SUBSTRINGS))

        # HTML DOM + JS features
        if out.get("http_status_code") == 200 and out.get("content_type","").startswith("text/html"):
            out.update(self.html_dom_features(out.get("final_url_after_redirects") or url))
        if out.get("page_text"):
            out.update(js_keyword_counts(out.get("page_text")))
        else:
            for kw in SUSPICIOUS_JS:
                out[f"js_{kw}"] = 0

        # Favicon
        try:
            out.update(fetch_favicon(url))
        except Exception as e:
            out["favicon_error"] = str(e)

        # Screenshot
        if render:
            try:
                base = safe_name_for_file(out["registered_domain"] + "_" + str(meta.get("row_id","0")))
                out.update(render_screenshot_and_pdf(url, base_name=base))
            except Exception as e:
                out["screenshot_error"] = str(e)

        # Detectors
        try:
            cname_chain = out.get("cname_chain", "").split(",") if out.get("cname_chain") else None
            cert_sans = out.get("tls_san_list", None)
            eph_flag, eph_provider = is_ephemeral_host(out["hostname"], cname_chain=cname_chain, cert_sans=cert_sans)
            out["is_ephemeral_host_flag"] = eph_flag
            out["ephemeral_provider"] = eph_provider or ""
        except Exception:
            out["is_ephemeral_host_flag"] = False
            out["ephemeral_provider"] = ""
        parked_flag, parked_reason = detect_parked(out.get("page_text"), out.get("content_length") or 0, out.get("whois_creation_date"))
        out["parked_flag"] = parked_flag
        out["parked_reason"] = parked_reason or ""
        try:
            lk_flag, lk_info = lexical_lookalike(out["registered_domain"], self.targets)
            out["lookalike_flag"] = lk_flag
            out["lookalike_target"] = lk_info.get("target")
            out["lookalike_edit_distance"] = lk_info.get("dist")
            out["lookalike_edit_distance_rel"] = lk_info.get("rel")
        except Exception:
            out["lookalike_flag"] = False

        # Stubs (AI/OSINT/visual)
        out["levenshtein_distance"] = None
        out["jaccard_similarity"] = None
        out["token_similarity_cse"] = None
        out["dictionary_word_ratio"] = None
        out["keyboard_overlap"] = None
        out["language_mismatch"] = None
        out["content_semantic"] = ""
        out["favicon_histogram"] = ""
        out["logo_detected"] = ""
        out["layout_dom_hash"] = ""
        out["image_exif"] = ""
        out["ocr_text"] = ""
        out["visual_phishing_intent"] = ""
        out["blocklist_hit"] = None
        out["ct_log_mentions"] = None
        out["passive_dns_count"] = None
        out["first_seen"] = ""
        out["last_seen"] = ""
        out["dom_drift_score"] = None

        # Scoring & label
        out["rule_score"] = self.compute_rule_score(out)
        out["label"] = self.assign_label(out)
        out["processed_at"] = datetime.utcnow().isoformat()
        return out
    
    def url_lexical_features(self, url, parsed):
        out = {}
        out["url_length"] = len(url)
        out["domain"] = parsed.hostname or ""
        out["tld"] = tldextract.extract(url).suffix or ""
        out["subdomain"] = tldextract.extract(url).subdomain or ""
        out["num_subdomains"] = len(out["subdomain"].split(".")) if out["subdomain"] else 0
        out["domain_length"] = len(out["domain"])
        out["num_dots"] = url.count(".")
        out["num_slashes"] = url.count("/")
        out["num_hyphens"] = url.count("-")
        out["num_underscores"] = url.count("_")
        out["num_digits"] = sum(c.isdigit() for c in url)
        out["num_uppercase"] = sum(c.isupper() for c in url)
        out["num_lowercase"] = sum(c.islower() for c in url)
        out["num_special_chars"] = sum(1 for c in url if not c.isalnum() and c not in "/:?&=#.%+-_")
        out["has_query"] = bool(parsed.query)
        out["has_fragment"] = bool(parsed.fragment)
        out["path_length"] = len(parsed.path or "")
        out["path_depth"] = len([p for p in (parsed.path or "").split("/") if p])
        out["query_length"] = len(parsed.query or "")
        out["num_query_params"] = parsed.query.count("&") + 1 if parsed.query else 0
        out["entropy_domain"] = shannon_entropy(out["domain"])
        out["entropy_subdomain"] = shannon_entropy(out["subdomain"])
        out["entropy_path"] = shannon_entropy(parsed.path or "")
        out["has_idn_homoglyph"] = idn_homoglyph_flag(out["domain"])
        out["tld_reputation"] = tld_reputation(out["tld"])
        out["suspicious_file_ext"] = file_extension_flag(parsed.path)
        out["percent_encoding_ratio"] = percent_encoding_ratio(parsed.path + parsed.query)
        out["sensitive_kw_in_pathquery"] = contains_sensitive_keywords(parsed.path + parsed.query)
        # N-grams
        grams3 = ngram_features(out["domain"], 3)
        out["num_unique_trigrams"] = len(set(grams3))
        out["top_trigram"] = max(grams3, key=grams3.count) if grams3 else ""
        return out

    def dns_features(self, hostname):
        out = {}
        try:
            resolver = dns.resolver.Resolver()
            a = []
            try:
                answers = resolver.resolve(hostname, "A", lifetime=5)
                a = [r.to_text() for r in answers]
            except Exception:
                a = []
            out["resolved_ips"] = ",".join(a)
            out["num_resolved_ips"] = len(a)
            try:
                ns = resolver.resolve(hostname, "NS", lifetime=5)
                out["nameservers"] = ",".join([r.to_text() for r in ns])
            except Exception:
                out["nameservers"] = ""
            try:
                mx = resolver.resolve(hostname, "MX", lifetime=5)
                out["mx_records"] = ",".join([r.exchange.to_text() for r in mx])
            except Exception:
                out["mx_records"] = ""
            try:
                cname = resolver.resolve(hostname, "CNAME", lifetime=3)
                out["cname_chain"] = ",".join([r.to_text() for r in cname])
            except Exception:
                out["cname_chain"] = ""
        except Exception as e:
            out["dns_error"] = str(e)
        return out

    def whois_features(self, hostname):
        out = {}
        try:
            w = whois.whois(hostname)
            out["registrar"] = getattr(w, "registrar", "")
            out["registrant_name"] = getattr(w, "name", "")
            out["registrant_org"] = getattr(w, "org", "")
            out["registrant_country"] = getattr(w, "country", "")
            try:
                created = w.creation_date
                if isinstance(created, list):
                    created = created[0]
                out["whois_creation_date"] = created.isoformat() if created else ""
                if created:
                    out["domain_age_days"] = (datetime.utcnow() - created).days
            except Exception:
                out["whois_creation_date"] = ""
            try:
                exp = w.expiration_date
                if isinstance(exp, list):
                    exp = exp[0]
                out["whois_expiration_date"] = exp.isoformat() if exp else ""
                if exp:
                    out["domain_expiry_days_left"] = (exp - datetime.utcnow()).days
            except Exception:
                out["whois_expiration_date"] = ""
                out["domain_expiry_days_left"] = None
        except Exception as e:
            out["whois_error"] = str(e)
        return out

    def tls_features(self, hostname):
        out = {"https": False}
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    out["https"] = True
                    out["tls_subject_cn"] = dict(x[0] for x in cert.get("subject", ())).get("commonName","")
                    out["tls_issuer"] = dict(x[0] for x in cert.get("issuer", ())).get("organizationName","")
                    out["tls_valid_from"] = cert.get("notBefore")
                    out["tls_valid_to"] = cert.get("notAfter")
                    sans = cert.get("subjectAltName", ())
                    out["tls_san_list"] = [s[1] for s in sans] if sans else []
                    # Extras
                    try:
                        exp_date = datetime.strptime(out["tls_valid_to"], "%b %d %H:%M:%S %Y %Z")
                        out["tls_expiry_days_left"] = (exp_date - datetime.utcnow()).days
                    except Exception:
                        out["tls_expiry_days_left"] = None
                    out["tls_self_signed"] = out.get("tls_issuer") == out.get("tls_subject_cn")
                    out["tls_wildcard"] = out.get("tls_subject_cn", "").startswith("*.") or any(s.startswith("*.") for s in out.get("tls_san_list", []))
                    cn = (out.get("tls_subject_cn") or "").lower()
                    out["tls_cn_mismatch"] = cn and not (hostname.lower() == cn or hostname.lower().endswith("." + cn))
                    free_cas = ["let's encrypt", "zerossl", "cloudflare"]
                    out["tls_free_ca"] = any(ca in (out.get("tls_issuer") or "").lower() for ca in free_cas)
        except Exception:
            pass
        return out

    def http_head_features(self, url):
        out = {}
        try:
            r = requests.head(url, allow_redirects=True, timeout=7)
            out["http_status_code"] = r.status_code
            out["final_url_after_redirects"] = r.url
            out["num_redirects"] = len(r.history)
            out["redirect_chain"] = " -> ".join([resp.url for resp in r.history] + [r.url])
            out["server_header"] = r.headers.get("Server","")
            out["content_type"] = r.headers.get("Content-Type","")
            out["content_length"] = int(r.headers.get("Content-Length") or 0)
        except Exception as e:
            out["http_error"] = str(e)
        return out

    def html_dom_features(self, url):
        out = {}
        try:
            r = requests.get(url, timeout=10)
            soup = BeautifulSoup(r.content, "lxml")
            out["page_text"] = soup.get_text(" ", strip=True)
            out["num_forms"] = len(soup.find_all("form"))
            inputs = soup.find_all("input")
            out["num_inputs_total"] = len(inputs)
            out["num_password_fields"] = len([i for i in inputs if i.get("type","").lower()=="password"])
            out["num_iframes"] = len(soup.find_all("iframe"))
            scripts = soup.find_all("script")
            out["num_external_scripts"] = len([s for s in scripts if s.get("src")])
            out["meta_refresh_present"] = bool(soup.find("meta", attrs={"http-equiv":"refresh"}))
            # Extra HTML
            html_size = len(r.content)
            scripts_size = sum(len(s.get_text() or "") for s in scripts)
            out["script_html_ratio"] = scripts_size / max(1, html_size)
            cross_forms = 0
            for f in soup.find_all("form"):
                action = f.get("action", "")
                if action.startswith("http") and urlparse(action).netloc != urlparse(url).netloc:
                    cross_forms += 1
            out["cross_domain_forms"] = cross_forms
            js_text = " ".join([s.get_text() or "" for s in scripts])
            for kw in SUSPICIOUS_JS:
                out[f"js_{kw}"] = js_text.count(kw)
            out["js_redirection"] = int("window.location" in js_text or "window.open" in js_text)
            otp_fields = [i for i in inputs if i.get("type") in ("number","tel") and i.get("maxlength") in ("4","6")]
            out["num_otp_fields"] = len(otp_fields)
        except Exception as e:
            out["html_error"] = str(e)
        return out

    def compute_rule_score(self, out):
        score = 0
        if out.get("domain_age_days") is not None and out.get("domain_age_days") < 30:
            score += 20
        if out.get("num_password_fields",0) > 0:
            score += 15
        if out.get("is_ephemeral_host_flag"):
            score += 25
        if out.get("num_hyphens",0) > 2:
            score += 5
        if out.get("lookalike_flag"):
            score += 20
        if out.get("parked_flag"):
            score += 10
        return min(100, score)

    def assign_label(self, out):
        s = out.get("rule_score", 0)
        if s >= 60:
            return "Phishing"
        if s >= 30:
            return "Suspected"
        return "Benign"
