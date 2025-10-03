# crawler/extractor.py
import re, socket, ssl, json, math, idna, os, base64
from urllib.parse import urlparse, unquote
import tldextract
import dns.resolver
import whois
import requests
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

# constants
SUSPICIOUS_SUBSTRINGS = ["login", "secure", "account", "update", "verify", "banking", "auth", "signin", "password"]
SUSPICIOUS_JS = ["eval", "document.write", "atob", "unescape", "fromCharCode", "window.open"]
SUSPICIOUS_EXTS = [".exe", ".scr", ".zip", ".rar", ".php", ".js", ".apk"]
RISKY_TLDS = ["xyz", "top", "click", "work", "loan", "gq", "tk", "cf"]

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

def ttl_features(hostname):
    out = {}
    try:
        resolver = dns.resolver.Resolver()
        answers = resolver.resolve(hostname, "A")
        ttls = []
        for rr in answers.response.answer:
            if hasattr(rr, "ttl"):
                ttls.append(rr.ttl)
        if ttls:
            out["ttl_min"] = min(ttls)
            out["ttl_max"] = max(ttls)
            out["ttl_avg"] = sum(ttls)/len(ttls)
    except Exception:
        out["ttl_min"] = out["ttl_max"] = out["ttl_avg"] = None
    return out

def dom_simhash(html_text):
    tokens = re.findall(r"[a-zA-Z0-9]{2,}", (html_text or "").lower())
    return Simhash(tokens).value if tokens else 0

class FeatureExtractor:
    def __init__(self, targets=None, trusted_gallery_dir=None, evidence_dir=None):
        self.targets = targets or []
        self.trusted_gallery_dir = trusted_gallery_dir or "trusted_gallery"
        self.evidence_dir = evidence_dir or "Phishing_Evidences"
        ensure_db()

    def process(self, raw_url, meta=None, page=None, render=True):
        """
        page: optional Playwright Page object (for reuse; allows rendered HTML capture)
        """
        meta = meta or {}
        out = {}
        out["original_url"] = raw_url
        url = normalize_url(raw_url)
        out["url_norm"] = url
        parsed = urlparse(url)
        out["hostname"] = parsed.hostname or ""
        out["registered_domain"] = extract_registered_domain(out["hostname"])

        # lexical
        out.update(self.url_lexical_features(url, parsed))

        # dns/whois/tls/http
        out.update(self.dns_features(out["hostname"]))
        out.update(ttl_features(out["hostname"]))
        if out.get("resolved_ips"):
            first_ip = out["resolved_ips"].split(",")[0]
            out.update(asn_geo_lookup(first_ip))
        out.update(self.whois_features(out["hostname"]))
        out.update(self.tls_features(out["hostname"]))
        out.update(self.http_head_features(url))

        # path/query analysis
        out["file_extension"] = os.path.splitext(parsed.path)[1] if parsed.path else ""
        out["long_query_string"] = int(len(parsed.query) > 100)
        out["num_query_names"] = parsed.query.count("=")
        out["query_value_entropy"] = shannon_entropy(parsed.query)
        out["encoded_param_flag"] = int(any(self._is_base64(v) or "%" in v for v in parsed.query.split("&") if "=" in v for v in v.split("=")[1:]))
        out["sensitive_kw_in_path"] = int(any(kw in (parsed.path or "").lower() for kw in SUSPICIOUS_SUBSTRINGS))

        # HTML/DOM (prefer rendered page content if page provided)
        html_text = None
        dom_html = None
        try:
            if page is not None:
                dom_html = page.content()
                html_text = BeautifulSoup(dom_html, "lxml").get_text(" ", strip=True)
            else:
                if out.get("http_status_code") == 200 and out.get("content_type","").startswith("text/html"):
                    r = requests.get(out.get("final_url_after_redirects") or url, timeout=10)
                    dom_html = r.text
                    html_text = BeautifulSoup(dom_html, "lxml").get_text(" ", strip=True)
        except Exception:
            dom_html = None
            html_text = None

        if dom_html:
            out.update(self._html_features_from_dom(dom_html, url))

        # JS keyword counts from page text
        if html_text:
            for kw in SUSPICIOUS_JS:
                out[f"js_{kw}"] = html_text.count(kw)
        else:
            for kw in SUSPICIOUS_JS:
                out[f"js_{kw}"] = 0

        # Favicon (saves file)
        try:
            fav = fetch_favicon(url, out_dir=self.evidence_dir)
            out.update(fav)
        except Exception as e:
            out["favicon_error"] = str(e)

        # Screenshot (reuse page where available)
        screenshot_info = {}
        if render:
            try:
                base = safe_name_for_file(out["registered_domain"] + "_" + str(meta.get("row_id","0")))
                screenshot_info = render_screenshot_and_pdf(url, out_dir=self.evidence_dir, base_name=base, page=page)
                out.update(screenshot_info)
            except Exception as e:
                out["screenshot_error"] = str(e)

        # Visual comparisons (if trusted gallery exists)
        out["max_ssim_with_gallery"] = None
        out["best_logo_match_count"] = None
        out["ocr_text"] = ""
        try:
            if out.get("evidence_png") and os.path.exists(out["evidence_png"]):
                # compute phash (already maybe present)
                if not out.get("screenshot_phash"):
                    out["screenshot_phash"] = compute_phash(out["evidence_png"])
                # OCR
                out["ocr_text"] = ocr_image(out["evidence_png"])
                # compare against gallery
                gallery = self.trusted_gallery_dir
                if os.path.isdir(gallery):
                    ssim_scores = []
                    best_logo = 0
                    for fname in os.listdir(gallery):
                        gpath = os.path.join(gallery, fname)
                        s = compute_ssim(out["evidence_png"], gpath)
                        if s is not None:
                            ssim_scores.append(s)
                        m = orb_logo_matches(out["evidence_png"], gpath)
                        if m > best_logo:
                            best_logo = m
                    out["max_ssim_with_gallery"] = max(ssim_scores) if ssim_scores else None
                    out["best_logo_match_count"] = best_logo
        except Exception:
            pass

        # detectors
        try:
            cname_chain = out.get("cname_chain", "").split(",") if out.get("cname_chain") else None
            cert_sans = out.get("tls_san_list", None)
            ephemeral_flag, ephemeral_provider = is_ephemeral_host(out["hostname"], cname_chain=cname_chain, cert_sans=cert_sans)
            out["is_ephemeral_host_flag"] = ephemeral_flag
            out["ephemeral_provider"] = ephemeral_provider or ""
        except Exception:
            out["is_ephemeral_host_flag"] = False
            out["ephemeral_provider"] = ""
        parked_flag, parked_reason = detect_parked(html_text, out.get("content_length") or 0, out.get("whois_creation_date"))
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

        # dom simhash (for drift)
        out["dom_simhash"] = dom_simhash(dom_html) if dom_html else 0

        # stubs
        out.update({
            "levenshtein_distance": None,
            "jaccard_similarity": None,
            "token_similarity_cse": None,
            "dictionary_word_ratio": None,
            "keyboard_overlap": None,
            "language_mismatch": None,
            "content_semantic": "",
            "favicon_histogram": "",
            "logo_detected": "",
            "layout_dom_hash": out.get("dom_simhash"),
            "image_exif": "",
            "visual_phishing_intent": None,
            "blocklist_hit": None,
            "ct_log_mentions": None,
            "passive_dns_count": None,
            "first_seen": "",
            "last_seen": ""
        })

        # scoring & persistence
        out["rule_score"] = self.compute_rule_score(out)
        out["label"] = self.assign_label(out)
        out["processed_at"] = datetime.utcnow().isoformat()

        # persist into sqlite
        try:
            evidence_paths = {"png": out.get("evidence_png"), "pdf": out.get("evidence_pdf"), "favicon": out.get("favicon_path")}
            upsert_page(out.get("url_norm"), out.get("registered_domain"), out.get("label"), evidence_paths, out.get("dom_simhash"), out.get("ocr_text"))
        except Exception:
            pass

        return out

    # helpers used above
    def _is_base64(self, s):
        try:
            return base64.b64encode(base64.b64decode(s)).decode() == s
        except Exception:
            return False

    def _html_features_from_dom(self, html, base_url):
        out = {}
        try:
            soup = BeautifulSoup(html, "lxml")
            out["page_text"] = soup.get_text(" ", strip=True)
            out["num_forms"] = len(soup.find_all("form"))
            inputs = soup.find_all("input")
            out["num_inputs_total"] = len(inputs)
            out["num_password_fields"] = len([i for i in inputs if i.get("type","").lower()=="password"])
            out["num_iframes"] = len(soup.find_all("iframe"))
            scripts = soup.find_all("script")
            out["num_external_scripts"] = len([s for s in scripts if s.get("src")])
            out["meta_refresh_present"] = bool(soup.find("meta", attrs={"http-equiv":"refresh"}))
            html_size = len(html.encode("utf-8"))
            scripts_size = sum(len(s.get_text() or "") for s in scripts)
            out["script_html_ratio"] = scripts_size / max(1, html_size)
            cross_forms = 0
            for f in soup.find_all("form"):
                action = f.get("action", "")
                if action.startswith("http") and urlparse(action).netloc != urlparse(base_url).netloc:
                    cross_forms += 1
            out["cross_domain_forms"] = cross_forms
            # js keywords & redirect detection
            js_text = " ".join([s.get_text() or "" for s in scripts])
            for kw in SUSPICIOUS_JS:
                out[f"js_{kw}"] = js_text.count(kw)
            out["js_redirection"] = int("window.location" in js_text or "window.open" in js_text)
            otp_fields = [i for i in inputs if i.get("type") in ("number","tel") and i.get("maxlength") in ("4","6")]
            out["num_otp_fields"] = len(otp_fields)
        except Exception as e:
            out["html_error"] = str(e)
        return out

    # deterministic feature methods (similar to your previous extractor)...
    # Implement url_lexical_features, dns_features, whois_features, tls_features, http_head_features, compute_rule_score, assign_label
    # For brevity: reuse your existing deterministic implementations here (paste from previous extractor)
    # Make sure to include fields used above: url_length, domain, entropy_domain, etc.

    # ---- placeholder stubs for the remaining methods ----
    def url_lexical_features(self, url, parsed):
        # copy your prior implementation; compute ngrams, entropy, etc.
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
        # n-grams
        grams3 = re.sub(r"[^a-z0-9]","", out["domain"].lower())
        grams3 = [grams3[i:i+3] for i in range(len(grams3)-2)] if len(grams3)>2 else []
        out["num_unique_trigrams"] = len(set(grams3))
        out["top_trigram"] = max(grams3, key=grams3.count) if grams3 else ""
        out["has_idn_homoglyph"] = "xn--" in out["domain"]
        out["tld_reputation"] = "risky" if out["tld"].lower() in RISKY_TLDS else "normal"
        out["suspicious_file_ext"] = next((ext for ext in SUSPICIOUS_EXTS if (parsed.path or "").lower().endswith(ext)), "")
        out["percent_encoding_ratio"] = (parsed.path + parsed.query).count("%") / max(1, len(parsed.path + parsed.query))
        out["sensitive_kw_in_pathquery"] = int(any(kw in (parsed.path + parsed.query).lower() for kw in SUSPICIOUS_SUBSTRINGS))
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
                a=[]
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
