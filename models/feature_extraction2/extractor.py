# extractor.py
import time
import re
import socket
import ssl
import requests
import tldextract
import dns.resolver
import whois
from urllib.parse import urlparse, urljoin
from collections import Counter
from bs4 import BeautifulSoup
from rapidfuzz.distance import Levenshtein
from image_utils import fetch_favicon_hash, screenshot_and_phash
from text_utils import shannon_entropy, top_ngrams
from detections import detect_tunneling, detect_parked, detect_lookalike

class FeatureExtractor:
    def __init__(self, workers=8, timeout=10):
        self.session = requests.Session()
        self.timeout = timeout
        self.workers = workers
        self.ephemeral_patterns = [
            "ngrok.io","vercel.app","pages.dev","onrender.com",
            "github.io","netlify.app","render.com"
        ]

    def process_url(self, raw_url, meta=None):
        meta = meta or {}
        out = {}
        out["original_url"] = raw_url

        url = self._normalize(raw_url)
        out["url_norm"] = url
        parsed = urlparse(url)

        # Lexical
        out.update(self.lexical_features(url, parsed))

        # DNS
        try:
            out.update(self.dns_features(parsed.hostname))
        except Exception as e:
            out["dns_error"] = str(e)

        # WHOIS
        try:
            out.update(self.whois_features(parsed.hostname))
        except Exception as e:
            out["whois_error"] = str(e)

        # TLS
        try:
            out.update(self.tls_features(parsed.hostname))
        except Exception as e:
            out["tls_error"] = str(e)

        # HTTP HEAD + timing
        try:
            t0 = time.time()
            out.update(self.http_head_features(url))
            out["fetch_duration_ms"] = int((time.time() - t0)*1000)
        except Exception as e:
            out["http_error"] = str(e)

        # HTML DOM
        if out.get("http_status_code") == 200 and "text/html" in out.get("content_type",""):
            try:
                t1 = time.time()
                out.update(self.html_dom_features(out.get("final_url_after_redirects") or url))
                out["render_duration_ms"] = int((time.time() - t1)*1000)
            except Exception as e:
                out["html_error"] = str(e)

        # Favicon
        try:
            out.update(fetch_favicon_hash(url, out_dir="Phishing_Evidences/favicons",
                                          ephemeral_patterns=self.ephemeral_patterns))
        except Exception as e:
            out["favicon_error"] = str(e)

        # Screenshot
        try:
            out.update(screenshot_and_phash(url,
                                            target_org=meta.get("target_org","Unknown"),
                                            serial_no=meta.get("row_id",1)))
        except Exception as e:
            out["screenshot_error"] = str(e)

         # --- Special Detection Flags ---
        out["is_tunneling"] = detect_tunneling(
            out.get("domain",""),
            cname_chain=out.get("cname_chain",""),
            tls_san_list=out.get("tls_san_list",[])
                )

        out["is_parked"] = detect_parked(
            page_text=out.get("page_text",""),
            html_length=out.get("page_text_length",0),
            domain_age_days=out.get("domain_age_days")
        )

        # Needs authorized CSE domains list from your dataset
        cse_domains = meta.get("cse_domains", [])  
        out["is_lookalike"] = detect_lookalike(
            out.get("domain",""),
            cse_domains=cse_domains,
            max_edit_distance=2
        )

        return out
       

    def _normalize(self, raw):
        if not raw:
            return raw
        u = raw.strip()
        if not u.lower().startswith(("http://","https://")):
            u = "http://" + u
        return u

    # -----------------------------
    # Lexical Features
    # -----------------------------
    def lexical_features(self, url, parsed):
        out = {}
        domain_info = tldextract.extract(url)
        domain = ".".join([domain_info.domain, domain_info.suffix]) if domain_info.suffix else domain_info.domain
        out["domain"] = domain
        out["tld"] = domain_info.suffix
        out["subdomain"] = domain_info.subdomain or ""
        out["num_subdomains"] = len(domain_info.subdomain.split(".")) if domain_info.subdomain else 0
        out["domain_length"] = len(domain)
        out["url_length"] = len(url)
        out["num_dots"] = url.count(".")
        out["num_slashes"] = url.count("/")
        out["num_hyphens"] = url.count("-")
        out["num_underscores"] = url.count("_")
        out["num_digits"] = sum(c.isdigit() for c in url)
        out["entropy_domain"] = shannon_entropy(domain)
        out["entropy_subdomain"] = shannon_entropy(out["subdomain"])
        out["char_3gram_top3"] = ",".join([f"{g}:{c}" for g,c in top_ngrams(url, 3, topn=3)])
        out["detect_idn"] = any(ord(c) > 127 for c in domain)
        return out

    # -----------------------------
    # DNS Features
    # -----------------------------
    def dns_features(self, hostname):
        out = {}
        resolver = dns.resolver.Resolver()
        try:
            a_records = [r.to_text() for r in resolver.resolve(hostname, 'A', lifetime=5)]
        except Exception:
            a_records = []
        out["resolved_ips"] = ",".join(a_records)
        out["num_resolved_ips"] = len(a_records)

        try:
            ns = resolver.resolve(hostname, 'NS', lifetime=5)
            out["nameservers"] = ",".join([r.to_text() for r in ns])
        except Exception:
            out["nameservers"] = ""

        try:
            mx = resolver.resolve(hostname, 'MX', lifetime=5)
            out["mx_records"] = ",".join([r.exchange.to_text() for r in mx])
        except Exception:
            out["mx_records"] = ""

        # TODO: add SPF/DKIM/DMARC checks
        out["spf_record"] = ""
        out["dkim_record_present"] = False
        out["dmarc_record"] = ""
        out["dnssec_enabled"] = False
        return out

    # -----------------------------
    # WHOIS Features
    # -----------------------------
    def whois_features(self, hostname):
        out = {}
        w = whois.whois(hostname)
        out["registrar"] = getattr(w, "registrar", "")
        out["registrant_name"] = getattr(w, "name", "")
        out["registrant_org"] = getattr(w, "org", "")
        out["registrant_country"] = getattr(w, "country", "")
        return out

    # -----------------------------
    # TLS Features
    # -----------------------------
    def tls_features(self, hostname, port=443):
        out = {"https": False}
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    out["https"] = True
                    out["tls_subject_cn"] = dict(x[0] for x in cert.get("subject", ())).get("commonName","")
                    out["tls_issuer"] = dict(x[0] for x in cert.get("issuer", ())).get("organizationName","")
                    out["tls_valid_from"] = cert.get("notBefore")
                    out["tls_valid_to"] = cert.get("notAfter")
                    # Extended placeholders
                    out["ocsp_stapling_present"] = False
                    out["tls_cipher_suites"] = ""
                    out["certificate_revoked"] = False
        except Exception:
            pass
        return out

    # -----------------------------
    # HTTP Head + Security Headers
    # -----------------------------
    def http_head_features(self, url):
        out = {}
        r = self.session.get(url, allow_redirects=True, timeout=self.timeout)
        out["http_status_code"] = r.status_code
        out["final_url_after_redirects"] = r.url
        out["num_redirects"] = len(r.history)
        out["server_header"] = r.headers.get("Server","")
        out["server_header_fingerprint"] = out["server_header"].lower().strip()
        out["content_type"] = r.headers.get("Content-Type","")
        out["content_length"] = r.headers.get("Content-Length","")

        # Security headers
        hsts = r.headers.get("Strict-Transport-Security","")
        out["hsts_present"] = bool(hsts)
        if hsts:
            if "max-age=" in hsts:
                try:
                    out["hsts_max_age"] = int(re.search(r"max-age=(\d+)", hsts).group(1))
                except Exception: out["hsts_max_age"] = 0
            out["hsts_include_subdomains"] = "includesubdomains" in hsts.lower()
        else:
            out["hsts_max_age"] = 0
            out["hsts_include_subdomains"] = False

        out["x_content_type_options_present"] = "X-Content-Type-Options" in r.headers
        out["x_frame_options"] = r.headers.get("X-Frame-Options","")
        out["x_xss_protection"] = r.headers.get("X-XSS-Protection","")
        out["content_security_policy"] = r.headers.get("Content-Security-Policy","")
        out["strict_transport_security"] = hsts

        # Cookies
        cookies = r.cookies
        out["set_cookie_count"] = len(cookies)
        total = len(cookies)
        if total > 0:
            httponly = sum(1 for c in cookies if getattr(c,"_rest",{}).get("HttpOnly"))
            secure = sum(1 for c in cookies if c.secure)
            # SameSite not always available via requests
            out["cookies_httponly_pct"] = httponly/total
            out["cookies_secure_pct"] = secure/total
            out["cookies_samesite_strict_pct"] = 0
        else:
            out["cookies_httponly_pct"] = 0
            out["cookies_secure_pct"] = 0
            out["cookies_samesite_strict_pct"] = 0

        return out

    # -----------------------------
    # HTML / DOM Features
    # -----------------------------
    def html_dom_features(self, url):
        out = {}
        r = self.session.get(url, timeout=self.timeout)
        soup = BeautifulSoup(r.content, "lxml")

        scripts = soup.find_all("script")
        out["num_script_tags"] = len(scripts)
        out["num_external_script_tags"] = len([s for s in scripts if s.get("src")])
        js_text = " ".join(s.get_text() for s in scripts if not s.get("src"))
        out["suspicious_js_eval_calls"] = any(x in js_text for x in ["eval(","Function(","atob(","unescape("])
        out["has_sri_attributes"] = any(s.get("integrity") for s in scripts)

        forms = soup.find_all("form")
        out["num_forms"] = len(forms)
        out["form_action_to_third_party"] = any(urlparse(f.get("action","")).netloc not in [urlparse(url).netloc,""] for f in forms)
        cred_forms = []
        for f in forms:
            if any(i.get("type","").lower() in ["password","email","username"] for i in f.find_all("input")):
                cred_forms.append(f.get("action",""))
        out["forms_credential_fields"] = ",".join(cred_forms)
        out["has_auto_submit_js"] = "submit()" in js_text.lower()

        out["mailto_links_count"] = len(soup.find_all("a", href=re.compile(r"^mailto:")))
        out["tel_links_count"] = len(soup.find_all("a", href=re.compile(r"^tel:")))
        out["social_links_count"] = len(soup.find_all("a", href=re.compile(r"(facebook|twitter|linkedin|youtube)")))

        # executables
        exts = (".exe",".zip",".scr",".msi",".apk")
        out["links_to_executables_count"] = len([a for a in soup.find_all("a", href=True) if a['href'].lower().endswith(exts)])
        out["binary_expected_content_mismatch"] = False

        return out
