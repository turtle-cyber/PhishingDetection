# extractor.py
import time
import socket
import ssl
import requests
import tldextract
import dns.resolver
import whois
from urllib.parse import urlparse, unquote
from collections import Counter
import math
from bs4 import BeautifulSoup
import re
from image_utils import fetch_favicon_hash, screenshot_and_phash
from text_utils import shannon_entropy, top_ngrams
from rapidfuzz.distance import Levenshtein

class FeatureExtractor:
    def __init__(self, workers=8, timeout=10):
        self.session = requests.Session()
        self.timeout = timeout
        self.workers = workers
        # ephemeral host provider patterns (local YAML recommended)
        self.ephemeral_patterns = ["ngrok.io","vercel.app","pages.dev","onrender.com","github.io","netlify.app","render.com"]

    def process_url(self, raw_url, meta=None):
        meta = meta or {}
        out = {}
        out["original_url"] = raw_url
        url = self._normalize(raw_url)
        out["url_norm"] = url
        parsed = urlparse(url)
        out["has_query"] = bool(parsed.query)
        out["has_fragment"] = bool(parsed.fragment)
        out["has_at_symbol"] = "@" in url

        # lexical/text features
        out.update(self.lexical_features(url, parsed))

        # dns + whois
        try:
            out.update(self.dns_features(parsed.hostname))
        except Exception as e:
            out["dns_error"] = str(e)

        try:
            out.update(self.whois_features(parsed.hostname))
        except Exception as e:
            out["whois_error"] = str(e)

        # TLS
        try:
            out.update(self.tls_features(parsed.hostname))
        except Exception as e:
            out["tls_error"] = str(e)

        # HTTP HEAD
        try:
            out.update(self.http_head_features(url))
        except Exception as e:
            out["http_error"] = str(e)

        # HTML fetch & parse (lightweight)
        if out.get("http_status_code") == 200 and out.get("content_type","").startswith("text/html"):
            try:
                out.update(self.html_dom_features(out.get("final_url_after_redirects") or url))
            except Exception as e:
                out["html_error"] = str(e)
        
        html_content = None
        if out.get("http_status_code") == 200 and "text/html" in out.get("content_type",""):
        # you probably already fetched the page; capture its HTML for favicon discovery
            html_content = self.last_fetched_html  # adapt to how you store fetched HTML in code
        favicon_info = fetch_favicon_hash(url, html_content=html_content, out_dir="Phishing_Evidences/favicons", timeout=8, ephemeral_patterns=self.ephemeral_patterns, attempt_playwright=False)
        out.update(favicon_info)
        # favicon + visual (best-effort)
        try:
            out.update(fetch_favicon_hash(url, timeout=self.timeout, ephemeral_patterns=self.ephemeral_patterns))
        except Exception as e:
            out["favicon_error"] = str(e)

        # screenshot phash (optional: heavy)
        try:
            out.update(screenshot_and_phash(url))
        except Exception as e:
            out["screenshot_error"] = str(e)

        # heuristic score
        out["rule_score"] = self.compute_rule_score(out)
        return out

    def _normalize(self, raw):
        if not raw:
            return raw
        u = raw.strip()
        if not u.lower().startswith(("http://","https://")):
            u = "http://" + u
        return u

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
        out["num_uppercase_chars"] = sum(c.isupper() for c in url)
        out["num_lowercase_chars"] = sum(c.islower() for c in url)
        out["entropy_domain"] = shannon_entropy(domain)
        out["entropy_subdomain"] = shannon_entropy(out["subdomain"])
        out["char_3gram_top3"] = ",".join([f"{g}:{c}" for g,c in top_ngrams(url, 3, topn=3)])
        out["longest_token_length_in_domain"] = max([len(t) for t in re.split(r"[.-]", domain) if t]) if domain else 0
        out["detect_idn"] = any(ord(c) > 127 for c in domain)
        return out

    def dns_features(self, hostname):
        out = {}
        resolver = dns.resolver.Resolver()
        a_records = []
        try:
            answers = resolver.resolve(hostname, 'A', lifetime=5)
            a_records = [r.to_text() for r in answers]
        except Exception:
            a_records = []
        out["resolved_ips"] = ",".join(a_records)
        out["num_resolved_ips"] = len(a_records)
        # nameservers, mx etc
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
        # Basic reverse DNS
        if a_records:
            try:
                out["reverse_dns_primary_ip"] = socket.gethostbyaddr(a_records[0])[0]
            except Exception:
                out["reverse_dns_primary_ip"] = ""
        return out

    def whois_features(self, hostname):
        out = {}
        w = whois.whois(hostname)
        out["registrar"] = w.registrar if hasattr(w, "registrar") else ""
        out["registrant_name"] = w.name if hasattr(w, "name") else ""
        out["registrant_org"] = w.org if hasattr(w, "org") else ""
        out["registrant_country"] = w.country if hasattr(w, "country") else ""
        try:
            created = w.creation_date
            if isinstance(created, list):
                created = created[0]
            out["whois_creation_date"] = created.isoformat() if created else ""
        except Exception:
            out["whois_creation_date"] = ""
        return out

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
        except Exception:
            # leave https False
            pass
        return out

    def http_head_features(self, url):
        out = {}
        r = self.session.head(url, allow_redirects=True, timeout=self.timeout)
        out["http_status_code"] = r.status_code
        out["final_url_after_redirects"] = r.url
        out["num_redirects"] = len(r.history)
        out["server_header"] = r.headers.get("Server","")
        out["content_type"] = r.headers.get("Content-Type","")
        out["content_length"] = r.headers.get("Content-Length","")
        return out

    def html_dom_features(self, url):
        out = {}
        r = self.session.get(url, timeout=self.timeout)
        soup = BeautifulSoup(r.content, "lxml")
        text = soup.get_text(" ", strip=True)
        out["page_text_length"] = len(text)
        forms = soup.find_all("form")
        out["num_forms"] = len(forms)
        inputs = soup.find_all("input")
        out["num_inputs_total"] = len(inputs)
        out["num_password_fields"] = len([i for i in inputs if i.get("type","").lower()=="password"])
        out["num_iframes"] = len(soup.find_all("iframe"))
        scripts = soup.find_all("script")
        out["num_external_scripts"] = len([s for s in scripts if s.get("src")])
        # simple login heuristic
        out["has_login_form"] = any("password" in str(f).lower() for f in forms)
        return out

    def compute_rule_score(self, out):
        score = 0
        # example rules
        if out.get("domain_length",0) > 30: score += 10
        if out.get("num_hyphens",0) >= 2: score += 5
        if out.get("detect_idn"): score += 15
        if out.get("domain_age_days") is not None and out["domain_age_days"] < 30: score += 20
        if out.get("num_password_fields",0) > 0: score += 15
        if out.get("is_ephemeral_host_flag"): score += 20
        return min(100, score)
