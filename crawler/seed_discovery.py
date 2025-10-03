# crawler/seed_discovery.py
import certstream
import json
import time
import threading
from urllib.parse import urlparse

SEEDS_FILE = "crawler_seed_urls.txt"

def _add_seed(domain):
    d = domain.lower().strip()
    if d and not d.startswith("*."):
        with open(SEEDS_FILE, "a") as f:
            f.write(d + "\n")

def _certstream_cb(message, context):
    if message["message_type"] == "certificate_update":
        try:
            leaf = message["data"]["leaf_cert"]
            for name in leaf.get("all_domains", []):
                parsed = urlparse("http://" + name)
                _add_seed(parsed.netloc)
        except Exception:
            pass

def start_certstream_listener(async_mode=True):
    """Runs certificate listener in a background thread and persists domains."""
    if async_mode:
        t = threading.Thread(target=lambda: certstream.listen_for_events(_certstream_cb, url='wss://certstream.calidog.io', skip_heartbeats=True), daemon=True)
        t.start()
    else:
        certstream.listen_for_events(_certstream_cb, url='wss://certstream.calidog.io', skip_heartbeats=True)

if __name__ == "__main__":
    print("Starting CertStream listener (ctrl-c to stop)")
    start_certstream_listener(async_mode=False)
