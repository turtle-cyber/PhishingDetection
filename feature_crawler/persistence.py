# crawler/persistence.py
import sqlite3
import json
import os

DB_PATH = "crawler_state.db"

def ensure_db(db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS pages (
        url TEXT PRIMARY KEY,
        domain TEXT,
        processed_at TEXT,
        label TEXT,
        evidence_paths TEXT,
        dom_simhash INTEGER,
        last_ocr TEXT
    )""")
    conn.commit()
    conn.close()

def upsert_page(url, domain, label, evidence_paths, dom_simhash, last_ocr, db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("""
    INSERT INTO pages (url, domain, processed_at, label, evidence_paths, dom_simhash, last_ocr)
    VALUES (?, datetime('now'), ?, ?, ?, ?, ?)
    ON CONFLICT(url) DO UPDATE SET
      processed_at = datetime('now'),
      label=excluded.label,
      evidence_paths=excluded.evidence_paths,
      dom_simhash=excluded.dom_simhash,
      last_ocr=excluded.last_ocr
    """, (url, domain, label, json.dumps(evidence_paths), dom_simhash or 0, last_ocr or ""))
    conn.commit()
    conn.close()
