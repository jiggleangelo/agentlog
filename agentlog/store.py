from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import secrets
import sqlite3
import threading

SCHEMA = '''
CREATE TABLE IF NOT EXISTS jobs(id INTEGER PRIMARY KEY, created_at TEXT, expires_at TEXT, share_token TEXT UNIQUE, delete_token_hash TEXT, format TEXT, report_json TEXT, is_internal INTEGER, client_key TEXT);
CREATE TABLE IF NOT EXISTS funnel_events(id INTEGER PRIMARY KEY, ts TEXT, kind TEXT, value TEXT, dedupe_key TEXT, is_internal INTEGER);
CREATE TABLE IF NOT EXISTS surveys(id INTEGER PRIMARY KEY, ts TEXT, q1 TEXT NOT NULL, q2 TEXT NOT NULL, q3 TEXT NOT NULL, is_internal INTEGER NOT NULL DEFAULT 0, dedupe_key TEXT, client_key TEXT);
'''


class Store:
    def __init__(self, path):
        self.db = sqlite3.connect(path, check_same_thread=False); self.lock = threading.RLock()
        with self.lock:
            self.db.executescript(SCHEMA)
            for table, column in (('jobs', 'client_key'), ('surveys', 'dedupe_key'), ('surveys', 'client_key')):
                columns = {row[1] for row in self.db.execute(f'PRAGMA table_info({table})')}
                if column not in columns: self.db.execute(f'ALTER TABLE {table} ADD COLUMN {column} TEXT')
            self.db.execute('DELETE FROM funnel_events WHERE dedupe_key IS NOT NULL AND id NOT IN (SELECT MIN(id) FROM funnel_events WHERE dedupe_key IS NOT NULL GROUP BY kind,dedupe_key)')
            self.db.execute('DELETE FROM surveys WHERE dedupe_key IS NOT NULL AND id NOT IN (SELECT MIN(id) FROM surveys WHERE dedupe_key IS NOT NULL GROUP BY dedupe_key)')
            self.db.execute('CREATE UNIQUE INDEX IF NOT EXISTS funnel_dedupe ON funnel_events(kind,dedupe_key) WHERE dedupe_key IS NOT NULL')
            self.db.execute('CREATE UNIQUE INDEX IF NOT EXISTS survey_dedupe ON surveys(dedupe_key) WHERE dedupe_key IS NOT NULL'); self.db.commit()

    def save_report(self, report, is_internal=False, client_key=None):
        now = datetime.now(timezone.utc); share = secrets.token_urlsafe(16); delete = secrets.token_urlsafe(24); digest = hashlib.sha256(delete.encode()).hexdigest()
        with self.lock:
            cur = self.db.execute('INSERT INTO jobs(created_at,expires_at,share_token,delete_token_hash,format,report_json,is_internal,client_key) VALUES(?,?,?,?,?,?,?,?)', (now.isoformat(), (now + timedelta(days=30)).isoformat(), share, digest, report['format'], json.dumps(report, separators=(',', ':')), int(is_internal), client_key)); self.db.commit()
        return cur.lastrowid, share, delete

    def get_report(self, token):
        with self.lock: row = self.db.execute('SELECT report_json,expires_at FROM jobs WHERE share_token=?', (token,)).fetchone()
        return None if not row or datetime.fromisoformat(row[1]) <= datetime.now(timezone.utc) else json.loads(row[0])

    def delete_report(self, token, delete_token):
        digest = hashlib.sha256(delete_token.encode()).hexdigest()
        with self.lock: cur = self.db.execute('DELETE FROM jobs WHERE share_token=? AND delete_token_hash=?', (token, digest)); self.db.commit()
        return cur.rowcount == 1

    def event(self, kind, value=None, dedupe_key=None, is_internal=False):
        with self.lock: cur = self.db.execute('INSERT OR IGNORE INTO funnel_events(ts,kind,value,dedupe_key,is_internal) VALUES(?,?,?,?,?)', (datetime.now(timezone.utc).isoformat(), kind, value, dedupe_key, int(is_internal))); self.db.commit(); return cur.rowcount == 1

    def delete_event(self, kind, dedupe_key):
        with self.lock: self.db.execute('DELETE FROM funnel_events WHERE kind=? AND dedupe_key=?', (kind, dedupe_key)); self.db.commit()

    def survey(self, q1, q2, q3, is_internal=False, dedupe_key=None, client_key=None):
        if not dedupe_key or not client_key: raise ValueError('survey client key is required')
        with self.lock: cur = self.db.execute('INSERT OR IGNORE INTO surveys(ts,q1,q2,q3,is_internal,dedupe_key,client_key) VALUES(?,?,?,?,?,?,?)', (datetime.now(timezone.utc).isoformat(), q1, q2, q3, int(is_internal), dedupe_key, client_key)); self.db.commit(); return cur.rowcount == 1

    def purge(self):
        now = datetime.now(timezone.utc); cutoff = (now - timedelta(days=90)).isoformat()
        with self.lock:
            reports = self.db.execute('DELETE FROM jobs WHERE expires_at < ?', (now.isoformat(),)).rowcount
            events = self.db.execute('DELETE FROM funnel_events WHERE ts < ?', (cutoff,)).rowcount
            surveys = self.db.execute('DELETE FROM surveys WHERE ts < ?', (cutoff,)).rowcount; self.db.commit()
        return reports, events + surveys
