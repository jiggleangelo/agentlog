from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
import hashlib
import hmac

Q1_VALUES = {'verify', 'cost', 'docs', 'llms', 'none'}
Q2_VALUES = {'known_agents', 'botcost', 'cloudflare', 'other', 'none'}
Q3_VALUES = {'free_enough', 'would_pay', 'missing', 'unknown'}


def dedupe(secret, email):
    return hmac.new(secret.encode(), email.strip().casefold().encode(), hashlib.sha256).hexdigest()


def client_key(secret, client, day=None):
    day = day or datetime.now(timezone.utc).date().isoformat()
    return hmac.new(secret.encode(), f'{day}:{client}'.encode(), hashlib.sha256).hexdigest()


def join_waitlist(store, vault, secret, email, internal=False):
    email = str(email).strip(); key = dedupe(secret, email)
    if not store.event('waitlist', dedupe_key=key, is_internal=internal): return False
    try: vault.put('waitlist_email', email)
    except Exception:
        store.delete_event('waitlist', key); raise
    return True


def save_survey(store, vault, answers, internal=False, dedupe_key=None):
    if not dedupe_key: raise ValueError('survey client key is required')
    q1, q2, q3 = (answers.get(name) for name in ('q1', 'q2', 'q3'))
    if q1 not in Q1_VALUES or q2 not in Q2_VALUES or q3 not in Q3_VALUES: raise ValueError('invalid survey answer')
    other = str(answers.get('other', '')).strip()
    if other and q2 != 'other': raise ValueError('unexpected survey text')
    if len(other.encode('utf-8')) > 1024: raise ValueError('survey text is too long')
    if not store.survey(q1, q2, q3, internal, dedupe_key, dedupe_key): return False
    if other: vault.put('survey_other', other)
    return True


def rung0_status(store, now=None):
    cutoff = ((now or datetime.now(timezone.utc)) - timedelta(days=14)).isoformat()
    with store.lock:
        jobs = store.db.execute('SELECT COUNT(DISTINCT client_key) FROM jobs WHERE is_internal=0 AND client_key IS NOT NULL AND created_at>=?', (cutoff,)).fetchone()[0]
        waitlist = store.db.execute("SELECT COUNT(*) FROM funnel_events WHERE is_internal=0 AND kind='waitlist' AND ts>=?", (cutoff,)).fetchone()[0]
        events = store.db.execute('SELECT kind FROM funnel_events WHERE is_internal=0 AND ts>=?', (cutoff,)).fetchall()
        surveys = store.db.execute('SELECT q1,q2,q3 FROM surveys WHERE is_internal=0 AND client_key IS NOT NULL AND ts>=?', (cutoff,)).fetchall()
    counts = Counter(kind for (kind,) in events); desired = {'verify', 'cost', 'docs', 'llms'}
    free = sum(q2 in {'known_agents', 'botcost', 'cloudflare'} and q3 == 'free_enough' for _, q2, q3 in surveys)
    conditions = [max(jobs, waitlist) >= 40, counts['payment'] >= 3, len(surveys) >= 10 and sum(q1 in desired for q1, _, _ in surveys) / len(surveys) >= .30, len(surveys) >= 10 and free / len(surveys) < .30]
    return {'uploads': jobs, 'waitlist': waitlist, 'pay_clicks': counts['pay_click'], 'payments': counts['payment'], 'survey_responses': len(surveys), 'conditions': conditions}
