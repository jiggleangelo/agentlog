from __future__ import annotations

from functools import lru_cache
import json
from pathlib import Path
import re

PURPOSES = {'fetch', 'index', 'train', 'mixed', 'unknown'}
METHODS = {'ip_ranges', 'rdns', 'none'}
_GENERIC = re.compile(r'(?i)(?:^|[^a-z0-9])(?:bot|crawler|spider)(?:$|[^a-z0-9])|(?i:(?<=[a-z]{3})(?:bot|crawler|spider)\b)')


@lru_cache(maxsize=512)
def _token_pattern(token):
    return re.compile(r'(?<![a-z0-9])' + re.escape(str(token)) + r'(?![a-z0-9])', re.I)


def load_catalog(path=None):
    path = Path(path) if path else Path(__file__).resolve().parent.parent / 'data' / 'agents.json'
    entries = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(entries, list): raise ValueError('catalog must be a list')
    seen = set()
    for entry in entries:
        required = {'id', 'operator', 'ua_tokens', 'robots_token', 'purpose', 'verify', 'source_url', 'checked_at'}
        method = entry.get('verify', {}).get('method')
        if not required <= entry.keys() or entry['id'] in seen or entry['purpose'] not in PURPOSES or method not in METHODS:
            raise ValueError(f"invalid catalog entry: {entry.get('id', '?')}")
        if method == 'rdns' and not entry['verify'].get('suffixes'):
            raise ValueError(f"rdns catalog entry requires suffixes: {entry['id']}")
        if not entry['source_url'].startswith('https://') or len(entry['checked_at']) != 10:
            raise ValueError(f"unsourced catalog entry: {entry['id']}")
        for token in entry['ua_tokens']:
            _token_pattern(token)
        seen.add(entry['id'])
    return entries


def classify(ua, catalog):
    text = str(ua)
    candidates = []
    for order, entry in enumerate(catalog):
        for token in entry['ua_tokens']:
            if _token_pattern(token).search(text):
                candidates.append((len(token), -order, entry)); break
    if candidates:
        return max(candidates, key=lambda item: (item[0], item[1]))[2], None
    match = _GENERIC.search(text)
    return (None, match.group(0).strip(' -_/().;').casefold()) if match else (None, None)
