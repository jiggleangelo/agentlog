from __future__ import annotations

from collections import Counter, defaultdict
from itertools import islice

from .catalog import classify
from .verify import prefix, proxy_suspected_summary

URL_KEYS = 1000
ERROR_KEYS = 500
DOC_KEYS = 500
OUTPUT_URLS = 200
OUTPUT_ERRORS = 100
OUTPUT_DOCS = 100
BATCH = 1024


def _counter_add(mapping, key, limit):
    if key in mapping or len(mapping) < limit:
        mapping[key] += 1; return
    victim, count = min(mapping.items(), key=lambda item: item[1])
    del mapping[victim]; mapping[key] = count + 1


def _url_row(urls, key, amount):
    if key in urls: return urls[key]
    if len(urls) < URL_KEYS:
        row = {'requests': 0, 'bytes': 0, 'spoofed_requests': 0, 'agents': Counter()}; urls[key] = row; return row
    victim, old = min(urls.items(), key=lambda item: item[1]['bytes'])
    del urls[victim]
    row = {'requests': old['requests'], 'bytes': old['bytes'], 'spoofed_requests': 0, 'agents': Counter()}
    urls[key] = row; return row


def aggregate(hits, catalog, verifier, format_name, lines_read=0, lines_skipped=0, stats=None):
    agents = defaultdict(lambda: {'requests': 0, 'bytes': 0, 's2xx': 0, 's3xx': 0, 's4xx': 0, 's5xx': 0})
    purposes = defaultdict(lambda: {'requests': 0, 'bytes': 0})
    urls = {}; errors, docs = Counter(), Counter()
    available = format_name != 'vercel'
    observed = spoofed = agent_hits = non_agent = 0; spoofed_prefixes = Counter(); time_start = time_end = None; iterator = iter(hits)
    while True:
        batch = list(islice(iterator, BATCH))
        if not batch: break
        classified = [classify(hit.ua, catalog) for hit in batch]
        pairs = [(entry, hit.ip) for hit, (entry, _) in zip(batch, classified) if entry]
        verified = iter(verifier.verify_many(pairs) if hasattr(verifier, 'verify_many') else (verifier.verify(*pair) for pair in pairs))
        statuses = [next(verified) if entry else 'unverifiable' for entry, _ in classified]
        for hit, (entry, generic), status in zip(batch, classified, statuses):
            if not entry and not generic: non_agent += 1; continue
            agent_id = entry['id'] if entry else 'unclassified-automated'; purpose = entry['purpose'] if entry else 'unknown'
            if entry and entry['verify']['method'] != 'none' and hit.ip is not None and status in {'verified', 'spoofed'}:
                observed += 1
                if status == 'spoofed':
                    spoofed += 1; p = prefix(hit.ip)
                    spoofed_prefixes[p if p in spoofed_prefixes or len(spoofed_prefixes) < 256 else '(other)'] += 1
            amount = (hit.bytes_sent or 0) if available else 0
            row = agents[(agent_id, status)]; row['requests'] += 1; row['bytes'] += amount
            bucket = hit.status // 100
            if bucket in (2, 3, 4, 5): row[f's{bucket}xx'] += 1
            purposes[purpose]['requests'] += 1; purposes[purpose]['bytes'] += amount
            url = _url_row(urls, hit.path, amount); url['requests'] += 1; url['bytes'] += amount; url['spoofed_requests'] += status == 'spoofed'; url['agents'][agent_id] += 1
            if hit.status >= 400: _counter_add(errors, (agent_id, hit.path, hit.status), ERROR_KEYS)
            lower = hit.path.casefold(); kind = 'llms' if lower in ('/llms.txt', '/llms-full.txt') else 'markdown' if lower.endswith('.md') else None
            if kind: _counter_add(docs, (kind, hit.path, agent_id, hit.status, status), DOC_KEYS)
            agent_hits += 1
            if hit.ts:
                stamp = hit.ts.isoformat(); time_start = stamp if time_start is None or stamp < time_start else time_start; time_end = stamp if time_end is None or stamp > time_end else time_end
    suspected = proxy_suspected_summary(observed, spoofed, spoofed_prefixes, min_samples=50)
    if suspected:
        replaced = defaultdict(lambda: {'requests': 0, 'bytes': 0, 's2xx': 0, 's3xx': 0, 's4xx': 0, 's5xx': 0})
        for (agent_id, status), row in agents.items():
            target = 'unchecked' if status in {'verified', 'spoofed'} else status
            for name, value in row.items(): replaced[(agent_id, target)][name] += value
        agents = replaced
        for row in urls.values(): row['spoofed_requests'] = 0
        downgraded = Counter()
        for (kind, path, agent_id, code, status), count in docs.items():
            downgraded[(kind, path, agent_id, code, 'unchecked' if status in {'verified', 'spoofed'} else status)] += count
        docs = downgraded
    if stats is not None: lines_read, lines_skipped = stats['lines_read'], stats['lines_skipped']
    url_rows = [{'path': path, 'top_agents': [a for a, _ in row['agents'].most_common(3)], 'requests': row['requests'], 'bytes': row['bytes'], 'spoofed_requests': row['spoofed_requests']} for path, row in sorted(urls.items(), key=lambda item: item[1]['bytes'], reverse=True)[:OUTPUT_URLS]]
    return {'format': format_name, 'format_beta': format_name == 'vercel', 'bytes_available': available, 'lines_read': lines_read, 'lines_skipped': lines_skipped, 'agent_hits': agent_hits, 'non_agent_lines': non_agent, 'proxy_suspected': suspected, 'time_start': time_start, 'time_end': time_end, 'agents': [{'agent_id': k[0], 'status': k[1], **v} for k, v in sorted(agents.items())], 'purposes': [{'purpose': k, **v} for k, v in sorted(purposes.items())], 'urls': url_rows, 'errors': [{'agent_id': k[0], 'path': k[1], 'status': k[2], 'requests': v} for k, v in errors.most_common(OUTPUT_ERRORS)], 'docs': [{'kind': k[0], 'path': k[1], 'agent_id': k[2], 'status': k[3], 'verify_status': k[4], 'requests': v} for k, v in docs.most_common(OUTPUT_DOCS)]}
