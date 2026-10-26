from __future__ import annotations

import html
import json


def as_json(report):
    return json.dumps(report, ensure_ascii=False, separators=(',', ':'))


def render(report):
    esc = lambda value: html.escape(str(value), quote=True)
    available = report.get('bytes_available', True)
    eligible = sum(int(row['bytes']) for row in report['agents'] if row['status'] in {'verified', 'spoofed'})
    spoofed = sum(int(row['bytes']) for row in report['agents'] if row['status'] == 'spoofed')
    share = 100 * spoofed / eligible if eligible else 0
    byte_head = '<th>Bytes</th>' if available else ''
    def bytes_cell(row): return f"<td>{int(row['bytes'])}</td>" if available else ''
    agents = ''.join(f"<tr><td>{esc(r['agent_id'])}</td><td>{esc(r['status'])}</td><td>{int(r['requests'])}</td>{bytes_cell(r)}</tr>" for r in report['agents'])
    purposes = ''.join(f"<tr><td>{esc(r['purpose'])}</td><td>{int(r['requests'])}</td>{bytes_cell(r)}</tr>" for r in report['purposes'])
    def url_cells(row):
        return f"<td class='bytes' data-bytes='{int(row['bytes'])}'>{int(row['bytes'])}</td><td class='cost'>—</td>" if available else ''
    urls = ''.join(f"<tr><td>{esc(r['path'])}</td><td>{int(r['requests'])}</td>{url_cells(r)}</tr>" for r in report['urls'])
    errors = ''.join(f"<li>{esc(r['agent_id'])}: {esc(r['path'])} returned {int(r['status'])} ({int(r['requests'])}×)</li>" for r in report['errors'])
    docs = ''.join(f"<li>{esc(r['agent_id'])}: {esc(r['path'])} — {int(r['status'])}, {esc(r['verify_status'])}</li>" for r in report['docs'])
    proxy = '<aside>Your log appears to record a proxy IP. Configure the real client-IP field and re-upload.</aside>' if report.get('proxy_suspected') else ''
    unavailable = '<aside>Bytes unavailable for this format; byte totals and cost estimates are hidden.</aside>' if not available else ''
    beta = ' <strong>(beta)</strong>' if report.get('format_beta') else ''
    cost_head = '<th>Estimated cost</th>' if available else ''
    rate = "<label>Your egress $/GB <input id='rate' type='number' min='0' step='.01'></label>" if available else ''
    summary = f'{share:.1f}% of verified-or-spoofed agent bytes came from spoofed claims. Unchecked and unverifiable traffic is excluded.' if available else 'Byte-based spoofing share is unavailable for this format.'
    return f"""<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width'><title>AgentLog report</title><link rel='stylesheet' href='/static/style.css'><script src='/static/report.js' defer></script></head><body><main><h1>AgentLog report</h1><aside><strong>Shared report:</strong> anyone with this link can see the bounded, shape-redacted path summaries below. Do not share if even redacted route structure is sensitive. Delete the report when it is no longer needed.</aside>{proxy}{unavailable}<section><h2>Summary</h2><p>{summary}</p><p>{int(report['agent_hits'])} agent hits; {int(report['non_agent_lines'])} non-agent lines; {int(report['lines_skipped'])} lines skipped.</p><p>Docs-file signals: {len(report['docs'])} grouped observations.</p></section><section><h2>Agents</h2><table><tr><th>Agent</th><th>Verification</th><th>Requests</th>{byte_head}</tr>{agents}</table></section><section><h2>Fetch / index / train split</h2><table><tr><th>Purpose</th><th>Requests</th>{byte_head}</tr>{purposes}</table></section><section><h2>Costliest URLs</h2>{rate}<table><tr><th>Path</th><th>Requests</th>{byte_head}{cost_head}</tr>{urls}</table></section><section><h2>Docs fix list</h2><ul>{errors or '<li>No agent errors found.</li>'}</ul><h3>llms.txt and Markdown</h3><ul>{docs or '<li>No docs-file requests found.</li>'}</ul></section><section><h2>Method &amp; caveats</h2><p>Format: {esc(report['format'])}{beta}. Paths are decoded, query-like suffixes removed, segment-count and length bounded, and non-allowlisted segments redacted. Raw IPs and user agents are not retained. Reverse-DNS verification discloses selected log IPs to the configured DNS resolver and is globally and per-job rate limited.</p></section></main></body></html>"""
