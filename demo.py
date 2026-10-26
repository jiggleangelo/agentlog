#!/usr/bin/env python3
"""Hosted, disposable AgentLog user-test demo."""
from __future__ import annotations

from collections import OrderedDict, defaultdict, deque
from datetime import datetime, timezone
import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import os
import secrets
import socket
import threading
import time
from urllib.parse import parse_qs, urlsplit

from agentlog.aggregate import aggregate
from agentlog.catalog import load_catalog
from agentlog.parsers import ParseError, stream_lines
from agentlog.rules import nginx, robots, waf
from agentlog.verify import FakeResolver, Verifier

MAX_BODY = 64 * 1024
MAX_REPORTS = 500
REPORT_TTL_SECONDS = 60 * 60
RATE_LIMIT = 30
RATE_WINDOW_SECONDS = 60
MAX_CONNECTIONS = 64
BANNER = (
    "Demo operated by AI agents. Made-up data. Do not enter real personal data. "
    "Nothing is charged."
)
SAMPLE_LOG = """192.0.2.10 - - [24/Oct/2026:12:00:00 +0000] "GET /docs/api.md HTTP/1.1" 200 24576 "-" "GPTBot"
198.51.100.20 - - [24/Oct/2026:12:00:01 +0000] "GET /llms.txt HTTP/1.1" 404 312 "-" "GPTBot"
192.0.2.11 - - [24/Oct/2026:12:00:02 +0000] "GET /docs/quickstart.md HTTP/1.1" 200 16384 "-" "OAI-SearchBot"
203.0.113.30 - - [24/Oct/2026:12:00:03 +0000] "GET /docs/missing.md HTTP/1.1" 404 128 "-" "ClaudeBot"
192.0.2.12 - - [24/Oct/2026:12:00:04 +0000] "GET /pricing HTTP/1.1" 200 8192 "-" "Mozilla/5.0"
"""


class DemoRateLimiter:
    def __init__(self, limit=RATE_LIMIT, window=RATE_WINDOW_SECONDS):
        self.limit = limit
        self.window = window
        self.rows = defaultdict(deque)
        self.lock = threading.Lock()
        self.calls = 0

    def allow(self, key):
        now = time.monotonic()
        with self.lock:
            self.calls += 1
            row = self.rows[key]
            while row and row[0] <= now - self.window:
                row.popleft()
            if self.calls % 256 == 0:
                for candidate in list(self.rows):
                    values = self.rows[candidate]
                    while values and values[0] <= now - self.window:
                        values.popleft()
                    if not values:
                        self.rows.pop(candidate, None)
            if len(row) >= self.limit:
                return False
            row.append(now)
            return True


def _ensure_socket_makefile():
    """Give the raw socket type the high-level makefile API used by HTTPServer."""
    if socket.socket is not socket.SocketType or hasattr(socket.socket, "makefile"):
        return

    class DemoSocket(socket.SocketType):
        def _decref_socketios(self):
            self.close()

        def makefile(self, mode="r", buffering=-1, *, encoding=None, errors=None, newline=None):
            if not set(mode) <= {"r", "w", "b"}:
                raise ValueError("invalid mode")
            writing = "w" in mode
            reading = "r" in mode or not writing
            binary = "b" in mode
            rawmode = ("r" if reading else "") + ("w" if writing else "")
            if buffering is None or buffering < 0:
                buffering = io.DEFAULT_BUFFER_SIZE
            if buffering == 0 and not binary:
                raise ValueError("unbuffered streams must be binary")
            descriptor = os.dup(self.fileno())
            try:
                duplicate = type(self)(self.family, self.type, self.proto, fileno=descriptor)
            except BaseException:
                os.close(descriptor)
                raise
            stream = None
            try:
                duplicate.settimeout(self.gettimeout())
                stream = socket.SocketIO(duplicate, rawmode)
                if buffering == 0:
                    return stream
                if reading and writing:
                    stream = io.BufferedRWPair(stream, stream, buffering)
                elif reading:
                    stream = io.BufferedReader(stream, buffering)
                else:
                    stream = io.BufferedWriter(stream, buffering)
                if binary:
                    return stream
                text = io.TextIOWrapper(stream, encoding=encoding, errors=errors, newline=newline)
                text.mode = mode
                return text
            except BaseException:
                if stream is not None:
                    stream.close()
                else:
                    duplicate.close()
                raise

        def accept(self):
            descriptor, address = self._accept()
            try:
                accepted = type(self)(self.family, self.type, self.proto, fileno=descriptor)
            except BaseException:
                os.close(descriptor)
                raise
            if socket.getdefaulttimeout() is None and self.gettimeout():
                accepted.setblocking(True)
            return accepted, address

    socket.socket = DemoSocket


def _escape(value):
    return html.escape(str(value), quote=True)


def _snapshot():
    stamp = datetime.now(timezone.utc).isoformat()
    return {"agents": {name: {"fetched_at": stamp, "ranges": ["192.0.2.0/24"]} for name in (
        "openai-gptbot", "openai-searchbot", "openai-user"
    )}}


def _page(title, content):
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>{_escape(title)}</title><style>
:root {{ color-scheme: light dark; font-family: system-ui,sans-serif; line-height:1.5 }} body {{ margin:0 }} main {{ max-width:70rem;margin:auto;padding:1rem }}
.demo-banner {{ background:#fff3a3;color:#241d00;border:2px solid #7a6200;padding:.8rem;font-weight:700 }} section {{ border:1px solid #8888;border-radius:.5rem;margin:1rem 0;padding:1rem }}
form,label {{ display:grid;gap:.6rem }} textarea {{ box-sizing:border-box;font:.85rem ui-monospace,monospace;min-height:15rem;width:100% }} button,input,select,textarea {{ font:inherit;padding:.55rem }}
table {{ border-collapse:collapse;width:100%;overflow-wrap:anywhere }} th,td {{ border-bottom:1px solid #8888;padding:.45rem;text-align:left }} pre {{ border:1px solid #8888;padding:.75rem;white-space:pre-wrap;overflow-wrap:anywhere }} .error {{ color:#b42318;font-weight:700 }}
</style></head><body><main><div class="demo-banner" role="note">{_escape(BANNER)}</div>{content}</main></body></html>"""


def landing_page():
    return _page("AgentLog user-test demo", f"""<h1>AgentLog log-upload report</h1><p>Try the complete flow with the made-up log already loaded. Click once to see verified-versus-spoofed identities, bandwidth by URL, docs failures, and copyable rules.</p>
<section><h2>1. Choose a synthetic log</h2><form method="post" action="/analyze"><label>Optional local log file<input id="log-file" type="file" accept=".log,.txt,text/plain"><span>This only loads the file into the box below. Keep this demo synthetic.</span></label>
<label>Log format<select name="format"><option value="combined">Nginx / Apache combined</option><option value="auto">Auto-detect</option><option value="caddy">Caddy JSON</option><option value="cloudflare">Cloudflare Logpush</option><option value="vercel">Vercel JSON (beta)</option></select></label>
<label>Log data<textarea id="log-data" name="log" maxlength="60000" required>{_escape(SAMPLE_LOG)}</textarea></label><button type="submit">2. Build my demo report</button></form></section>
<p>No account is needed. Reports live only in this process and disappear when it restarts.</p><script src="/demo.js"></script>""")


def report_page(token, report, catalog, snapshot):
    available = report.get("bytes_available", True)
    byte_head = "<th>Bytes</th>" if available else ""
    unavailable = "" if available else "<aside>Bytes unavailable for this format; byte totals are hidden.</aside>"
    agent_rows = "".join(
        "<tr><td>{}</td><td>{}</td><td>{}</td>{}</tr>".format(
            _escape(row["agent_id"]), _escape(row["status"]), int(row["requests"]),
            f'<td>{int(row["bytes"])}</td>' if available else "",
        ) for row in report["agents"]
    )
    url_rows = "".join(
        "<tr><td>{}</td><td>{}</td>{}</tr>".format(
            _escape(row["path"]), int(row["requests"]),
            f'<td>{int(row["bytes"])}</td>' if available else "",
        ) for row in report["urls"]
    )
    docs = "".join(
        "<li>{}: {} returned HTTP {} — {} ({} request(s))</li>".format(
            _escape(row["agent_id"]), _escape(row["path"]), int(row["status"]),
            _escape(row["verify_status"]), int(row["requests"]),
        ) for row in report["docs"]
    ) or "<li>No llms.txt or Markdown requests were found.</li>"
    selected = {row["agent_id"] for row in report["agents"] if row["agent_id"] != "unclassified-automated"}
    generated_robots = robots(catalog, selected, ["/docs/"])
    generated_waf = waf(catalog, snapshot, selected)
    generated_nginx = nginx(catalog, selected)
    content = f"""<h1>Your AgentLog demo report</h1><p><a href="/">Try another made-up log</a> · <a href="/report/{_escape(token)}">Permalink for this process</a></p>{unavailable}
<section><h2>Summary</h2><p><strong>{int(report['agent_hits'])}</strong> agent hits, <strong>{int(report['non_agent_lines'])}</strong> ordinary hits, and <strong>{int(report['lines_skipped'])}</strong> skipped lines.</p></section>
<section><h2>Verified versus claimed identity</h2><table><thead><tr><th>Agent</th><th>Result</th><th>Requests</th>{byte_head}</tr></thead><tbody>{agent_rows}</tbody></table></section>
<section><h2>{'Bytes' if available else 'Requests'} by URL</h2><table><thead><tr><th>Path</th><th>Requests</th>{byte_head}</tr></thead><tbody>{url_rows}</tbody></table></section>
<section><h2>llms.txt and Markdown signals</h2><ul>{docs}</ul></section><section><h2>Suggested copy-only rules</h2><p>Review these before using them outside this demo.</p>
<h3>robots.txt</h3><pre>{_escape(generated_robots or 'No robots.txt rule available.')}</pre><h3>WAF expression</h3><pre>{_escape(generated_waf or 'No WAF expression available for these agents.')}</pre><h3>nginx map</h3><pre>{_escape(generated_nginx)}</pre></section>"""
    return _page("AgentLog demo report", content)


DEMO_JS = b"""document.getElementById('log-file').addEventListener('change', async event => {
  const file = event.target.files[0]; if (!file) return;
  if (file.size > 60000) { alert('Choose a synthetic file smaller than 60 KB.'); event.target.value = ''; return; }
  document.getElementById('log-data').value = await file.text();
});
"""


class DemoHandler(BaseHTTPRequestHandler):
    server_version = "AgentLogDemo/1.1"
    timeout = 10

    def log_message(self, format, *args):
        pass

    def _send(self, status, body, content_type="text/html; charset=utf-8", extra=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _error(self, status, message, extra=None):
        self._send(status, _page("AgentLog demo error", f'<h1>Could not build the report</h1><p class="error">{_escape(message)}</p><p><a href="/">Return to the demo</a></p>'), extra=extra)

    def do_GET(self):
        route = urlsplit(self.path).path
        if route == "/healthz":
            self._send(200, b"ok", "text/plain; charset=utf-8")
        elif route == "/":
            self._send(200, landing_page())
        elif route == "/demo.js":
            self._send(200, DEMO_JS, "text/javascript; charset=utf-8")
        elif route.startswith("/report/"):
            token = route.removeprefix("/report/")
            report = self.server.get_report(token)
            if report is None:
                self._error(404, "That in-memory report is unavailable, expired, or the demo restarted.")
            else:
                self._send(200, report_page(token, report, self.server.catalog, self.server.snapshot))
        else:
            self._error(404, "Page not found.")

    def do_POST(self):
        if urlsplit(self.path).path != "/analyze":
            self._error(404, "Page not found.")
            return
        client = str(self.client_address[0]).split("%", 1)[0]
        if not self.server.rate_limiter.allow(client):
            self._error(429, "Too many requests. Try again in a minute.", {"Retry-After": "60"})
            return
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self._error(400, "Invalid Content-Length header.")
            return
        if length < 0:
            self._error(400, "Invalid request-body size.")
            return
        if length > MAX_BODY:
            self._error(413, "Request bodies are limited to 64 KB.")
            return
        raw = self.rfile.read(length)
        if len(raw) != length:
            self._error(400, "Incomplete request body.")
            return
        try:
            form = parse_qs(raw.decode("utf-8"), keep_blank_values=True, max_num_fields=10)
        except (UnicodeDecodeError, ValueError):
            self._error(400, "Invalid form data.")
            return
        log_text = form.get("log", [""])[0]
        format_name = form.get("format", ["combined"])[0]
        if format_name not in {"auto", "combined", "caddy", "cloudflare", "vercel"}:
            self._error(400, "Unknown log format.")
            return
        if not log_text.strip():
            self._error(400, "Paste or select a synthetic log first.")
            return
        try:
            name, hits, stats = stream_lines(log_text.splitlines(), format_name)
            try:
                report = aggregate(hits, self.server.catalog, Verifier(self.server.snapshot, self.server.resolver), name, stats=stats)
            finally:
                hits.close()
        except ParseError as exc:
            self._error(400, str(exc))
            return
        token = secrets.token_urlsafe(12)
        self.server.save_report(token, report)
        self._send(303, b"", "text/plain; charset=utf-8", {"Location": f"/report/{token}"})


class AgentLogDemoServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address):
        self.catalog = load_catalog()
        self.snapshot = _snapshot()
        self.resolver = FakeResolver()
        self.reports = OrderedDict()
        self.report_limit = MAX_REPORTS
        self.report_ttl = REPORT_TTL_SECONDS
        self.state_lock = threading.Lock()
        self.rate_limiter = DemoRateLimiter()
        # Keep admission itself serialized so a saturated dispatcher rejects
        # immediately, while a separate semaphore enforces the actual worker cap.
        self.connection_gate = threading.Lock()
        self.connection_slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        super().__init__(address, DemoHandler)

    def _prune_reports(self, now):
        cutoff = now - self.report_ttl
        # Accesses reorder this LRU, so creation time is not ordered. Inspect all
        # entries instead of stopping at the first unexpired report.
        for token, (created, _) in list(self.reports.items()):
            if created <= cutoff:
                self.reports.pop(token, None)

    def save_report(self, token, report):
        now = time.monotonic()
        with self.state_lock:
            self._prune_reports(now)
            self.reports[token] = (now, report)
            self.reports.move_to_end(token)
            while len(self.reports) > self.report_limit:
                self.reports.popitem(last=False)

    def get_report(self, token):
        now = time.monotonic()
        with self.state_lock:
            self._prune_reports(now)
            row = self.reports.get(token)
            if row is None:
                return None
            self.reports.move_to_end(token)
            return row[1]

    def process_request(self, request, client_address):
        if not self.connection_gate.acquire(False):
            request.close()
            return
        slot_acquired = False
        try:
            slot_acquired = self.connection_slots.acquire(False)
            if not slot_acquired:
                request.close()
                return
            try:
                super().process_request(request, client_address)
            except BaseException:
                self.connection_slots.release()
                slot_acquired = False
                raise
        finally:
            self.connection_gate.release()

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.connection_slots.release()


def create_server(host="0.0.0.0", port=8080):
    _ensure_socket_makefile()
    return AgentLogDemoServer((host, port))


def main():
    try:
        port = int(os.environ.get("PORT", "8080"))
    except ValueError as exc:
        raise SystemExit("PORT must be an integer") from exc
    server = create_server("0.0.0.0", port)
    try:
        print(f"AgentLog demo listening on http://0.0.0.0:{port}")
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
