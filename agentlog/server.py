from __future__ import annotations

from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from itertools import chain
import hashlib
import hmac
import ipaddress
import json
import logging
import mimetypes
from pathlib import Path
import threading
import time
from urllib.parse import parse_qs, urlsplit
import zlib

from .aggregate import aggregate
from .catalog import classify
from .funnel import client_key, join_waitlist, save_survey
from .parsers import ParseError, stream_lines
from .report import as_json, render
from .rules import robots, waf, nginx
from .verify import FakeResolver, Verifier

MAX_LINE = 16 * 1024
DECOMPRESS_WINDOW = 64 * 1024
# Keep the existing conservative decompression limit and its regression tests.
MAX_DECOMPRESSED = 100 * 1024 * 1024
UPLOAD_SECONDS = 30


class RateLimiter:
    def __init__(self, limit=30, window=60):
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
            while row and row[0] <= now - self.window: row.popleft()
            if self.calls % 256 == 0:
                for candidate in list(self.rows):
                    values = self.rows[candidate]
                    while values and values[0] <= now - self.window: values.popleft()
                    if not values: self.rows.pop(candidate, None)
            if len(row) >= self.limit: return False
            row.append(now)
            return True


class Handler(BaseHTTPRequestHandler):
    server_version = 'AgentLog/0.5'
    timeout = 15

    def log_message(self, fmt, *args): pass

    def _send(self, status, body=b'', content_type='text/plain; charset=utf-8', report=False, extra=None):
        if isinstance(body, str): body = body.encode()
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Content-Security-Policy', "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        if report:
            self.send_header('X-Robots-Tag', 'noindex')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('Cache-Control', 'no-store')
        for key, value in (extra or {}).items(): self.send_header(key, value)
        self.end_headers()
        if body: self.wfile.write(body)

    def _address(self):
        raw_peer = self.client_address[0].split('%', 1)[0]
        try: peer = ipaddress.ip_address(raw_peer)
        except ValueError: return raw_peer
        address = peer
        if any(peer in network for network in self.server.trusted_proxies):
            for value in reversed(self.headers.get('X-Forwarded-For', '').split(',')):
                try: candidate = ipaddress.ip_address(value.strip().split('%', 1)[0])
                except ValueError: continue
                if not any(candidate in network for network in self.server.trusted_proxies):
                    address = candidate
                    break
        if address.version == 6: return str(ipaddress.ip_network(f'{address}/64', strict=False))
        return str(address)

    def _client(self):
        return hmac.new(self.server.secret.encode(), self._address().encode(), hashlib.sha256).hexdigest()

    def _limited(self, group='general'):
        if self.server.rate_limiter.allow(group + ':' + self._client()): return False
        self._send(429, '{"error":"rate limit exceeded"}', 'application/json', extra={'Retry-After': '60'})
        return True

    def _json_body(self, maximum=4096):
        try: length = int(self.headers.get('Content-Length', ''))
        except ValueError: raise ParseError('invalid content length')
        if length < 0 or length > maximum: raise ParseError('invalid body size')
        raw = self.rfile.read(length)
        if len(raw) != length: raise ParseError('incomplete body')
        try: value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc: raise ParseError('invalid JSON') from exc
        if not isinstance(value, dict): raise ParseError('JSON object required')
        return value

    def _origin_ok(self):
        origin = self.headers.get('Origin')
        if not origin: return self.headers.get('Sec-Fetch-Site', 'same-origin') in {'same-origin', 'same-site', 'none'}
        parsed = urlsplit(origin)
        return parsed.netloc == self.headers.get('Host') and parsed.scheme in {'http', 'https'}

    def _crawler(self):
        entry, generic = classify(self.headers.get('User-Agent', ''), self.server.catalog)
        return bool(entry or generic)

    def do_GET(self):
        route = urlsplit(self.path).path
        try:
            if route == '/': self._send(200, self.server.index_html, 'text/html; charset=utf-8')
            elif route in self.server.static:
                body, kind = self.server.static[route]
                self._send(200, body, kind)
            elif route == '/sample':
                self._send(200, render(sample_report(self.server.catalog)), 'text/html; charset=utf-8', report=True)
            elif route.startswith('/r/'):
                token = route[3:]
                want_json = token.endswith('.json')
                token = token[:-5] if want_json else token
                report = self.server.store.get_report(token)
                if report is None: self._send(404, 'not found', report=True)
                elif want_json: self._send(200, as_json(report), 'application/json', report=True)
                else: self._send(200, render(report), 'text/html; charset=utf-8', report=True)
            elif route == '/go/preorder':
                if self._limited('funnel'): return
                if not self._crawler():
                    self.server.store.event('pay_click', dedupe_key=client_key(self.server.secret, self._client()))
                self._send(302, extra={'Location': self.server.preorder_url, 'Cache-Control': 'no-store'})
            else: self._send(404, 'not found')
        except Exception as exc:
            logging.error('GET failed: %s', exc.__class__.__name__)
            self._send(500, 'internal server error')

    def _body_chunks(self, length):
        remaining = length
        deadline = time.monotonic() + UPLOAD_SECONDS
        while remaining:
            if time.monotonic() > deadline: raise ParseError('upload timed out')
            chunk = self.rfile.read(min(65536, remaining))
            if not chunk: raise ParseError('incomplete upload')
            remaining -= len(chunk)
            yield chunk

    def _decoded_chunks(self, length):
        chunks = iter(self._body_chunks(length))
        try: first = next(chunks)
        except StopIteration: return
        encoding = self.headers.get('Content-Encoding', '').casefold().strip()
        compressed = encoding == 'gzip' or (not encoding and first.startswith(b'\x1f\x8b'))
        if encoding not in {'', 'identity', 'gzip'}: raise ParseError('unsupported content encoding')
        if not compressed:
            yield first
            yield from chunks
            return
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        produced = 0
        try:
            for chunk in chain((first,), chunks):
                if decoder.eof: raise ParseError('trailing or multi-member gzip data')
                while chunk:
                    maximum = min(DECOMPRESS_WINDOW, MAX_DECOMPRESSED - produced + 1)
                    output = decoder.decompress(chunk, maximum)
                    produced += len(output)
                    if produced > MAX_DECOMPRESSED: raise ParseError('decompressed upload too large')
                    if decoder.unused_data: raise ParseError('trailing or multi-member gzip data')
                    tail = decoder.unconsumed_tail
                    if tail == chunk and not output: raise ParseError('invalid gzip upload')
                    if output: yield output
                    chunk = tail
        except zlib.error as exc: raise ParseError('invalid gzip upload') from exc
        if not decoder.eof or decoder.unused_data: raise ParseError('invalid gzip upload')

    def _lines(self, chunks):
        buffer = bytearray()
        overflow = False
        for chunk in chunks:
            for part in chunk.splitlines(keepends=True):
                if overflow:
                    if part.endswith((b'\n', b'\r')):
                        yield b'x' * (MAX_LINE + 1)
                        overflow = False
                    continue
                buffer.extend(part)
                if len(buffer) > MAX_LINE:
                    buffer.clear()
                    overflow = True
                    if part.endswith((b'\n', b'\r')):
                        yield b'x' * (MAX_LINE + 1)
                        overflow = False
                elif part.endswith((b'\n', b'\r')):
                    yield bytes(buffer)
                    buffer.clear()
        if overflow: yield b'x' * (MAX_LINE + 1)
        elif buffer: yield bytes(buffer)

    def _upload(self):
        if self._limited('upload'): return
        query = parse_qs(urlsplit(self.path).query)
        consent = self.headers.get('X-AgentLog-Share-Consent', '').casefold() in {'1', 'true', 'yes'} or query.get('share') == ['1']
        if not consent:
            self._send(428, json.dumps({'error': 'share consent required', 'warning': 'The resulting public link exposes bounded, redacted route summaries.'}), 'application/json')
            return
        try: size = int(self.headers.get('Content-Length', ''))
        except ValueError:
            self._send(400, '{"error":"invalid content length"}', 'application/json')
            return
        if size <= 0 or size > self.server.max_upload:
            self._send(413, '{"error":"upload too large"}', 'application/json')
            return
        if not self.server.upload_gate.acquire(False):
            self._send(503, '{"error":"upload capacity reached"}', 'application/json', extra={'Retry-After': '5'})
            return
        hits = None
        try:
            if query.get('client_ip_field'): raise ParseError('client_ip_field overrides are not supported')
            lines = (line.decode('utf-8', errors='replace') for line in self._lines(self._decoded_chunks(size)))
            name, hits, stats = stream_lines(lines, query.get('format', [None])[0])
            report = aggregate(hits, self.server.catalog, Verifier(self.server.snapshot, self.server.resolver), name, stats=stats)
            daily = client_key(self.server.secret, self._client())
            _, share, delete = self.server.store.save_report(report, self._crawler(), daily)
            self._send(201, json.dumps({'report_url': f'/r/{share}', 'json_url': f'/r/{share}.json', 'delete_token': delete}), 'application/json', report=True)
        except ParseError as exc:
            self._send(400, json.dumps({'error': str(exc)}), 'application/json')
        finally:
            if hits is not None: hits.close()
            self.server.upload_gate.release()

    def _rules(self, body):
        selected = body.get('selected', [])
        paths = body.get('paths') or ['/']
        known = {entry['id'] for entry in self.server.catalog}
        if not isinstance(selected, list) or not selected or any(not isinstance(value, str) or value not in known for value in selected):
            raise ParseError('select known agent IDs')
        if not isinstance(paths, list) or len(paths) > 50:
            raise ParseError('invalid rule paths')
        for path in paths:
            if not isinstance(path, str) or not path.startswith('/') or len(path) > 1024 or any(ord(c) < 32 or ord(c) == 127 for c in path):
                raise ParseError('invalid rule path')
        result = {'robots': robots(self.server.catalog, selected, paths),
                  'waf': waf(self.server.catalog, self.server.snapshot, selected),
                  'nginx': nginx(self.server.catalog, selected)}
        self._send(200, json.dumps(result), 'application/json')

    def do_POST(self):
        if not self._origin_ok():
            self._send(403, '{"error":"origin rejected"}', 'application/json')
            return
        route = urlsplit(self.path).path
        try:
            if route in {'/upload', '/api/upload'}:
                self._upload()
                return
            if self._limited('funnel'): return
            body = self._json_body()
            daily = client_key(self.server.secret, self._client())
            if route == '/api/rules':
                self._rules(body)
                return
            if route in {'/waitlist', '/api/waitlist'}:
                created = join_waitlist(self.server.store, self.server.vault, self.server.secret, body.get('email', ''), self._crawler())
            elif route in {'/survey', '/api/survey'}:
                created = save_survey(self.server.store, self.server.vault, body, self._crawler(), daily)
            else:
                self._send(404, 'not found')
                return
            self._send(201 if created else 200, json.dumps({'created': created}), 'application/json')
        except (ParseError, ValueError) as exc:
            self._send(400, json.dumps({'error': str(exc)}), 'application/json')
        except Exception as exc:
            logging.error('POST failed: %s', exc.__class__.__name__)
            self._send(500, 'internal server error')


def sample_report(catalog):
    from datetime import datetime, timezone
    stamp = datetime.now(timezone.utc).isoformat()
    snapshot = {'agents': {'openai-gptbot': {'fetched_at': stamp, 'ranges': ['192.0.2.0/24']}}}
    rows = [
        ('192.0.2.1', '/docs/api.md', 200, 900, 'GPTBot'),
        ('198.51.100.1', '/llms.txt', 404, 30, 'GPTBot'),
        ('192.0.2.2', '/docs/missing.md', 500, 20, 'ClaudeBot'),
        ('192.0.2.3', '/docs/', 200, 100, 'OAI-SearchBot'),
    ]
    lines = [f'{ip} - - [24/Oct/2026:12:00:00 +0000] "GET {path} HTTP/1.1" {code} {size} "-" "{ua}"' for ip, path, code, size, ua in rows]
    name, hits, stats = stream_lines(lines)
    return aggregate(hits, catalog, Verifier(snapshot, FakeResolver()), name, stats=stats)


class AgentLogServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, store, catalog, snapshot, resolver, static_dir, max_upload, preorder_url, vault, secret, upload_concurrency=2, trusted_proxies=()):
        self.store = store
        self.catalog = catalog
        self.snapshot = snapshot
        self.resolver = resolver
        self.max_upload = max_upload
        self.preorder_url = preorder_url
        self.vault = vault
        self.secret = secret
        self.upload_gate = threading.BoundedSemaphore(max(1, upload_concurrency))
        self.rate_limiter = RateLimiter()
        self.trusted_proxies = []
        for value in trusted_proxies:
            try: self.trusted_proxies.append(ipaddress.ip_network(value, strict=False))
            except ValueError: pass
        root = Path(static_dir)
        index = root / 'index.html'
        self.index_html = index.read_bytes() if index.exists() else b'AgentLog'
        self.static = {}
        if root.exists():
            for path in root.iterdir():
                if path.is_file() and path.name != 'index.html':
                    self.static['/static/' + path.name] = (path.read_bytes(), mimetypes.guess_type(path.name)[0] or 'application/octet-stream')
        super().__init__(address, Handler)
