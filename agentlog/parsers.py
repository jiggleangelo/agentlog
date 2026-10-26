import io
import ipaddress
import json
import pickle
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from itertools import chain, islice
from urllib.parse import unquote

MAX_PATH = 1024
MAX_LINES = 5_000_000
MAX_LINE_LENGTH = 16 * 1024
DETECTION_LINES = 50
MAX_BUFFER_BYTES = 16 * 1024 * 1024


class ParseError(ValueError):
    pass


@dataclass(frozen=True)
class Hit:
    timestamp: datetime
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address
    method: str
    path: str
    status: int
    size: int
    user_agent: str

    @property
    def ts(self): return self.timestamp

    @property
    def ua(self): return self.user_agent

    @property
    def bytes_sent(self): return self.size


_COMBINED = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<timestamp>[^]]+)]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<target>\S+)(?:\s+HTTP/[^"\s]+)?"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\d+|-)\s+'
    r'"(?:[^"\\]|\\.)*"\s+"(?P<user_agent>(?:[^"\\]|\\.)*)"'
)
_PRIVATE_ROUTES = {
    'account', 'accounts', 'author', 'authors', 'customer', 'customers',
    'member', 'members', 'people', 'person', 'profile', 'profiles',
    'u', 'user', 'users',
}
_DOC_ROOTS = {'doc', 'docs', 'documentation', 'guide', 'guides'}
_SAFE_SUFFIXES = {'.htm', '.html', '.markdown', '.md', '.rst', '.txt'}
_EMAIL = re.compile(r'(?i)^[^/@\s]+@[^/@\s]+\.[^/@\s]+$')
_UUID = re.compile(r'(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')
_LONG_SECRET = re.compile(r'^[A-Za-z0-9_-]{24,}$')
_PERSON_WITH_NUMBER = re.compile(r'^[A-Za-z]+-[A-Za-z]+-\d{2,}$')
_PERSON_SLUG = re.compile(r'^[A-Za-z]+-[A-Za-z]+$')


def _decode_target(value):
    text = str(value or '/')
    for _ in range(2):
        decoded = unquote(text, errors='replace')
        if decoded == text: break
        text = decoded
    return re.split(r'[?#]', text, maxsplit=1)[0]


def _split_suffix(segment):
    for suffix in sorted(_SAFE_SUFFIXES, key=len, reverse=True):
        if segment.lower().endswith(suffix):
            return segment[:-len(suffix)], segment[-len(suffix):]
    return segment, ''


def _is_sensitive_segment(segment, in_docs):
    stem, _ = _split_suffix(segment)
    return bool(_EMAIL.fullmatch(segment) or _EMAIL.fullmatch(stem)
                or _UUID.fullmatch(stem) or _LONG_SECRET.fullmatch(stem)
                or _PERSON_WITH_NUMBER.fullmatch(stem)
                or (not in_docs and _PERSON_SLUG.fullmatch(stem)))


def _bounded_path(segments):
    path = '/' + '/'.join(segments)
    if len(path) <= MAX_PATH: return path
    kept = []
    for segment in segments:
        if len('/' + '/'.join(kept + [segment, '{truncated}'])) > MAX_PATH: break
        kept.append(segment)
    return '/' + '/'.join(kept + ['{truncated}'])


def clean_path(path):
    cleaned = []
    private_shape = in_docs = False
    for raw_segment in _decode_target(path).split('/'):
        segment = ''.join(c for c in raw_segment if ord(c) >= 32 and ord(c) != 127)
        if not segment: continue
        lowered = segment.lower()
        if lowered in _PRIVATE_ROUTES: private_shape = True
        if lowered in _DOC_ROOTS and not private_shape: in_docs = True
        if private_shape or _is_sensitive_segment(segment, in_docs):
            cleaned.append('{redacted}' + _split_suffix(segment)[1])
        else:
            cleaned.append(segment)
    return _bounded_path(cleaned)


def _parse_timestamp(value):
    if value is None or value == '': return datetime.now(timezone.utc)
    if isinstance(value, datetime): return value.astimezone(timezone.utc)
    text = str(value).strip()
    try: number = float(text)
    except ValueError: number = None
    try:
        if number is not None:
            if number > 10_000_000_000_000_000: number /= 1_000_000_000
            elif number > 10_000_000_000: number /= 1000
            return datetime.fromtimestamp(number, timezone.utc)
        parsed = datetime.fromisoformat(text.replace('Z', '+00:00'))
        if parsed.tzinfo is None: parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (ValueError, OverflowError, OSError) as exc:
        raise ParseError('invalid timestamp') from exc


def _make_hit(timestamp, address, method, path, status, size, user_agent):
    try:
        parsed_ip = ipaddress.ip_address(str(address))
        parsed_status = int(status)
        parsed_size = int(size or 0)
    except (TypeError, ValueError) as exc:
        raise ParseError('invalid request fields') from exc
    if isinstance(user_agent, list): user_agent = user_agent[0] if user_agent else ''
    return Hit(_parse_timestamp(timestamp), parsed_ip, str(method or 'GET').upper(),
               clean_path(path), parsed_status, max(0, parsed_size), str(user_agent or ''))


def parse_combined(line):
    match = _COMBINED.match(line.strip())
    if not match: raise ParseError('invalid combined log line')
    row = match.groupdict()
    try: stamp = datetime.strptime(row['timestamp'], '%d/%b/%Y:%H:%M:%S %z')
    except ValueError as exc: raise ParseError('invalid combined timestamp') from exc
    return _make_hit(stamp, row['ip'], row['method'], row['target'], row['status'],
                     0 if row['size'] == '-' else row['size'], row['user_agent'].replace(r'\"', '"'))


def _json_object(line):
    try: value = json.loads(line)
    except (TypeError, json.JSONDecodeError) as exc: raise ParseError('invalid JSON log line') from exc
    if not isinstance(value, dict): raise ParseError('JSON log line must be an object')
    return value


def _header(headers, name):
    if isinstance(headers, dict):
        for key, value in headers.items():
            if str(key).lower() == name.lower():
                return str(value[0]) if isinstance(value, list) and value else '' if isinstance(value, list) else str(value)
    return ''


def parse_caddy(line):
    row = _json_object(line)
    request = row.get('request')
    if not isinstance(request, dict): raise ParseError('invalid Caddy log line')
    return _make_hit(row.get('ts') or row.get('timestamp'),
                     request.get('client_ip') or request.get('remote_ip'),
                     request.get('method'), request.get('uri'), row.get('status'),
                     row.get('size'), _header(request.get('headers'), 'user-agent'))


def parse_cloudflare(line):
    row = _json_object(line)
    return _make_hit(row.get('EdgeStartTimestamp') or row.get('ClientRequestTimestamp'),
                     row.get('ClientIP'), row.get('ClientRequestMethod'),
                     row.get('ClientRequestURI'), row.get('EdgeResponseStatus'),
                     row.get('EdgeResponseBytes'), row.get('ClientRequestUserAgent'))


def parse_vercel(line):
    row = _json_object(line)
    proxy = row.get('proxy')
    if not isinstance(proxy, dict): raise ParseError('invalid Vercel log line')
    return _make_hit(proxy.get('timestamp') or row.get('timestamp'),
                     proxy.get('clientIp') or proxy.get('client_ip'),
                     proxy.get('method'), proxy.get('path') or proxy.get('url'),
                     proxy.get('statusCode') or proxy.get('status'),
                     proxy.get('responseBytes') or proxy.get('size') or 0,
                     proxy.get('userAgent') or proxy.get('user_agent'))


def _parsers():
    return {'combined': parse_combined, 'caddy': parse_caddy,
            'cloudflare': parse_cloudflare, 'vercel': parse_vercel}


def detect(lines):
    sample = list(islice((line for line in lines if line.strip()), DETECTION_LINES))
    counts = {}
    for name, parser in _parsers().items():
        count = 0
        for line in sample:
            try: parser(line)
            except ParseError: continue
            count += 1
        counts[name] = count
    best = max(counts, key=counts.get)
    if not sample or counts[best] / len(sample) < .8:
        raise ParseError('unable to detect log format; choose a format explicitly')
    return best


@dataclass
class ParseStats:
    read: int = 0
    skipped: int = 0


def _bounded_lines(lines):
    for number, line in enumerate(lines, 1):
        if number > MAX_LINES: raise ParseError(f'log exceeds {MAX_LINES} lines')
        if len(line.encode('utf-8')) > MAX_LINE_LENGTH:
            raise ParseError(f'log line exceeds {MAX_LINE_LENGTH} characters/bytes')
        yield line


def _parse_hits(lines, parser, stats):
    for line in lines:
        if not line.strip(): continue
        stats.read += 1
        try: hit = parser(line)
        except ParseError:
            stats.skipped += 1
            continue
        yield hit


class _MemorySpool(io.BytesIO):
    """Legacy eager API buffer, also used for the bounded detection sample."""
    def __init__(self):
        super().__init__()
        self._limit = MAX_BUFFER_BYTES

    def write(self, data):
        if self.tell() + len(data) > self._limit:
            raise ParseError(f'parsed upload exceeds {self._limit} byte memory limit')
        return super().write(data)


class _StoredHits:
    def __init__(self, spool, count):
        self._spool = spool
        self._remaining = count

    def __iter__(self): return self

    def __next__(self):
        if self._remaining == 0 or self._spool.closed:
            self.close()
            raise StopIteration
        try: hit = pickle.load(self._spool)
        except BaseException:
            self.close()
            raise
        self._remaining -= 1
        if not self._remaining: self.close()
        return hit

    def close(self): self._spool.close()

    def __del__(self): self.close()


def _sample(remaining):
    sample = []
    for line in remaining:
        if line.strip(): sample.append(line)
        if len(sample) == DETECTION_LINES: break
    return sample


def parse_lines(lines):
    """Compatibility API: eager final counters and a bounded RAM-only iterator.

    HTTP uploads use stream_lines instead, so total upload size is independent
    of this compatibility buffer. No raw or parsed request data reaches disk.
    """
    remaining = iter(_bounded_lines(lines))
    sample = _sample(remaining)
    name = detect(sample)
    stats = ParseStats()
    spool = _MemorySpool()
    try:
        for hit in _parse_hits(chain(sample, remaining), _parsers()[name], stats):
            pickle.dump(hit, spool, protocol=pickle.HIGHEST_PROTOCOL)
        spool.seek(0)
        hits = _StoredHits(spool, stats.read - stats.skipped)
        if not hits._remaining: hits.close()
        return name, hits, stats.read, stats.skipped
    except BaseException:
        spool.close()
        raise


def stream_lines(lines, format_name=None):
    """Bounded detection followed by one-pass parsing with live counters."""
    remaining = iter(_bounded_lines(lines))
    sample = _sample(remaining)
    parsers = _parsers()
    if format_name in (None, '', 'auto'):
        name = detect(sample)
    elif format_name in parsers:
        name = format_name
        if not any(_valid(line, parsers[name]) for line in sample):
            raise ParseError('requested format does not match log format')
    else:
        raise ParseError('unknown log format')
    stats = {'lines_read': 0, 'lines_skipped': 0}
    # Preserve the existing memory guard, but apply it only to the bounded
    # detection sample rather than accumulating the entire upload.
    spool = _MemorySpool()
    try:
        for line in sample:
            stats['lines_read'] += 1
            try: hit = parsers[name](line)
            except ParseError:
                stats['lines_skipped'] += 1
                continue
            pickle.dump(hit, spool, protocol=pickle.HIGHEST_PROTOCOL)
        spool.seek(0)
    except BaseException:
        spool.close()
        raise
    initial = _StoredHits(spool, stats['lines_read'] - stats['lines_skipped'])

    def hits():
        try:
            yield from initial
            for line in remaining:
                if not line.strip(): continue
                stats['lines_read'] += 1
                try: hit = parsers[name](line)
                except ParseError:
                    stats['lines_skipped'] += 1
                    continue
                yield hit
        finally:
            initial.close()
    return name, hits(), stats


def _valid(line, parser):
    try: parser(line)
    except ParseError: return False
    return True
