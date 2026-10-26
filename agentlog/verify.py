from __future__ import annotations

from bisect import bisect_right
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, TimeoutError, wait
from datetime import datetime, timezone
import ipaddress
import json
import re
import socket
import threading
import time
from pathlib import Path
from typing import Protocol


class Resolver(Protocol):
    def reverse(self, ip: str) -> str | None: ...
    def forward(self, host: str) -> list[str]: ...


class SocketResolver:
    _pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix='agentlog-dns')
    _gate = threading.BoundedSemaphore(4); _rate_lock = threading.Lock(); _calls = []
    @classmethod
    def _allowed(cls):
        now = time.monotonic()
        with cls._rate_lock:
            cls._calls[:] = [stamp for stamp in cls._calls if stamp > now - 60]
            if len(cls._calls) >= 20: return False
            cls._calls.append(now); return True
    def _call(self, function, *args):
        if not self._allowed() or not self._gate.acquire(False): return None
        try:
            future = self._pool.submit(function, *args)
            try: return future.result(timeout=2)
            except (OSError, TimeoutError): future.cancel(); return None
        finally: self._gate.release()
    def reverse(self, ip):
        value = self._call(socket.gethostbyaddr, ip); return value[0] if value else None
    def forward(self, host):
        rows = self._call(socket.getaddrinfo, host, None); return sorted({row[4][0] for row in rows}) if rows else []


class FakeResolver:
    def __init__(self, reverse=None, forward=None): self.reverse_map = reverse or {}; self.forward_map = forward or {}
    def reverse(self, ip): return self.reverse_map.get(ip)
    def forward(self, host): return self.forward_map.get(host, [])


def load_ranges(path):
    path = Path(path)
    if not path.exists(): return {'agents': {}}
    try:
        value = json.loads(path.read_text(encoding='utf-8'))
        return value if isinstance(value, dict) and isinstance(value.get('agents'), dict) else {'agents': {}}
    except (OSError, json.JSONDecodeError): return {'agents': {}}


def _fresh(stamp, now=None):
    if not stamp: return False
    try: then = datetime.fromisoformat(stamp.replace('Z', '+00:00'))
    except (TypeError, ValueError): return False
    return 0 <= ((now or datetime.now(timezone.utc)) - then).total_seconds() <= 7 * 86400


def _normalized(value):
    try:
        address = ipaddress.ip_address(str(value).split('%', 1)[0])
        return address.ipv4_mapped if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped else address
    except ValueError: return None


def _network_index(values):
    valid = []
    for value in values:
        try: valid.append(ipaddress.ip_network(value, strict=False))
        except (TypeError, ValueError): pass
    result = {}
    for version in (4, 6):
        merged = list(ipaddress.collapse_addresses(n for n in valid if n.version == version))
        result[version] = ([int(n.network_address) for n in merged], merged)
    return result


class Verifier:
    _pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix='agentlog-verify')
    def __init__(self, snapshot, resolver=None, rdns_budget=10, now=None, wall_clock_budget=8):
        self.snapshot = snapshot or {'agents': {}}; self.resolver = resolver or SocketResolver()
        self.rdns_budget = min(max(int(rdns_budget), 0), 20); self.wall_clock_budget = min(max(float(wall_clock_budget), .1), 15)
        self.now = now; self.cache = {}; self.checked = 0; self.networks = {}
    def _rdns(self, entry, ip):
        host = self.resolver.reverse(str(ip))
        if not host: return 'unchecked'
        normalized_host = host.casefold().rstrip('.')
        if len(normalized_host) > 253 or not re.fullmatch(r'[a-z0-9.-]+', normalized_host): return 'unchecked'
        suffixes = tuple(str(s).casefold().strip('.') for s in entry['verify']['suffixes'])
        if not any(normalized_host == suffix or normalized_host.endswith('.' + suffix) for suffix in suffixes): return 'spoofed'
        forward = self.resolver.forward(host)
        if not forward: return 'unchecked'
        addresses = [_normalized(value) for value in forward]
        if any(value is None for value in addresses): return 'unchecked'
        return 'verified' if ip in addresses else 'spoofed'
    def verify(self, entry, ip):
        method = entry['verify']['method']
        if method == 'none': return 'unverifiable'
        ip = _normalized(ip) if ip is not None else None
        if ip is None: return 'unchecked'
        if method == 'ip_ranges':
            row = self.snapshot.get('agents', {}).get(entry['id'])
            if not row or not _fresh(row.get('fetched_at'), self.now): return 'unchecked'
            starts, networks = self.networks.setdefault(entry['id'], _network_index(row.get('ranges', [])))[ip.version]
            if not networks: return 'unchecked'
            position = bisect_right(starts, int(ip)) - 1
            return 'verified' if position >= 0 and ip in networks[position] else 'spoofed'
        key = (entry['id'], str(ip))
        if key in self.cache: return self.cache[key]
        if self.checked >= self.rdns_budget: return 'unchecked'
        self.checked += 1; result = self._rdns(entry, ip); self.cache[key] = result; return result
    def _batch(self, pairs):
        results = [None] * len(pairs); groups = {}; metadata = {}
        for index, (entry, ip) in enumerate(pairs):
            normalized = _normalized(ip) if ip is not None else None
            if entry['verify']['method'] != 'rdns' or normalized is None:
                results[index] = self.verify(entry, ip); continue
            key = (entry['id'], str(normalized)); groups.setdefault(key, []).append(index); metadata[key] = (entry, normalized)
        pending = {}
        for key in sorted(groups, key=lambda value: (-len(groups[value]), value)):
            if key in self.cache:
                for index in groups[key]: results[index] = self.cache[key]
            elif self.checked < self.rdns_budget:
                self.checked += 1; pending[key] = self._pool.submit(self._rdns, *metadata[key])
            else:
                for index in groups[key]: results[index] = 'unchecked'
        done, _ = wait(set(pending.values()), timeout=self.wall_clock_budget)
        for key, future in pending.items():
            result = future.result() if future in done else 'unchecked'
            if future not in done: future.cancel()
            self.cache[key] = result
            for index in groups[key]: results[index] = result
        return [value or 'unchecked' for value in results]
    def verify_many(self, pairs, batch_size=1024):
        batch = []
        for pair in pairs:
            batch.append(pair)
            if len(batch) >= batch_size: yield from self._batch(batch); batch.clear()
        if batch: yield from self._batch(batch)


def prefix(ip):
    return str(ipaddress.ip_network(f'{ip}/{24 if ip.version == 4 else 48}', strict=False))


def proxy_suspected_summary(observed, spoofed, prefixes, min_samples=20):
    if observed < min_samples or not spoofed or spoofed / observed < .95:
        return False
    dominant = sum(count for key, count in Counter(prefixes).most_common(3) if key != '(other)') / spoofed
    if dominant < .90:
        return False
    if observed == spoofed:
        return True
    for value, _ in Counter(prefixes).most_common(3):
        if value == '(other)': continue
        try:
            network = ipaddress.ip_network(value, strict=False)
            if network.is_private or network.is_loopback or network.is_link_local:
                return True
        except ValueError:
            pass
    return False


def proxy_suspected(observations, min_samples=20):
    eligible = [(ip, status) for ip, status in observations if ip is not None and status in {'verified', 'spoofed'}]
    failures = [(ip, status) for ip, status in eligible if status == 'spoofed']
    return proxy_suspected_summary(len(eligible), len(failures), [prefix(ip) for ip, _ in failures], min_samples)
