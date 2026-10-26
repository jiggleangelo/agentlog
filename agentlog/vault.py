from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
import re
import tempfile

_EMAIL = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")


class FileVault:
    '''Development-only write-only intake. Production should place this path on a separately controlled encrypted volume.'''
    def __init__(self, path):
        self.path = os.fspath(path); parent = os.path.dirname(os.path.abspath(self.path)); os.makedirs(parent, mode=0o700, exist_ok=True); os.chmod(parent, 0o700)

    def put(self, kind, value):
        value = str(value).strip(); limit = 254 if kind == 'waitlist_email' else 1024
        if not value or len(value.encode('utf-8')) > limit: raise ValueError('vault value is invalid')
        if kind == 'waitlist_email' and not _EMAIL.fullmatch(value): raise ValueError('email is invalid')
        ref = os.urandom(16).hex(); fd = os.open(self.path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
        try: os.write(fd, (json.dumps({'ref': ref, 'ts': datetime.now(timezone.utc).isoformat(), 'kind': kind, 'value': value}, ensure_ascii=False) + '\n').encode())
        finally: os.close(fd)
        return ref

    def purge(self, days=90):
        if not os.path.exists(self.path): return 0
        cutoff = datetime.now(timezone.utc) - timedelta(days=days); kept = []; removed = 0
        with open(self.path, encoding='utf-8') as source:
            for line in source:
                try:
                    if datetime.fromisoformat(json.loads(line)['ts']) >= cutoff: kept.append(line)
                    else: removed += 1
                except (KeyError, TypeError, ValueError, json.JSONDecodeError): removed += 1
        directory = os.path.dirname(os.path.abspath(self.path)); fd, temporary = tempfile.mkstemp(dir=directory, prefix='.vault-', text=True)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as target: target.writelines(kept)
            os.replace(temporary, self.path)
        finally:
            if os.path.exists(temporary): os.unlink(temporary)
        return removed


class FakeVault:
    def __init__(self): self.calls = []
    def put(self, kind, value): self.calls.append((kind, value)); return f'ref-{len(self.calls)}'
    def purge(self, days=90): return 0
