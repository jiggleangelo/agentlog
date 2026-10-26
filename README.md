# agentlog

Prototype: See which AI crawlers hit your site – agentlog

**Try the live demo (made-up data):** https://try-agentlog.manykiln.com/  
**Product page:** https://agentlog.manykiln.com/

> Built and maintained by AI agents at [Manykiln](https://manykiln.com), a studio whose products are written, tested and operated by AI agents. This is a working prototype, not a finished product. No payment is taken anywhere: any checkout, waitlist or payment code in this project runs against fakes only, and the hosted demo uses made-up data.

- Status: prototype; run the 53 automated tests yourself with `python3 -m unittest discover`
- Runs on the Python 3.12 standard library; external services are faked
- Licence: MIT
- Issues and pull requests are not monitored.

---

# AgentLog MVP

AgentLog turns access logs into aggregate reports with verified, spoofed, unverifiable and unchecked agent identities, bytes by URL, and llms.txt/Markdown failures.

## Hosted user-test demo

Run the disposable, offline demo with:

```sh
python3 demo.py
```

It listens on `0.0.0.0:$PORT`, using port 8080 when `PORT` is unset. The demo includes a made-up access log, requires no account, makes no outbound network requests, and keeps at most 500 reports in memory for one hour. Everything disappears when the process restarts. Do not enter real personal data.

The demo health check is `GET /healthz`, which returns `200 ok`. Demo form bodies are limited to 64 KB. Client sockets time out after 10 seconds, concurrent connections are capped, and report creation is rate limited per client IP.

## Run

Python 3.12 and the standard library are required. Set a persistent secret before serving:

```sh
export AGENTLOG_SECRET="$(python3.12 -c 'import secrets; print(secrets.token_hex(32))')"
export AGENTLOG_PREORDER_URL="https://your-checkout.example/preorder"
python3.12 -m agentlog serve --port 8080
```

Open http://localhost:8080. The existing `python3.12 -m agentlog.cli` entry point also works. A public synthetic sample is available at `/sample`; it does not count as an upload.

When serving behind a reverse proxy, explicitly trust only that proxy's network so client deduplication and rate limiting can safely use `X-Forwarded-For`:

```sh
python3.12 -m agentlog serve --trusted-proxy 10.0.0.0/8
# Or use comma-separated CIDRs:
export AGENTLOG_TRUSTED_PROXIES="10.0.0.0/8,2001:db8::/32"
```

Do not trust `0.0.0.0/0` or `::/0`; doing so lets direct clients spoof their address.

Optional range refresh:

```sh
python3.12 -m agentlog refresh-ranges
```

Without fresh ranges, affected identities are unchecked. Production reverse-DNS verification also uses the network. Tests use FakeResolver and an in-memory range snapshot.

## Upload flow

Select a log and format, accept the share-link disclosure, and build a report. The browser posts raw bytes to `/api/upload?format=...` with explicit share consent. Gzip is detected from its signature. `/upload` remains an alias.

The page renders the report summary before showing the optional survey. It provides a full report link, copyable share link, and the one-time deletion credential. The rule builder calls `/api/rules` and provides separately copyable robots.txt, WAF and nginx output. The preorder link records a click before redirecting to the configured checkout.

Waitlist contact details and survey free text go to the vault. Payments are recorded by the operator, not inferred from clicks:

```sh
python3.12 -m agentlog record-payment --count 1 --idempotency-key payment-unique-reference
python3.12 -m agentlog rung0-status
python3.12 -m agentlog purge
```

## Limits and privacy

HTTP uploads stream through parsing, verification and aggregation. Only the first 50 nonempty lines are sampled; the job no longer accumulates pickled hits. The original eager `parse_lines` API remains available with its 16 MB RAM-only limit for compatibility. HTTP uploads use `stream_lines` instead.

Limits are 50 MB uploaded, five million physical lines, and 16 KB per line. The existing conservative gzip limit remains 100 MB decompressed. Oversized lines remain rejected to preserve existing security tests. Malformed ordinary lines are counted and skipped.

Raw logs, IP addresses and complete user agents are not persisted by the reporting pipeline. Reports retain sanitized paths and aggregates. Anyone holding a share link can read that report. Reports expire after 30 days; funnel data is purged after 90 days.

The existing CLI still places its development vault inside the runtime data directory and exposes operator retention cleanup through `purge`. Separate vault placement and a strictly put-only operator interface remain limitations of that existing implementation.

## Offline tests

```sh
python3.12 -m unittest discover -s tests
python3.12 -m unittest tests.test_e2e_demo
python3.12 -m unittest tests.test_demo
python3.12 -m unittest tests.test_reviewer_fixes
```

No browser engine is included in the stdlib suite. The tests verify the browser/server contracts and corresponding HTTP requests; they do not execute JavaScript.

## Catalog and scope

The supplied catalog remains a small seed requiring operator-documentation review and reviewer sign-off before deployment. Vercel support is beta. Current vendor schemas and real scrubbed exports have not been independently validated here. This is a demand-test instrument, not a production security control.
