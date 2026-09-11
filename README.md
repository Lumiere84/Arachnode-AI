# Arachnode AI — Policy Engine

A Flask service that evaluates access / threat / data-governance events
against a signed policy library, records every decision in a
hash-linked audit chain, and gates any *loosening* of enforcement
behind a human-held Discernment Key — plus the console UI, served by
this same service, so there is exactly one Arachnode AI, not a demo
and a backend that happen to agree with each other.

(A separate, fully self-contained HTML file — no backend, no server —
also exists for sharing the concept with people who won't run this
project: same look, but its "engine" is a JS mirror running in the
browser. This one is the real thing.)

## Quickstart

```bash
pip install -r requirements.txt
python seed.py          # loads the 7-policy library into arachnode.db
python run.py            # starts the dev server on :5000
```

Open **http://127.0.0.1:5000/** — that's the console, served by Flask
itself and talking to its own API over plain relative fetches
(`/events`, `/policies`, …). Same origin, so there's no CORS to
configure and nothing for a browser's cross-origin rules to block.

No other services or accounts are required — storage is a local
sqlite3 file, and Flask is the only third-party dependency.

Set real secrets before running this anywhere but your own machine:

```bash
export ARACHNODE_SIGNING_SECRET="<long random string, held by the service>"
export ARACHNODE_DISCERNMENT_KEY="<a different string, held by a human approver>"
```

## The security model, in one paragraph

Every policy is HMAC-signed with a secret only the service holds. A
write that goes through `PATCH /policies/:id` re-signs the policy, so
the engine keeps trusting and enforcing it. A write that bypasses the
API — a compromised process with raw database access, simulated here
by `POST /admin/rogue-edit/:id` — changes the policy's behavior without
updating its signature, and `evaluate()` catches the mismatch on the
next event, ignores that policy, and raises a SECURITY ALERT block in
the audit chain instead of quietly enforcing the tampered rule.
Signing proves a write came from the service. It does not prove a
human approved it — so two specific actions (setting a policy to
`allow`, or releasing something from quarantine) require a second,
separate secret: the Discernment Key, supplied via the
`X-Discernment-Key` header. The engine can tighten enforcement on its
own; only a human can loosen it.

## API

| Method | Path                          | Notes |
|---|---|---|
| GET  | `/health`                        | liveness check |
| GET  | `/policies?domain=`              | list policies, optionally filtered |
| PATCH| `/policies/<id>`                 | signed edit path; `action:"allow"` needs the Discernment Key |
| POST | `/events`                        | `{"domain": "...", "payload": {...}}` → runs `evaluate()` |
| GET  | `/audit-chain`                   | the full hash-linked block list |
| POST | `/audit-chain/verify`            | recomputes hashes, reports the first broken block if any |
| GET  | `/quarantine`                    | contained items |
| POST | `/quarantine/<id>/release`       | needs the Discernment Key |
| POST | `/admin/rogue-edit/<id>`         | demo-only; 404s unless `DEBUG=True` |
| POST | `/admin/corrupt-block/<idx>`     | demo-only; rewrites a block's content without touching its hash, so `/audit-chain/verify` has something real to catch |

Example — fire the same "agent requests admin scope" scenario the
console's Scenario Console runs, and see the decision trace:

```bash
curl -X POST localhost:5000/events -H 'Content-Type: application/json' -d '{
  "domain": "threat",
  "payload": {"agent": {"requested_scope": "admin", "granted_scope": "read_only"}}
}'
```

## Project layout

```
app/
  crypto.py    canonical JSON, HMAC policy signing, audit-chain hashing
  engine.py    evaluate() — pure function, no I/O, fully unit-testable
  db.py        sqlite3 data access (no ORM dependency)
  routes.py    the Flask blueprint above
  __init__.py  app factory; also serves webui/index.html at "/"
webui/
  index.html   the console — same origin as the API, calls it directly
seed.py        the 7-policy library, identical to the console demo
tests/
  test_engine.py   unit tests: the console's 8 demo scenarios + tamper cases
  test_api.py      end-to-end tests through the real Flask API
```

## Tests

```bash
python -m unittest discover -s tests -v
```

13 tests: the 8 scenarios the console's Scenario Console advertises,
plus tamper-detection (rogue edit is caught and skipped), signed-edit
trust, audit-chain rewrite detection, and both Discernment Key gates.
All pass against the actual engine and API — not a mock.

## What's deliberately out of scope for this MVP

- Auth/session management for the API itself (assumes it sits behind
  something that already authenticates callers — an API gateway, mTLS,
  etc.) — the Discernment Key is a *second* factor on top of that, not
  a substitute for it.
- Multi-writer concurrency control on the audit chain (sqlite3's
  default locking is fine for a demo; a production deployment would
  want a real append-only log or a database with proper isolation).
- Policy CRUD beyond `PATCH` (create/delete), and pagination on the
  list endpoints — straightforward to add once real usage shows what's
  needed.
