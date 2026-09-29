# ProShield — Phase 4.1

Phase 4.1 establishes the **SecurityEvent ingestion and persistence
foundation** only: canonical event model, validation, idempotent
MongoDB persistence, repository boundary, the connector boundary
(with a working `SimulatedConnector`), and the in-process ingestion
service.

The detection engine, rule registry, correlation, timeline, severity,
confidence, incident, report, routing, AI, and HTTP API are **not**
part of this slice (see `docs/PROSHIELD_PROJECT_UNDERSTANDING.md`
Section 18 for the locked vs provisional vs open split).

## Prerequisites

* Python 3.13 (the self-contained UUIDv7 generator in this slice
  follows RFC 9562 §5.7; if you change Python version, verify it
  against `tests/unit/test_uuid7.py`).
* MongoDB 6+ running on `127.0.0.1:27017`, no auth, with the
  ability to create databases. The default test database is
  `proshield`; integration tests use a per-session `proshield_test`
  database.

## Install

```text
pip install -r requirements.txt
```

## Bootstrap the database (idempotent)

```text
python -m scripts.init_mongo
```

This creates the `proshield` database, the `security_events`
collection, applies the `$jsonSchema` validator, and creates the
documented indexes (`ev_event_id_unique`, `ev_time_desc`,
`ev_source_time`, `ev_type_time`, `ev_asset_time`, `ev_account_time`,
`ev_provenance_source_id`).

## Run the live smoke

```text
python -m scripts.live_smoke
```

This drops and recreates the collection, ingests 5 simulated
events, then exercises the idempotent-replay path, the conflict
path, the provenance lookup, and every documented index.

## Run the test suite

```text
python -m pytest           # everything (requires MongoDB)
python -m pytest tests/unit  # no infrastructure needed
```

## Run the deployment listeners (Phase 4.10 / STRIX patch)

Two separate planes, two separate processes:

```text
# Analyst plane  (frontend + 40-op wire boundary, session-token gated)
python -m scripts.proxy_server --host 127.0.0.1 --port 8088 --backend mongo
# Frontend:      http://127.0.0.1:8088/static/login.html
# Wire boundary: http://127.0.0.1:8088/api/proxy

# Ingress plane  (trusted inbound telemetry, source-identity-token gated)
python -m scripts.ingress_server --host 127.0.0.1 --port 8089 --backend mongo
# Ingest:         POST http://127.0.0.1:8089/api/ingress
# Health:         GET  http://127.0.0.1:8089/api/ingress/health
```

* `--backend mongo` wires the real MongoDB repositories and the
  production `MongoReplayStore` (`app/sources/replay_store.py`) which
  enforces single-use source-identity tokens across processes with a
  TTL index. Production deployments MUST use `--backend mongo`.
* `--backend memory` wires in-memory fakes plus a process-local
  replay double — for development only; it is NOT cross-process safe.
* Both planes MUST share `PROSHIELD_SOURCE_SIGNING_KEY` so a token
  issued by `source.issue_token` on the analyst plane verifies at the
  ingress boundary.
* The ingress plane never serves the frontend and never exposes
  analyst operations; the analyst plane never accepts raw source
  telemetry.

Current results on this machine: **79 passed in 4.98s** (61 unit
+ 18 integration, against real local MongoDB).

## Run ProShield as an installed Windows application

ProShield ships as a real Windows application: a native desktop shell, a
Windows Service managed by the SCM, and an installer with a versioned upgrade
path. See **`docs/WINDOWS_DEPLOYMENT.md`** for the full architecture, layout,
update design and limitations.

```text
ProShield.exe            native window (WinForms host + Edge WebView2)
                         loads the authoritative UI from the analyst plane
ProShieldService.exe     Windows Service: supervises the two planes,
                         waits for MongoDB at boot, recovers failed children
ProShieldSetup-v1.0.0.exe  installer (auto-start, recovery, Start Menu,
                         uninstaller, in-place upgrade)
```

### Build a release

```text
python -m pip install -r deploy/requirements-build.txt
winget install -e --id JRSoftware.InnoSetup

python -m deploy.signing.generate_keys --channel testing   # once per channel

powershell -ExecutionPolicy Bypass -File deploy\build_release.ps1 ^
    -Version 1.0.0 -Channel testing -UpdateUrl http://<host>:8099 ^
    -WithTestModeInstaller
```

Artefacts land only in `dist/windows/<version>/` (`ProShield.exe`,
`ProShieldService.exe`, `ProShieldSetup-vX.Y.Z.exe`, `manifest.json`,
`checksums.txt`, `build-report.json`). The build refuses to produce a release
whose payload contains `__pycache__`, `.pyc` files, debug dumps, the private
signing key or any legacy frontend file.

### Install, upgrade, uninstall

```text
ProShieldSetup-v1.0.0.exe                      install (elevated)
...setup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART     silent update
deploy\scripts\install_service.ps1             register/repair the service
unins000.exe                                   uninstall
```

A normal upgrade is just the newer installer — no manual uninstall, no data
loss. Runtime data lives in `C:\ProgramData\ProShield\` (config, secrets, logs,
state, staged updates, rollback backups) and is never in the installer's file
set, so upgrades cannot touch it. MongoDB is an independent Windows service and
is never installed, restarted or deleted by ProShield packaging.

### Verify an installation

```text
python -m scripts.verify_windows_stack --start-console --dev-credentials
python -m scripts.verify_windows_stack --data-dir "C:\ProgramData\ProShield"
```

That harness runs the real security workflow over the wire boundary
(`source -> capability -> ingress -> rule -> detection -> capability
correlation -> case -> timeline/evidence -> analyst -> central correlation`),
plus plane separation, crash recovery, and update trust checks (unsigned /
forged / tampered package rejection and rollback).

### Development mode is unchanged

`python -m scripts.proxy_server ...`, `python -m scripts.ingress_server ...` and
the whole pytest suite keep working exactly as before. The packaged build runs
the same `app/` and the same `scripts/proxy_server.py` — no security logic was
moved, duplicated or rewritten.

## Architecture map

```
app/
  config.py                        runtime config from env
  observability/logging.py         structured JSON logger (no secrets)
  domain/
    uuid7.py                       RFC 9562 UUIDv7 generator
    security_event.py              canonical SecurityEvent model
    errors.py                      safe-error envelope
  connectors/
    base.py                        connector interface
    simulated.py                   SimulatedConnector
  ingestion/
    service.py                     the documented trust boundary
  persistence/
    mongo.py                       connection management
    schema.py                      $jsonSchema validator
    security_event_repository.py   the documented repository boundary
scripts/
  init_mongo.py                    bootstrap
  live_smoke.py                    end-to-end runtime verification
tests/
  unit/                            no infrastructure needed
  integration/                     real MongoDB on 127.0.0.1:27017
```

## What is NOT in this slice

Anything in `docs/PROSHIELD_PROJECT_UNDERSTANDING.md` Section 18
marked as "later slice" — including but not limited to:

* detection rules, rule registry, candidate/approved governance,
* source-specific detection engine (WAF, NGINX, IAM, rate-limiter),
* correlation engine, timeline engine, severity engine, confidence
  engine, incident engine, report engine, routing engine,
* audit-event persistence (the schema is defined; the collection
  and writer land in a later slice),
* authentication, RBAC, object-level authorization enforcement
  (the data model carries the necessary fields, but no enforcement
  exists yet — Phase 4.1 is intentionally pre-auth),
* HTTP API (the FastAPI dependency is installed for future slices
  but no routes are exposed),
* AI, future ML dataset pipeline, adversarial test factory,
* any production deployment / packaging / containerization.

## Architectural decisions that are PROVISIONAL

* Python + FastAPI + pymongo (could be swapped; nothing in the
  contract depends on it),
* in-process ingestion service (could be replaced by an HTTP
  surface in Phase 4.2; the in-process boundary is the smallest
  defensible choice for Phase 4.1),
* exact physical index set is the documented MVP minimum; further
  indexes are query-driven and ADR-043 PROVISIONAL.

See `docs/PROSHIELD_PROJECT_UNDERSTANDING.md` Section 18 for the
full list.
