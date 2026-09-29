# ProShield on Windows — deployment architecture

This document describes how ProShield is productized as a Windows application:
the technology choices, the on-disk layout, the service architecture, the
versioning and update design, and the exact build/install/verify commands.

It does **not** describe the security architecture. That is unchanged and
authoritative: `docs/PROSHIELD_PROJECT_UNDERSTANDING.md` and the phase
documents remain the source of truth.

---

## 1. What was added, and what was deliberately left alone

**Added (new code, no security logic):**

| Path | Role |
|---|---|
| `service/` | Windows deployment layer: service host, supervisor, updater, paths, settings, probes |
| `desktop/` | Native Windows desktop shell (WebView2) |
| `deploy/` | Build orchestration, Inno Setup definition, update signing tool, service helpers |
| `scripts/verify_windows_stack.py` | Installed-stack acceptance harness |
| `tests/unit/test_windows_platform.py` | Platform layer tests |
| `tests/unit/test_update_trust.py` | Update trust chain + failure-recovery tests |

**Untouched:** `app/`, `scripts/proxy_server.py`, `scripts/ingress_server.py`
and the whole existing test suite. The packaged application runs the
**unmodified** implementation — see §8.

> `deploy/` is deliberately *not* named `packaging/`: the repository root is on
> `sys.path` for `python -m ...` runs, and a top-level `packaging` directory
> would shadow the PyPI `packaging` library that PyInstaller and pip depend on.

---

## 2. Architecture

```
                        ┌──────────────────────────────┐
   double-click         │  ProShield.exe               │
   ──────────────────►  │  native window (WinForms     │
                        │  host + Edge WebView2)       │
                        └──────────────┬───────────────┘
                                       │ loads
                                       │ http://127.0.0.1:8088/static/soc/index.html
                                       ▼
   Windows SCM                          (same origin as /api/proxy)
        │                    ┌──────────────────────────────────┐
        ▼                    │  Analyst / SecureProxy plane     │
   ┌─────────────────┐       │  scripts.proxy_server  :8088     │
   │ ProShieldService│──────►└──────────────────────────────────┘
   │      .exe       │       ┌──────────────────────────────────┐
   │  (supervisor)   │──────►│  Ingress / trust boundary :8089  │
   └─────────────────┘       │  scripts.ingress_server          │
        │                    └──────────────┬───────────────────┘
        │ waits for readiness               │
        ▼                                   ▼
   MongoDB Windows service  ────────►  127.0.0.1:27017  (existing install)
```

### Desktop shell technology: `pywebview` + Edge WebView2

Chosen over Tauri and Electron because of what the repository actually
contains:

* The authoritative UI is already a **single self-contained file**. The Vite
  config uses `vite-plugin-singlefile`, so `frontend/soc/index.html` is one
  ~1.2 MB document with all CSS and JS inlined. The shell therefore needs an
  embedded browser **control**, not an application framework.
* **WebView2 Runtime is already present** on the target OS. It ships with
  Windows 10 (1809+, via Edge) and Windows 11; verified on the build host at
  `153.0.4234.32` via both `HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-...}`
  and `C:\Program Files (x86)\Microsoft\EdgeWebView\Application`. No ~150 MB
  Chromium bundle has to be installed or shipped, and there is no Electron/Node
  runtime dependency for the shell.
* **One language, one toolchain, one test framework.** The service, the
  updater, the shell and the tests are all Python + pytest. Adding Electron
  would introduce a second runtime language purely for a window.
* Tauri was rejected on evidence: it requires a Rust toolchain plus MSVC Build
  Tools (~2 GB) that are absent on this host and unused by every other part of
  ProShield.

The shell is intentionally thin (see `desktop/main.py`):

* it loads the UI from the **analyst plane**, so the React app is same-origin
  with `/api/proxy` — no CORS shim, no second API layer, and no way for the GUI
  to bypass SecureProxy;
* it reads settings with `include_secrets=False`, so it **never even opens** the
  signing-key/credential file and holds no MongoDB credentials;
* while the backend is starting it shows a native status page
  (`desktop/status.html`) driven by real process state (plane health, MongoDB
  readiness, service state, update channel, version/build/commit);
* `private_mode=False` with `storage_path` under the data directory so the
  browser-internal session token (localStorage) survives restarts.

### Service architecture

`ProShieldService.exe` is a real Windows service (`pywin32`
`ServiceFramework`) registered with the SCM. It does exactly one thing: run the
supervisor (`service/supervisor.py`), which owns the two existing entry points
as child processes.

* Accepted controls include `SERVICE_ACCEPT_STOP`, `SERVICE_ACCEPT_SHUTDOWN`
  and `SERVICE_ACCEPT_PRESHUTDOWN`, so a machine shutdown terminates the planes
  gracefully instead of leaving a half-dead stack.
* Children are spawned with `CREATE_NO_WINDOW` (no console flashes) and
  `CREATE_NEW_PROCESS_GROUP`.
* Each child's stdout/stderr is pumped into a size-rotating log
  (`logs/analyst.log`, `logs/ingress.log`).
* **Recovery:** a crashed child is restarted with exponential backoff
  (2 s → 60 s, capped). A child that has been *running but unhealthy* for
  ≥30 s with 3 consecutive failed health probes is restarted too. The backoff
  counter resets once a child has been stable for 60 s.
* The service also writes `state/health.json` (process status only — no
  security events) which the installer, the updater, the desktop status page
  and `ProShieldService.exe status` all read.

The GUI and the service are separate processes. Closing `ProShield.exe` does
not affect the service, and the service keeps running after the user logs out.

---

## 3. On-disk layout

### Install tree — replaced by upgrades (`Program Files`)

```
C:\Program Files\ProShield\
    app\                     authoritative security implementation
    scripts\                 proxy_server.py, ingress_server.py, __init__.py
    frontend\soc\index.html  authoritative React UI (single-file bundle)
    frontend\login.html      redirect shim to /static/soc/index.html
    runtime\                 relocatable CPython + pinned site-packages
    service\ProShieldService.exe
    desktop\ProShield.exe, status.html
    deploy\build_info.json   version stamp
    deploy\version.json
    deploy\proshield-update.pub.pem   update-channel public key
```

### Data tree — never replaced by upgrades (`ProgramData`)

```
C:\ProgramData\ProShield\
    config\     proshield.json (non-secret settings), install-info.json,
                initial-credentials.txt
    secrets\    proshield.env  <- signing keys + subject credentials
    logs\       service.log, analyst.log, ingress.log, updater.log,
                desktop.log, installer logs
    state\      health.json, update-state.json, webview\ (localStorage profile)
    updates\    <version>\ staged package + manifest, helper\ detached updater
    backup\     <version>-<timestamp>\ previous install trees for rollback
```

**Two invariants** make upgrades safe:

1. Nothing the installer replaces holds runtime data.
2. Nothing that holds runtime data is in the installer's `[Files]` set, so an
   upgrade cannot touch it.

`secrets/` is a separate directory specifically so the installer can ACL it to
Administrators + SYSTEM only (see §7).

### 5.1 Signing in — where the credentials are

ProShield has **no hard-coded default password** (`app/auth/identity.py`: "no
default password is ever hard-coded"). On first start the service generates four
random credentials, one per identity class, and writes them once:

| File | ACL | Purpose |
|---|---|---|
| `C:\ProgramData\ProShield\config\initial-credentials.txt` | readable | the operator-facing copy — **read the credentials here** |
| `C:\ProgramData\ProShield\secrets\proshield.env` | Administrators + SYSTEM | the live `PROSHIELD_DEFAULT_SUBJECT_CREDENTIALS` value the planes read |

Read the operator copy (no elevation needed):

```
type C:\ProgramData\ProShield\config\initial-credentials.txt
```

```
ProShield - initial analyst credentials
=======================================

  subject_id : admin
  credential : <generated>

  subject_id : analyst
  credential : <generated>

  subject_id : collector
  credential : <generated>

  subject_id : internal
  credential : <generated>
```

Enter both fields in the ProShield sign-in screen (`LoginGate` → `auth.issue`):
**Subject ID** = one of `admin` / `analyst` / `collector` / `internal`, and
**Credential** = the matching generated string. There is no separate username
and email field, and no "admin/admin" default.

> A non-elevated user cannot read `secrets\proshield.env` (`PermissionError`);
> that is the intended ACL, not a fault. Use `initial-credentials.txt` instead.
> The file is written **only when it does not already exist**, so it also serves
> as the record of the original credentials after a credential rotation.

Role capabilities (from `app/auth/permissions.py`):

| Subject | Role | Can do |
|---|---|---|
| `admin` | admin | everything the analyst can, plus rule/source/capability **write**, routing override, centralized-analysis request |
| `analyst` | analyst | read cases / detections / correlations / timeline / overview / rules / sources / capabilities, generate reports |
| `collector` | collector | **no analyst-plane read permission at all** (it is a *source* identity: it authenticates to the ingress boundary only) |
| `internal` | internal_service | internal read surface; no write, no override |

Verified against a live installed service (`/api/proxy` on `:8088`):
all four subjects → `HTTP 200` with a token; a wrong credential → `401`;
`analyst` → `overview.summary` `200`; `collector` → `rule.list` **`403`**;
no session → `401`.

**Development parity.** The VS Code workflow uses the documented development
credentials instead, which are opted into explicitly:

```
python -m scripts.proxy_server --backend mongo --port 8088 --seed-credentials
```

`--seed-credentials` seeds `admin-dev-credential`, `analyst-dev-credential`,
`collector-dev-credential`, `internal-dev-credential` (`service/settings.py::
DEV_CREDENTIALS`; the same set `ProShieldService.exe console --dev-credentials`
uses). These never exist in an installed deployment unless an operator asks for
them.

MongoDB lives entirely outside both trees and is never installed, modified,
restarted or deleted by ProShield packaging.

---

## 4. Startup sequence

After a reboot, with no logon and no manual step:

```
Windows boot
  → MongoDB Windows service starts (ProShield Service depends on it)
  → ProShield Service starts (start=auto)
  → supervisor polls the MongoDB readiness probe
        (a real `admin.command("ping")` handshake; TCP-connect only as a
         degraded fallback when pymongo is unavailable)
  → analyst plane starts   (python -m scripts.proxy_server  :8088)
  → ingress plane starts   (python -m scripts.ingress_server :8089)
  → health checks every second; state written to state/health.json
  → ProShield ready
```

The MongoDB dependency is registered **softly**: the installer only adds it if
a `MongoDB` service is actually present, and the supervisor's readiness wait
covers the case where it is not (or where `mongod` is still replaying its
journal). If MongoDB never becomes ready the supervisor starts the planes
anyway and keeps retrying, logging the condition — the service does not
crash-loop.

---

## 5. Versioning

`deploy/version.json` is the single source of truth (product name, version,
channel, update mode, ports, MongoDB endpoint). At build time
`deploy/build_windows.py` writes `deploy/build_info.json`, which adds:

```json
{
  "version": "1.0.0",
  "channel": "testing",
  "build_id": "1.0.0+20260918085232",
  "git_commit": "f674f09a63bfbb01876dd5fc89c05302413a605d",
  "built_at": "2026-09-18T08:52:32+00:00",
  "tools": { "python": "3.13.3", "pyinstaller": "6.22.3", ... }
}
```

`service/version.py` resolves, in order:

1. `<install>\deploy\build_info.json` — authoritative for an installed
   ProShield (`version_source: "install"`);
2. `deploy/version.json` — authoritative for development mode
   (`version_source: "repository"`);
3. a hard-coded fallback so the module can never fail to import.

The same value is therefore visible in all five places the requirement asks
for: `ProShield.exe --version`, `ProShieldService.exe` (log line + status),
the installer filename and `VersionInfoVersion` resource, `manifest.json`, and
the desktop status page's *About / System information* panel.

---

## 6. Update design (testing channel)

```
test → patch → improve → build new version → publish testing release
     → existing ProShield detects update
     → verify package (Ed25519 signature + SHA-256)
     → upgrade (detached helper runs the installer silently)
     → restart service
     → health check
     → continue testing
```

### Endpoint and modes

`update_manifest_url` in `proshield.json` (or `PROSHIELD_UPDATE_URL`) selects
which manifest to read. The **same** updater therefore serves the `testing`
channel now and a `stable`/`production` channel later with no code change — only
a different endpoint and a differently signed manifest. A manifest may declare
`testing`, `beta`, `stable`, `production` or `development`; a mismatch with the
configured channel is refused, except that a `stable` manifest is always
accepted (promoting a testing install onto stable is deliberate).

`update_mode` selects behaviour:

| Mode | Behaviour |
|---|---|
| `automatic` | check, verify and apply without asking (current testing phase) |
| `notify-only` | check and record the available version; never apply |
| `manual` | never checks on its own; an operator or the GUI triggers a check |

### Trust chain

Two independent facts must agree before anything is installed:

1. **Signature** — the manifest is signed with an Ed25519 private key. The
   signature covers the canonical JSON serialisation of the manifest with the
   `signature` field removed (`update_manifest.canonical_payload`, shared by the
   publisher and the verifier so they cannot drift).
2. **Hash** — the SHA-256 of the downloaded installer must equal the SHA-256
   recorded *inside the signed payload*, which authenticates the hash
   transitively. Size is checked during download and again before use.

Only the **public** key ships (`deploy/proshield-update.pub.pem`). The private
key is never committed, never packaged and never present on a customer machine.
The updater is **fail-closed**: with no public key installed, a signed manifest
is refused, and an unsigned manifest is refused unless
`update_allow_unsigned` is explicitly enabled for isolated testing.

### Apply path

The installer must replace `ProShieldService.exe`, and Windows locks a running
image — and the installer's first action is to stop the service, which would
kill the process doing the update. The applier is therefore a **detached helper
staged outside the install tree** (`updates\helper\`), launched with
`DETACHED_PROCESS`, which:

1. independently re-verifies the manifest signature and the package hash;
2. snapshots the current install tree into `backup\<version>-<timestamp>\`;
3. runs the verified installer silently
   (`/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /NOCANCEL /UPDATE=1 /LOG=...`);
4. waits for the new version stamp *and* both planes to answer their health
   endpoints;
5. on any failure, restores the snapshot, restarts the service and records
   `rolled-back`.

The service only spawns the helper when MongoDB is ready and **both planes are
already healthy**, so a broken install is never replaced mid-failure.

### Failure containment

| Failure | Result |
|---|---|
| invalid signature | rejected before anything is downloaded or applied |
| invalid hash | rejected before anything is applied |
| corrupted / truncated package | rejected by size + SHA-256; partial file discarded |
| interrupted download | partial file removed, bounded retry (3 attempts, backoff) |
| unavailable server / no internet | check fails, zero state change; planes keep running |
| failed installer | previous install tree restored, service restarted |
| failed post-update health check | previous install tree restored, service restarted |
| manual rollback | `ProShieldService.exe` / helper `--rollback-only`, or restore newest backup |

Preserved across every update: the MongoDB database (never touched — it is an
independent service), and everything under `ProgramData` — configuration,
signing keys, security events, detections, correlations, cases, timeline,
evidence and history.

### Why an upgrade needs `stop-planes`

An upgrade must replace `runtime\python.exe`, and Windows locks the image of a
running executable. The bundled interpreter is shared by **both** backend
planes, so any plane still alive during an upgrade makes the installer fail on
that file:

```
Dest filename: ...\runtime\python.exe
DeleteFile: The existing file appears to be in use (5). Retrying.
DeleteFile failed; code 5. Access is denied.
User canceled the installation process. → Rolling back changes.
```

`net stop ProShieldService` is the primary mechanism (the supervisor terminates
its children on stop), but it is not sufficient on its own: a per-user install
has no service to stop, a plane can outlive its supervisor, and an operator may
be running `ProShieldService.exe console` by hand.

`service/proc_cleanup.py` therefore terminates exactly the processes whose
**executable path** lies inside the install directory - never any other
`python.exe` on the machine - and is invoked from three places:

| Caller | When |
|---|---|
| `ProShieldService.exe stop-planes` | installer `PrepareToInstall`, after `net stop` |
| `UpdateApplier.quiesce_install_tree()` | before running the installer, and before any rollback |
| `verify_update_flow` / operators | manual repair |

It is a safety net as well as a fix: restoring an install tree underneath a
running stack is exactly how a "partially updated" state gets created, so
`restore_install_tree()` quiesces first.

### Configuring the post-update restart

`update_restart_command` in `proshield.json` (a JSON array, or a
space-separated string) selects how the backend is brought back after an
update. Empty means `sc start ProShieldService`. The *testing* channel needs
this because a per-user install has no Windows Service to start:

```json
"update_restart_command": ["cmd", "/c", "C:\\ProgramData\\ProShield\\state\\restart-backend.cmd"]
```

After the installer finishes, the applier waits briefly for health; if the
backend is not up it runs this command once and keeps waiting. A healthy stack
is treated as part of "the update succeeded", so an update that installs
correctly but leaves the backend down is still rolled back.

---

## 7. Security posture of the packaging

| Property | How it is preserved |
|---|---|
| Source ≠ Capability | unchanged — the planes are the unmodified implementation |
| Capability owns Rules | unchanged |
| Detection retains provenance | verified in the acceptance run (detections carry `event_id`) |
| Correlation stays capability-specific | verified (`NGINX-CORR-BRUTEFORCE-001`) |
| Central correlation stays explicit | `case.centralized` is still analyst-initiated |
| Evidence protected | original events are never rewritten by packaging |
| GUI does not bypass SecureProxy | the shell loads the UI from the analyst plane and reads settings with `include_secrets=False` |
| MongoDB stays private/local | the GUI has no database client and no credentials; the planes own all DB access on loopback |
| Plane separation | separate processes, separate ports; an analyst op sent to the ingress plane is refused (verified: HTTP 404) |
| Signing keys not readable by users | `ProgramData\ProShield\secrets` has inheritance broken and is granted to Administrators + SYSTEM only (`icacls /inheritance:r /grant:r *S-1-5-32-544:(OI)(CI)F *S-1-5-18:(OI)(CI)F`, using SIDs so it works on any Windows language) |
| Keys not rotated by restart/upgrade | `bootstrap_secrets` is idempotent and never rewrites existing values |

Inno's `Permissions` parameter could not do this on its own: it only *adds*
ACEs (so `ProgramData`'s inherited `Users` access would have survived) and it
rejects `read`/`read & execute` as access types. Hence the explicit `icacls`
hardening in `[Code]`.

---

## 8. How the packaged build stays identical to development

The install tree ships the **source**, not a frozen backend:

* `app/` is copied verbatim (minus caches);
* `scripts/` contains exactly `__init__.py`, `proxy_server.py`,
  `ingress_server.py` — nothing else;
* `runtime/` is a relocatable CPython 3.13 with pinned dependencies;
* the service spawns `runtime\python.exe -m scripts.proxy_server ...` with
  `cwd` = install root.

Because `ROOT = Path(__file__).resolve().parents[1]` in `proxy_server.py` still
resolves to the install root, `ROOT/frontend/soc/index.html` and the
`/static` mount work exactly as in development. **No source change to the
security implementation was required**, which is why the packaged behaviour is
identical by construction rather than by assertion.

The only difference is configuration, supplied through the environment exactly
as `app/config.py` already expects:

```
PROSHIELD_ENV=production            PROSHIELD_MONGO_URI=mongodb://127.0.0.1:27017
PROSHIELD_MONGO_DB=proshield        PROSHIELD_INGRESS_BACKEND=mongo
PROSHIELD_INGRESS_REPLAY_STORE_REQUIRED=1
PROSHIELD_AUTH_SIGNING_KEY=...      PROSHIELD_SOURCE_SIGNING_KEY=...
PROSHIELD_DEFAULT_SUBJECT_CREDENTIALS=admin:...,analyst:...
PYTHONDONTWRITEBYTECODE=1
```

Development mode is untouched: `python -m scripts.proxy_server` and the whole
existing pytest suite still work and still pass.

---

## 9. Build

Prerequisites (one-time):

```
python -m pip install -r deploy/requirements-build.txt
winget install -e --id JRSoftware.InnoSetup      # provides ISCC.exe
node + npm                                        # to build the React UI
```

Generate the update signing key once per channel (keep the private key out of
Git — it is already in `.gitignore`):

```
python -m deploy.signing.generate_keys --channel testing
```

Full release build:

```
powershell -ExecutionPolicy Bypass -File deploy\build_release.ps1 `
    -Version 1.0.0 -Channel testing -UpdateUrl http://<host>:8099 `
    -WithTestModeInstaller
```

or directly:

```
python -m deploy.build_windows --version 1.0.0 --channel testing `
    --update-url http://<host>:8099 --with-testmode-installer
```

Fast iteration (reuse the staged runtime and UI):

```
python -m deploy.build_windows --skip-frontend --skip-runtime --with-testmode-installer
```

The build is staged, ordered and gated:

1. build the React UI (`npm run build` → `frontend/soc/index.html`);
2. stage a relocatable runtime and `pip install --target` the pinned
   dependencies, then **verify** `runtime\python.exe` can import them;
3. stage the implementation from an **allow-list** (never a blanket copy);
4. freeze `ProShieldService.exe` and `ProShield.exe` with PyInstaller;
5. **prune** caches/compiled artefacts from the payload;
6. **audit** the payload and *fail the build* if anything forbidden is present
   (`__pycache__`, `.pyc`, `.part`, debug dumps, the private signing key, a
   legacy frontend directory or asset, or an unexpected script);
7. compile the installer with Inno Setup;
8. sign `manifest.json`;
9. write `checksums.txt` and `build-report.json`.

Everything lands in `dist/windows/<version>/` and nowhere else:

```
dist/windows/1.0.0/
    ProShield.exe                       43.7 MB
    ProShieldService.exe                40.5 MB
    ProShieldSetup-v1.0.0.exe           96.7 MB
    ProShieldSetup.exe                  (alias of the above)
    ProShieldSetup-v1.0.0-testmode.exe  per-user, no-service validation build
    manifest.json                       signed update metadata
    checksums.txt                       SHA-256 of every artefact
    build-report.json                   toolchain + hashes + payload audit
```

Nothing generated is written into `app/`, `scripts/`,
`frontend/src_upgraded_gemini/` or any other source directory. `dist/` and
`build/` are gitignored, so generated binaries are handled separately from
source tracking while all build/package configuration *is* tracked.

---

## 10. Install / upgrade / repair / uninstall

| Operation | Command |
|---|---|
| Install | `ProShieldSetup-v1.0.0.exe` |
| Silent install | `... /VERYSILENT /SUPPRESSMSGBOXES /NORESTART` |
| Upgrade | run the newer installer — **no manual uninstall needed** |
| Repair / reinstall | run the same installer over the existing install |
| Register/repair service by hand | `deploy\scripts\install_service.ps1` (elevated) |
| Uninstall | Settings → Apps, or `unins000.exe` |
| Silent uninstall | `"C:\Program Files\ProShield\unins000.exe" /VERYSILENT` |

Upgrade mechanics: Inno uses a stable `AppId`, so an install over the same
`AppId` is an **in-place upgrade** — `UsePreviousAppDir=yes` and
`DisableDirPage=auto` mean the previous directory is reused, so there is no
duplicate installation, no duplicate service, no duplicate shortcut and no
orphaned registration. Before replacing files, `PrepareToInstall`:

1. records whether `ProShield.exe` was running and force-closes it (Windows
   locks a running image);
2. runs `net stop ProShieldService` (which blocks until stopped — the service
   terminates its planes and flushes logs on `STOP`/`PRESHUTDOWN`), waits up to
   45 s, and force-kills only if it refuses to stop;
3. restarts the service afterwards via
   `ProShieldService.exe install --wait 180`, which also re-applies auto-start,
   the MongoDB dependency and SCM recovery.

Service registration is idempotent (`win32serviceutil.ChangeServiceConfig` when
the service already exists), so repair and upgrade cannot create a second
service.

Uninstall stops and deletes the service **before** its image is removed, then
asks (defaulting to *No*) whether to also delete the runtime data. The prompt
states explicitly that MongoDB security data is never removed by the installer.

---

## 11. Verification

### Automated tests

```
python -m pytest tests/unit                       # platform + update trust, no infrastructure
python -m pytest                                  # the full existing suite (needs local MongoDB)
```

### Installed-stack acceptance harness

```
# self-contained: start the supervisor, run every check, stop it
python -m scripts.verify_windows_stack --start-console --dev-credentials

# against an already-running install
python -m scripts.verify_windows_stack --data-dir "C:\ProgramData\ProShield"
```
Checks performed: `stack` (both planes, `/api/meta`, MongoDB reachability
through the analyst plane), `gateway` (the GUI origin is served by the analyst
plane and defers to `/api/proxy`), `desktop` (the shell reports real state and
holds no credentials), `recovery` (kill a supervised plane and confirm the
supervisor restarts it), `trust` (unsigned/forged/tampered rejection and
rollback), and `workflow` — the real security workflow over the wire boundary:

```
source → capability → ingress → rule → detection → capability correlation
       → case → timeline/evidence → analyst → explicit central correlation
```

plus a plane-separation assertion (an analyst op sent to the ingress plane must
be refused).

### Update-channel tools

```
# publish a built release as the testing channel (loopback HTTP)
python -m scripts.publish_update_channel --version 1.0.1 --port 8099 --forge

# drive the whole flow against a real installation
python -m scripts.verify_update_flow \
    --install-dir "C:\ProgramData\ProShield" \
    --data-dir    "C:\ProgramData\ProShield" \
    --release-version 1.0.1 --expect-version 1.0.1
```

`--forge` also publishes two manifests that **must** be rejected -
`manifest-forged.json` (signed with a different key) and
`manifest-badhash.json` (correctly signed but describing a package whose hash
does not match) - so the negative path can be proven against a live install.

`verify_update_flow` asserts: the manifest is signed; the install detects and
verifies the release; the update applies and health-checks; the installed
version changes; the backend is healthy afterwards; an untrusted signature is
refused with nothing staged; and a hash mismatch is refused with nothing
applied.

> The updater persists state in `state/update-state.json`, which every
> ProShield tool shares. The verifier archives that file before each phase and
> waits for a real *transition*, so a previous run's state cannot be mistaken
> for the current one.

---

## 12. Defects that packaging/installation testing caught

Recorded because each one would have shipped silently. Every entry has a
regression test in `tests/`.

| Defect | Impact if shipped | Guard |
|---|---|---|
| Version resolved from `<install>\packaging\build_info.json` after the build directory was renamed to `deploy/` | An installed ProShield reported **0.0.0** instead of its real version, which also breaks update version comparison | `test_version_info_reads_build_info_from_the_install_deploy_dir`, `test_paths_resolve_the_install_deploy_dir` |
| `INSTALL_TREE_DIRS` still named `packaging` | Rollback did **not** restore `deploy/`, leaving the new version stamp and public key after a "rollback" | `test_applier_rolls_back_when_health_check_fails` |
| Runtime *verification* step (`python -c "import fastapi..."`) wrote bytecode into the bundled runtime | 805 `.pyc` files and 77 `__pycache__` dirs were staged for packaging | `prune_stage` + `audit_stage` build gate; `test_staged_payload_contains_no_forbidden_content` |
| An upgrade failed with `DeleteFile failed; code 5` on `runtime\python.exe` | Upgrade aborted and rolled back, because a backend plane still held the shared interpreter | `service/proc_cleanup.py` (`stop-planes`) + `test_proc_cleanup.py` |
| `restore_install_tree` replaced files under a **running** stack | Half-written install tree; the running planes die | `restore_install_tree` now quiesces first |
| `spawn_apply_helper` used `sys` without importing it | `on_tick` raised `NameError` every tick: a **verified, staged update was never applied** and the install silently stayed on the old version | `test_spawn_apply_helper_frozen_branch_stages_and_launches` |
| The frozen update helper is a *copy* of `ProShieldService.exe`, but the service host's argparse did not know the `update-apply` subcommand | Every frozen helper exited with `invalid choice: 'update-apply'`, so a verified, staged update was never applied | `test_service_host_dispatches_the_update_apply_subcommand`, `test_service_host_lists_the_contract_subcommands` |
| A build refresh step replaced a freshly frozen (fixed) service with an older copy | The packaged installer carried stale code | `verify_frozen_freshness` build gate |
| Inno `Permissions: admins-full users-read` | ISCC rejects `read` as an access type, and Inno only *adds* ACEs, so ProgramData's inherited `Users` access would have survived | Valid types verified empirically; `icacls /inheritance:r` hardening |
| `StringChangeEx` used inside an expression, `BoolToStr` (not an Inno function), `{app}` inside a `{ }` comment | Installer would not compile | compile is part of every release build |
| `packaging/` as a top-level Python package | Would shadow the PyPI `packaging` library that PyInstaller and pip depend on | directory renamed to `deploy/` |
| Update state shared between tools | A verifier could read a previous run's state and conclude the update finished | `reset_update_state` + transition-based waiting in `verify_update_flow` |
| The installer records `PROSHIELD_UPDATE_URL` as a channel *base* URL, but the updater expected a manifest URL | The check fetched the base, received a directory listing and failed with "manifest is not valid JSON" | `check_now` normalises a base URL to `<base>/manifest.json`; `test_engine_accepts_a_channel_base_url` |
| The detached update helper was inside the kill set for a **per-user** install (data root == install root) | `stop-planes` terminated the helper part-way through applying the update, so the post-apply health check / restart / state write never completed | `NEVER_TERMINATE_NAMES` in `service/proc_cleanup.py`; `test_update_helper_is_never_a_cleanup_target` |
| `ProShieldService.exe stop-planes` defined only `--wait`, while the installer's `PrepareToInstall`, the update helper's `quiesce_install_tree()` and this document all spell it `--timeout` | argparse exited **2** with `unrecognized arguments: --timeout 25`; the installer logged the exit code and considered the tree quiesced, so a plane kept `runtime\python.exe` locked and the upgrade died again with `DeleteFile failed; code 5` | `--timeout` accepted as an alias of `--wait` (explicit `--timeout` wins); `test_service_host_accepts_the_documented_stop_planes_timeout_alias` |
| `scripts/verify_update_flow.py` began its cleanup with an **unscoped** `taskkill /IM ProShieldService.exe /F` | Verifying a per-user testing install killed the **machine-wide Windows service** too, taking the real deployment down and leaving it looking like a crash loop (`restarts=20`). The opposite of an isolated verification run | cleanup is now scoped to `paths.install_root` via `terminate_processes_in`; the verifier also gained `--release-dir` so it can serve a temporary channel instead of the published release |
| Ambient `PROSHIELD_*` environment variables changed test outcomes | `test_engine_without_endpoint_is_disabled_and_harmless` reported `server-unavailable` instead of `no-endpoint`, because a leftover `PROSHIELD_UPDATE_URL` (written to `HKCU\Environment` by the per-user installer) pointed at a released test channel | autouse `_scrub_proshield_environment` fixture in the root `conftest.py`, plus an explicit `monkeypatch.delenv` in that test; `test_ambient_proshield_env_cannot_leak_into_a_test` |
| `test_default_child_specs_match_the_documented_topology` called `resolve_paths()` with no arguments | The unit test read the **live** `C:\ProgramData\ProShield\secrets\proshield.env`, which the installer ACLs to Administrators + SYSTEM, so a non-elevated `pytest` died with `PermissionError: [WinError 5]`. (Production is unaffected: the service runs as LocalSystem and the desktop shell passes `include_secrets=False`.) | test now resolves paths into `tmp_path` |
| `test_deliverables_are_confined_to_the_release_directory` flagged `frontend/src_upgraded_gemini/node_modules/@esbuild/win32-x64/esbuild.exe` | The guard failed on any machine where `npm install` had run, i.e. it punished normal development instead of detecting a stray release artefact | dependency directories (`node_modules`, `.venv`, caches) are excluded from the scan |

---

## 13. Known limitations

1. **The machine-wide paths were validated under elevation for the 1.0.3
   release** — registration, `sc stop`/`sc start`, cold start, the real
   `1.0.2 → 1.0.3` installer upgrade, and the 1.0.3 installer's `--timeout`
   quiesce call all ran for real (see §14). What is still *not* exercised is a
   literal **reboot**: a cold start through the SCM with MongoDB already
   running is the same sequence Windows performs at boot, and auto-start +
   MongoDB dependency + recovery actions are asserted from `sc qc` /
   `sc qfailure`, but no machine restart was performed.
2. **Rollback restores code/UI/service binaries, not the runtime.** The
   snapshot covers `app`, `scripts`, `frontend`, `service`, `desktop`, `deploy`
   and `runtime`; a rollback therefore also reverts the bundled interpreter only
   if it was part of the snapshot. MongoDB data is never part of a rollback.
3. **The desktop shell requires the WebView2 Runtime.** It is present on
   Windows 10 1809+ and Windows 11; the shell refuses to start with a clear
   message if it is missing (and `MinVersion=10.0.17763` in the installer
   enforces the OS floor).
4. **Local log files are writable by users** (the desktop shell writes its own
   log there). The authoritative audit record is MongoDB, not these
   diagnostics; `secrets`, `updates` and `backup` are Administrator-only.
5. **The GUI is not code-signed.** The installer and executables are unsigned,
   so SmartScreen will warn on first run until a code-signing certificate is
   configured. The *update channel* is signed (Ed25519) independently of
   Authenticode.
6. **`update_allow_unsigned` exists** as an escape hatch for isolated testing.
   It must remain `false` for any real channel; the default policy is
   fail-closed.

---

## 14. 1.0.3 validation record

Everything below was measured on this machine against the **installed**
application, not against a development process.

### Build

```
python -m deploy.build_windows --version 1.0.3 --channel testing \
    --update-url http://127.0.0.1:8099 --with-testmode-installer \
    --skip-frontend --skip-runtime --publish-installer primary
```

`dist/windows/1.0.3/`: `ProShield.exe` (43,652,811 B), `ProShieldService.exe`
(40,469,657 B), `ProShieldSetup-v1.0.3.exe` (96,718,652 B),
`ProShieldSetup-v1.0.3-testmode.exe` (96,718,670 B), `manifest.json` (signed,
binds the machine-wide installer's SHA-256), `checksums.txt`,
`build-report.json` (`build_id 1.0.3+20260918154146`, `git_commit f674f09a…`).
The freshness gate and payload audit both passed; no generated binary exists
anywhere else in the tree.

### Frozen binaries carry the fix

| Probe | Result |
|---|---|
| `ProShieldService.exe` (1.0.3) `stop-planes --timeout 5 --zzz-probe` | `unrecognized arguments: --zzz-probe` → **`--timeout` accepted** |
| `ProShieldService.exe` (1.0.2) same probe | `unrecognized arguments: --timeout 5 --zzz-probe` → rejected |

The probe is side-effect free (argparse fails before any cleanup) and the
1.0.2 image proves it detects the defect, so the fix is demonstrably **in the
shipped image** rather than only in source. The private signing key is not
embedded in any of the three executables.

### Machine-wide 1.0.2 → 1.0.3 upgrade (elevated)

`ProShieldSetup-v1.0.3.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /NOCANCEL
/SP-` → exit **0** in 49 s.

| Check | Result |
|---|---|
| installed version 1.0.2 → **1.0.3** | pass |
| `secrets\proshield.env` byte-identical | pass |
| `config\proshield.json` byte-identical | pass |
| `config\initial-credentials.txt` byte-identical | pass |
| a marker written into the data tree before the upgrade survived | pass |
| MongoDB reachable after the upgrade | pass |
| service RUNNING and still `AUTO_START` | pass |
| `all_healthy: true`, version 1.0.3, both planes HTTP 200 | pass |

### Service lifecycle

`sc qc` → `TYPE : 10 WIN32_OWN_PROCESS`, `START_TYPE : 2 AUTO_START`,
`DEPENDENCIES : MongoDB`, `SERVICE_START_NAME : LocalSystem`, binary inside the
install tree. `sc qfailure` → three `RESTART` actions (5 s / 10 s / 30 s),
reset period 86400 s. `sc stop` → `STOPPED` and both planes released 8088/8089.
`sc start` (cold start) → RUNNING and healthy in **17.6 s**, version 1.0.3,
both planes listening.

### Clean environment

Database `proshield`. Operational collections after the clean: `security_events`,
`detections`, `correlations`, `incidents`, `notifications`, `reports`,
`source_instances`, `source_audit`, `source_telemetry`, `source_token_replay`,
`capability_audit` — **all 0**. Preserved and verified structurally (validator +
index count intact): `capabilities` (6: nginx/simulator `active`, waf/iam/
rate_limit/network `planned`), `managed_rules` (5, all bound to `cap-nginx`),
`counters` (5, `capability` re-seated to 9 so new ids continue at `CAP-000010`).

Verified stable: counts identical at three checkpoints — at the start, after
110 s of live runtime, and after a full `pytest tests/unit` +
`test_windows_release.py` run (**1583 + 12 passed, 0 failed**) — so neither the
running service nor the test suite mutates the live database.

Installed application over the wire: both health endpoints HTTP 200; real login
works and a wrong credential is `401`; `source.list`, `detection.list`,
`correlation.list`, `case.list`, `notification.list` all empty;
`overview.summary` counters all zero; `capability.list` = 6 and `rule.list` = 5
matching MongoDB; an unauthenticated read is `401`.

Desktop shell: `ProShield.exe` launched natively, logged
`desktop shell starting (version=1.0.3-testing install=C:\inetpub\ProShield)`
then `backend ready; loading http://127.0.0.1:8088/static/soc/index.html`; the
UI rendered `BACKEND LINKED`, `All Healthy`, **0** incidents / detections /
correlations, `0/0` telemetry sources, `Matching 5 active backend rules`, and
the Sources page showed `0 Configured Sources` and `No source instances exist
yet.` No browser was needed.

### Residue removed from the final database

`cap-audit-tmp` (archived test capability), `LIVE-VERIFY-RULE-001` (a rule with
**no** `capability_id`, which violates "capability owns rules"), the capability
audit trail, and a `retired`/`archived` status left on `cap-iam` by a
capability-lifecycle verification run. 3408 operational documents in total. No
other database was touched (440 unrelated databases still present).
