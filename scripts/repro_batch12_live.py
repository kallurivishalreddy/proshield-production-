"""Batch 1 & 2 forensic reproduction probe (T04 / T22 / T28) — LIVE planes.

Drives the REAL running product exactly as a manual tester would:

* analyst plane  : ``http://127.0.0.1:8088`` (``/api/proxy``, session token)
* ingress plane  : ``http://127.0.0.1:8089`` (``/api/ingress``, source token)
* MongoDB        : the planes' own database (read back for evidence)

What it does (it patches nothing):

1. T04 — proves the two-plane wiring and the ingress auth boundary
   (``source.ingest`` without a token must be refused).
2. T22 — sends the canonical ``event_time`` matrix (valid / invalid string /
   wrong type / null / missing / malformed / impossible date / tz variants)
   through the live ingress and reports accept/reject plus the persisted
   ``event_time`` / ``ingested_at`` for every variant.
3. T28 — ingests exactly THRESHOLD (4) authentication-failure events from one
   ``source_ip`` on one endpoint (no more), drives no extra calls, and reports
   the evidence sizes of the persisted correlation, the auto-opened case, the
   wire ``case.get`` view and ``timeline.build_for_incident``.

Usage:
    python -m scripts.repro_batch12_live [--analyst URL] [--ingress URL]
        [--db NAME] [--skip-t22] [--skip-t28]
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

MONGO_URI = "mongodb://127.0.0.1:27017"

#: Operator-facing credential file written once by the Windows installer /
#: first service start (``service/credentials.py``). Read only when the
#: environment does not provide a credential explicitly.
_INSTALLED_CREDENTIAL_FILE = Path(
    "C:/ProgramData/ProShield/config/initial-credentials.txt"
)

#: Fallbacks for a repository-launched pair (``--seed-credentials``).
_FALLBACK_CREDENTIALS = (
    ("admin-dev-credential", "admin"),
    ("adminpw", "admin"),
    ("admin-password", "admin"),
)


def _installed_credentials() -> List[Tuple[str, str]]:
    """Parse ``initial-credentials.txt`` -> [(credential, subject), ...]."""
    try:
        text = _INSTALLED_CREDENTIAL_FILE.read_text(encoding="utf-8")
    except OSError:
        return []
    out: List[Tuple[str, str]] = []
    subject = None
    for raw in text.splitlines():
        stripped = raw.strip()
        if stripped.startswith("subject_id :"):
            subject = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("credential :") and subject:
            out.append((stripped.split(":", 1)[1].strip(), subject))
            subject = None
    return out


def _http(
    method: str,
    url: str,
    *,
    body: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 20.0,
) -> Tuple[int, Any]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            try:
                return resp.status, json.loads(raw)
            except json.JSONDecodeError:
                return resp.status, raw
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            return exc.code, json.loads(raw)
        except json.JSONDecodeError:
            return exc.code, raw
    except Exception as exc:  # noqa: BLE001 - a probe reports, it never raises
        return 0, f"{type(exc).__name__}: {exc}"


def line(text: str = "") -> None:
    print(text, flush=True)


# ------------------------------------------------------------------ T04
def probe_t04(
    analyst: str, ingress: str, credentials: Optional[str] = None
) -> Optional[str]:
    line("=" * 78)
    line("T04 — ingress / source architecture (live planes)")
    line("=" * 78)
    st, body = _http("GET", f"{analyst}/health")
    line(f"  analyst /health              -> {st} {body}")
    st, body = _http("GET", f"{ingress}/health")
    line(f"  ingress /health              -> {st} {body}")

    # Unauthenticated source.ingest through the LIVE ingress listener.
    st, body = _http(
        "POST",
        f"{ingress}/api/ingress",
        body={"operation": "source.ingest", "events": []},
    )
    line(f"  unauth source.ingest         -> {st} {json.dumps(body)[:200]}")
    st, body = _http("GET", f"{ingress}/api/ingress/health")
    line(f"  ingress health op            -> {st} {json.dumps(body)[:200]}")

    # Analyst session token (explicit --credential, the installed product's
    # operator-facing file, then the repository-launched dev seed).
    candidates: List[Tuple[str, str]] = []
    if credentials:
        subject, _, credential = credentials.partition(":")
        candidates.append((credential, subject or "admin"))
    candidates.extend(_installed_credentials())
    candidates.extend(_FALLBACK_CREDENTIALS)

    token = None
    for credential, subject in candidates:
        st, body = _http(
            "POST",
            f"{analyst}/api/proxy",
            body={
                "operation": "auth.issue",
                "subject_id": subject,
                "credential": credential,
            },
        )
        if st == 200 and isinstance(body, dict) and body.get("data", {}).get("token"):
            token = body["data"]["token"]
            line(f"  auth.issue                   -> 200 (credential={credential!r})")
            break
    if token is None:
        line("  auth.issue                   -> FAILED (no known credential)")
        return None
    return token


def _proxy(analyst: str, token: str, op: str, body: Optional[Dict[str, Any]] = None):
    return _http(
        "POST",
        f"{analyst}/api/proxy",
        body=dict({"operation": op}, **(body or {})),
        headers={"X-ProShield-Session": token},
    )


def _register_source(
    analyst: str, token: str, name: str, endpoint: str
) -> Optional[str]:
    st, body = _proxy(
        analyst, token, "source.register",
        {"source_type": "nginx", "display_name": name, "tags": ["BATCH12"]},
    )
    if st != 200:
        line(f"  source.register -> {st} {json.dumps(body)[:300]}")
        return None
    sid = body["data"]["source"]["source_instance_id"]
    st2, _ = _proxy(
        analyst, token, "source.configure",
        {
            "source_instance_id": sid,
            "configuration": {"connection_type": "push", "endpoint": endpoint},
        },
    )
    st3, _ = _proxy(analyst, token, "source.validate", {"source_instance_id": sid})
    st4, body4 = _proxy(analyst, token, "source.enable", {"source_instance_id": sid})
    line(
        f"  source {sid} register/configure/validate/enable -> "
        f"{st}/{st2}/{st3}/{st4}"
    )
    if st4 != 200:
        line(f"    enable body: {json.dumps(body4)[:300]}")
        return None
    return sid


def _new_token(analyst: str, token: str, sid: str) -> Optional[str]:
    st, body = _proxy(analyst, token, "source.issue_token", {"source_instance_id": sid})
    if st != 200:
        line(f"  source.issue_token -> {st} {json.dumps(body)[:200]}")
        return None
    return body["data"]["source_token"]


def _ingest(ingress: str, source_token: str, events: List[Dict[str, Any]]):
    return _http(
        "POST",
        f"{ingress}/api/ingress",
        body={"operation": "source.ingest", "events": events},
        headers={"Authorization": f"Bearer {source_token}"},
    )

# ------------------------------------------------------------------ T22
def _probe_config():
    """The probe reads the planes' own database with the ambient config."""
    from app.config import ProShieldConfig

    base = ProShieldConfig.from_env()
    return ProShieldConfig(
        env_name=base.env_name or "development",
        log_level="WARNING",
        mongo_uri=base.mongo_uri,
        mongo_db=base.mongo_db,
    )


def probe_t22(analyst: str, token: str, ingress: str, db, sid: str) -> None:
    line()
    line("=" * 78)
    line("T22 — canonical event_time handling (live ingress, canonical field)")
    line("=" * 78)
    from app.persistence.security_event_repository import SecurityEventRepository

    repo = SecurityEventRepository(db=db, config=_probe_config())
    base = datetime.now(timezone.utc).replace(microsecond=0)
    stamp = base - timedelta(minutes=30)
    variants: List[Tuple[str, Dict[str, Any]]] = [
        ("valid Z", {"event_time": stamp.isoformat().replace("+00:00", "Z")}),
        ("valid +00:00", {"event_time": stamp.isoformat()}),
        ("valid +05:30 (IST offset)", {
            "event_time": (stamp + timedelta(hours=5, minutes=30))
            .isoformat().replace("+00:00", "+05:30"),
        }),
        ("valid -08:00", {
            "event_time": (stamp - timedelta(hours=8))
            .isoformat().replace("+00:00", "-08:00"),
        }),
        ("naive (no offset)", {"event_time": stamp.strftime("%Y-%m-%dT%H:%M:%S")}),
        ("invalid string", {"event_time": "not-a-real-timestamp"}),
        ("malformed", {"event_time": "2026-13-45T99:99:99Z"}),
        ("impossible date", {"event_time": "2026-02-30T10:00:00Z"}),
        ("wrong type (int)", {"event_time": 1234567890}),
        ("wrong type (list)", {"event_time": ["2026-01-01T00:00:00Z"]}),
        ("null", {"event_time": None}),
        ("missing", {}),
        ("future-dated (+3h)", {
            "event_time": (base + timedelta(hours=3)).isoformat().replace("+00:00", "Z"),
        }),
        ("T22 as reported (non-canonical 'timestamp' only)", {
            "timestamp": "not-a-real-timestamp",
        }),
    ]

    for label, extra in variants:
        event: Dict[str, Any] = {
            "event_type": "authentication_failure",
            "source_event_id": f"b12-t22-{uuid.uuid4().hex[:12]}",
            "source_ip": "198.51.100.24",
            "endpoint": "/probe/t22",
            "asset": "web-app",
            "details": {"http_method": "POST", "status_code": 401},
        }
        event.update(extra)
        source_token = _new_token(analyst, token, sid)
        if source_token is None:
            return
        st, body = _ingest(ingress, source_token, [event])
        data = body.get("data", {}) if isinstance(body, dict) else {}
        accepted = data.get("accepted_event_ids") or []
        rejected = data.get("rejected") or []
        outcome = "ACCEPTED" if accepted else "REJECTED"
        if accepted:
            row = repo.get_by_event_id(accepted[0])
            detail = (
                "event_time=%s ingested_at=%s" % (
                    row.event_time.isoformat(), row.ingested_at.isoformat(),
                )
                if row is not None else "persisted row not found"
            )
        else:
            detail = json.dumps(rejected)[:170]
        line(f"  [{outcome:8}] {label:48} http={st} {detail}")



# ------------------------------------------------------------------ T28
def probe_t28(analyst: str, token: str, ingress: str, db, sid: str) -> None:
    line()
    line("=" * 78)
    line("T28 — case evidence completeness (threshold-exact 4-event cluster)")
    line("=" * 78)
    from app.correlation.service import CorrelationReadService
    from app.detection.service import DetectionReadService
    from app.domain.uuid7 import uuid7
    from app.incidents.repository import IncidentRepository
    from app.persistence.correlation_repository import CorrelationRepository
    from app.persistence.detection_repository import DetectionRepository
    from app.persistence.security_event_repository import SecurityEventRepository
    from app.timeline.engine import TimelineEngine
    from app.timeline.service import TimelineReadService

    cfg = _probe_config()
    events_repo = SecurityEventRepository(db=db, config=cfg)
    detections_repo = DetectionRepository(db=db, config=cfg)
    corr_repo = CorrelationRepository(db=db, config=cfg)
    case_repo = IncidentRepository(db=db, config=cfg)

    run_tag = uuid.uuid4().hex[:6]
    attacker_ip = "203.0.113.%d" % (int(run_tag[:2], 16) % 200 + 20)
    endpoint = "/probe/t28-%s" % run_tag
    now = datetime.now(timezone.utc).replace(microsecond=0)

    batch = [
        {
            "event_id": str(uuid7()),
            "event_type": "authentication_failure",
            "source_event_id": "b12-t28-%s-%d" % (run_tag, i),
            "event_time": (now - timedelta(seconds=40 - i))
            .isoformat().replace("+00:00", "Z"),
            "source_ip": attacker_ip,
            "endpoint": endpoint,
            "asset": "web-app",
            "account": {"id": "probe-user-%d" % (i % 2)},
            "details": {"http_method": "POST", "status_code": 401},
        }
        for i in range(4)
    ]
    source_token = _new_token(analyst, token, sid)
    if source_token is None:
        return
    st, body = _ingest(ingress, source_token, batch)
    data = body.get("data", {}) if isinstance(body, dict) else {}
    accepted = data.get("accepted_event_ids") or []
    line("  ingest 4 auth-failure events -> http=%s accepted=%d "
         "(source_ip=%s, endpoint=%s)" % (st, len(accepted), attacker_ip, endpoint))
    if len(accepted) != 4:
        line(f"    body: {json.dumps(body)[:400]}")
        return

    dets = [d for eid in accepted for d in detections_repo.find_by_event_id(eid)]
    line(f"  detections persisted         -> {len(dets)}")
    for d in dets:
        line("     %s  rule=%s v%s event=%s"
             % (d.detection_id, d.rule_id, d.rule_version, d.event_id))


    corrs = corr_repo.find_recent(limit=200)
    mine = [
        c for c in corrs
        if endpoint in (c.key.parts[1] if len(c.key.parts) > 1 else "")
    ]
    if not mine:
        line("  correlation                  -> NONE (pattern did not fire)")
        return
    corr = mine[0]
    line(f"  correlation                  -> {corr.correlation_id}")
    line(f"     key={corr.key.parts} count={corr.count}")
    line(f"     detection_ids={len(corr.detection_ids)} "
         f"event_ids={len(corr.event_ids)}")
    line("     correlation covers all 4 accepted events: "
         f"{set(corr.event_ids) >= set(accepted)}")

    cases = [
        c for c in case_repo.find_recent(limit=200)
        if corr.correlation_id in tuple(c.evidence.correlation_ids)
    ]
    if not cases:
        line("  case                         -> NONE (no auto case for correlation)")
        return
    case = cases[0]
    line(f"  case                         -> {case.incident_id}")
    line("     evidence.event_ids       = %d %s"
         % (len(case.evidence.event_ids), list(case.evidence.event_ids)))
    line("     evidence.detection_ids   = %d %s"
         % (len(case.evidence.detection_ids), list(case.evidence.detection_ids)))
    line(f"     evidence.correlation_ids = {list(case.evidence.correlation_ids)}")
    complete = (
        set(accepted) <= set(case.evidence.event_ids)
        and {d.detection_id for d in dets} <= set(case.evidence.detection_ids)
        and corr.correlation_id in case.evidence.correlation_ids
    )
    line("  CASE EVIDENCE COMPLETE (4 events / all detections / correlation): "
         f"{complete}")

    timeline = TimelineReadService(
        TimelineEngine(),
        events_repo,
        DetectionReadService(repository=detections_repo),
        CorrelationReadService(repository=corr_repo),
    )
    result = timeline.build_for_incident(case=case)
    items = getattr(result, "items", result)
    kinds: Dict[str, int] = {}
    for item in items:
        kind = getattr(item, "kind", None)
        if kind is None and isinstance(item, dict):
            kind = item.get("kind")
        if hasattr(kind, "value"):
            kind = kind.value
        kinds[str(kind)] = kinds.get(str(kind), 0) + 1
    line(f"  timeline items for the case  -> {len(items)} {kinds}")

    st, body = _proxy(analyst, token, "case.get", {"incident_id": case.incident_id})
    if st == 200:
        wire = body["data"]["case"]["evidence"]
        line("  wire case.get evidence       -> events=%d detections=%d correlations=%d"
             % (len(wire["event_ids"]), len(wire["detection_ids"]),
                len(wire["correlation_ids"])))
    else:
        line(f"  wire case.get                -> {st} {json.dumps(body)[:200]}")

    st, body = _proxy(
        analyst, token, "timeline.build_for_incident",
        {"incident_id": case.incident_id},
    )
    if st == 200:
        tdata = body.get("data", {})
        line("  wire timeline.build_for_incident -> http=%s items=%d kinds=%s"
             % (st, len(tdata.get("items", [])), tdata.get("kinds")))
    else:
        line(f"  wire timeline.build_for_incident -> {st} "
             f"{json.dumps(body)[:200]}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--analyst", default="http://127.0.0.1:8088")
    parser.add_argument("--ingress", default="http://127.0.0.1:8089")
    parser.add_argument("--db", default=None)
    parser.add_argument("--skip-t22", action="store_true")
    parser.add_argument("--skip-t28", action="store_true")
    parser.add_argument(
        "--credential",
        default=None,
        help="<subject>:<credential> for the analyst plane "
             "(default: installed credentials file / dev seed)",
    )
    args = parser.parse_args()

    from pymongo import MongoClient

    token = probe_t04(args.analyst, args.ingress, args.credential)
    if token is None:
        return 1

    db_name = args.db or _probe_config().mongo_db
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=2000)
    db = client[db_name]
    line(f"  database                     -> {db_name}")

    sid = _register_source(
        args.analyst, token, "b12-probe-%s" % uuid.uuid4().hex[:6], "/probe/*"
    )
    if sid is None:
        client.close()
        return 1

    try:
        if not args.skip_t22:
            probe_t22(args.analyst, token, args.ingress, db, sid)
        if not args.skip_t28:
            probe_t28(args.analyst, token, args.ingress, db, sid)
    finally:
        client.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

