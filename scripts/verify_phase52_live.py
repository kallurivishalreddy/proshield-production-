"""Phase 5.2 — live runtime verification (real MongoDB, real composition).

Builds the *production* Mongo backend and service wiring through the same
code path the shipped server uses (``scripts.proxy_server``), then exercises
the Phase 5.2 contract end-to-end against a fresh throwaway database.

This is the runtime-plane proof that the composition wires; it is not a
substitute for the pytest gates.

Usage:  python scripts/verify_phase52_live.py [--keep]
"""
from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path
from typing import Any, List

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

_RESULTS: List[Any] = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    _RESULTS.append((name, bool(ok)))
    print(
        f"  [{'PASS' if ok else 'FAIL'}] {name}"
        + (f"  -- {detail}" if detail and not ok else ""),
        flush=True,
    )
    return bool(ok)


def _config(db_name: str):
    from app.config import ProShieldConfig

    return ProShieldConfig(
        env_name="test",
        log_level="WARNING",
        mongo_uri="mongodb://127.0.0.1:27017",
        mongo_db=db_name,
        mongo_collection_events="security_events",
        auth_signing_key=os.urandom(32).hex(),
        source_signing_key=os.urandom(32).hex(),
        # The dev seed subjects are admin/analyst/collector/internal; the
        # credential map defaults to empty so it must be injected here.
        default_subject_credentials={
            "admin": "admin-password",
            "analyst": "analyst-password",
        },
    )


class _Ctx:
    """Boot the real proxy plane against a database."""

    def __init__(self, config) -> None:  # noqa: ANN001
        import scripts.proxy_server as ps
        from app.proxy import SecureProxy

        self.bundle = ps._build_mongo_backend(config)
        self.proxy = SecureProxy(
            config=config, identity_store=ps._build_identity_store(config),
        )
        ps._attach_services(self.proxy, self.bundle)

    def token(self) -> str:
        from app.proxy import OP_AUTH_ISSUE, ProxyRequest

        resp = self.proxy.handle(ProxyRequest(
            operation=OP_AUTH_ISSUE,
            headers={},
            body={
                "subject_id": "admin",
                "credential": "admin-password",
            },
        ))
        if resp.status != 200:
            raise RuntimeError(f"auth failed: {resp.body}")
        return resp.body["data"]["token"]

    def call(self, op: str, token: str, body=None):  # noqa: ANN001
        from app.proxy import ProxyRequest

        return self.proxy.handle(ProxyRequest(
            operation=op,
            headers={"Authorization": f"Bearer {token}"},
            body=body or {},
        ))


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()

    from pymongo import MongoClient

    db_name = f"proshield_phase52_live_{uuid.uuid4().hex[:8]}"
    client = MongoClient("mongodb://127.0.0.1:27017")
    client.drop_database(db_name)
    config = _config(db_name)
    print(f"Phase 5.2 live verification against {db_name}", flush=True)

    try:
        ctx = _Ctx(config)
        check("mongo backend + services wired", True)

        db = client[db_name]
        check(
            "source_audit collection exists",
            "source_audit" in set(db.list_collection_names()),
        )
        idx = {i["name"] for i in db["source_instances"].list_indexes()}
        check(
            "source capability indexes applied",
            {"source_capability_id", "source_capability_binding_status"}
            <= idx,
            str(sorted(idx)),
        )

        token = ctx.token()
        reg = ctx.call(
            "source.register", token,
            {"source_type": "nginx", "display_name": "p52-live"},
        )
        if not check(
            "source.register", reg.status == 200, str(reg.body)[:200]
        ):
            return _summary()
        src = reg.body["data"]["source"]
        sid = src["source_instance_id"]
        check(
            "new source is capability-bound server-side",
            src.get("capability_id") == "cap-nginx"
            and src.get("capability_binding_status") == "bound",
            str(src)[:200],
        )

        for op, body in (
            ("source.configure", {
                "source_instance_id": sid,
                "configuration": {
                    "connection_type": "push",
                    "endpoint": "https://ingest.example.test/hook",
                    "secret_ref": "",
                },
            }),
            ("source.validate", {"source_instance_id": sid}),
            ("source.enable", {"source_instance_id": sid}),
            ("source.issue_token", {"source_instance_id": sid}),
        ):
            r = ctx.call(op, token, body)
            check(op, r.status == 200, str(r.body)[:200])

        mig = ctx.call("source.migrate", token, {})
        check(
            "source.migrate defaults to dry-run",
            mig.status == 200 and mig.body["data"]["dry_run"] is True,
            str(mig.body)[:200],
        )
        applied = ctx.call("source.migrate", token, {"dry_run": False})
        check(
            "source.migrate applies idempotently",
            applied.status == 200
            and applied.body["data"]["sources"]["bound"] == 0,
            str(applied.body)[:200],
        )

        aud = ctx.call("source.audit", token, {"source_instance_id": sid})
        actions = (
            {r["action"] for r in aud.body["data"]["audit"]}
            if aud.status == 200 else set()
        )
        check(
            "audit trail records security-sensitive writes",
            {"source_register", "source_token_issue"} <= actions,
            str(sorted(actions)),
        )

        ctx2 = _Ctx(config)  # simulated restart over the same database
        reloaded = ctx2.bundle.source_management.get(sid)
        check(
            "binding survives a second boot",
            reloaded.capability_id == "cap-nginx"
            and reloaded.capability_binding_status == "bound",
            str(reloaded)[:200],
        )
        second = ctx2.call("source.migrate", token, {"dry_run": False})
        check(
            "migration is a no-op on the second boot",
            second.status == 200
            and second.body["data"]["documents_modified"] == 0,
            str(second.body)[:200],
        )
    finally:
        if not args.keep:
            client.drop_database(db_name)
            print(f"  (dropped {db_name})", flush=True)

    return _summary()


def _summary() -> int:
    passed = sum(1 for _, ok in _RESULTS if ok)
    print(f"\n{passed}/{len(_RESULTS)} checks passed", flush=True)
    return 0 if passed == len(_RESULTS) else 1


if __name__ == "__main__":
    raise SystemExit(main())