"""Deep health / subsystem observability (capability patch gap 8).

Reference: docs/PHASE 4/PROSHIELD-BACKEND-CAPABILITY-PATCH-REPORT.md;
contract §10 (which documented the liveness-only deferral that this
slice closes).

The :class:`DeepHealthService` produces a truthful per-subsystem
report. Statuses are a closed four-value set:

* ``healthy``       - the probe ran and answered within bounds.
* ``degraded``      - the probe ran but the answer indicates reduced
  capability (e.g. an in-memory backend instead of MongoDB).
* ``unavailable``   - the probe FAILED. A dead dependency is never
  reported healthy.
* ``not_configured``- the subsystem has no wiring in this deployment
  (truthfully distinct from healthy).

Probes are time-bounded (per-probe latency measured and reported)
and never raise: a probe failure IS the result.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from pymongo.database import Database


HEALTHY = "healthy"
DEGRADED = "degraded"
UNAVAILABLE = "unavailable"
NOT_CONFIGURED = "not_configured"

STATUS_ORDER = {HEALTHY: 0, NOT_CONFIGURED: 1, DEGRADED: 2, UNAVAILABLE: 3}


class DeepHealthService:
    """Truthful per-subsystem health for the analyst plane."""

    def __init__(
        self,
        *,
        db: Optional[Database] = None,
        config: Any = None,
        rule_registry: Optional[Any] = None,
        incident_service: Optional[Any] = None,
        correlation_service: Optional[Any] = None,
        detection_service: Optional[Any] = None,
        source_management_service: Optional[Any] = None,
        telemetry_store: Optional[Any] = None,
        capability_service: Optional[Any] = None,
        backend_kind: str = "memory",
    ) -> None:
        self._db = db
        self._config = config
        self._rule_registry = rule_registry
        self._incident_service = incident_service
        self._correlation_service = correlation_service
        self._detection_service = detection_service
        self._source_management_service = source_management_service
        self._telemetry_store = telemetry_store
        self._capability_service = capability_service
        self._backend_kind = backend_kind

    # ------------------------------------------------------------------
    def run_checks(self) -> Dict[str, Any]:
        subsystems: List[Dict[str, Any]] = []
        subsystems.append(self._probe_database())
        subsystems.append(self._probe_persistence_collections())
        subsystems.append(self._probe_rule_registry())
        subsystems.append(self._probe_incident_subsystem())
        subsystems.append(self._probe_detection_subsystem())
        subsystems.append(self._probe_correlation_subsystem())
        subsystems.append(self._probe_source_registry())
        subsystems.append(self._probe_ingress_telemetry())
        subsystems.append(self._probe_capability_registry())
        overall = HEALTHY
        for s in subsystems:
            if STATUS_ORDER.get(s["status"], 0) > STATUS_ORDER[overall]:
                overall = s["status"]
        return {
            "status": overall,
            "backend_kind": self._backend_kind,
            "subsystems": subsystems,
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }

    # ------------------------------------------------------------------
    def _timed(self, probe: Callable[[], Dict[str, Any]]) -> Dict[str, Any]:
        start = time.perf_counter()
        try:
            result = probe()
            latency_ms = (time.perf_counter() - start) * 1000.0
            result["latency_ms"] = round(latency_ms, 3)
            return result
        except Exception as exc:  # noqa: BLE001 - probe failure IS the result
            latency_ms = (time.perf_counter() - start) * 1000.0
            return {
                "status": UNAVAILABLE,
                "detail": f"probe failed: {type(exc).__name__}",
                "latency_ms": round(latency_ms, 3),
            }

    def _probe_database(self) -> Dict[str, Any]:
        def probe() -> Dict[str, Any]:
            if self._backend_kind != "mongo" or self._db is None:
                return {
                    "status": DEGRADED,
                    "detail": (
                        "in-memory backend; persistence does not "
                        "survive restart"
                    ),
                }
            start = time.perf_counter()
            self._db.command("ping")
            latency = (time.perf_counter() - start) * 1000.0
            return {
                "status": HEALTHY,
                "detail": "MongoDB ping ok",
                "ping_latency_ms": round(latency, 3),
            }

        out = self._timed(probe)
        out["name"] = "database"
        return out

    def _probe_persistence_collections(self) -> Dict[str, Any]:
        def probe() -> Dict[str, Any]:
            if self._backend_kind != "mongo" or self._db is None:
                return {
                    "status": DEGRADED,
                    "detail": "in-memory collections (fake backend)",
                }
            names = set(self._db.list_collection_names())
            required = {
                "security_events", "detections", "correlations",
                "incidents", "managed_rules", "source_instances",
            }
            missing = sorted(required - names)
            if missing:
                return {
                    "status": UNAVAILABLE,
                    "detail": f"missing collections: {missing}",
                }
            return {
                "status": HEALTHY,
                "detail": "all documented collections present",
                "collections": sorted(required & names),
            }

        out = self._timed(probe)
        out["name"] = "persistence"
        return out

    def _probe_rule_registry(self) -> Dict[str, Any]:
        def probe() -> Dict[str, Any]:
            if self._rule_registry is None:
                return {
                    "status": NOT_CONFIGURED,
                    "detail": "rule registry not wired",
                }
            rules = self._rule_registry.list_all()
            return {
                "status": HEALTHY,
                "detail": f"{len(rules)} rule(s) registered",
                "rule_count": len(rules),
            }

        out = self._timed(probe)
        out["name"] = "rule_registry"
        return out

    def _probe_incident_subsystem(self) -> Dict[str, Any]:
        def probe() -> Dict[str, Any]:
            if self._incident_service is None:
                return {
                    "status": NOT_CONFIGURED,
                    "detail": "incident service not wired",
                }
            count = self._incident_service.repository.count()
            return {
                "status": HEALTHY,
                "detail": "incident repository answered",
                "case_count": int(count),
            }

        out = self._timed(probe)
        out["name"] = "incident_subsystem"
        return out

    def _probe_detection_subsystem(self) -> Dict[str, Any]:
        def probe() -> Dict[str, Any]:
            if self._detection_service is None:
                return {
                    "status": NOT_CONFIGURED,
                    "detail": "detection service not wired",
                }
            count = self._detection_service.repository.count()
            return {
                "status": HEALTHY,
                "detail": "detection repository answered",
                "detection_count": int(count),
            }

        out = self._timed(probe)
        out["name"] = "detection_subsystem"
        return out

    def _probe_correlation_subsystem(self) -> Dict[str, Any]:
        def probe() -> Dict[str, Any]:
            if self._correlation_service is None:
                return {
                    "status": NOT_CONFIGURED,
                    "detail": "correlation service not wired",
                }
            count = self._correlation_service.repository.count()
            return {
                "status": HEALTHY,
                "detail": "correlation repository answered",
                "correlation_count": int(count),
            }

        out = self._timed(probe)
        out["name"] = "correlation_subsystem"
        return out

    def _probe_source_registry(self) -> Dict[str, Any]:
        def probe() -> Dict[str, Any]:
            svc = self._source_management_service
            if svc is None:
                return {
                    "status": NOT_CONFIGURED,
                    "detail": "source management not wired",
                }
            sources = svc.list_all()
            by_state: Dict[str, int] = {}
            for s in sources:
                state = str(getattr(s, "state", "?"))
                by_state[state] = by_state.get(state, 0) + 1
            return {
                "status": HEALTHY,
                "detail": f"{len(sources)} source instance(s)",
                "source_count": len(sources),
                "by_state": by_state,
            }

        out = self._timed(probe)
        out["name"] = "source_registry"
        return out

    def _probe_ingress_telemetry(self) -> Dict[str, Any]:
        def probe() -> Dict[str, Any]:
            if self._telemetry_store is None:
                return {
                    "status": NOT_CONFIGURED,
                    "detail": (
                        "ingress telemetry not wired in this process "
                        "(counters live in the ingress plane)"
                    ),
                }
            snaps = self._telemetry_store.snapshot_all()
            return {
                "status": HEALTHY,
                "detail": (
                    f"telemetry present for {len(snaps)} source(s)"
                ),
                "tracked_sources": len(snaps),
            }

        out = self._timed(probe)
        out["name"] = "ingress_telemetry"
        return out

    def _probe_capability_registry(self) -> Dict[str, Any]:
        def probe() -> Dict[str, Any]:
            svc = self._capability_service
            if svc is None:
                return {
                    "status": NOT_CONFIGURED,
                    "detail": "capability registry not wired",
                }
            items = svc.list(limit=200)
            by_status: Dict[str, int] = {}
            for raw in items:
                st = str(raw.get("status", "?"))
                by_status[st] = by_status.get(st, 0) + 1
            return {
                "status": HEALTHY,
                "detail": f"{len(items)} capabilit(ies)",
                "capability_count": len(items),
                "by_status": by_status,
            }

        out = self._timed(probe)
        out["name"] = "capability_registry"
        return out


__all__ = [
    "DEGRADED",
    "HEALTHY",
    "NOT_CONFIGURED",
    "DeepHealthService",
    "UNAVAILABLE",
]
