"""Overview read service (Phase 4.10 wire-promotion).

Reference: docs/PHASE 4/PROSHIELD-FINAL-FRONTEND-BACKEND-CONTRACT.md
(Component 1 / Action 2.1).

The :class:`OverviewReadService` is the thin orchestration layer
for the dashboard summary tile. It exposes a single documented op:

* :meth:`summary` -> ``overview.summary``

It is intentionally minimal. It does NOT own an IncidentService
or DetectionEngine directly; it asks the (already-attached) domain
read services for the counts and aggregates them. The wire contract
documents the response shape (counts only - no PII, no evidence).

Why a dedicated service
-----------------------

The dashboard tile is a single aggregate call. The service keeps the
aggregate logic in one place so a future IAM / multi-tenant slice
can scope it without touching the proxy.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from ..auth.identity import Identity
from ..auth.permissions import has_permission
from ..incidents import IncidentService
from ..detection.service import DetectionReadService
from ..correlation.service import CorrelationReadService


class OverviewReadService:
    """The Phase 4.10 overview aggregator."""

    def __init__(
        self,
        incident_service: IncidentService,
        detection_service: DetectionReadService,
        correlation_service: CorrelationReadService,
    ) -> None:
        if incident_service is None:
            raise ValueError("incident_service is required")
        if detection_service is None:
            raise ValueError("detection_service is required")
        if correlation_service is None:
            raise ValueError("correlation_service is required")
        self._incident_service = incident_service
        self._detection_service = detection_service
        self._correlation_service = correlation_service

    def summary(self, identity: Identity) -> Dict[str, Any]:
        """Return aggregate counts for the dashboard tile.

        The shape is intentionally narrow: counts only, no evidence.
        A tenant-wide view is granted to admins / internal services;
        an analyst sees their own-case counts.
        """
        from ..auth.permissions import Permission

        is_admin = has_permission(
            role=identity.role,
            identity_permissions=tuple(identity.permissions),
            permission=Permission.CASE_READ_ANY,
        )

        # Case list (analyst-scoped or admin-scoped); the service
        # already applies the documented ownership filter.
        cases = self._incident_service.list_cases(
            identity=identity, state="open", limit=200,
        )

        # Detection count via the documented repository total.
        try:
            n_detections = self._detection_service.repository.count()
        except Exception:  # noqa: BLE001 - fail-closed aggregate.
            n_detections = 0

        # Correlation count via the documented repository total.
        try:
            n_correlations = self._correlation_service.repository.count()
        except Exception:  # noqa: BLE001
            n_correlations = 0

        # A minimal aggregate - count of open cases. Future
        # expansions (severity bands, source counts) are
        # documented in the contract as future slices.
        return {
            "open_case_count": len(cases),
            "detection_count": int(n_detections),
            "correlation_count": int(n_correlations),
            "scope": "all" if is_admin else "own",
            "produced_at": datetime.now(timezone.utc).isoformat(),
        }


__all__ = ["OverviewReadService"]