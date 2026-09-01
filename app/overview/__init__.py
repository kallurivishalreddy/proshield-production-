"""ProShield overview / dashboard aggregate (Phase 4.10).

The :mod:`app.overview` package is the thin aggregation layer for
the dashboard summary tile (the ``overview.summary`` wire op).

It does NOT own an IncidentService or DetectionEngine directly; it
asks the (already-attached) domain read services for the counts and
aggregates them. The wire contract documents the response shape
(counts only - no PII, no evidence).
"""
from __future__ import annotations

from .service import OverviewReadService

__all__ = ["OverviewReadService"]