"""Idempotent built-in Capability seeds (Phase 5.1).

Two live capabilities ship with a real in-repo implementation:
``cap-nginx`` (nginx connector + 5-rule library) and
``cap-simulator`` (simulated connector). Four declared-but-unbuilt
families ship as ``planned`` so the catalogue is truthful and the UI
never advertises phantom live coverage.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

from .models import CapabilityStatus, ImplementationRef


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def build_builtin_capabilities(*, created_by: str = "system") -> List[Dict[str, Any]]:
    now = _utcnow()
    return [
        {
            "capability_id": "cap-nginx",
            "name": "NGINX Access & Security Gateway",
            "description": "NGINX access-log ingestion, normalization, detection and correlation.",
            "responsibility": "Owns nginx source configuration schema, nginx mapping profiles, the 5-rule nginx library and the brute-force correlation pattern.",
            "implementation_ref": ImplementationRef.NGINX.value,
            "version": 1,
            "status": CapabilityStatus.ACTIVE.value,
            "configuration_schema": {
                "type": "object",
                "required": ["connection_type", "endpoint"],
                "properties": {
                    "connection_type": {"type": "string", "enum": ["push", "proxy", "pull"]},
                    "endpoint": {"type": "string", "maxLength": 512},
                },
            },
            "mapping_profiles": [
                {
                    "profile_id": "nginx-access-default",
                    "source_type": "nginx",
                    "field_map": {"status_code": "details.status_code", "request_path": "endpoint"},
                }
            ],
            "created_by": created_by,
            "created_at": now,
            "updated_by": created_by,
            "updated_at": now,
        },
        {
            "capability_id": "cap-simulator",
            "name": "Simulated Telemetry Source",
            "description": "Deterministic simulated canonical events for demos and regression.",
            "responsibility": "Owns simulator source configuration schema and deterministic demo mapping profiles.",
            "implementation_ref": ImplementationRef.SIMULATOR.value,
            "version": 1,
            "status": CapabilityStatus.ACTIVE.value,
            "configuration_schema": {
                "type": "object",
                "required": ["connection_type", "endpoint"],
                "properties": {
                    "connection_type": {"type": "string", "enum": ["push", "proxy", "pull"]},
                    "endpoint": {"type": "string", "maxLength": 512},
                },
            },
            "mapping_profiles": [
                {
                    "profile_id": "simulator-default",
                    "source_type": "simulator",
                    "field_map": {"scenario": "details.scenario", "sequence": "details.seq"},
                }
            ],
            "created_by": created_by,
            "created_at": now,
            "updated_by": created_by,
            "updated_at": now,
        },
        {
            "capability_id": "cap-waf",
            "name": "WAF Telemetry (Planned)",
            "description": "Declared WAF family; no connector implementation ships in 5.1.",
            "responsibility": "Reserved for future WAF ingestion ownership.",
            "implementation_ref": ImplementationRef.PLANNED.value,
            "version": 1,
            "status": CapabilityStatus.PLANNED.value,
            "configuration_schema": {"type": "object"},
            "mapping_profiles": [],
            "created_by": created_by,
            "created_at": now,
            "updated_by": created_by,
            "updated_at": now,
        },
        {
            "capability_id": "cap-iam",
            "name": "IAM Telemetry (Planned)",
            "description": "Declared IAM family; no connector implementation ships in 5.1.",
            "responsibility": "Reserved for future IAM ingestion ownership.",
            "implementation_ref": ImplementationRef.PLANNED.value,
            "version": 1,
            "status": CapabilityStatus.PLANNED.value,
            "configuration_schema": {"type": "object"},
            "mapping_profiles": [],
            "created_by": created_by,
            "created_at": now,
            "updated_by": created_by,
            "updated_at": now,
        },
        {
            "capability_id": "cap-rate-limit",
            "name": "Rate-Limit Telemetry (Planned)",
            "description": "Declared rate-limit family; no connector implementation ships in 5.1.",
            "responsibility": "Reserved for future rate-limit ingestion ownership.",
            "implementation_ref": ImplementationRef.PLANNED.value,
            "version": 1,
            "status": CapabilityStatus.PLANNED.value,
            "configuration_schema": {"type": "object"},
            "mapping_profiles": [],
            "created_by": created_by,
            "created_at": now,
            "updated_by": created_by,
            "updated_at": now,
        },
        {
            "capability_id": "cap-network",
            "name": "Network Telemetry (Planned)",
            "description": "Declared network family; no connector implementation ships in 5.1.",
            "responsibility": "Reserved for future network ingestion ownership.",
            "implementation_ref": ImplementationRef.PLANNED.value,
            "version": 1,
            "status": CapabilityStatus.PLANNED.value,
            "configuration_schema": {"type": "object"},
            "mapping_profiles": [],
            "created_by": created_by,
            "created_at": now,
            "updated_by": created_by,
            "updated_at": now,
        },
    ]


BUILTIN_CAPABILITIES = build_builtin_capabilities()

__all__ = ["BUILTIN_CAPABILITIES", "build_builtin_capabilities"]
