"""Phase 4.9 — Source Management + trusted external connector integration.

Reference: docs/PHASE 4/PHASE-04-09-REPORT.md.

This package adds the **external-source management layer** to
ProShield. It is the boundary between an external security
system and the existing Phase 4.1-4.8 pipeline.

Concepts
--------

* :class:`SourceInstance` - the authoritative record of a
  configured external system. State machine: REGISTERED ->
  CONFIGURED -> VALIDATED -> ENABLED -> DISABLED -> RETIRED.
* :class:`SourceRegistry` - the in-memory authoritative
  catalogue of configured source instances.
* :class:`SourceRepository` - the MongoDB persistence boundary
  for the ``source_instances`` collection.
* :class:`SourceManagementService` - the orchestrator that
  enforces the state machine, validates configuration, and
  issues source-identity tokens.
* :class:`SourceIdentityTokenIssuer` /
  :class:`SourceIdentityTokenVerifier` - HMAC-signed,
  time-bounded trust tokens for the inbound boundary.
* :class:`InboundIngressProxy` - the trusted inbound
  integration boundary, distinct from the client-facing
  ``app.proxy.SecureProxy``. Accepts telemetry from an
  external system only when a verified source-identity token
  proves the source is registered, enabled, and bound to the
  claimed connector type and canonical source string.

What this package does NOT do
-----------------------------

* It does NOT execute arbitrary Python code from a configured
  source. Each connector lives in :mod:`app.connectors`;
  the source-management layer only carries the configuration.
* It does NOT bypass the Phase 4.1 ingestion service.
  Connectors (and the ingress proxy's connector shim) feed
  canonical SecurityEvents through the existing ingestion
  pipeline.
* It does NOT expose filesystem structure or connector
  implementation details to the client. The client sees the
  safe :class:`SourceInstanceView` only.
* It does NOT silently convert a failed ingestion into a
  SecurityEvent. Malformed / unauthenticated / unauthorized
  payloads are rejected with a documented error.
"""
from __future__ import annotations

from .errors import (
    DuplicateSourceInstanceError,
    SourceAuthorizationError,
    SourceConfigurationError,
    SourceIdentityTokenError,
    SourceInstanceNotFoundError,
    SourceInstanceStateError,
    SourceIntegrityError,
    SourceManagementError,
    SourcePersistenceError,
    SourceRateLimitedError,
    SourceRetiredError,
)
from .models import (
    AssetTag,
    SourceConnectionType,
    SourceIdentityToken,
    SourceInstance,
    SourceInstanceConfiguration,
    SourceInstanceHealth,
    SourceInstanceId,
    SourceInstanceView,
    SourceState,
    SourceType,
    Tag,
    source_string_for_type,
    source_type_for_string,
)
from .registry import (
    SUPPORTED_CONNECTOR_TYPES,
    ALLOWED_TRANSITIONS,
    SourceRegistry,
    can_transition,
    supported_connector_types,
)
from .repository import (
    INDEX_SPECS,
    SOURCE_INSTANCES_VALIDATOR,
    SourceRepository,
    managed_source_collection_name,
)
from .service import SourceManagementService
from .trust import (
    SourceIdentityTokenIssuer,
    SourceIdentityTokenKeyring,
    SourceIdentityTokenVerifier,
    new_development_signing_key,
)


__all__ = [
    "ALLOWED_TRANSITIONS",
    "AssetTag",
    "DuplicateSourceInstanceError",
    "INDEX_SPECS",
    "SOURCE_INSTANCES_VALIDATOR",
    "SourceAuthorizationError",
    "SourceConfigurationError",
    "SourceConnectionType",
    "SourceIdentityToken",
    "SourceIdentityTokenError",
    "SourceIdentityTokenIssuer",
    "SourceIdentityTokenKeyring",
    "SourceIdentityTokenVerifier",
    "SourceInstance",
    "SourceInstanceConfiguration",
    "SourceInstanceHealth",
    "SourceInstanceId",
    "SourceInstanceNotFoundError",
    "SourceInstanceStateError",
    "SourceInstanceView",
    "SourceIntegrityError",
    "SourceManagementError",
    "SourceManagementService",
    "SourcePersistenceError",
    "SourceRateLimitedError",
    "SourceRegistry",
    "SourceRepository",
    "SourceRetiredError",
    "SourceState",
    "SourceType",
    "SUPPORTED_CONNECTOR_TYPES",
    "Tag",
    "can_transition",
    "managed_source_collection_name",
    "new_development_signing_key",
    "source_string_for_type",
    "source_type_for_string",
    "supported_connector_types",
]