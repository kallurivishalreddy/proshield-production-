"""SecurityEvent ingestion service.

The ingestion service sits at the documented Boundary 2
(Collector -> Trusted Processing, docs/PHASE 1/THREAT_MODEL.md). It
is the SOLE point that may accept an event from a connector and write
it to the repository.  Its responsibilities:

1. Authenticate the source where the connector contract requires it
   (Phase 4.1 does not implement authentication; that lands in a
   later slice per docs/PHASE 3/SECURE_FOUNDATION.md).
2. Validate the event (Pydantic model + size constraints + sensitive
   key rejection).
3. Normalise the source data into the canonical SecurityEvent (a
   no-op for already-canonical events produced by the simulator).
4. Preserve provenance (the event already carries it; the service
   MUST NOT strip or replace it).
5. Create / store the canonical SecurityEvent with documented
   idempotency semantics.

The service DOES NOT:

* trust client-supplied severity, confidence, routing, analyst
  assignment, incident state, or detection result (Phase 3 zero
  trust),
* weaken validation under any flag,
* log the raw payload,
* call out to the network for any reason,
* call another connector,
* perform any detection, correlation, or routing work.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from pydantic import ValidationError as PydanticValidationError

from ..config import ProShieldConfig
from ..connectors.base import SecurityEventConnector
from ..domain.errors import (
    ConflictEventError,
    DuplicateEventError,
    IngestionError,
    ValidationError,
)
from ..domain.security_event import (
    SecurityEvent,
    to_canonical_dict,
    validate_size_constraints,
)
from ..domain.uuid7 import uuid7
from ..observability.logging import get_request_id
from ..persistence.security_event_repository import (
    SecurityEventRepository,
    canonical_content_equal,
)


_log = logging.getLogger(__name__)


class SecurityEventIngestionService:
    """Orchestrates validation and persistence of SecurityEvents."""

    def __init__(
        self,
        repository: SecurityEventRepository,
        config: ProShieldConfig,
    ) -> None:
        self._repository = repository
        self._config = config

    # ----------------------------------------------------------------- public
    def ingest(self, event: SecurityEvent) -> SecurityEvent:
        """Validate, normalise, and persist a single SecurityEvent.

        Returns the persisted event (which may be the existing one
        when the call was an idempotent re-delivery).  Raises a
        :class:`DomainError` subclass on failure.  The caller is
        expected to translate these into the documented safe-error
        envelope (Phase 3, Section 30).
        """
        self._validate(event)
        stamped = self._stamp(event)

        # Boundary 2 source-marker identity: a repeated
        # (source, collector, source_event_id) is a re-delivery even when
        # the caller supplied a new canonical event_id.  Let the repository
        # create() path handle the same-event_id case so H-04's documented
        # event_id conflict message is preserved.
        existing = self._repository.find_by_canonical_identity(
            source=stamped.source,
            source_event_id=stamped.provenance.source_event_id,
            collector=stamped.provenance.collector,
        )
        if existing is not None and existing.event_id != stamped.event_id:
            if canonical_content_equal(existing, stamped, ignore_event_id=True):
                _log.info(
                    "ingest.source_identity_replay",
                    extra={
                        "event_id": existing.event_id,
                        "incoming_event_id": stamped.event_id,
                        "source_event_id": stamped.provenance.source_event_id,
                        "request_id": get_request_id(),
                    },
                )
                return existing
            _log.warning(
                "ingest.source_identity_conflict",
                extra={
                    "event_id": existing.event_id,
                    "incoming_event_id": stamped.event_id,
                    "source_event_id": stamped.provenance.source_event_id,
                    "request_id": get_request_id(),
                },
            )
            raise ConflictEventError(
                safe_message=(
                    "source identity already exists with different content"
                ),
                internal_detail=(
                    "source_event_id="
                    f"{stamped.provenance.source_event_id}"
                ),
            )

        try:
            persisted = self._repository.create(stamped)
        except DuplicateEventError as exc:
            # Idempotent re-delivery: the original event is canonical
            # and we already have it.  This is a successful no-op for
            # the caller.  We log the no-op for observability.
            _log.info(
                "ingest.idempotent_replay",
                extra={
                    "event_id": stamped.event_id,
                    "request_id": get_request_id(),
                },
            )
            existing = getattr(exc, "existing", None)
            return existing if existing is not None else stamped
        except ConflictEventError:
            _log.warning(
                "ingest.conflict_replay",
                extra={
                    "event_id": stamped.event_id,
                    "request_id": get_request_id(),
                },
            )
            raise
        _log.info(
            "ingest.persisted",
            extra={
                "event_id": persisted.event_id,
                "source": persisted.source,
                "event_type": persisted.event_type,
                "request_id": get_request_id(),
            },
        )
        return persisted

    def ingest_from_connector(
        self, connector: SecurityEventConnector
    ) -> int:
        """Pull events from a connector and ingest each one.

        Stops on the first error so the caller can fix the
        configuration.  Returns the number of events persisted.
        """
        n = 0
        for event in connector.collect():
            self.ingest(event)
            n += 1
        return n

    # ---------------------------------------------------------------- internal
    def _validate(self, event: SecurityEvent) -> None:
        """Defence-in-depth validation, in addition to Pydantic.

        Pydantic has already enforced the model constraints.  This
        method enforces the size and shape constraints that the
        Pydantic model itself cannot express (raw byte-size caps on
        the serialised payload).
        """
        try:
            payload = to_canonical_dict(event)
            validate_size_constraints(
                payload,
                max_body_bytes=self._config.ingest_max_body_bytes,
                max_details_bytes=self._config.ingest_max_details_bytes,
            )
        except ValidationError:
            raise
        except PydanticValidationError as exc:
            raise ValidationError(
                safe_message="event failed validation",
                internal_detail=(
                    f"pydantic raised: {type(exc).__name__}: "
                    f"{len(exc.errors())} error(s)"
                ),
            ) from exc
        except Exception as exc:  # noqa: BLE001
            raise IngestionError(
                safe_message="ingestion failed unexpectedly",
                internal_detail=f"unexpected {type(exc).__name__}",
            ) from exc

    def _stamp(self, event: SecurityEvent) -> SecurityEvent:
        """Server-side stamps: ``ingested_at`` and (if missing) ``event_id``.

        The model is frozen, so we construct a new instance.  We
        deliberately do NOT overwrite fields that the source
        legitimately set; we only fill gaps.
        """
        now = datetime.now(timezone.utc)
        stamped = event.model_copy(update={"ingested_at": now})
        if not stamped.event_id or not _looks_like_uuidv7_str(stamped.event_id):
            stamped = stamped.model_copy(update={"event_id": str(uuid7())})
        return stamped


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _looks_like_uuidv7_str(s: str) -> bool:
    try:
        from uuid import UUID

        from ..domain.uuid7 import is_uuid7
        return is_uuid7(UUID(s))
    except Exception:  # noqa: BLE001
        return False


# ---------------------------------------------------------------------------
# Connector registration
#
# Phase 4.1 ships with one connector: the simulator.  Additional
# connectors are added in later phases by mapping a name to a class
# in :data:`CONNECTOR_REGISTRY`.  The ingest service itself does not
# own connector construction; the host (CLI, future API) is
# responsible for instantiating registered connectors and handing them
# to the service.
# ---------------------------------------------------------------------------
from ..connectors.simulated import SimulatedConnector  # noqa: E402
from ..connectors.nginx import NginxConnector  # noqa: E402

CONNECTOR_REGISTRY = {
    "simulated": SimulatedConnector,
    "nginx": NginxConnector,
}
