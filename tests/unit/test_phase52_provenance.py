"""Phase 5.2 — capability provenance through detection / correlation (§8, §12).

Reference: docs/PHASE 5(V3)/PHASE-05-V3-IMPLEMENTATION-MASTER-PLAN.md

* §8 V3 Domain Model (target):
    - ``Detection += capability_id`` (copied from rule at fire time)
    - ``Correlation += capability_ids[]`` (derived from member detections)
* §12 Database Strategy:
    - ``MODIFIED: ... detections (+capability_id), correlations (+capability_ids)``
* §19 acceptance: "live nginx event carries ``capability_id`` end-to-end to
  detection".

These tests pin the implemented contract:

1. ``Detection.capability_id`` / ``Correlation.capability_ids`` are
   **derived**, never caller-supplied: enrichment reads the capability from
   the supporting event's server-derived provenance only.
2. A detection for an event with no derived capability stays EMPTY — the
   code never invents an owner.
3. A correlation derives ``capability_ids`` from its own member detections,
   de-duplicated and sorted (deterministic / replay-stable).
4. Detection-id and correlation-id determinism is untouched (neither new
   field participates in an id derivation).
5. The Mongo ``$jsonSchema`` validators and index specs carry the new
   fields, and the document→domain readers round-trip them.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

import pytest

from app.correlation.models import (
    MAX_CORRELATION_CAPABILITIES,
    Correlation,
    CorrelationKey,
)
from app.detection.models import Detection
from app.domain.security_event import (
    SecurityEvent,
    SecurityEventProvenance,
)
from app.severity.enrichment import enrich_correlation, enrich_detection

FIXED_NOW = datetime(2026, 8, 30, 12, 0, 0, tzinfo=timezone.utc)

EVENT_IDS = (
    "01923456-7890-7abc-9def-0123456789a1",
    "01923456-7890-7abc-9def-0123456789a2",
    "01923456-7890-7abc-9def-0123456789a3",
    "01923456-7890-7abc-9def-0123456789a4",
)
EVENT_ID = EVENT_IDS[0]
DETECTION_ID = "det-01923456-7890-7abc-9def-0123456789ab"
CORRELATION_ID = "corr-01923456-7890-7abc-9def-0123456789ab"
SRC_ONE = "src-01923456-7890-7abc-9def-000000000001"


def _make_event(
    *,
    event_id: str = EVENT_ID,
    capability_id: str | None = None,
    source_instance_id: str | None = SRC_ONE,
    details: Dict[str, Any] | None = None,
) -> SecurityEvent:
    return SecurityEvent(
        event_id=event_id,
        event_time=FIXED_NOW,
        ingested_at=FIXED_NOW,
        source="nginx",
        event_type="authentication_failure",
        source_ip="198.51.100.7",
        endpoint="/api/login",
        details=details if details is not None else {"status_code": 401},
        provenance=SecurityEventProvenance(
            collector="test",
            source_event_id="src-1",
            source_instance_id=source_instance_id,
            capability_id=capability_id,
        ),
    )


def _make_detection(
    *,
    detection_id: str = DETECTION_ID,
    event_id: str = EVENT_ID,
    capability_id: str = "",
) -> Detection:
    return Detection(
        detection_id=detection_id,
        rule_id="NGINX-AUTH-FAILURE-001",
        rule_version=1,
        category="source_specific",
        event_id=event_id,
        evidence_refs=(event_id,),
        reasoning="nginx HTTP 401 authentication_failure",
        detected_at=FIXED_NOW,
        capability_id=capability_id,
    )


def _make_correlation(
    *,
    capability_ids: tuple = (),
    detection_ids: tuple = (DETECTION_ID,),
) -> Correlation:
    return Correlation(
        correlation_id=CORRELATION_ID,
        pattern_id="NGINX-CORR-BRUTEFORCE-001",
        pattern_version=1,
        trigger="brute_force_count_threshold",
        key=CorrelationKey(parts=("198.51.100.7", "/api/login")),
        detection_ids=detection_ids,
        event_ids=(EVENT_ID,),
        window_start=FIXED_NOW - timedelta(seconds=60),
        window_end=FIXED_NOW,
        count=1,
        reasoning="brute-force clustering: 1 ...",
        correlated_at=FIXED_NOW,
        capability_ids=capability_ids,
    )


# --------------------------------------------------------------------- model
class TestDetectionCapabilityField:
    def test_defaults_to_empty(self) -> None:
        assert _make_detection().capability_id == ""

    def test_accepts_a_well_formed_capability_id(self) -> None:
        assert _make_detection(capability_id="cap-nginx").capability_id == "cap-nginx"

    def test_wire_renders_null_when_unstamped(self) -> None:
        assert _make_detection().to_dict()["capability_id"] is None

    def test_wire_renders_the_id_when_stamped(self) -> None:
        assert (
            _make_detection(capability_id="cap-nginx").to_dict()["capability_id"]
            == "cap-nginx"
        )

    @pytest.mark.parametrize("bad", ["nginx", "conn-nginx", "cap-", "cap-NGINX"])
    def test_rejects_malformed_capability_id(self, bad: str) -> None:
        with pytest.raises(Exception):
            _make_detection(capability_id=bad)

    def test_surrounding_whitespace_is_stripped(self) -> None:
        """``str_strip_whitespace=True`` on the model normalises padding."""
        assert _make_detection(capability_id=" cap-nginx ").capability_id == "cap-nginx"

    def test_capability_id_is_not_part_of_the_detection_id(self) -> None:
        """Detection-id determinism must be untouched by the new field."""
        a = _make_detection(capability_id="cap-nginx")
        b = _make_detection(capability_id="cap-simulator")
        c = _make_detection(capability_id="")
        assert a.detection_id == b.detection_id == c.detection_id


class TestCorrelationCapabilityIds:
    def test_defaults_to_empty_tuple(self) -> None:
        assert _make_correlation().capability_ids == ()

    def test_wire_renders_empty_list(self) -> None:
        assert _make_correlation().to_dict()["capability_ids"] == []

    def test_deduplicates_and_sorts(self) -> None:
        corr = _make_correlation(
            capability_ids=("cap-simulator", "cap-nginx", "cap-nginx")
        )
        assert corr.capability_ids == ("cap-nginx", "cap-simulator")

    def test_rejects_empty_items(self) -> None:
        """An empty item is rejected by the item pattern — the producer
        never emits one (it filters blanks before constructing)."""
        with pytest.raises(Exception):
            _make_correlation(capability_ids=("cap-nginx", ""))

    def test_rejects_malformed_ids(self) -> None:
        with pytest.raises(Exception):
            _make_correlation(capability_ids=("nginx",))

    def test_bound_is_enforced(self) -> None:
        with pytest.raises(Exception):
            _make_correlation(
                capability_ids=tuple(
                    f"cap-c{i}" for i in range(MAX_CORRELATION_CAPABILITIES + 1)
                )
            )


# ----------------------------------------------------------------- enrichment
class TestEnrichDetectionCapability:
    def test_stamps_the_events_derived_capability(self) -> None:
        enriched = enrich_detection(
            _make_detection(),
            _make_event(capability_id="cap-nginx"),
            now=FIXED_NOW,
        )
        assert enriched.capability_id == "cap-nginx"

    def test_event_without_derived_capability_leaves_it_empty(self) -> None:
        """No invention: an un-stamped event yields an un-stamped detection."""
        enriched = enrich_detection(
            _make_detection(), _make_event(capability_id=None), now=FIXED_NOW
        )
        assert enriched.capability_id == ""

    def test_no_event_leaves_it_empty(self) -> None:
        enriched = enrich_detection(_make_detection(), None, now=FIXED_NOW)
        assert enriched.capability_id == ""

    def test_input_is_not_mutated(self) -> None:
        det = _make_detection()
        enrich_detection(det, _make_event(capability_id="cap-nginx"), now=FIXED_NOW)
        assert det.capability_id == ""

    def test_detection_id_survives_enrichment(self) -> None:
        det = _make_detection()
        enriched = enrich_detection(
            det, _make_event(capability_id="cap-nginx"), now=FIXED_NOW
        )
        assert enriched.detection_id == det.detection_id

    def test_payload_cannot_forge_the_capability(self) -> None:
        """The capability comes from provenance, never from event details.

        A source-supplied ``details.capability_id`` must not influence the
        stamped value — the ingress is the only place that derives it.
        """
        event = _make_event(
            capability_id=None,
            details={
                "status_code": 401,
                "capability_id": "cap-simulator",
            },
        )
        enriched = enrich_detection(_make_detection(), event, now=FIXED_NOW)
        assert enriched.capability_id == ""


class TestEnrichCorrelationUnaffected:
    def test_capability_ids_survive_enrichment(self) -> None:
        corr = _make_correlation(capability_ids=("cap-nginx",))
        assert enrich_correlation(corr, now=FIXED_NOW).capability_ids == ("cap-nginx",)

    def test_correlation_id_survives_enrichment(self) -> None:
        corr = _make_correlation(capability_ids=("cap-nginx",))
        assert enrich_correlation(corr, now=FIXED_NOW).correlation_id == corr.correlation_id


# -------------------------------------------------------------------- schema
class TestValidatorAndIndexCoverage:
    def test_detections_validator_declares_capability_id(self) -> None:
        from app.persistence.detection_repository import DETECTIONS_VALIDATOR

        props = DETECTIONS_VALIDATOR["$jsonSchema"]["properties"]
        assert "capability_id" in props
        assert props["capability_id"]["bsonType"] == ["string", "null"]

    def test_correlations_validator_declares_capability_ids(self) -> None:
        from app.persistence.correlation_repository import CORRELATIONS_VALIDATOR

        props = CORRELATIONS_VALIDATOR["$jsonSchema"]["properties"]
        assert "capability_ids" in props
        assert props["capability_ids"]["bsonType"] == "array"
        assert props["capability_ids"]["maxItems"] == 16

    def test_detection_index_specs_include_capability_id(self) -> None:
        from app.persistence.detection_repository import (
            INDEX_SPECS as DET_INDEX_SPECS,
        )

        assert "det_capability_id" in {spec["name"] for spec in DET_INDEX_SPECS}

    def test_correlation_index_specs_include_capability_ids(self) -> None:
        from app.persistence.correlation_repository import (
            INDEX_SPECS as CORR_INDEX_SPECS,
        )

        assert "corr_capability_ids" in {spec["name"] for spec in CORR_INDEX_SPECS}


# ---------------------------------------------------------------- round-trip
class TestDocumentRoundTrip:
    def test_detection_none_round_trips_to_empty_string(self) -> None:
        from app.persistence.detection_repository import _document_to_detection

        doc: Dict[str, Any] = _make_detection(capability_id="cap-nginx").to_dict()
        doc["detected_at"] = FIXED_NOW
        doc["capability_id"] = None
        assert _document_to_detection(doc).capability_id == ""

    def test_detection_id_round_trips(self) -> None:
        from app.persistence.detection_repository import _document_to_detection

        doc: Dict[str, Any] = _make_detection(capability_id="cap-nginx").to_dict()
        doc["detected_at"] = FIXED_NOW
        assert _document_to_detection(doc).capability_id == "cap-nginx"

    def test_correlation_list_round_trips_to_tuple(self) -> None:
        from app.persistence.correlation_repository import _document_to_correlation

        doc: Dict[str, Any] = _make_correlation(capability_ids=("cap-nginx",)).to_dict()
        doc["window_start"] = FIXED_NOW
        doc["window_end"] = FIXED_NOW
        doc["correlated_at"] = FIXED_NOW
        doc["key"] = ["198.51.100.7", "/api/login"]
        assert _document_to_correlation(doc).capability_ids == ("cap-nginx",)

    def test_correlation_missing_capability_ids_defaults_empty(self) -> None:
        """Pre-5.2 rows (field absent entirely) must still load."""
        from app.persistence.correlation_repository import _document_to_correlation

        doc: Dict[str, Any] = _make_correlation().to_dict()
        doc.pop("capability_ids", None)
        doc["window_start"] = FIXED_NOW
        doc["window_end"] = FIXED_NOW
        doc["correlated_at"] = FIXED_NOW
        doc["key"] = ["198.51.100.7", "/api/login"]
        assert _document_to_correlation(doc).capability_ids == ()


# ------------------------------------------------------------------- pattern
class TestPatternDerivesCapabilityIds:
    """The brute-force pattern derives capability_ids from member detections."""

    @staticmethod
    def _det(det_id: str, event_id: str, capability_id: str) -> Detection:
        return Detection(
            detection_id=det_id,
            rule_id="NGINX-AUTH-FAILURE-001",
            rule_version=1,
            category="source_specific",
            event_id=event_id,
            evidence_refs=(event_id,),
            reasoning="nginx HTTP 401 authentication_failure",
            detected_at=FIXED_NOW,
            capability_id=capability_id,
        )

    @staticmethod
    def _run(dets: List[Detection]) -> List[Correlation]:
        from app.correlation.patterns import BruteForceClusteringPattern

        events = {
            eid: _make_event(event_id=eid, capability_id="cap-nginx")
            for eid in EVENT_IDS
        }
        return list(
            BruteForceClusteringPattern().group(
                detections=dets, events=events, now=FIXED_NOW
            )
        )

    @classmethod
    def _dets(cls, capability_ids: List[str]) -> List[Detection]:
        return [
            cls._det(
                f"det-01923456-7890-7abc-9def-00000000000{i + 1}",
                EVENT_IDS[i],
                capability_ids[i],
            )
            for i in range(len(EVENT_IDS))
        ]

    def test_single_capability_is_stamped(self) -> None:
        corrs = self._run(self._dets(["cap-nginx"] * 4))
        assert corrs
        assert all(c.capability_ids == ("cap-nginx",) for c in corrs)

    def test_mixed_capabilities_are_deduplicated_and_sorted(self) -> None:
        corrs = self._run(
            self._dets(["cap-nginx", "cap-simulator", "cap-nginx", "cap-nginx"])
        )
        assert corrs
        assert all(
            c.capability_ids == ("cap-nginx", "cap-simulator") for c in corrs
        )

    def test_unstamped_detections_produce_no_capability_ids(self) -> None:
        corrs = self._run(self._dets([""] * 4))
        assert corrs
        assert all(c.capability_ids == () for c in corrs)

    def test_correlation_id_is_unchanged_by_capability(self) -> None:
        stamped = self._run(self._dets(["cap-nginx"] * 4))
        unstamped = self._run(self._dets([""] * 4))
        assert {c.correlation_id for c in stamped} == {
            c.correlation_id for c in unstamped
        }
