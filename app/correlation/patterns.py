"""Correlation patterns: the documented, observed patterns
the correlation engine knows how to apply.

Reference: docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md
           (Sections 14-17, 87-91).

This module is the *pattern catalogue* for the correlation
engine. Each pattern is a small, well-documented, deterministic
function that consumes a sequence of per-event detections and
returns zero or more :class:`Correlation` records.

Design rules (documented in DETECTION_ENGINEERING Section 87-91)
----------------------------------------------------------------

* **Centralized.** A pattern lives here, not in any individual
  rule, connector, or per-event rule framework module. The
  pattern's only inputs are per-event detections; its only
  outputs are :class:`Correlation` records.
* **Deterministic.** A pattern is a pure function of its input
  detections. The engine injects ``now``; the pattern does not
  call ``datetime.now()``.
* **Evidence-only.** A pattern only groups detections whose
  evidence points back to a real :class:`SecurityEvent`. The
  engine injects the events alongside the detections.
* **No cross-source coupling without evidence.** A pattern must
  only require multiple sources when multiple sources of
  evidence actually exist. Cross-source patterns (WAF + NGINX,
  etc.) are intentionally **deferred** because the WAF,
  network, TLS, IAM, and rate-limiter connectors are not part
  of the MVP; inventing cross-source patterns would invent
  evidence.
* **Threshold-based, not statistical.** Every pattern is a
  documented count / time-window threshold. The engine does
  not use ML, AI, or statistical inference.
* **Fail-closed per pattern.** A pattern that raises during
  grouping is caught by the engine and routed into
  ``CorrelationResult.errors`` (mirroring the per-event
  detection engine's behaviour).

Why exactly one pattern in Phase 4.5
------------------------------------

The Phase 4.5 slice ships **one** correlation pattern:

* :class:`BruteForceClusteringPattern` — NGINX-observed
  authentication failures on the same auth-shaped endpoint
  from the same ``source_ip``, exceeding a documented count
  threshold within a documented time window.

This is the **only** pattern the observed MVP telemetry can
defensibly support today. Every other pattern would require
either:

* a second source of telemetry (WAF, rate-limiter, network,
  TLS, IAM) that does not exist in the MVP,
* a per-account correlation that the connectors do not yet
  reliably populate (``account.id`` is sparse in the Phase 4.3
  NGINX connector), or
* a geographic / ASN signal that ProShield does not model.

Cross-source and per-account patterns are explicitly
**deferred** to a later slice that ships the corresponding
connectors. Inventing them now would violate the documented
"do not invent evidence" rule.
"""
from __future__ import annotations

import abc
import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List, Sequence, Tuple

from ..detection.models import Detection
from ..detection.redact import redact_endpoint
from ..domain.security_event import SecurityEvent
from .errors import CorrelationWindowError
from .models import (
    Correlation,
    CorrelationKey,
    CorrelationTrigger,
    MAX_KEY_PART_LEN,
    validate_trigger,
)


# ============================================================================
# Pattern base
# ============================================================================
class CorrelationPattern(abc.ABC):
    """Abstract base for a single correlation pattern.

    A :class:`CorrelationPattern` is the correlation engine's
    equivalent of a per-event :class:`app.rules.rule.Rule`. It
    declares its identity (id + version), its applicability
    (which per-event detections it considers), and its
    grouping logic (how it turns the selected detections into
    :class:`Correlation` records).

    The engine constructs the catalogue of patterns once and
    iterates it deterministically. The pattern's grouping
    function is called with the pattern's selected detections
    plus the events they reference; the function is total (it
    may return an empty list, but it must not raise under
    normal operating conditions).
    """

    @property
    @abc.abstractmethod
    def pattern_id(self) -> str:
        """Stable, rule-shaped pattern id (e.g. ``NGINX-CORR-BRUTEFORCE-001``)."""

    @property
    @abc.abstractmethod
    def pattern_version(self) -> int:
        """Pattern version (monotonically increasing per pattern_id)."""

    @property
    @abc.abstractmethod
    def trigger(self) -> str:
        """The documented trigger string (one of
        :data:`app.correlation.models._ALLOWED_TRIGGERS`)."""

    @abc.abstractmethod
    def select(
        self,
        detections: Sequence[Detection],
        events: Dict[str, SecurityEvent],
    ) -> List[Detection]:
        """Return the subset of detections this pattern considers.

        The result is the input to :meth:`group`. Detections that
        do not match the pattern's applicability filter are
        ignored. The implementation must not raise; it returns an
        empty list if no detection is applicable.
        """

    @abc.abstractmethod
    def group(
        self,
        detections: Sequence[Detection],
        events: Dict[str, SecurityEvent],
        *,
        now: datetime,
    ) -> List[Correlation]:
        """Group the selected detections into zero or more correlations.

        Implementations must be deterministic: equal inputs and
        equal ``now`` must produce equal outputs. Implementations
        must be total: an empty input returns an empty list.
        Implementations must NOT raise under normal operating
        conditions; the engine catches unexpected exceptions and
        routes them to ``CorrelationResult.errors``.
        """


# ============================================================================
# Helper: deterministic correlation_id derivation
# ============================================================================
def _build_correlation_id(
    *,
    pattern_id: str,
    pattern_version: int,
    trigger: str,
    key_parts: Tuple[str, ...],
) -> str:
    """Build a deterministic ``corr-<uuidv7>`` correlation_id.

    The construction mirrors the per-event ``detection_id`` in
    :mod:`app.detection.engine`: SHA-256 of a stable
    concatenation, formatted as a UUIDv7 (RFC 9562) with the
    ``corr-`` prefix.

    Why deterministic: the same cluster signature always produces the
    same correlation_id, so re-running the same batch is replay-safe.

    V2-08 fix — **stable logical-cluster identity.** The digest is a
    pure function of the cluster *signature* (``pattern_id``,
    ``pattern_version``, ``trigger``, ``key_parts``) and deliberately
    NOT of the moving window bounds or the exact detection-id set.
    The previous construction folded ``window_start`` / ``window_end``
    / ``detection_ids`` into the digest, so a growing brute-force
    cluster produced a **new correlation_id (a new row, and a new
    case reference) every time another detection joined** — the
    proliferation the V2 audit measured (2 correlation rows for one
    logical cluster). With the signature-only digest a growing
    cluster keeps the *same* correlation_id; its evidence (window
    bounds, detection/event id sets) still grows on the single row
    via :meth:`CorrelationRepository.upsert_growth`.
    """
    blob = "|".join(
        [
            pattern_id,
            str(pattern_version),
            trigger,
            "|".join(key_parts),
        ]
    ).encode("utf-8")
    digest = hashlib.sha256(blob).digest()
    unix_ms = int.from_bytes(digest[0:6], "big") & ((1 << 48) - 1)
    b = bytearray(digest)
    b[6] = (b[6] & 0x0F) | 0x70
    b[8] = (b[8] & 0x3F) | 0x80
    b[0:6] = unix_ms.to_bytes(6, "big")
    hexstr = b.hex()
    canonical = (
        f"{hexstr[0:8]}-{hexstr[8:12]}-{hexstr[12:16]}-"
        f"{hexstr[16:20]}-{hexstr[20:32]}"
    )
    return f"corr-{canonical}"


# ============================================================================
# BruteForceClusteringPattern
# ============================================================================
DEFAULT_BRUTEFORCE_WINDOW = timedelta(minutes=5)
DEFAULT_BRUTEFORCE_THRESHOLD = 4

# The detection rule ids that count toward the brute-force count.
# ``NGINX-AUTH-FAILURE-001`` is the broad per-event rule; every
# NGINX 401 fires it. ``NGINX-AUTH-BRUTEFORCE-001`` is the
# auth-shaped-endpoint rule; every 401/403 on a login-shaped
# endpoint fires it. Both are documented as "candidate signals
# for brute force" in the per-event rules' docstrings. Including
# both is correct: the broad rule catches 401s on any endpoint
# the attacker might rotate through, and the auth-shaped rule
# catches the concentrated burst on a single login endpoint.
_BRUTEFORCE_RULE_IDS: frozenset[str] = frozenset(
    {
        "NGINX-AUTH-FAILURE-001",
        "NGINX-AUTH-BRUTEFORCE-001",
    }
)


@dataclass(frozen=True)
class BruteForceClusteringPattern(CorrelationPattern):
    """A documented correlation pattern for NGINX-observed
    authentication-failure bursts.

    See the long docstring in the Phase 4.5 report for the full
    contract (window, threshold, evidence retention, benign
    look-alikes, what makes a burst *not* correlate).

    Quick reference
    ---------------

    * ``pattern_id = "NGINX-CORR-BRUTEFORCE-001"``
    * ``pattern_version = 1``
    * ``trigger = "brute_force_count_threshold"``
    * Key: ``(source_ip, endpoint)``
    * Default window: 5 minutes
    * Default threshold: 4 detections

    The default window + threshold are conservative. The pattern
    is intentionally narrow: same source_ip, same endpoint, only
    auth-failure detections. Cross-source amplification and
    per-account correlation are deferred (see module docstring).
    """

    window: timedelta = DEFAULT_BRUTEFORCE_WINDOW
    threshold: int = DEFAULT_BRUTEFORCE_THRESHOLD

    # ----------------------------------------------------------------- identity
    @property
    def pattern_id(self) -> str:
        return "NGINX-CORR-BRUTEFORCE-001"

    @property
    def pattern_version(self) -> int:
        return 1

    @property
    def trigger(self) -> CorrelationTrigger:
        return "brute_force_count_threshold"

    # ----------------------------------------------------------------- public
    def select(
        self,
        detections: Sequence[Detection],
        events: Dict[str, SecurityEvent],
    ) -> List[Detection]:
        """Return auth-failure detections whose underlying event
        has both ``source_ip`` and ``endpoint``.

        Detections whose event is missing from the engine's
        event lookup, or whose event lacks the key fields, are
        silently skipped: the engine never invents a key.
        """
        out: List[Detection] = []
        for d in detections:
            if d.rule_id not in _BRUTEFORCE_RULE_IDS:
                continue
            ev = events.get(d.event_id)
            if ev is None:
                continue
            if ev.source_ip is None or ev.endpoint is None:
                continue
            if d.detected_at.tzinfo is None:
                continue
            out.append(d)
        return out

    def group(
        self,
        detections: Sequence[Detection],
        events: Dict[str, SecurityEvent],
        *,
        now: datetime,
    ) -> List[Correlation]:
        """Group the selected detections into correlations.

        See the class docstring for the full contract.
        """
        if self.window.total_seconds() <= 0:
            raise CorrelationWindowError(
                safe_message="brute-force window must be a positive duration",
                internal_detail=f"window={self.window}",
            )
        if self.threshold < 1:
            raise CorrelationWindowError(
                safe_message="brute-force threshold must be >= 1",
                internal_detail=f"threshold={self.threshold}",
            )

        groups: Dict[Tuple[str, str], Tuple[str, List[Detection]]] = {}
        for d in detections:
            ev = events.get(d.event_id)
            if ev is None:
                continue
            # The correlation key part is bounded by MAX_KEY_PART_LEN
            # (= 64).  ``redact_endpoint`` returns a string up to
            # ``MAX_REDACTED_ENDPOINT_LEN`` (= 128), so a long
            # endpoint would otherwise overflow the key.  We
            # truncate to 64 chars here (no suffix) so the key is
            # deterministic: two events whose endpoints share the
            # first 64 chars will collide in the same key, which
            # is the intended grouping for cross-event correlation.
            # The full 128-char redacted endpoint is still used in
            # the analyst-facing ``reasoning`` and in the
            # evidence: we only restrict the *key* namespace here.
            redacted = redact_endpoint(ev.endpoint)
            key_ep = redacted[:MAX_KEY_PART_LEN]
            key = (ev.source_ip, key_ep)
            # Group by key, but keep the full redacted endpoint
            # alongside so the analyst-facing ``reasoning`` is
            # built from the full redacted string (preserves
            # evidence for long endpoints).
            bucket = groups.setdefault(key, (redacted, []))
            bucket[1].append(d)

        out: List[Correlation] = []
        for (source_ip, endpoint_key), (full_endpoint, group_dets) in groups.items():
            sorted_dets = sorted(group_dets, key=lambda x: x.detected_at)
            n = len(sorted_dets)
            # CORRELATION-01: count DISTINCT events, not
            # detection rows. A single failed-login event may
            # trigger multiple rules (e.g. BRUTEFORCE-001 +
            # ACCOUNT-LOCKOUT-001) and would otherwise be
            # double-counted. The reported ``count`` is the
            # number of unique auth-failure events.
            distinct_event_ids: List[str] = list(
                dict.fromkeys(d.event_id for d in sorted_dets)
            )
            distinct_count = len(distinct_event_ids)
            if distinct_count < self.threshold:
                continue
            earliest = sorted_dets[0].detected_at
            latest = sorted_dets[-1].detected_at
            if (latest - earliest) > self.window:
                continue
            det_ids = tuple(sorted(d.detection_id for d in sorted_dets))
            ev_ids = tuple(distinct_event_ids)
            trigger = validate_trigger(self.trigger)
            correlation_id = _build_correlation_id(
                pattern_id=self.pattern_id,
                pattern_version=self.pattern_version,
                trigger=trigger,
                key_parts=(source_ip, endpoint_key),
            )
            correlation = Correlation(
                correlation_id=correlation_id,
                pattern_id=self.pattern_id,
                pattern_version=self.pattern_version,
                trigger=trigger,
                key=CorrelationKey(parts=(source_ip, endpoint_key)),
                detection_ids=det_ids,
                event_ids=ev_ids,
                window_start=earliest,
                window_end=latest,
                count=distinct_count,
                reasoning=self._build_reasoning(
                    source_ip=source_ip,
                    endpoint=full_endpoint,
                    count=distinct_count,
                    threshold=self.threshold,
                    window_seconds=int(self.window.total_seconds()),
                ),
                correlated_at=now,
                extra=(
                    ("threshold", self.threshold),
                    ("window_seconds", int(self.window.total_seconds())),
                    ("detection_count", n),
                ),
            )
            out.append(correlation)

        out.sort(key=lambda c: (c.key.parts[0], c.key.parts[1]))
        return out

    # ----------------------------------------------------------------- helpers
    @staticmethod
    def _build_reasoning(
        *,
        source_ip: str,
        endpoint: str,
        count: int,
        threshold: int,
        window_seconds: int,
    ) -> str:
        return (
            f"brute-force clustering: {count} authentication-failure "
            f"detections from source_ip={source_ip!r} targeting "
            f"endpoint={endpoint!r} exceeded the threshold of "
            f"{threshold} within a {window_seconds}-second window"
        )
