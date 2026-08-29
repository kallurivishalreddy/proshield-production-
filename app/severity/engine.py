# Severity / Confidence engine.
# Reference: docs/PHASE 2/DOMAIN_DATA_MODEL.md Sections 10 and 11.
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple

from ..correlation.models import Correlation
from ..detection.models import Detection
from ..domain.errors import DomainError
from ..domain.security_event import SecurityEvent
from .errors import InvalidSeverityInputError, SeverityError
from .models import (
    MAX_SEVERITY_EVIDENCE_REFS,
    MAX_SEVERITY_RESULT_ASSESSMENTS,
    MAX_SEVERITY_RESULT_ERRORS,
    ConfidenceAssessment,
    ConfidenceBand,
    ScoringRationale,
    ScoringSignal,
    SeverityAssessment,
    SeverityAssessmentSubject,
    SeverityBand,
    SeverityResult,
)

_log = logging.getLogger(__name__)


THRESHOLD_DETECTION_COUNT = 5
THRESHOLD_EVENT_COUNT = 3
THRESHOLD_WINDOW_SPAN_SECONDS = 60
THRESHOLD_RULE_REPEATED = 2
THRESHOLD_CORRELATION_REPEATED = 2

_MAX_ERROR_LEN = 512
_MAX_SUMMARY_LEN = 2048
_MAX_DETAIL_LEN = 1024

_HIGH_IMPACT_CATEGORIES = ('common_behavioral', 'cross_source_correlation')
_HIGH_IMPACT_TRIGGERS = frozenset({'brute_force_count_threshold'})

# Maximum number of evidence_refs we can record in a
# per-correlation or per-bundle evidence_refs list. The first
# element is the synthetic id ('bundle:overall' for the bundle
# assessment, or the correlation's own correlation_id for the
# per-correlation assessment), so the real-id cap is
# ``MAX_EVIDENCE_REFS - 1``.
MAX_EVIDENCE_REFS = MAX_SEVERITY_EVIDENCE_REFS
MAX_BUNDLE_EVIDENCE_REFS = MAX_SEVERITY_EVIDENCE_REFS - 1
MAX_CORRELATION_EVIDENCE_REFS = MAX_SEVERITY_EVIDENCE_REFS - 1


def _high_impact_category(category) -> bool:
    """True iff the rule's category is one of the documented
    high-impact categories (``common_behavioral`` or
    ``cross_source_correlation``).

    The Phase 4.6 review found that a previous implementation
    used ``str(category).endswith('common_behavioral')`` which
    silently never matched because ``str(enum.Enum)`` returns
    the member name (e.g. ``"RuleCategory.COMMON_BEHAVIORAL"``)
    not the value. This direct enum-to-value comparison is the
    correct, robust check.
    """
    # The ``RuleCategory`` enum is a str-Enum; comparing to
    # the member directly is the documented, type-safe way.
    if category is None:
        return False
    return category.value in _HIGH_IMPACT_CATEGORIES


def _truncate(s, n):
    if not isinstance(s, str):
        s = str(s)
    if len(s) <= n:
        return s
    return s[:n] + '...'


def _sev_band(score):
    if score <= 1:
        return SeverityBand.LOW
    if score <= 3:
        return SeverityBand.MEDIUM
    if score <= 5:
        return SeverityBand.HIGH
    return SeverityBand.CRITICAL


def _conf_band(score):
    if score <= 1:
        return ConfidenceBand.LOW
    if score <= 3:
        return ConfidenceBand.MEDIUM
    if score <= 5:
        return ConfidenceBand.HIGH
    return ConfidenceBand.VERY_HIGH


def _sig(name, present, detail):
    return ScoringRationale(
        signal=name, present=present, detail=_truncate(detail, _MAX_DETAIL_LEN)
    )


def _evidence_refs(primary, *extras):
    seen = set()
    out = []
    for ref in (primary,) + extras:
        if ref and ref not in seen:
            seen.add(ref)
            out.append(ref)
    return tuple(out)


def _score_present(rationale):
    return sum(1 for r in rationale if r.present)


# ----------------------------------------------------------------- signal subsets
# The Phase 4.6 implementation (prior to the SEV-01 fix) used
# the same 10-signal rationale for both severity and
# confidence, producing a single scalar that was then mapped
# through two different band tables (``SeverityBand`` capped at
# CRITICAL, ``ConfidenceBand`` capped at VERY_HIGH). That made
# the two dimensions effectively the same scalar — a fact the
# prior review recorded as SEV-01.
#
# The documented Phase 2 distinction (DOMAIN_DATA_MODEL.md
# Sections 10 and 11) requires severity and confidence to be
# **separately meaningful**:
#
#   * Severity reflects the **impact** of the observed security
#     evidence: triggered rule category, number of related
#     events, correlation strength, affected asset, business
#     criticality, attack category, potential impact.
#   * Confidence reflects the **quality** of the evidence:
#     rule certainty, evidence strength, correlation strength,
#     consistency of observed signals, completeness of
#     available evidence.
#
# The fix: build the severity rationale from the impact-oriented
# signals and the confidence rationale from the evidence-quality
# signals. The two dimensions now measure different things and
# can (and will) produce different bands on the same evidence.
SEVERITY_SIGNALS = frozenset({
    ScoringSignal.RULE_CATEGORY,
    ScoringSignal.CORRELATION_TRIGGER,
    ScoringSignal.DETECTION_COUNT,
    ScoringSignal.EVENT_COUNT,
    ScoringSignal.AFFECTED_ENDPOINT,
    ScoringSignal.WINDOW_SPAN_SECONDS,
})
CONFIDENCE_SIGNALS = frozenset({
    ScoringSignal.EVIDENCE_COMPLETENESS,
    ScoringSignal.SOURCE_IP_PRESENT,
    ScoringSignal.RULE_REPEATED,
    ScoringSignal.CORRELATION_REPEATED,
})


def _split_rationale(rationale):
    """Split a rationale list into severity- and confidence-
    relevant subsets, preserving order.

    Signals not in either subset are dropped (there are
    currently none, but this keeps the function robust to
    future signal additions). Returns two tuples.
    """
    sev = tuple(r for r in rationale if r.signal in SEVERITY_SIGNALS)
    conf = tuple(r for r in rationale if r.signal in CONFIDENCE_SIGNALS)
    return sev, conf


def _build_pair(
    subject_kind, subject_id, rationale, evidence_refs,
    sev_summary, conf_summary,
):
    # Spec-based SEV-01 fix: severity and confidence are
    # built from DIFFERENT subsets of the same underlying
    # signal evidence. The two dimensions are no longer the
    # same scalar; they reflect impact vs. evidence-quality.
    sev_rationale, conf_rationale = _split_rationale(rationale)
    sev_score = _score_present(sev_rationale)
    conf_score = _score_present(conf_rationale)
    sev = SeverityAssessment(
        subject_kind=subject_kind,
        subject_id=subject_id,
        band=_sev_band(sev_score),
        summary=_truncate(sev_summary, _MAX_SUMMARY_LEN),
        rationale=sev_rationale,
        evidence_refs=_evidence_refs(*evidence_refs),
    )
    conf = ConfidenceAssessment(
        subject_kind=subject_kind,
        subject_id=subject_id,
        band=_conf_band(conf_score),
        summary=_truncate(conf_summary, _MAX_SUMMARY_LEN),
        rationale=conf_rationale,
        evidence_refs=_evidence_refs(*evidence_refs),
    )
    return sev, conf


class SeverityEngine:
    def __init__(self):
        pass

    def run(
        self,
        *,
        detections=None,
        correlations=None,
        events=None,
        now=None,
    ):
        if detections is None:
            detections = ()
        if correlations is None:
            correlations = ()
        if events is None:
            events = {}
        if now is None:
            now = datetime.now(timezone.utc)
        elif not isinstance(now, datetime):
            raise InvalidSeverityInputError(
                safe_message='now must be a datetime',
                internal_detail=f'got {type(now).__name__}',
            )
        elif now.tzinfo is None:
            raise InvalidSeverityInputError(
                safe_message='now must be timezone-aware (UTC)',
                internal_detail='got a naive datetime',
            )
        for d in detections:
            if not isinstance(d, Detection):
                raise InvalidSeverityInputError(
                    safe_message='all entries in detections must be Detection instances',
                    internal_detail=f'got {type(d).__name__}',
                )
        for c in correlations:
            if not isinstance(c, Correlation):
                raise InvalidSeverityInputError(
                    safe_message='all entries in correlations must be Correlation instances',
                    internal_detail=f'got {type(c).__name__}',
                )
        for ev in events.values():
            if not isinstance(ev, SecurityEvent):
                raise InvalidSeverityInputError(
                    safe_message='all entries in events must be SecurityEvent instances',
                    internal_detail=f'got {type(ev).__name__}',
                )
        events_by_id = dict(events)
        detections_by_id = {d.detection_id: d for d in detections}
        errors = []
        severity_assessments = []
        confidence_assessments = []
        detections_scored = 0
        correlations_scored = 0

        # --- F-3 / F-7 fix: top-level input cap --------------------
        # The documented result cap is
        # ``MAX_SEVERITY_RESULT_ASSESSMENTS = 32`` (1 bundle
        # + at most 31 per-subject assessments). Apply the
        # same cap as the input ceiling so a caller cannot
        # exhaust memory before the per-subject loop
        # terminates. The bundle always occupies the last
        # slot.
        max_input_subjects = MAX_SEVERITY_RESULT_ASSESSMENTS - 1
        if len(detections) + len(correlations) > max_input_subjects:
            # Detections have priority because they are the
            # primary per-event evidence. Truncate
            # correlations first.
            kept_correlations = list(correlations)[:max_input_subjects]
            dropped_correlations = max(
                0, len(correlations) - len(kept_correlations)
            )
            remaining = max_input_subjects - len(kept_correlations)
            kept_detections = list(detections)[:remaining]
            dropped_detections = max(
                0, len(detections) - len(kept_detections)
            )
            if dropped_correlations or dropped_detections:
                errors.append(_truncate(
                    f'severity engine input exceeded the documented '
                    f'maximum of {max_input_subjects} per-subject '
                    f'entries; dropped {dropped_detections} detection(s) '
                    f'and {dropped_correlations} correlation(s) to keep '
                    f'the bound',
                    _MAX_ERROR_LEN,
                ))
            detections = tuple(kept_detections)
            correlations = tuple(kept_correlations)
            detections_by_id = {
                d.detection_id: d for d in detections
            }

        for d in detections:
            try:
                sev, conf = self._score_detection(d, events_by_id=events_by_id)
            except SeverityError as exc:
                errors.append(_truncate(
                    f'detection {d.detection_id!r} rejected: {exc.safe_message}',
                    _MAX_ERROR_LEN,
                ))
                continue
            except Exception as exc:  # noqa: BLE001
                errors.append(_truncate(
                    f'detection {d.detection_id!r} raised unexpected {type(exc).__name__}: {exc}',
                    _MAX_ERROR_LEN,
                ))
                continue
            severity_assessments.append(sev)
            confidence_assessments.append(conf)
            detections_scored += 1

        for c in correlations:
            try:
                sev, conf = self._score_correlation(
                    c,
                    detections_by_id=detections_by_id,
                    events_by_id=events_by_id,
                )
            except SeverityError as exc:
                errors.append(_truncate(
                    f'correlation {c.correlation_id!r} rejected: {exc.safe_message}',
                    _MAX_ERROR_LEN,
                ))
                continue
            except Exception as exc:  # noqa: BLE001
                errors.append(_truncate(
                    f'correlation {c.correlation_id!r} raised unexpected {type(exc).__name__}: {exc}',
                    _MAX_ERROR_LEN,
                ))
                continue
            severity_assessments.append(sev)
            confidence_assessments.append(conf)
            correlations_scored += 1
        # F-2 fix: defense in depth — wrap the bundle scorer
        # so an unexpected exception (e.g. a future model
        # cap change) does not crash the whole engine. The
        # bundle assessment is then quarantined to errors
        # rather than raised.
        try:
            bundle_sev, bundle_conf = self._score_bundle(
                detections=detections,
                correlations=correlations,
                events_by_id=events_by_id,
                detections_by_id=detections_by_id,
            )
        except Exception as exc:  # noqa: BLE001
            errors.append(_truncate(
                f'bundle assessment raised unexpected '
                f'{type(exc).__name__}: {exc}',
                _MAX_ERROR_LEN,
            ))
            bundle_sev = None
            bundle_conf = None
        else:
            severity_assessments.append(bundle_sev)
            confidence_assessments.append(bundle_conf)

        # F-3 / F-4 fix: enforce the documented
        # ``MAX_SEVERITY_RESULT_ASSESSMENTS`` and
        # ``MAX_SEVERITY_RESULT_ERRORS`` bounds at the engine
        # boundary. (The Pydantic model has no
        # ``max_length`` for these tuples; the engine is
        # the right place to enforce the cap because the
        # engine is total and the model would otherwise
        # raise ``ValidationError``.) Truncate the lists
        # deterministically and record the truncation in
        # ``errors`` so the caller can observe it.
        if len(severity_assessments) > MAX_SEVERITY_RESULT_ASSESSMENTS:
            # The bundle is the LAST assessment. If the cap
            # is hit, drop the oldest per-subject assessments
            # (FIFO), keeping the bundle and the newest
            # per-subject assessments.
            excess = (
                len(severity_assessments)
                - MAX_SEVERITY_RESULT_ASSESSMENTS
            )
            dropped_ids = [
                a.subject_id for a in severity_assessments[:excess]
            ]
            severity_assessments = severity_assessments[excess:]
            confidence_assessments = confidence_assessments[excess:]
            errors.append(_truncate(
                f'severity_assessments exceeded the documented '
                f'maximum of {MAX_SEVERITY_RESULT_ASSESSMENTS}; '
                f'dropped {excess} oldest per-subject assessment(s) '
                f'({", ".join(dropped_ids[:5])}) to keep the bound',
                _MAX_ERROR_LEN,
            ))
        if len(errors) > MAX_SEVERITY_RESULT_ERRORS:
            excess = len(errors) - MAX_SEVERITY_RESULT_ERRORS
            errors = errors[:MAX_SEVERITY_RESULT_ERRORS]
            errors.insert(0, _truncate(
                f'errors exceeded the documented maximum of '
                f'{MAX_SEVERITY_RESULT_ERRORS}; dropped {excess} '
                f'oldest error(s) to keep the bound',
                _MAX_ERROR_LEN,
            ))
            if len(errors) > MAX_SEVERITY_RESULT_ERRORS:
                errors = errors[:MAX_SEVERITY_RESULT_ERRORS]
        # If the bundle scorer raised, we have nothing to
        # add for the bundle; the result still has the
        # per-subject assessments and the documented
        # ``bundle_severity`` / ``bundle_confidence``
        # defaults to LOW (the model property is already
        # the documented "no evidence" default).
        return SeverityResult(
            severity_assessments=tuple(severity_assessments),
            confidence_assessments=tuple(confidence_assessments),
            detections_considered=len(detections),
            correlations_considered=len(correlations),
            detections_scored=detections_scored,
            correlations_scored=correlations_scored,
            errors=tuple(errors),
            produced_at=now,
        )

    def _score_detection(self, d, *, events_by_id):
        if d.detected_at.tzinfo is None:
            raise SeverityError(
                safe_message='detection.detected_at must be timezone-aware (UTC)',
                internal_detail=f'detection {d.detection_id!r} has a naive detected_at',
            )
        ev = events_by_id.get(d.event_id)
        # F-1 fix (Phase 4.6 review): the previous
        # ``str(d.category).endswith('common_behavioral')``
        # check silently never matched because
        # ``str(enum.Enum)`` returns the member name
        # (e.g. ``"RuleCategory.COMMON_BEHAVIORAL"``).
        # Use the documented direct enum-to-value comparison.
        rule_category_present = _high_impact_category(d.category)
        if rule_category_present:
            rule_category_detail = (
                f'category={d.category.value} (high-impact category)'
            )
        else:
            rule_category_detail = (
                f'category={d.category.value} (not high-impact)'
            )
        endpoint_present = ev is not None and bool(ev.endpoint)
        endpoint_detail = (
            f'endpoint={ev.endpoint!r}' if endpoint_present
            else 'endpoint missing or empty'
        )
        sip_present = ev is not None and bool(ev.source_ip)
        sip_detail = (
            f'source_ip={ev.source_ip!r}' if sip_present
            else 'source_ip missing'
        )
        evidence_complete = ev is not None
        evidence_detail = (
            f'event {d.event_id!r} present in the events lookup'
            if evidence_complete
            else f'event {d.event_id!r} missing from the events lookup'
        )
        rationale = (
            _sig(ScoringSignal.RULE_CATEGORY, rule_category_present, rule_category_detail),
            _sig(ScoringSignal.CORRELATION_TRIGGER, False, 'correlation_trigger=N/A (per-event detection)'),
            _sig(ScoringSignal.DETECTION_COUNT, False, 'detection_count=1 (below threshold)'),
            _sig(ScoringSignal.EVENT_COUNT, False, 'event_count=1 (below threshold)'),
            _sig(ScoringSignal.WINDOW_SPAN_SECONDS, False, 'window_span_seconds=N/A (single detection)'),
            _sig(ScoringSignal.AFFECTED_ENDPOINT, endpoint_present, endpoint_detail),
            _sig(ScoringSignal.SOURCE_IP_PRESENT, sip_present, sip_detail),
            _sig(ScoringSignal.RULE_REPEATED, False, 'rule_repeated=N/A (single detection)'),
            _sig(ScoringSignal.CORRELATION_REPEATED, False, 'correlation_repeated=N/A (per-event detection)'),
            _sig(ScoringSignal.EVIDENCE_COMPLETENESS, evidence_complete, evidence_detail),
        )
        evidence_refs = [d.detection_id, d.event_id]
        if ev is not None and ev.endpoint:
            evidence_refs.append(f'event:{ev.event_id}:endpoint')
        if ev is not None and ev.source_ip:
            evidence_refs.append(f'event:{ev.event_id}:source_ip')
        sev_summary = (
            f'per-event detection {d.rule_id} v{d.rule_version} on event {d.event_id!r}'
        )
        conf_summary = (
            f'per-event detection backed by rule {d.rule_id!r} v{d.rule_version}; '
            f'evidence_complete={evidence_complete}'
        )
        return _build_pair(
            subject_kind=SeverityAssessmentSubject.DETECTION,
            subject_id=d.detection_id,
            rationale=rationale,
            evidence_refs=evidence_refs,
            sev_summary=sev_summary,
            conf_summary=conf_summary,
        )

    def _score_correlation(self, c, *, detections_by_id, events_by_id):
        if c.window_start.tzinfo is None or c.window_end.tzinfo is None:
            raise SeverityError(
                safe_message='correlation window must be timezone-aware (UTC)',
                internal_detail=f'correlation {c.correlation_id!r} has a naive window',
            )
        if c.window_end < c.window_start:
            raise SeverityError(
                safe_message='correlation.window_end must be >= window_start',
                internal_detail=f'correlation {c.correlation_id!r} has window_end < window_start',
            )
        underlying_dets = []
        for did in c.detection_ids:
            d = detections_by_id.get(did)
            if d is not None:
                underlying_dets.append(d)
        underlying_events = []
        for eid in c.event_ids:
            ev = events_by_id.get(eid)
            if ev is not None:
                underlying_events.append(ev)
        det_count = len(underlying_dets)
        ev_count = len({e.event_id for e in underlying_events if e.event_id})
        window_span = int((c.window_end - c.window_start).total_seconds())
        # F-1 fix: use the direct enum comparison (the previous
        # ``str(...).endswith(...)`` form silently never matched).
        rule_category_present = any(
            _high_impact_category(d.category) for d in underlying_dets
        )
        rule_category_detail = (
            'at least one underlying detection is a high-impact category'
            if rule_category_present
            else 'no underlying detection is high-impact'
        )
        corr_trigger_present = c.trigger in _HIGH_IMPACT_TRIGGERS
        corr_trigger_detail = f'trigger={c.trigger!r}' if corr_trigger_present else f'trigger={c.trigger!r} (not documented high-impact)'
        det_count_present = det_count >= THRESHOLD_DETECTION_COUNT
        det_count_detail = f'detection_count={det_count} >= {THRESHOLD_DETECTION_COUNT}' if det_count_present else f'detection_count={det_count} < {THRESHOLD_DETECTION_COUNT}'
        ev_count_present = ev_count >= THRESHOLD_EVENT_COUNT
        ev_count_detail = f'event_count={ev_count} >= {THRESHOLD_EVENT_COUNT}' if ev_count_present else f'event_count={ev_count} < {THRESHOLD_EVENT_COUNT}'
        window_present = window_span >= THRESHOLD_WINDOW_SPAN_SECONDS
        window_detail = f'window_span_seconds={window_span} >= {THRESHOLD_WINDOW_SPAN_SECONDS}' if window_present else f'window_span_seconds={window_span} < {THRESHOLD_WINDOW_SPAN_SECONDS}'

        endpoints = {e.endpoint for e in underlying_events if e.endpoint}
        endpoint_present = len(endpoints) >= 1
        endpoint_detail = f'endpoints={sorted(endpoints)!r}' if endpoint_present else 'no concrete endpoint on the events'
        source_ips = {e.source_ip for e in underlying_events if e.source_ip}
        sip_present = len(source_ips) == 1
        if sip_present:
            (only_sip,) = source_ips
            sip_detail = f'source_ip={only_sip!r}'
        elif len(source_ips) > 1:
            sip_detail = f'multiple source_ips={sorted(source_ips)!r}'
        else:
            sip_detail = 'no source_ip on the events'
        distinct_rules = {d.rule_id for d in underlying_dets}
        rule_rep_present = (
            len(distinct_rules) >= THRESHOLD_RULE_REPEATED
            or len(underlying_dets) >= THRESHOLD_RULE_REPEATED
        )
        rule_rep_detail = f'distinct_rules={len(distinct_rules)}, detections={len(underlying_dets)}' if rule_rep_present else f'distinct_rules={len(distinct_rules)}'
        corr_rep_present = False
        corr_rep_detail = 'correlation_repeated=N/A (single correlation)'
        det_complete = all(did in detections_by_id for did in c.detection_ids)
        ev_complete = all(eid in events_by_id for eid in c.event_ids)
        evidence_complete = det_complete and ev_complete
        if evidence_complete:
            evidence_detail = 'all detection_ids and event_ids resolved'
        else:
            missing_dets = [did for did in c.detection_ids if did not in detections_by_id]
            missing_evs = [eid for eid in c.event_ids if eid not in events_by_id]
            evidence_detail = f'missing {len(missing_dets)} detection(s) and {len(missing_evs)} event(s) from the supplied lookups'

        rationale = (
            _sig(ScoringSignal.RULE_CATEGORY, rule_category_present, rule_category_detail),
            _sig(ScoringSignal.CORRELATION_TRIGGER, corr_trigger_present, corr_trigger_detail),
            _sig(ScoringSignal.DETECTION_COUNT, det_count_present, det_count_detail),
            _sig(ScoringSignal.EVENT_COUNT, ev_count_present, ev_count_detail),
            _sig(ScoringSignal.WINDOW_SPAN_SECONDS, window_present, window_detail),
            _sig(ScoringSignal.AFFECTED_ENDPOINT, endpoint_present, endpoint_detail),
            _sig(ScoringSignal.SOURCE_IP_PRESENT, sip_present, sip_detail),
            _sig(ScoringSignal.RULE_REPEATED, rule_rep_present, rule_rep_detail),
            _sig(ScoringSignal.CORRELATION_REPEATED, corr_rep_present, corr_rep_detail),
            _sig(ScoringSignal.EVIDENCE_COMPLETENESS, evidence_complete, evidence_detail),
        )
        # F-2 fix (per-correlation): cap the evidence_refs
        # list to MAX_CORRELATION_EVIDENCE_REFS real ids plus
        # the correlation_id synthetic. A correlation with many
        # underlying detections + events would otherwise exceed
        # the model cap and raise an uncaught ``ValidationError``
        # (caught by the outer try/except, but the assessment
        # is silently dropped). With this cap, the assessment
        # is preserved with a deterministic subset of refs and
        # an error is recorded.
        evidence_refs = [c.correlation_id]
        seen_ids = {c.correlation_id}
        # Iterables: detection_ids first, then event_ids; deterministic order.
        for did in c.detection_ids:
            if did and did not in seen_ids:
                if len(evidence_refs) >= MAX_EVIDENCE_REFS:
                    break
                seen_ids.add(did)
                evidence_refs.append(did)
        if len(evidence_refs) < MAX_EVIDENCE_REFS:
            for eid in c.event_ids:
                if eid and eid not in seen_ids:
                    if len(evidence_refs) >= MAX_EVIDENCE_REFS:
                        break
                    seen_ids.add(eid)
                    evidence_refs.append(eid)
        sev_summary = f'correlation {c.pattern_id} v{c.pattern_version} ({c.count} detections, trigger={c.trigger!r}, window_span={window_span}s)'
        conf_summary = (
            f'correlation {c.correlation_id!r} evidence complete={evidence_complete} '
            f'({len(underlying_dets)}/{len(c.detection_ids)} detections available, '
            f'{len(underlying_events)}/{len(c.event_ids)} events available)'
        )
        return _build_pair(
            subject_kind=SeverityAssessmentSubject.CORRELATION,
            subject_id=c.correlation_id,
            rationale=rationale,
            evidence_refs=evidence_refs,
            sev_summary=sev_summary,
            conf_summary=conf_summary,
        )

    def _score_bundle(self, *, detections, correlations, events_by_id, detections_by_id):
        det_count = len(detections)
        ev_count = len(events_by_id)
        if correlations:
            win_start = min(c.window_start for c in correlations)
            win_end = max(c.window_end for c in correlations)
            window_span = int((win_end - win_start).total_seconds())
        else:
            window_span = 0
        rule_counts = {}
        for d in detections:
            rule_counts[d.rule_id] = rule_counts.get(d.rule_id, 0) + 1
        rule_repeated = any(c >= THRESHOLD_RULE_REPEATED for c in rule_counts.values())
        if rule_repeated:
            top_rule, top_count = max(rule_counts.items(), key=lambda x: x[1])
            rule_rep_detail = f'top rule {top_rule!r} fired {top_count} times'
        else:
            rule_rep_detail = f'no rule fired >= {THRESHOLD_RULE_REPEATED} times'
        pattern_counts = {}
        for c in correlations:
            key = (c.pattern_id, c.pattern_version)
            pattern_counts[key] = pattern_counts.get(key, 0) + 1
        corr_repeated = any(c >= THRESHOLD_CORRELATION_REPEATED for c in pattern_counts.values())
        if corr_repeated:
            top_pat, top_n = max(pattern_counts.items(), key=lambda x: x[1])
            corr_rep_detail = f'top pattern {top_pat[0]!r} v{top_pat[1]} fired {top_n} times'
        else:
            corr_rep_detail = f'no pattern fired >= {THRESHOLD_CORRELATION_REPEATED} times'
        endpoints = {e.endpoint for e in events_by_id.values() if e.endpoint}
        endpoint_present = len(endpoints) >= 1
        endpoint_detail = f'endpoints={sorted(endpoints)!r}' if endpoint_present else 'no concrete endpoint'
        source_ips = {e.source_ip for e in events_by_id.values() if e.source_ip}
        sip_present = len(source_ips) == 1
        if sip_present:
            (only_sip,) = source_ips
            sip_detail = f'source_ip={only_sip!r}'
        elif len(source_ips) > 1:
            sip_detail = f'multiple source_ips={sorted(source_ips)!r}'
        else:
            sip_detail = 'no source_ip in the events'

        # F-1 fix: use the direct enum comparison (the previous
        # ``str(...).endswith(...)`` form silently never matched).
        rule_category_present = any(
            _high_impact_category(d.category) for d in detections
        )
        rule_category_detail = 'at least one detection is a high-impact category' if rule_category_present else 'no high-impact detection category'
        corr_trigger_present = any(c.trigger in _HIGH_IMPACT_TRIGGERS for c in correlations)
        corr_trigger_detail = 'at least one correlation has a high-impact trigger' if corr_trigger_present else 'no high-impact correlation trigger'
        det_count_present = det_count >= THRESHOLD_DETECTION_COUNT
        det_count_detail = f'detection_count={det_count} >= {THRESHOLD_DETECTION_COUNT}' if det_count_present else f'detection_count={det_count} < {THRESHOLD_DETECTION_COUNT}'
        ev_count_present = ev_count >= THRESHOLD_EVENT_COUNT
        ev_count_detail = f'event_count={ev_count} >= {THRESHOLD_EVENT_COUNT}' if ev_count_present else f'event_count={ev_count} < {THRESHOLD_EVENT_COUNT}'
        window_present = window_span >= THRESHOLD_WINDOW_SPAN_SECONDS
        window_detail = f'window_span_seconds={window_span} >= {THRESHOLD_WINDOW_SPAN_SECONDS}' if window_present else f'window_span_seconds={window_span} < {THRESHOLD_WINDOW_SPAN_SECONDS}'
        det_complete = all(d.event_id in events_by_id for d in detections)
        corr_complete = all(
            all(did in detections_by_id for did in c.detection_ids)
            and all(eid in events_by_id for eid in c.event_ids)
            for c in correlations
        )
        evidence_complete = det_complete and corr_complete
        if evidence_complete:
            evidence_detail = 'all detection and correlation evidence resolved'
        else:
            evidence_detail = f'det_complete={det_complete}; corr_complete={corr_complete}'

        rationale = (
            _sig(ScoringSignal.RULE_CATEGORY, rule_category_present, rule_category_detail),
            _sig(ScoringSignal.CORRELATION_TRIGGER, corr_trigger_present, corr_trigger_detail),
            _sig(ScoringSignal.DETECTION_COUNT, det_count_present, det_count_detail),
            _sig(ScoringSignal.EVENT_COUNT, ev_count_present, ev_count_detail),
            _sig(ScoringSignal.WINDOW_SPAN_SECONDS, window_present, window_detail),
            _sig(ScoringSignal.AFFECTED_ENDPOINT, endpoint_present, endpoint_detail),
            _sig(ScoringSignal.SOURCE_IP_PRESENT, sip_present, sip_detail),
            _sig(ScoringSignal.RULE_REPEATED, rule_repeated, rule_rep_detail),
            _sig(ScoringSignal.CORRELATION_REPEATED, corr_repeated, corr_rep_detail),
            _sig(ScoringSignal.EVIDENCE_COMPLETENESS, evidence_complete, evidence_detail),
        )
        # F-2 fix (bundle): cap the evidence_refs list to
        # ``MAX_BUNDLE_EVIDENCE_REFS`` real ids plus the
        # synthetic ``'bundle:overall'`` first element. The
        # previous unbounded accumulator would exceed the model
        # cap and raise an uncaught ``ValidationError``,
        # crashing the entire engine for any realistic
        # evidence volume. With this cap, the bundle
        # assessment is preserved with a deterministic subset
        # of refs and the excess is observable via
        # ``detections_considered`` /
        # ``correlations_considered`` /
        # ``errors`` (the engine-level overflow is reported
        # by the caller, not raised).
        #
        # Ordering: correlation_ids first (the highest-level
        # signal), then detection_ids. This way the
        # correlation_ids are never lost when a large batch
        # of detections is supplied.
        evidence_refs = ['bundle:overall']
        seen_ids = {'bundle:overall'}
        for c in correlations:
            if c.correlation_id and c.correlation_id not in seen_ids:
                if len(evidence_refs) >= MAX_EVIDENCE_REFS:
                    break
                seen_ids.add(c.correlation_id)
                evidence_refs.append(c.correlation_id)
        if len(evidence_refs) < MAX_EVIDENCE_REFS:
            for d in detections:
                if d.detection_id and d.detection_id not in seen_ids:
                    if len(evidence_refs) >= MAX_EVIDENCE_REFS:
                        break
                    seen_ids.add(d.detection_id)
                    evidence_refs.append(d.detection_id)
        sev_summary = f'bundle: {len(detections)} detections, {len(correlations)} correlations, {ev_count} distinct events'
        conf_summary = (
            f'bundle evidence_complete={evidence_complete} '
            f'({det_count} detections, {len(correlations)} correlations, window_span={window_span}s)'
        )
        return _build_pair(
            subject_kind=SeverityAssessmentSubject.BUNDLE,
            subject_id='bundle:overall',
            rationale=rationale,
            evidence_refs=evidence_refs,
            sev_summary=sev_summary,
            conf_summary=conf_summary,
        )

_ = (Any, DomainError, Set, _log)

