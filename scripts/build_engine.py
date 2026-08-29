"""Build app/severity/engine.py as a single concatenated string.

We avoid triple-quoted strings inside this script by building
each section as a list of single-line strings, then joining
them. The output file may contain triple-quoted strings
(docstrings), but the build script itself never does.
"""
from __future__ import annotations

import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGET = os.path.join(ROOT, "app", "severity", "engine.py")

# Each section is a list[str] of single-line code lines.
SECTIONS = []


def add(*lines):
    SECTIONS.append(list(lines))


# ---------------------------------------------------------------- header
add(
    "# Severity / Confidence engine.",
    "# Reference: docs/PHASE 2/DOMAIN_DATA_MODEL.md Sections 10 and 11.",
    "from __future__ import annotations",
    "",
    "import logging",
    "from datetime import datetime, timezone",
    "from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple",
    "",
    "from ..correlation.models import Correlation",
    "from ..detection.models import Detection",
    "from ..domain.errors import DomainError",
    "from ..domain.security_event import SecurityEvent",
    "from .errors import InvalidSeverityInputError, SeverityError",
    "from .models import (",
    "    ConfidenceAssessment,",
    "    ConfidenceBand,",
    "    ScoringRationale,",
    "    ScoringSignal,",
    "    SeverityAssessment,",
    "    SeverityAssessmentSubject,",
    "    SeverityBand,",
    "    SeverityResult,",
    ")",
    "",
    "_log = logging.getLogger(__name__)",
    "",
)


# Documented thresholds and module-level constants.
add(
    "THRESHOLD_DETECTION_COUNT = 5",
    "THRESHOLD_EVENT_COUNT = 3",
    "THRESHOLD_WINDOW_SPAN_SECONDS = 60",
    "THRESHOLD_RULE_REPEATED = 2",
    "THRESHOLD_CORRELATION_REPEATED = 2",
    "",
    "_MAX_ERROR_LEN = 512",
    "_MAX_SUMMARY_LEN = 2048",
    "_MAX_DETAIL_LEN = 1024",
    "",
    "_HIGH_IMPACT_CATEGORIES = ('common_behavioral', 'cross_source_correlation')",
    "_HIGH_IMPACT_TRIGGERS = frozenset({'brute_force_count_threshold'})",
    "",
)
print("section 1 added")


# Helper functions.
add(
    "def _truncate(s, n):",
    "    if not isinstance(s, str):",
    "        s = str(s)",
    "    if len(s) <= n:",
    "        return s",
    "    return s[:n] + '...'",
    "",
    "",
    "def _sev_band(score):",
    "    if score <= 1:",
    "        return SeverityBand.LOW",
    "    if score <= 3:",
    "        return SeverityBand.MEDIUM",
    "    if score <= 5:",
    "        return SeverityBand.HIGH",
    "    return SeverityBand.CRITICAL",
    "",
    "",
    "def _conf_band(score):",
    "    if score <= 1:",
    "        return ConfidenceBand.LOW",
    "    if score <= 3:",
    "        return ConfidenceBand.MEDIUM",
    "    if score <= 5:",
    "        return ConfidenceBand.HIGH",
    "    return ConfidenceBand.VERY_HIGH",
    "",
    "",
    "def _sig(name, present, detail):",
    "    return ScoringRationale(",
    "        signal=name, present=present, detail=_truncate(detail, _MAX_DETAIL_LEN)",
    "    )",
    "",
    "",
    "def _evidence_refs(primary, *extras):",
    "    seen = set()",
    "    out = []",
    "    for ref in (primary,) + extras:",
    "        if ref and ref not in seen:",
    "            seen.add(ref)",
    "            out.append(ref)",
    "    return tuple(out)",
    "",
    "",
    "def _score_present(rationale):",
    "    return sum(1 for r in rationale if r.present)",
    "",
    "",
    "def _build_pair(subject_kind, subject_id, rationale, evidence_refs, sev_summary, conf_summary):",
    "    score = _score_present(rationale)",
    "    sev = SeverityAssessment(",
    "        subject_kind=subject_kind,",
    "        subject_id=subject_id,",
    "        band=_sev_band(score),",
    "        summary=_truncate(sev_summary, _MAX_SUMMARY_LEN),",
    "        rationale=tuple(rationale),",
    "        evidence_refs=_evidence_refs(*evidence_refs),",
    "    )",
    "    conf = ConfidenceAssessment(",
    "        subject_kind=subject_kind,",
    "        subject_id=subject_id,",
    "        band=_conf_band(score),",
    "        summary=_truncate(conf_summary, _MAX_SUMMARY_LEN),",
    "        rationale=tuple(rationale),",
    "        evidence_refs=_evidence_refs(*evidence_refs),",
    "    )",
    "    return sev, conf",
    "",
)
print("section 2 added")


# SeverityEngine class: __init__ + run()
add(
    "class SeverityEngine:",
    "    def __init__(self):",
    "        pass",
    "",
    "    def run(",
    "        self,",
    "        *,",
    "        detections=None,",
    "        correlations=None,",
    "        events=None,",
    "        now=None,",
    "    ):",
    "        if detections is None:",
    "            detections = ()",
    "        if correlations is None:",
    "            correlations = ()",
    "        if events is None:",
    "            events = {}",
    "        if now is None:",
    "            now = datetime.now(timezone.utc)",
    "        elif not isinstance(now, datetime):",
    "            raise InvalidSeverityInputError(",
    "                safe_message='now must be a datetime',",
    "                internal_detail=f'got {type(now).__name__}',",
    "            )",
    "        elif now.tzinfo is None:",
    "            raise InvalidSeverityInputError(",
    "                safe_message='now must be timezone-aware (UTC)',",
    "                internal_detail='got a naive datetime',",
    "            )",
    "        for d in detections:",
    "            if not isinstance(d, Detection):",
    "                raise InvalidSeverityInputError(",
    "                    safe_message='all entries in detections must be Detection instances',",
    "                    internal_detail=f'got {type(d).__name__}',",
    "                )",
    "        for c in correlations:",
    "            if not isinstance(c, Correlation):",
    "                raise InvalidSeverityInputError(",
    "                    safe_message='all entries in correlations must be Correlation instances',",
    "                    internal_detail=f'got {type(c).__name__}',",
    "                )",
    "        for ev in events.values():",
    "            if not isinstance(ev, SecurityEvent):",
    "                raise InvalidSeverityInputError(",
    "                    safe_message='all entries in events must be SecurityEvent instances',",
    "                    internal_detail=f'got {type(ev).__name__}',",
    "                )",
    "        events_by_id = dict(events)",
    "        detections_by_id = {d.detection_id: d for d in detections}",
    "        errors = []",
    "        severity_assessments = []",
    "        confidence_assessments = []",
    "        detections_scored = 0",
    "        correlations_scored = 0",
)
print("section 3 added")
print("section 0 added")


# run() body: per-detection loop
add(
    "        for d in detections:",
    "            try:",
    "                sev, conf = self._score_detection(d, events_by_id=events_by_id)",
    "            except SeverityError as exc:",
    "                errors.append(_truncate(",
    "                    f'detection {d.detection_id!r} rejected: {exc.safe_message}',",
    "                    _MAX_ERROR_LEN,",
    "                ))",
    "                continue",
    "            except Exception as exc:  # noqa: BLE001",
    "                errors.append(_truncate(",
    "                    f'detection {d.detection_id!r} raised unexpected {type(exc).__name__}: {exc}',",
    "                    _MAX_ERROR_LEN,",
    "                ))",
    "                continue",
    "            severity_assessments.append(sev)",
    "            confidence_assessments.append(conf)",
    "            detections_scored += 1",
)
print("section 4 added")




# run() body: per-correlation loop + bundle + return
add(
    "        for c in correlations:",
    "            try:",
    "                sev, conf = self._score_correlation(",
    "                    c,",
    "                    detections_by_id=detections_by_id,",
    "                    events_by_id=events_by_id,",
    "                )",
    "            except SeverityError as exc:",
    "                errors.append(_truncate(",
    "                    f'correlation {c.correlation_id!r} rejected: {exc.safe_message}',",
    "                    _MAX_ERROR_LEN,",
    "                ))",
    "                continue",
    "            except Exception as exc:  # noqa: BLE001",
    "                errors.append(_truncate(",
    "                    f'correlation {c.correlation_id!r} raised unexpected {type(exc).__name__}: {exc}',",
    "                    _MAX_ERROR_LEN,",
    "                ))",
    "                continue",
    "            severity_assessments.append(sev)",
    "            confidence_assessments.append(conf)",
    "            correlations_scored += 1",
    "        bundle_sev, bundle_conf = self._score_bundle(",
    "            detections=detections,",
    "            correlations=correlations,",
    "            events_by_id=events_by_id,",
    "            detections_by_id=detections_by_id,",
    "        )",
    "        severity_assessments.append(bundle_sev)",
    "        confidence_assessments.append(bundle_conf)",
    "        return SeverityResult(",
    "            severity_assessments=tuple(severity_assessments),",
    "            confidence_assessments=tuple(confidence_assessments),",
    "            detections_considered=len(detections),",
    "            correlations_considered=len(correlations),",
    "            detections_scored=detections_scored,",
    "            correlations_scored=correlations_scored,",
    "            errors=tuple(errors),",
    "            produced_at=now,",
    "        )",
)
print("section 5 added")



# _score_detection
add(
    "    def _score_detection(self, d, *, events_by_id):",
    "        if d.detected_at.tzinfo is None:",
    "            raise SeverityError(",
    "                safe_message='detection.detected_at must be timezone-aware (UTC)',",
    "                internal_detail=f'detection {d.detection_id!r} has a naive detected_at',",
    "            )",
    "        ev = events_by_id.get(d.event_id)",
    "        cat = str(d.category)",
    "        rule_category_present = cat.endswith('common_behavioral') or cat.endswith('cross_source_correlation')",
    "        rule_category_detail = (",
    "            f'category={d.category.value}' if rule_category_present",
    "            else f'category={d.category.value} (per-event source_specific, not high-impact)'",
    "        )",
    "        endpoint_present = ev is not None and bool(ev.endpoint)",
    "        endpoint_detail = (",
    "            f'endpoint={ev.endpoint!r}' if endpoint_present",
    "            else 'endpoint missing or empty'",
    "        )",
    "        sip_present = ev is not None and bool(ev.source_ip)",
    "        sip_detail = (",
    "            f'source_ip={ev.source_ip!r}' if sip_present",
    "            else 'source_ip missing'",
    "        )",
    "        evidence_complete = ev is not None",
    "        evidence_detail = (",
    "            f'event {d.event_id!r} present in the events lookup'",
    "            if evidence_complete",
    "            else f'event {d.event_id!r} missing from the events lookup'",
    "        )",
    "        rationale = (",
    "            _sig(ScoringSignal.RULE_CATEGORY, rule_category_present, rule_category_detail),",
    "            _sig(ScoringSignal.CORRELATION_TRIGGER, False, 'correlation_trigger=N/A (per-event detection)'),",
    "            _sig(ScoringSignal.DETECTION_COUNT, False, 'detection_count=1 (below threshold)'),",
    "            _sig(ScoringSignal.EVENT_COUNT, False, 'event_count=1 (below threshold)'),",
    "            _sig(ScoringSignal.WINDOW_SPAN_SECONDS, False, 'window_span_seconds=N/A (single detection)'),",
    "            _sig(ScoringSignal.AFFECTED_ENDPOINT, endpoint_present, endpoint_detail),",
    "            _sig(ScoringSignal.SOURCE_IP_PRESENT, sip_present, sip_detail),",
    "            _sig(ScoringSignal.RULE_REPEATED, False, 'rule_repeated=N/A (single detection)'),",
    "            _sig(ScoringSignal.CORRELATION_REPEATED, False, 'correlation_repeated=N/A (per-event detection)'),",
    "            _sig(ScoringSignal.EVIDENCE_COMPLETENESS, evidence_complete, evidence_detail),",
    "        )",
    "        evidence_refs = [d.detection_id, d.event_id]",
    "        if ev is not None and ev.endpoint:",
    "            evidence_refs.append(f'event:{ev.event_id}:endpoint')",
    "        if ev is not None and ev.source_ip:",
    "            evidence_refs.append(f'event:{ev.event_id}:source_ip')",
    "        sev_summary = (",
    "            f'per-event detection {d.rule_id} v{d.rule_version} on event {d.event_id!r}'",
    "        )",
    "        conf_summary = (",
    "            f'per-event detection backed by rule {d.rule_id!r} v{d.rule_version}; '",
    "            f'evidence_complete={evidence_complete}'",
    "        )",
    "        return _build_pair(",
    "            subject_kind=SeverityAssessmentSubject.DETECTION,",
    "            subject_id=d.detection_id,",
    "            rationale=rationale,",
    "            evidence_refs=evidence_refs,",
    "            sev_summary=sev_summary,",
    "            conf_summary=conf_summary,",
    "        )",
)
print("section 6 added")



# _score_correlation
add(
    "    def _score_correlation(self, c, *, detections_by_id, events_by_id):",
    "        if c.window_start.tzinfo is None or c.window_end.tzinfo is None:",
    "            raise SeverityError(",
    "                safe_message='correlation window must be timezone-aware (UTC)',",
    "                internal_detail=f'correlation {c.correlation_id!r} has a naive window',",
    "            )",
    "        if c.window_end < c.window_start:",
    "            raise SeverityError(",
    "                safe_message='correlation.window_end must be >= window_start',",
    "                internal_detail=f'correlation {c.correlation_id!r} has window_end < window_start',",
    "            )",
    "        underlying_dets = []",
    "        for did in c.detection_ids:",
    "            d = detections_by_id.get(did)",
    "            if d is not None:",
    "                underlying_dets.append(d)",
    "        underlying_events = []",
    "        for eid in c.event_ids:",
    "            ev = events_by_id.get(eid)",
    "            if ev is not None:",
    "                underlying_events.append(ev)",
    "        det_count = len(underlying_dets)",
    "        ev_count = len({e.event_id for e in underlying_events if e.event_id})",
    "        window_span = int((c.window_end - c.window_start).total_seconds())",
    "        rule_category_present = any(",
    "            str(d.category).endswith('common_behavioral')",
    "            or str(d.category).endswith('cross_source_correlation')",
    "            for d in underlying_dets",
    "        )",
    "        rule_category_detail = (",
    "            'at least one underlying detection is a high-impact category'",
    "            if rule_category_present",
    "            else 'no underlying detection is high-impact'",
    "        )",
    "        corr_trigger_present = c.trigger in _HIGH_IMPACT_TRIGGERS",
    "        corr_trigger_detail = f'trigger={c.trigger!r}' if corr_trigger_present else f'trigger={c.trigger!r} (not documented high-impact)'",
    "        det_count_present = det_count >= THRESHOLD_DETECTION_COUNT",
    "        det_count_detail = f'detection_count={det_count} >= {THRESHOLD_DETECTION_COUNT}' if det_count_present else f'detection_count={det_count} < {THRESHOLD_DETECTION_COUNT}'",
    "        ev_count_present = ev_count >= THRESHOLD_EVENT_COUNT",
    "        ev_count_detail = f'event_count={ev_count} >= {THRESHOLD_EVENT_COUNT}' if ev_count_present else f'event_count={ev_count} < {THRESHOLD_EVENT_COUNT}'",
    "        window_present = window_span >= THRESHOLD_WINDOW_SPAN_SECONDS",
    "        window_detail = f'window_span_seconds={window_span} >= {THRESHOLD_WINDOW_SPAN_SECONDS}' if window_present else f'window_span_seconds={window_span} < {THRESHOLD_WINDOW_SPAN_SECONDS}'",
)
print("section 7a added")



add(
    "        endpoints = {e.endpoint for e in underlying_events if e.endpoint}",
    "        endpoint_present = len(endpoints) >= 1",
    "        endpoint_detail = f'endpoints={sorted(endpoints)!r}' if endpoint_present else 'no concrete endpoint on the events'",
    "        source_ips = {e.source_ip for e in underlying_events if e.source_ip}",
    "        sip_present = len(source_ips) == 1",
    "        if sip_present:",
    "            (only_sip,) = source_ips",
    "            sip_detail = f'source_ip={only_sip!r}'",
    "        elif len(source_ips) > 1:",
    "            sip_detail = f'multiple source_ips={sorted(source_ips)!r}'",
    "        else:",
    "            sip_detail = 'no source_ip on the events'",
    "        distinct_rules = {d.rule_id for d in underlying_dets}",
    "        rule_rep_present = (",
    "            len(distinct_rules) >= THRESHOLD_RULE_REPEATED",
    "            or len(underlying_dets) >= THRESHOLD_RULE_REPEATED",
    "        )",
    "        rule_rep_detail = f'distinct_rules={len(distinct_rules)}, detections={len(underlying_dets)}' if rule_rep_present else f'distinct_rules={len(distinct_rules)}'",
    "        corr_rep_present = False",
    "        corr_rep_detail = 'correlation_repeated=N/A (single correlation)'",
    "        det_complete = all(did in detections_by_id for did in c.detection_ids)",
    "        ev_complete = all(eid in events_by_id for eid in c.event_ids)",
    "        evidence_complete = det_complete and ev_complete",
    "        if evidence_complete:",
    "            evidence_detail = 'all detection_ids and event_ids resolved'",
    "        else:",
    "            missing_dets = [did for did in c.detection_ids if did not in detections_by_id]",
    "            missing_evs = [eid for eid in c.event_ids if eid not in events_by_id]",
    "            evidence_detail = f'missing {len(missing_dets)} detection(s) and {len(missing_evs)} event(s) from the supplied lookups'",
)
print("section 7b added")



# rationale + return for _score_correlation
add(
    "        rationale = (",
    "            _sig(ScoringSignal.RULE_CATEGORY, rule_category_present, rule_category_detail),",
    "            _sig(ScoringSignal.CORRELATION_TRIGGER, corr_trigger_present, corr_trigger_detail),",
    "            _sig(ScoringSignal.DETECTION_COUNT, det_count_present, det_count_detail),",
    "            _sig(ScoringSignal.EVENT_COUNT, ev_count_present, ev_count_detail),",
    "            _sig(ScoringSignal.WINDOW_SPAN_SECONDS, window_present, window_detail),",
    "            _sig(ScoringSignal.AFFECTED_ENDPOINT, endpoint_present, endpoint_detail),",
    "            _sig(ScoringSignal.SOURCE_IP_PRESENT, sip_present, sip_detail),",
    "            _sig(ScoringSignal.RULE_REPEATED, rule_rep_present, rule_rep_detail),",
    "            _sig(ScoringSignal.CORRELATION_REPEATED, corr_rep_present, corr_rep_detail),",
    "            _sig(ScoringSignal.EVIDENCE_COMPLETENESS, evidence_complete, evidence_detail),",
    "        )",
    "        evidence_refs = [c.correlation_id]",
    "        for did in c.detection_ids:",
    "            evidence_refs.append(did)",
    "        for eid in c.event_ids:",
    "            evidence_refs.append(eid)",
    "        sev_summary = f'correlation {c.pattern_id} v{c.pattern_version} ({c.count} detections, trigger={c.trigger!r}, window_span={window_span}s)'",
    "        conf_summary = (",
    "            f'correlation {c.correlation_id!r} evidence complete={evidence_complete} '",
    "            f'({len(underlying_dets)}/{len(c.detection_ids)} detections available, '",
    "            f'{len(underlying_events)}/{len(c.event_ids)} events available)'",
    "        )",
    "        return _build_pair(",
    "            subject_kind=SeverityAssessmentSubject.CORRELATION,",
    "            subject_id=c.correlation_id,",
    "            rationale=rationale,",
    "            evidence_refs=evidence_refs,",
    "            sev_summary=sev_summary,",
    "            conf_summary=conf_summary,",
    "        )",
)
print("section 7c added")



# _score_bundle (header + first signals)
add(
    "    def _score_bundle(self, *, detections, correlations, events_by_id, detections_by_id):",
    "        det_count = len(detections)",
    "        ev_count = len(events_by_id)",
    "        if correlations:",
    "            win_start = min(c.window_start for c in correlations)",
    "            win_end = max(c.window_end for c in correlations)",
    "            window_span = int((win_end - win_start).total_seconds())",
    "        else:",
    "            window_span = 0",
    "        rule_counts = {}",
    "        for d in detections:",
    "            rule_counts[d.rule_id] = rule_counts.get(d.rule_id, 0) + 1",
    "        rule_repeated = any(c >= THRESHOLD_RULE_REPEATED for c in rule_counts.values())",
    "        if rule_repeated:",
    "            top_rule, top_count = max(rule_counts.items(), key=lambda x: x[1])",
    "            rule_rep_detail = f'top rule {top_rule!r} fired {top_count} times'",
    "        else:",
    "            rule_rep_detail = f'no rule fired >= {THRESHOLD_RULE_REPEATED} times'",
    "        pattern_counts = {}",
    "        for c in correlations:",
    "            key = (c.pattern_id, c.pattern_version)",
    "            pattern_counts[key] = pattern_counts.get(key, 0) + 1",
    "        corr_repeated = any(c >= THRESHOLD_CORRELATION_REPEATED for c in pattern_counts.values())",
    "        if corr_repeated:",
    "            top_pat, top_n = max(pattern_counts.items(), key=lambda x: x[1])",
    "            corr_rep_detail = f'top pattern {top_pat[0]!r} v{top_pat[1]} fired {top_n} times'",
    "        else:",
    "            corr_rep_detail = f'no pattern fired >= {THRESHOLD_CORRELATION_REPEATED} times'",
    "        endpoints = {e.endpoint for e in events_by_id.values() if e.endpoint}",
    "        endpoint_present = len(endpoints) >= 1",
    "        endpoint_detail = f'endpoints={sorted(endpoints)!r}' if endpoint_present else 'no concrete endpoint'",
    "        source_ips = {e.source_ip for e in events_by_id.values() if e.source_ip}",
    "        sip_present = len(source_ips) == 1",
    "        if sip_present:",
    "            (only_sip,) = source_ips",
    "            sip_detail = f'source_ip={only_sip!r}'",
    "        elif len(source_ips) > 1:",
    "            sip_detail = f'multiple source_ips={sorted(source_ips)!r}'",
    "        else:",
    "            sip_detail = 'no source_ip in the events'",
)
print("section 8a added")



add(
    "        rule_category_present = any(",
    "            str(d.category).endswith('common_behavioral')",
    "            or str(d.category).endswith('cross_source_correlation')",
    "            for d in detections",
    "        )",
    "        rule_category_detail = 'at least one detection is a high-impact category' if rule_category_present else 'no high-impact detection category'",
    "        corr_trigger_present = any(c.trigger in _HIGH_IMPACT_TRIGGERS for c in correlations)",
    "        corr_trigger_detail = 'at least one correlation has a high-impact trigger' if corr_trigger_present else 'no high-impact correlation trigger'",
    "        det_count_present = det_count >= THRESHOLD_DETECTION_COUNT",
    "        det_count_detail = f'detection_count={det_count} >= {THRESHOLD_DETECTION_COUNT}' if det_count_present else f'detection_count={det_count} < {THRESHOLD_DETECTION_COUNT}'",
    "        ev_count_present = ev_count >= THRESHOLD_EVENT_COUNT",
    "        ev_count_detail = f'event_count={ev_count} >= {THRESHOLD_EVENT_COUNT}' if ev_count_present else f'event_count={ev_count} < {THRESHOLD_EVENT_COUNT}'",
    "        window_present = window_span >= THRESHOLD_WINDOW_SPAN_SECONDS",
    "        window_detail = f'window_span_seconds={window_span} >= {THRESHOLD_WINDOW_SPAN_SECONDS}' if window_present else f'window_span_seconds={window_span} < {THRESHOLD_WINDOW_SPAN_SECONDS}'",
    "        det_complete = all(d.event_id in events_by_id for d in detections)",
    "        corr_complete = all(",
    "            all(did in detections_by_id for did in c.detection_ids)",
    "            and all(eid in events_by_id for eid in c.event_ids)",
    "            for c in correlations",
    "        )",
    "        evidence_complete = det_complete and corr_complete",
    "        if evidence_complete:",
    "            evidence_detail = 'all detection and correlation evidence resolved'",
    "        else:",
    "            evidence_detail = f'det_complete={det_complete}; corr_complete={corr_complete}'",
)
print("section 8b added")



# _score_bundle rationale + return
add(
    "        rationale = (",
    "            _sig(ScoringSignal.RULE_CATEGORY, rule_category_present, rule_category_detail),",
    "            _sig(ScoringSignal.CORRELATION_TRIGGER, corr_trigger_present, corr_trigger_detail),",
    "            _sig(ScoringSignal.DETECTION_COUNT, det_count_present, det_count_detail),",
    "            _sig(ScoringSignal.EVENT_COUNT, ev_count_present, ev_count_detail),",
    "            _sig(ScoringSignal.WINDOW_SPAN_SECONDS, window_present, window_detail),",
    "            _sig(ScoringSignal.AFFECTED_ENDPOINT, endpoint_present, endpoint_detail),",
    "            _sig(ScoringSignal.SOURCE_IP_PRESENT, sip_present, sip_detail),",
    "            _sig(ScoringSignal.RULE_REPEATED, rule_repeated, rule_rep_detail),",
    "            _sig(ScoringSignal.CORRELATION_REPEATED, corr_repeated, corr_rep_detail),",
    "            _sig(ScoringSignal.EVIDENCE_COMPLETENESS, evidence_complete, evidence_detail),",
    "        )",
    "        evidence_refs = ['bundle:overall']",
    "        for d in detections:",
    "            evidence_refs.append(d.detection_id)",
    "        for c in correlations:",
    "            evidence_refs.append(c.correlation_id)",
    "        sev_summary = f'bundle: {len(detections)} detections, {len(correlations)} correlations, {ev_count} distinct events'",
    "        conf_summary = (",
    "            f'bundle evidence_complete={evidence_complete} '",
    "            f'({det_count} detections, {len(correlations)} correlations, window_span={window_span}s)'",
    "        )",
    "        return _build_pair(",
    "            subject_kind=SeverityAssessmentSubject.BUNDLE,",
    "            subject_id='bundle:overall',",
    "            rationale=rationale,",
    "            evidence_refs=evidence_refs,",
    "            sev_summary=sev_summary,",
    "            conf_summary=conf_summary,",
    "        )",
)
print("section 8c added")



# Main: concatenate all sections, write to target.
add(
    "_ = (Any, DomainError, Set, _log)",
    "",
)


def main():
    parts = []
    for section in SECTIONS:
        parts.extend(section)
        parts.append("")
    content = "\n".join(parts)
    with open(TARGET, "w", encoding="utf-8") as fh:
        fh.write(content)
    print(f"wrote {len(content)} bytes to {TARGET}")


if __name__ == "__main__":
    main()
