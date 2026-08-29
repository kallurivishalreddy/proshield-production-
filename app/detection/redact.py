"""Redaction helpers for analyst-visible detection strings.

Reference: docs/PHASE 4/PHASE 4-04/PHASE-04-04-REPORT.md
           (Section 4.1, "Sensitive data handling")
           docs/PHASE 4/PHASE 4-04/PHASE-04-04-REVIEW.md (defect D-1).

The :class:`app.detection.models.Detection` record is intended to
be persisted (a future slice) and read by analysts. Its
``reasoning`` field is a short, free-text human-readable string
built by the rule's ``_reasoner``. The string includes the
canonical event's ``endpoint`` and ``source_ip``.

The ``endpoint`` field on :class:`app.domain.security_event.SecurityEvent`
is the raw URL as recorded by the connector. It can include:

* a query string (``?token=...&next=...``) — these frequently
  carry one-time tokens, OAuth authorization codes, API keys,
  signed reset links, internal debug parameters, and other
  attacker-influenced values that must NOT be persisted in an
  audit/SIEM feed.
* a fragment (``#...``) — less sensitive in HTTP because the
  fragment is not sent to the server, but still attacker-
  controlled and best stripped for analyst display.
* a long path with embedded identifiers that exceed a
  reasonable display length.

The :func:`redact_endpoint` helper here is the single source of
truth for "what a Detection's reasoning string is allowed to
show for an endpoint". It is a pure, deterministic function:

* strips the query string (``?...``),
* strips the fragment (``#...``),
* truncates the path to a bounded length (default 128 chars,
  matching the rule library's ``MAX_RULE_REASONING_LEN / 16``),
* replaces ``None`` with the string ``"<none>"`` so the
  analyst never sees a literal ``None`` in the reasoning.

The function is deliberately small and side-effect free. It is
imported by the rule library's ``_reasoner`` functions; rules
do not implement their own redaction.

What this module does NOT do
----------------------------

* It does NOT scrub the ``extra`` field. The framework's
  ``RuleEvaluation.extra`` is rule-supplied metadata; rules
  must not put raw URLs there either, but that is a rule-
  author responsibility, not a redaction concern.
* It does NOT hash or truncate ``source_ip``. The source IP
  is an observation, not a secret; the GDPR / PII question
  is out of scope for the per-event layer.
* It does NOT change the canonical ``SecurityEvent`` itself.
  Redaction only affects the analyst-visible ``reasoning``
  string.
"""
from __future__ import annotations

from typing import Optional


# The maximum length of the redacted endpoint as it appears in
# a ``Detection.reasoning`` string. 128 is generous for a path
# (most legitimate paths fit in 80 chars) and well below the
# framework's ``MAX_RULE_REASONING_LEN = 2048`` ceiling.
MAX_REDACTED_ENDPOINT_LEN = 128

# The placeholder used when the event's endpoint is None. The
# analyst sees a clearly-synthetic string instead of a literal
# Python ``None``.
_NONE_PLACEHOLDER = "<none>"


def redact_endpoint(
    endpoint: Optional[str],
    *,
    max_len: int = MAX_REDACTED_ENDPOINT_LEN,
) -> str:
    """Return an analyst-safe rendering of a canonical event's endpoint.

    The function is pure, deterministic, and total:

    * ``None`` -> ``"<none>"`` (placeholder, not the literal ``None``).
    * ``""`` -> ``""`` (empty path is allowed; some events have
      only ``source_ip`` and no path).
    * strips the query string at the first ``?``,
    * strips the fragment at the first ``#``,
    * truncates to ``max_len`` characters; the truncation suffix
      is ``"..."`` and is included in the bound so the total
      length is at most ``max_len``.

    The order of operations is "fragment first, then query, then
    truncate". The fragment is stripped first because the RFC 3986
    grammar puts the fragment after the query (``scheme://host/path?q#f``),
    so the first ``#`` in a malformed URL might be inside a query
    parameter value. Stripping fragment first (which uses the
    first ``#``) and then query (which uses the first ``?`` of the
    remainder) is robust to that.

    Parameters
    ----------
    endpoint:
        The raw endpoint string from a ``SecurityEvent`` (may be
        ``None``).
    max_len:
        The maximum length of the returned string. Must be >= 4
        (otherwise the ``"..."`` suffix would not fit).

    Returns
    -------
    str
        An analyst-safe rendering. Never ``None``; never contains
        a query string; never contains a fragment; never longer
        than ``max_len`` characters.
    """
    if endpoint is None:
        return _NONE_PLACEHOLDER
    # Defensive: the model already constrains this to ``str``,
    # but a non-str input is rendered with ``str(...)`` rather
    # than crashing (the engine is total).
    if not isinstance(endpoint, str):
        endpoint = str(endpoint)
    # Strip fragment first. RFC 3986 puts fragment after query
    # in absolute URIs; in the relative-form ``endpoint`` we
    # have here, fragment is also a trailing ``#...``.
    hash_idx = endpoint.find("#")
    if hash_idx != -1:
        endpoint = endpoint[:hash_idx]
    # Strip query string.
    q_idx = endpoint.find("?")
    if q_idx != -1:
        endpoint = endpoint[:q_idx]
    # Truncate. ``max_len`` must be at least 4 to fit the "..."
    # suffix, but the caller may pass a smaller value in tests
    # — we clamp to 0 to be defensive.
    if max_len < 0:
        max_len = 0
    if len(endpoint) <= max_len:
        return endpoint
    if max_len <= 3:
        return endpoint[:max_len]
    return endpoint[: max_len - 3] + "..."
