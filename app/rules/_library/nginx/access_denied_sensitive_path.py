"""Per-event rule: NGINX 4xx on a sensitive / admin / dotfile path.

Reference: docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md
           (Sections 8, 9, 13, 18, 23, 28, 32, 49, 59, 87-91)

This is the **per-event** detection for the NGINX-observable pattern
of a request to a known-sensitive or known-attractive path that
returned a 4xx (excluding 401, which is the auth failure signal and
handled by ``NGINX-AUTH-FAILURE-001``).

Observable pattern
------------------

A 4xx response on a path that is *known to be security-relevant*
(admin endpoints, configuration files, dotfiles, exposed
infrastructure) is a candidate signal for:

* directory traversal / enumeration
* scanner activity (sqlmap, nikto, dirbuster)
* admin probing
* IDOR probing
* information disclosure attempts

A 404 is the most common scanner signal in real telemetry (see
``docs/PHASE 4/PHASE 4-04/PHASE-04-04-REPORT.md`` Section 4, the
Phase 4.4 safe-simulation dataset, which produced 50x 404s from one
IP across ``.env``, ``/wp-admin``, ``/phpmyadmin``).

Why the rule is scoped (and not "any 404")
------------------------------------------

A blanket "any 404 fires" rule produces overwhelming false positives
on a typical site (typo'd URLs, removed blog posts, deleted
products). The rule therefore restricts to a documented, bounded
list of sensitive-path patterns. The list is:

* admin endpoints (``/admin``, ``/admin/*``)
* dotfiles / hidden config (``/.env``, ``/.git``, ``/.htaccess``)
* known CMS / infra paths (``/wp-admin``, ``/wp-login``,
  ``/phpmyadmin``, ``/cgi-bin``, ``/manager``)
* infrastructure secrets (``/server-status``, ``/server-info``,
  ``/actuator``, ``/api/internal``)

A new path is added by an explicit rule version, not a runtime
patch (Section 33: rule versioning).

What the rule does NOT do
-------------------------

* It does NOT count repeated requests over a window.
* It does NOT correlate with WAF or rate-limit signals.
* It does NOT decide whether the request was successful at
  exfiltrating data (the response is 4xx; we observe the attempt,
  not the result).
* It does NOT cover 5xx (handled by ``NGINX-STATUS-ANOMALY-001``).
* It does NOT cover 401 (handled by ``NGINX-AUTH-FAILURE-001``).
* It does NOT cover 429 (handled by ``NGINX-RATE-LIMIT-001``).
"""
from __future__ import annotations

import re
from typing import Tuple

from ....domain.security_event import SecurityEvent
from ....detection.redact import redact_endpoint
from ...rule import SimpleRule
from ...types import RuleCategory, RuleMetadata, RuleState


_RULE_ID = "NGINX-ACCESS-DENIED-001"

# Documented sensitive-path patterns. Each pattern is a lowercase
# substring; we match case-insensitively against the canonical
# event's ``endpoint``. The list is intentionally narrow: a new
# high-signal path requires a new rule version (Section 33).
_SENSITIVE_PATH_PATTERNS: Tuple[str, ...] = (
    "/admin",
    "/administrator",
    "/.env",
    "/.git",
    "/.htaccess",
    "/.htpasswd",
    "/wp-admin",
    "/wp-login",
    "/wp-config",
    "/phpmyadmin",
    "/pma",
    "/server-status",
    "/server-info",
    "/actuator",
    "/cgi-bin",
    "/manager",
    "/api/internal",
    "/internal",
    "/.svn",
    "/.hg",
    "/backup",
    "/db/",
    "/database",
    "/.DS_Store",
    "/web.config",
)
_SENSITIVE_RE = re.compile(
    "|".join(re.escape(p) for p in _SENSITIVE_PATH_PATTERNS),
    re.IGNORECASE,
)

# Statuses the rule fires on. 401 is excluded (handled by
# NGINX-AUTH-FAILURE-001). 429 is excluded (handled by
# NGINX-RATE-LIMIT-001). 5xx is excluded (handled by
# NGINX-STATUS-ANOMALY-001). 2xx/3xx do not enter the mapping
# function as ``request_blocked`` (the connector returns None for
# 1xx and for non-auth 2xx/3xx), so they cannot reach this rule.
_FIRE_STATUSES = frozenset({400, 403, 404, 405, 406, 408, 409, 410, 412, 413, 415, 418, 422})


def _predicate(event: SecurityEvent) -> bool:
    """True iff the event is a NGINX-observed 4xx on a sensitive path."""
    if event.source != "nginx":
        return False
    if event.event_type != "request_blocked":
        return False
    status = event.details.get("status_code")
    if status not in _FIRE_STATUSES:
        return False
    endpoint = event.endpoint
    if endpoint is None:
        return False
    return _SENSITIVE_RE.search(endpoint) is not None


def _reasoner(event: SecurityEvent) -> str:
    """Build the analyst-facing reasoning string.

    The ``endpoint`` is passed through :func:`redact_endpoint` so
    any query string (e.g. ``?token=...``), fragment, or oversized
    path is stripped before being put into the persisted
    ``Detection.reasoning`` field. The canonical event is
    unchanged; only the analyst-facing string is redacted. See
    ``app/detection/redact.py`` and the Phase 4.4 review
    (defect D-1).
    """
    status = event.details.get("status_code")
    return (
        f"nginx HTTP {status} on sensitive path "
        f"{redact_endpoint(event.endpoint)!r} "
        f"from {event.source_ip!r}"
    )


def _make_metadata() -> RuleMetadata:
    return RuleMetadata(
        rule_id=_RULE_ID,
        version=1,
        name="NGINX 4xx on sensitive/admin path",
        category=RuleCategory.SOURCE_SPECIFIC,
        sources=("nginx",),
        event_types=("request_blocked",),
        # Phase 5.2: capability ownership (see NGINX-AUTH-FAILURE-001).
        capability_id="cap-nginx",
        state=RuleState.APPROVED,
        enabled=True,
        description=(
            "Per-event detection: each NGINX-observed 4xx (excluding "
            "401 and 429) on a documented sensitive path (admin "
            "endpoints, dotfiles, known CMS / infra paths, "
            "infrastructure secrets) is a candidate signal for "
            "directory enumeration, scanner activity, admin probing, "
            "or information-disclosure attempts. Correlation rules "
            "are responsible for counting and grouping."
        ),
        tags=(
            "ADMIN-PROBE", "ENUMERATION", "NGINX", "PER-EVENT",
            "SCANNER", "SENSITIVE-PATH",
        ),
        references=(
            "docs/PHASE 2/SECURITY_EVENT_SCHEMA.md#5-required-canonical-fields",
            "docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md#8-rule-categories",
            "docs/PHASE 4/PHASE 4-04/PHASE-04-04-REPORT.md",
        ),
    )


def build_nginx_access_denied_sensitive_path_rule() -> SimpleRule:
    """Factory: build a fresh rule instance."""
    return SimpleRule(_make_metadata(), _predicate, _reasoner)
