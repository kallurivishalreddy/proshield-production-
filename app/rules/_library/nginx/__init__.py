"""NGINX-specific rules (Section 8.1).

Phase 4.3 shipped the first production rule for the NGINX connector:

* ``NGINX-AUTH-BRUTEFORCE-001`` -- HTTP 401/403 on
  authentication-shaped NGINX endpoints. See
  :mod:`app.rules._library.nginx.brute_force_pattern`.

Phase 4.4 adds four more per-event production rules for the
NGINX connector. They are deliberately **per-event** (no
correlation, no time windows, no counts); correlation is the
responsibility of the next detection / correlation slice.

* ``NGINX-AUTH-FAILURE-001`` -- every NGINX-observed HTTP 401.
  Broader than ``NGINX-AUTH-BRUTEFORCE-001`` (which is scoped to
  auth-shaped endpoints); the broad per-event observation belongs
  here. See :mod:`app.rules._library.nginx.auth_failure_observation`.
* ``NGINX-ACCESS-DENIED-001`` -- NGINX 4xx (excluding 401 / 429)
  on a documented sensitive / admin / dotfile path. See
  :mod:`app.rules._library.nginx.access_denied_sensitive_path`.
* ``NGINX-STATUS-ANOMALY-001`` -- every NGINX-observed HTTP 5xx.
  See :mod:`app.rules._library.nginx.server_error_observation`.
* ``NGINX-RATE-LIMIT-001`` -- every NGINX-observed HTTP 429. See
  :mod:`app.rules._library.nginx.rate_limit_observation`.

All five rules are exposed via the documented :data:`RULE_FACTORIES`
export so the existing :func:`app.rules.load_rules_from_specs` loader
can pick them up. The candidate -> approved -> enabled funnel
(Section 89) is preserved by the registry, not by this module: each
rule ships as APPROVED + enabled, and a future re-enable on a
superseded version is rejected by the registry (Phase 4.2
FINDING-1 guard).
"""
from __future__ import annotations

from .access_denied_sensitive_path import (
    build_nginx_access_denied_sensitive_path_rule,
)
from .auth_failure_observation import build_nginx_auth_failure_observation_rule
from .brute_force_pattern import build_nginx_auth_brute_force_rule
from .rate_limit_observation import build_nginx_rate_limit_observation_rule
from .server_error_observation import build_nginx_server_error_observation_rule

# The rule loader looks for ``RULES`` (instances) and
# ``RULE_FACTORIES`` (zero-arg callables). We export factories
# so every ``load_rules_from_specs`` call gets a fresh instance
# and each rule's mutable instance attributes stay isolated.
RULE_FACTORIES = (
    build_nginx_access_denied_sensitive_path_rule,
    build_nginx_auth_brute_force_rule,
    build_nginx_auth_failure_observation_rule,
    build_nginx_rate_limit_observation_rule,
    build_nginx_server_error_observation_rule,
)

__all__ = [
    "RULE_FACTORIES",
    "build_nginx_access_denied_sensitive_path_rule",
    "build_nginx_auth_brute_force_rule",
    "build_nginx_auth_failure_observation_rule",
    "build_nginx_rate_limit_observation_rule",
    "build_nginx_server_error_observation_rule",
]

