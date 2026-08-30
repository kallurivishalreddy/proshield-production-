"""ProShield backend package.

Phase 4.1 establishes the SecurityEvent ingestion and persistence foundation.
Phase 4.2 adds the deterministic Rule Framework and Rule Registry
(``app/rules/``). Phase 4.3 implements the first real source connector
(NGINX) and the first small production rule for that connector
(``app/rules/_library/nginx/``). Phase 4.4 adds the deterministic
per-event detection engine (``app/detection/``) and four additional
per-event production rules for the NGINX connector. Phase 4.5 adds
detection persistence, ingestion->detection wiring, the cross-event
correlation engine (``app/correlation/``), and correlation persistence.
Phase 4.6 adds the attack-timeline engine (``app/timeline/``) and the
severity / confidence engine (``app/severity/``). Phase 4.7 adds the
generic rule management backend (``app/rules/management/``).
Phase 4.8 adds the analyst-investigation backend: incident / case
(``app/incidents/``), reports (``app/reports/``), routing
(``app/routing/``), the minimal auth foundation (``app/auth/``),
and the secure application proxy / gateway (``app/proxy/``).

Analyst queue / escalation / advanced severity-aware routing /
future IAM are explicit future scope.

Reference: docs/PROSHIELD_PROJECT_UNDERSTANDING.md
"""

__version__ = "4.8.0"
__phase__ = "4.8"
