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
severity / confidence engine (``app/severity/``).

Incident creation, early incident reports, analyst routing, escalation
workflows, queue assignment, the report generator, the audit subsystem,
the AI engine, the HTTP API, and the frontend belong to later slices.

Reference: docs/PROSHIELD_PROJECT_UNDERSTANDING.md
"""

__version__ = "4.6.0"
__phase__ = "4.6"
