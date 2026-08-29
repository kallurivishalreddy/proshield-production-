"""Reserved subpackage for the production rule library.

Reference: docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md,
Section 9 (Rule Organization). Phase 4.2 ships the **framework** and
the **registry**; it deliberately does NOT ship any production
detection rules. The candidate/approved funnel (Section 89) is the
mandatory path for any rule to enter this package:

```text
research -> candidate -> testing -> review -> approved -> enabled
```

Submodules intentionally created in Phase 4.2:

* ``common`` -- source-independent behavioral rules (Section 8.2).
* ``waf`` -- WAF-specific rules (Section 8.1).
* ``nginx`` -- NGINX-specific rules (Section 8.1).
* ``iam`` -- IAM-specific rules (Section 8.1).
* ``rate_limit`` -- rate-limiter-specific rules (Section 8.1).
* ``network`` -- network / TLS anomaly rules (Section 8.1).
* ``correlation`` -- cross-source correlation rules (Section 8.3).

The submodules are present so the on-disk organisation matches the
documented structure, and so subsequent slices can drop rule modules
into the right bucket without renaming. The modules themselves export
no rules and contribute no behaviour.
"""
from __future__ import annotations
