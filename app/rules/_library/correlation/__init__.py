"""Cross-source correlation rules (Section 8.3, 91).

Intentionally empty in Phase 4.2. The correlation engine itself is a
later slice. The framework is in place: a correlation rule's metadata
must declare at least two sources; the registry accepts it but the
correlator will own dispatch.
"""
from __future__ import annotations
