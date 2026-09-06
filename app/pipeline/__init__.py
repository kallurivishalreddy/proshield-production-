"""ProShield live processing pipeline (production composition).

This package is the **product** wiring that connects the individual,
already-tested engines into a single live chain:

    SecurityEvent
        -> DetectionPipeline (ingestion -> detection engine ->
           DetectionRepository)
        -> CorrelationEngine (window/threshold ->
           CorrelationRepository)
        -> automatic correlation-driven case creation
           (IncidentService.create_case_for_correlation,
            idempotent on the correlation's cluster key)

It exists to close the STRIX F-1 / F-2 architectural gap: the
previously shipped deployment composition never ran detection ->
correlation -> case. The engines themselves are NOT modified here;
they are reused as-is.

Exported symbols:

* :class:`LivePipeline` -- orchestrates the full chain.
* :func:`build_live_pipeline` -- builds a :class:`LivePipeline`
  from an ``app/`` db (pymongo) or a ``FakeDatabase``-compatible
  db (the scripts/*_server.py fakes).
"""
from .service import LivePipeline, build_live_pipeline  # noqa: F401

__all__ = ["LivePipeline", "build_live_pipeline"]
