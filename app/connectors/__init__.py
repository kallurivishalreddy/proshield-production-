"""Connector layer: per-source adapters producing canonical SecurityEvents.

The connector layer is the only place licensed to know source-specific
formats. It must NOT perform detection, correlation, or any other core
engine work.

Reference: docs/PHASE 4/DETECTION_ENGINEERING_AND_FUTURE_AI.md (Section 4).
"""
