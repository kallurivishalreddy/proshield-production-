"""Persistence layer: MongoDB access, repositories, schema validators,
and index management.

The persistence layer is the only place that may speak MongoDB driver
calls. Route handlers and connectors must NOT import pymongo directly.

Reference: docs/PHASE 2/CONTRACT_DECISIONS.md (ADR-001, ADR-002).
"""
