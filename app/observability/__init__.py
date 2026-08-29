"""Observability: structured logging and request-id propagation.

Logging never writes secrets, credentials, full payloads, stack traces, or
internal driver error messages to client-visible output. Request IDs are
carried for safe-error correlation.

Reference: docs/PHASE 3/SECURE_FOUNDATION.md, Section 30.
"""
