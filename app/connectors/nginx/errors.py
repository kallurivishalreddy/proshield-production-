"""Connector-internal errors for the NGINX connector.

These errors are scoped to the connector and are CAUGHT inside
the connector itself. They never cross the connector boundary:

* :class:`NginxConnectorError` -- the umbrella for any
  connector-level failure (e.g. file not found, permission
  denied). The connector catches and converts to a
  ``health()`` status update.
* :class:`NginxParseError` -- a single log line could not be
  parsed. Lives in :mod:`app.connectors.nginx.parser` (where
  the parser raises it). The connector catches it per-line and
  counts / logs it.

The connector never raises across the
:meth:`SecurityEventConnector.collect` boundary: callers see a
generator that may simply yield fewer events than the source
contained, with the failure surfaced via :meth:`health` and
:attr:`NginxConnector.stats`. This is consistent with the
documented "connector must not silently discard" principle
(docs/PHASE 0/PRODUCT_SCOPE.md, Section 16): per-line failures
are never silently swallowed, they are reported in the
connector's stats and health.
"""
from __future__ import annotations


class NginxConnectorError(RuntimeError):
    """A connector-level failure (file not found, permission denied, ...).

    The connector catches these and surfaces them in
    :meth:`NginxConnector.health` and the per-call ``stats``
    attribute. They are NOT re-raised across ``collect()``
    because the documented contract is that the connector is a
    generator that the ingestion service walks; if the first
    line fails, the caller is left with a half-populated stream
    and no clear error.
    """
