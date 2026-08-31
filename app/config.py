"""Runtime configuration loader.

Configuration is loaded from environment variables (with sensible local
defaults) and is treated as security-sensitive data
(docs/PHASE 3/SECURITY_CONFIGURATION.md). We do NOT read secrets from
files on disk in this slice; environment variables are sufficient and
keep the deployment story minimal.

No value is ever logged. No value is ever sent back through a public
API. The configuration object exposes only safe-to-print summaries via
:meth:`ProShieldConfig.safe_summary`.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List


def _env(name: str, default: str) -> str:
    val = os.environ.get(name)
    return val if val is not None and val != "" else default


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(
            f"environment variable {name} must be an integer, got {raw!r}"
        ) from exc


@dataclass(frozen=True)
class ProShieldConfig:
    """Immutable runtime configuration."""

    env_name: str = "development"
    log_level: str = "INFO"

    mongo_uri: str = "mongodb://127.0.0.1:27017"
    mongo_db: str = "proshield"
    mongo_collection_events: str = "security_events"

    ingest_max_body_bytes: int = 16_384
    ingest_max_details_bytes: int = 8_192
    ingest_rate_limit_per_minute: int = 600

    # Phase 4.8: auth / proxy / routing configuration.
    # The signing key MUST be supplied through a secure
    # mechanism (env-var injection). The Phase 4.8 slice
    # defaults to an empty string so a misconfigured
    # production startup fails fast (see Phase 3 secret
    # validation rules); tests inject a deterministic key.
    auth_signing_key: str = ""
    auth_token_lifetime_seconds: int = 3600
    # Proxy rate-limit / abuse-protection knobs. The proxy
    # uses ``proxy_rate_limit_per_minute`` as the per-subject
    # budget; ``proxy_max_request_bytes`` caps the wire body
    # size of any client request; ``proxy_max_response_bytes``
    # caps the largest response the proxy will emit (so a
    # pathological analyst-side dump cannot exhaust memory).
    proxy_rate_limit_per_minute: int = 120
    proxy_max_request_bytes: int = 32_768
    proxy_max_response_bytes: int = 1_048_576  # 1 MiB
    # Centralized-analysis rate-limit: a tighter budget
    # because centralized correlation is expensive.
    proxy_centralized_rate_limit_per_minute: int = 5

    # Phase 4.9: source-management / ingress boundary knobs.
    # ``source_signing_key`` is the HMAC key for the
    # source-identity tokens that prove a source instance is
    # trusted. ``source_token_lifetime_seconds`` bounds the
    # window a token can be replayed. ``ingress_rate_limit_per_minute``
    # is the per-source-instance budget for inbound
    # telemetry so a malicious / misconfigured external
    # system cannot flood the canonical pipeline. The
    # ``ingress_max_request_bytes`` caps the wire-body size
    # at the trusted inbound boundary so a single oversized
    # payload cannot exhaust memory. ``ingress_max_response_bytes``
    # caps the response size the boundary will emit.
    source_signing_key: str = ""
    source_token_lifetime_seconds: int = 3600
    ingress_rate_limit_per_minute: int = 600
    ingress_max_request_bytes: int = 32_768
    ingress_max_response_bytes: int = 1_048_576  # 1 MiB

    # Comma-separated "name:module.path:ClassName" entries.
    connector_specs: List[str] = field(default_factory=list)

    @classmethod
    def from_env(cls) -> "ProShieldConfig":
        connector_specs_raw = _env("PROSHIELD_CONNECTORS", "")
        connector_specs = [
            s.strip() for s in connector_specs_raw.split(",") if s.strip()
        ]
        return cls(
            env_name=_env("PROSHIELD_ENV", "development"),
            log_level=_env("PROSHIELD_LOG_LEVEL", "INFO"),
            mongo_uri=_env("PROSHIELD_MONGO_URI", "mongodb://127.0.0.1:27017"),
            mongo_db=_env("PROSHIELD_MONGO_DB", "proshield"),
            mongo_collection_events=_env(
                "PROSHIELD_MONGO_COLLECTION_EVENTS", "security_events"
            ),
            ingest_max_body_bytes=_env_int(
                "PROSHIELD_INGEST_MAX_BODY_BYTES", 16_384
            ),
            ingest_max_details_bytes=_env_int(
                "PROSHIELD_INGEST_MAX_DETAILS_BYTES", 8_192
            ),
            ingest_rate_limit_per_minute=_env_int(
                "PROSHIELD_INGEST_RATE_LIMIT_PER_MINUTE", 600
            ),
            auth_signing_key=_env("PROSHIELD_AUTH_SIGNING_KEY", ""),
            auth_token_lifetime_seconds=_env_int(
                "PROSHIELD_AUTH_TOKEN_LIFETIME_SECONDS", 3600
            ),
            proxy_rate_limit_per_minute=_env_int(
                "PROSHIELD_PROXY_RATE_LIMIT_PER_MINUTE", 120
            ),
            proxy_max_request_bytes=_env_int(
                "PROSHIELD_PROXY_MAX_REQUEST_BYTES", 32_768
            ),
            proxy_max_response_bytes=_env_int(
                "PROSHIELD_PROXY_MAX_RESPONSE_BYTES", 1_048_576
            ),
            proxy_centralized_rate_limit_per_minute=_env_int(
                "PROSHIELD_PROXY_CENTRALIZED_RATE_LIMIT_PER_MINUTE", 5
            ),
            source_signing_key=_env("PROSHIELD_SOURCE_SIGNING_KEY", ""),
            source_token_lifetime_seconds=_env_int(
                "PROSHIELD_SOURCE_TOKEN_LIFETIME_SECONDS", 3600
            ),
            ingress_rate_limit_per_minute=_env_int(
                "PROSHIELD_INGRESS_RATE_LIMIT_PER_MINUTE", 600
            ),
            ingress_max_request_bytes=_env_int(
                "PROSHIELD_INGRESS_MAX_REQUEST_BYTES", 32_768
            ),
            ingress_max_response_bytes=_env_int(
                "PROSHIELD_INGRESS_MAX_RESPONSE_BYTES", 1_048_576
            ),
            connector_specs=connector_specs,
        )

    def safe_summary(self) -> dict:
        """Redacted view suitable for diagnostics. Never includes secrets."""
        # Note: mongo_uri may carry credentials. We strip them defensively.
        uri = self.mongo_uri
        if "@" in uri:
            scheme, _, rest = uri.partition("://")
            _, _, hostpart = rest.partition("@")
            uri = f"{scheme}://***@{hostpart}"
        return {
            "env": self.env_name,
            "log_level": self.log_level,
            "mongo_uri": uri,
            "mongo_db": self.mongo_db,
            "mongo_collection_events": self.mongo_collection_events,
            "ingest_max_body_bytes": self.ingest_max_body_bytes,
            "ingest_max_details_bytes": self.ingest_max_details_bytes,
            "ingest_rate_limit_per_minute": self.ingest_rate_limit_per_minute,
            "auth_signing_key_set": bool(self.auth_signing_key),
            "auth_token_lifetime_seconds": self.auth_token_lifetime_seconds,
            "proxy_rate_limit_per_minute": self.proxy_rate_limit_per_minute,
            "proxy_max_request_bytes": self.proxy_max_request_bytes,
            "proxy_max_response_bytes": self.proxy_max_response_bytes,
            "proxy_centralized_rate_limit_per_minute":
                self.proxy_centralized_rate_limit_per_minute,
            "source_signing_key_set": bool(self.source_signing_key),
            "source_token_lifetime_seconds": self.source_token_lifetime_seconds,
            "ingress_rate_limit_per_minute": self.ingress_rate_limit_per_minute,
            "ingress_max_request_bytes": self.ingress_max_request_bytes,
            "ingress_max_response_bytes": self.ingress_max_response_bytes,
            "connectors": self.connector_specs,
        }
