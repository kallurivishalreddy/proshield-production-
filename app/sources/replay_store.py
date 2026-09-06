"""Production single-use replay store for source-identity tokens.

Reference: docs/PHASE 4/PHASE-04-09-REVIEW.md (R-1, ST-02) and
STRIX-PROSHIELD-ISSUE-REGISTER.md (D-1).

The Phase 4.9 verifier requires a ``replay_store`` that enforces
the documented **single-use** property of source-identity tokens
(R-1).  This module ships the production, cross-process, TTL-aware
implementation backed by MongoDB so a deployment no longer has to
write one (the STRIX D-1 finding).

Design
------

* **Cross-process safe** — MongoDB's unique ``_id`` index on
  ``token_id`` makes ``claim()`` an atomic insert: exactly one
  worker process (or one request in a multi-worker deployment)
  can win the token, every concurrent request sees ``False`` for
  a losing claim.

* **TTL-aware** — a MongoDB TTL index on ``expires_at`` lets the
  database delete claims shortly after the signed token itself
  expires.  Expired tokens are rejected by the verifier's expiry
  check before the replay store is consulted, so dropping expired
  claims is always safe.  An explicit :meth:`MongoReplayStore.gc`
  is also provided for deterministic cleanup.

* **Failure-safe (fail-closed)** — any backend error raises
  ``PersistenceError`` (never a bare ``False``), so the ingress
  boundary can translate an unavailable store into a 5xx and
  reject the request rather than accept telemetry without replay
  protection.

* **Configurable** — the collection name is configurable via
  ``ProShieldConfig.ingress_replay_collection`` (env
  ``PROSHIELD_INGRESS_REPLAY_COLLECTION``).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from ..config import ProShieldConfig
from ..domain.errors import PersistenceError

# MongoDB deletes a document roughly ``expire_after_seconds`` after
# the indexed ``expires_at`` value.  1s is the finest coarse grid
# Mongo supports; the verifier's own expiry check is authoritative.
DEFAULT_EXPIRE_AFTER_SECONDS = 1


class MongoReplayStore:
    """MongoDB-backed, TTL-aware, cross-process single-use store.

    Compatible with the verifier contract: ``claim(token_id=...,
    expires_at=...) -> bool``, ``release(token_id)``, ``gc(now)``.
    """

    def __init__(
        self,
        db: Any,
        config: ProShieldConfig,
        *,
        collection_name: Optional[str] = None,
    ) -> None:
        if db is None:
            raise ValueError("db is required")
        if config is None:
            raise ValueError("config is required")
        self._config = config
        self._collection = db[
            collection_name or config.ingress_replay_collection
        ]
        self._ensure_schema()

    # ----------------------------------------------------------------- schema
    def _ensure_schema(self) -> None:
        """Create the unique + TTL indexes.

        The unique ``_id`` index is implicit; an explicit unique
        index on ``token_id`` makes the single-use guarantee
        self-documenting.  The TTL index on ``expires_at`` bounds
        the growth of the store without any application-level
        sweeper.
        """
        try:
            self._collection.create_index(
                [("token_id", 1)],
                name="source_token_replay_token_id_unique",
                unique=True,
            )
            self._collection.create_index(
                [("expires_at", 1)],
                name="source_token_replay_ttl",
                expireAfterSeconds=DEFAULT_EXPIRE_AFTER_SECONDS,
            )
        except Exception as exc:  # noqa: BLE001 - driver errors
            raise PersistenceError(
                safe_message="replay store schema could not be applied",
                internal_detail=(
                    f"{type(exc).__name__}: {exc}"
                ),
            ) from exc

    # ----------------------------------------------------------------- claim
    def claim(self, *, token_id: str, expires_at: datetime) -> bool:
        """Atomically claim ``token_id``.

        Returns ``True`` iff this call is the first use of the
        token.  ``False`` for any replay.  Raises
        ``PersistenceError`` when the database is unavailable so
        callers fail closed.
        """
        if not isinstance(token_id, str) or not token_id:
            raise PersistenceError(
                safe_message="replay store claim requires a token_id",
                internal_detail="non-string token_id",
            )
        if expires_at is None:
            expires_at = datetime.now(timezone.utc)
        elif expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        try:
            self._collection.insert_one(
                {
                    "_id": token_id,
                    "token_id": token_id,
                    "claimed_at": datetime.now(timezone.utc),
                    "expires_at": expires_at,
                }
            )
            return True
        except Exception as exc:  # noqa: BLE001 - DuplicateKeyError is expected
            name = type(exc).__name__
            if name == "DuplicateKeyError":
                # The token was already claimed by this worker or
                # another process sharing the database.
                return False
            raise PersistenceError(
                safe_message="replay store unavailable",
                internal_detail=f"{name}: {exc}",
            ) from exc

    # --------------------------------------------------------------- lifecycle
    def release(self, token_id: str) -> None:
        """Remove a claim (used by tests / token revocation flows)."""
        try:
            self._collection.delete_one({"token_id": token_id})
        except Exception as exc:  # noqa: BLE001
            raise PersistenceError(
                safe_message="replay store release failed",
                internal_detail=f"{type(exc).__name__}: {exc}",
            ) from exc

    def gc(self, now: datetime) -> int:
        """Deterministically purge claims whose ``expires_at`` has passed.

        Returns the number of purged documents.  The MongoDB TTL
        index performs the same purge asynchronously; this method
        is for bounded, deterministic cleanup (parity with the
        in-memory test double).
        """
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        try:
            result = self._collection.delete_many(
                {"expires_at": {"$lte": now}}
            )
            return int(getattr(result, "deleted_count", 0))
        except Exception as exc:  # noqa: BLE001
            raise PersistenceError(
                safe_message="replay store gc failed",
                internal_detail=f"{type(exc).__name__}: {exc}",
            ) from exc

    def count(self) -> int:
        """Number of live (not yet TTL-purged) claims."""
        try:
            return int(self._collection.count_documents({}))
        except Exception as exc:  # noqa: BLE001
            raise PersistenceError(
                safe_message="replay store count failed",
                internal_detail=f"{type(exc).__name__}: {exc}",
            ) from exc


__all__ = ["MongoReplayStore", "DEFAULT_EXPIRE_AFTER_SECONDS"]