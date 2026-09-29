"""Rule repository: the documented boundary for rule-definition persistence.

Reference: docs/PHASE 4/PHASE 4-07/PHASE-04-07-REPORT.md
           docs/PHASE 2/CONTRACT_DECISIONS.md (ADR-001, ADR-002).

The :class:`RuleRepository` is the only place in the
codebase that talks to pymongo about rule-definition
documents. It mirrors the documented security-event,
detection, and correlation repository policies:

* Translates driver errors to safe :class:`DomainError`
  subclasses so callers have a single error contract.
* Maintains a documented index set and the
  idempotency / duplicate-handling policy for the
  ``managed_rules`` collection.
* Pairs every read / write with the framework's Pydantic
  :class:`RuleDefinition` model, so the wire form is
  the only thing that ever reaches pymongo.

A retired rule is preserved with ``state = "retired"``
(matching the framework's documented lifecycle: CANDIDATE
-> APPROVED -> enabled -> retired is a one-way trip).
The retire operation is a soft-delete: the document
remains in the collection for audit traceability but is
invisible to the runtime evaluator.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from pymongo import ASCENDING, DESCENDING
from pymongo.collection import Collection
from pymongo.database import Database
from pymongo.errors import (
    DuplicateKeyError,
    PyMongoError,
)
from pydantic import ValidationError as PydanticValidationError

from ..config import ProShieldConfig
from ..capabilities.models import CAPABILITY_ID_RE
from ..domain.errors import (
    PersistenceError,
    ValidationError,
)
from ..domain.security_event import (
    ALLOWED_EVENT_TYPES,
    ALLOWED_SOURCES,
)
from ..rules.management.conditions import (
    CONDITION_OPERATOR_VALUES,
    ConditionCombinator,
)
from ..rules.management.definition import RuleDefinition
from ..rules.management.errors import (
    DuplicateManagedRuleError,
    RulePersistenceError,
)
from ..rules.types import RuleCategory, RuleState


_log = logging.getLogger(__name__)

# Stable, sorted snapshot of the closed-set enums. We
# freeze these into the BSON-level validator so a
# misconfigured / hostile write to ``managed_rules`` is
# rejected at the database boundary even when the
# service-layer gate is bypassed.
_VALID_SOURCES: tuple = tuple(sorted(ALLOWED_SOURCES))
_VALID_EVENT_TYPES: tuple = tuple(sorted(ALLOWED_EVENT_TYPES))
_VALID_OPERATORS: tuple = tuple(sorted(CONDITION_OPERATOR_VALUES))
_VALID_COMBINATORS: tuple = tuple(
    sorted(c.value for c in ConditionCombinator)
)
_VALID_CATEGORIES: tuple = tuple(
    sorted(c.value for c in RuleCategory)
)


# ----------------------------------------------------------------- index specs
INDEX_SPECS: List[Dict[str, Any]] = [
    {
        "name": "rule_rule_id_version_unique",
        "key": [("rule_id", ASCENDING), ("version", ASCENDING)],
        "unique": True,
    },
    {
        "name": "rule_rule_id",
        "key": [("rule_id", ASCENDING), ("version", DESCENDING)],
    },
    {
        "name": "rule_state",
        "key": [("state", ASCENDING)],
    },
    {
        "name": "rule_enabled",
        "key": [("enabled", ASCENDING)],
    },
    {
        "name": "rule_type",
        "key": [("type", ASCENDING)],
    },
]


# ----------------------------------------------------------------- validator
# A ``$jsonSchema`` validator for the ``managed_rules``
# collection. The validator is the second line of defence
# after the Pydantic model: it MUST reject at the database
# boundary every shape the model rejects. The Pydantic
# model is the source of truth for field-level rules
# (regexes, ranges, cross-field constraints); the BSON
# validator mirrors the closed-set enums and the
# cross-field ``state``/``enabled`` invariant so a direct
# pymongo write cannot smuggle in a value the model would
# reject.
#
# The ``dependencies`` clause enforces
# ``enabled == true => state == 'approved'`` (matching the
# model-level check in :class:`RuleDefinition`).
MANAGED_RULES_VALIDATOR: Dict[str, Any] = {
    "$jsonSchema": {
        "bsonType": "object",
        "additionalProperties": False,
        "required": [
            "rule_id",
            "version",
            "name",
            "description",
            "category",
            "type",
            "state",
            "enabled",
            "severity",
            "sources",
            "event_types",
            "tags",
            "references",
            "combinator",
            "scope",
            "evidence_requirements",
            "thresholds",
            "window_seconds",
            "actions",
        ],
        # The closed-set cross-field invariant
        # ``enabled == true => state == 'approved'``.
        # The model layer is the source of truth; this
        # $jsonSchema rule is a defence-in-depth statement
        # of the same rule.
        #
        # ``oneOf`` is used (not ``dependencies``) because
        # MongoDB's ``dependencies`` keyword fires whenever
        # the property is *present*, not when the value is
        # ``true``; that would reject ``enabled=false`` on a
        # CANDIDATE / retired rule. ``oneOf`` with two
        # branches expresses the same rule without that
        # false positive.
        "oneOf": [
            {
                "properties": {
                    "enabled": {"enum": [False]},
                },
            },
            {
                "properties": {
                    "enabled": {"enum": [True]},
                    "state": {
                        "bsonType": "string",
                        "enum": ["approved"],
                    },
                },
            },
        ],
        "properties": {
            "_id": {"bsonType": "objectId"},
            "rule_id": {
                "bsonType": "string",
                "minLength": 3,
                "maxLength": 64,
                "pattern": r"^[A-Z][A-Z0-9]*(-[A-Z0-9]+)*$",
            },
            "version": {"bsonType": "int", "minimum": 1, "maximum": 999999},
            "name": {"bsonType": "string", "minLength": 1, "maxLength": 128},
            "description": {"bsonType": "string", "maxLength": 1024},
            "category": {
                "bsonType": "string",
                "enum": list(_VALID_CATEGORIES),
            },
            "type": {
                "bsonType": "string",
                "enum": ["detection", "threshold", "rate_limit", "correlation"],
            },
            "state": {
                "bsonType": "string",
                "enum": ["candidate", "approved", "retired"],
            },
            "enabled": {"bsonType": "bool"},
            "severity": {
                "bsonType": "string",
                "enum": ["low", "medium", "high", "critical"],
            },
            "sources": {
                "bsonType": "array",
                "items": {
                    "bsonType": "string",
                    "enum": list(_VALID_SOURCES),
                },
                "minItems": 0,
                "maxItems": 16,
            },
            "event_types": {
                "bsonType": "array",
                "items": {
                    "bsonType": "string",
                    "enum": list(_VALID_EVENT_TYPES),
                },
                "minItems": 0,
                "maxItems": 16,
            },
            # Phase 5.2: authoritative capability ownership. ``null`` is the
            # persisted form of "legacy rule, not yet bound" — the honest
            # state required by freeze §38, so the property is optional and
            # nullable rather than required.
            "capability_id": {
                "bsonType": ["string", "null"],
                "minLength": 5,
                "maxLength": 64,
                "pattern": r"^cap-[a-z][a-z0-9-]{1,47}$",
            },
            "tags": {
                "bsonType": "array",
                "items": {"bsonType": "string"},
                "maxItems": 16,
            },
            "references": {
                "bsonType": "array",
                "items": {"bsonType": "string"},
                "maxItems": 16,
            },
            "combinator": {
                "bsonType": "string",
                "enum": list(_VALID_COMBINATORS),
            },
            "conditions": {
                "bsonType": ["object", "null"],
            },
            "scope": {
                "bsonType": "array",
                "items": {"bsonType": "string"},
                "maxItems": 32,
            },
            "evidence_requirements": {
                "bsonType": "array",
                "items": {"bsonType": "string"},
                "maxItems": 16,
            },
            "thresholds": {
                "bsonType": "object",
            },
            "window_seconds": {
                "bsonType": ["int", "null"],
                "minimum": 1,
                "maximum": 86400 * 30,
            },
            "actions": {
                "bsonType": "array",
                "items": {
                    "bsonType": "string",
                    "enum": ["alert", "log", "block_remediation"],
                },
                "maxItems": 8,
            },
        },
    }
}


def managed_rule_collection_name(config: ProShieldConfig) -> str:
    """The collection name for the ``managed_rules`` collection."""
    return getattr(config, "mongo_collection_managed_rules", "managed_rules")



# ----------------------------------------------------------------- repository
class RuleRepository:
    """Repository for the ``managed_rules`` collection."""

    def __init__(self, db: Database, config: ProShieldConfig) -> None:
        self._db = db
        self._config = config
        self._collection: Collection = db[managed_rule_collection_name(config)]

    @property
    def collection(self) -> Collection:
        """The raw pymongo collection (for tests and scripts)."""
        return self._collection

    # --------------------------------------------------------- schema / indexes
    def ensure_schema(self) -> None:
        """Apply the documented ``$jsonSchema`` validator."""
        try:
            existing = self._db.command(
                "listCollections", filter={"name": self._collection.name}
            )
            cursor = existing.get("cursor", {})
            first_batch = cursor.get("firstBatch", [])
            if first_batch:
                if "validator" in (first_batch[0].get("options") or {}):
                    # Leave the existing validator in place.
                    return
                # The collection exists but has no
                # validator: install one via ``collMod``.
                self._db.command(
                    "collMod",
                    self._collection.name,
                    validator=MANAGED_RULES_VALIDATOR,
                    validationLevel="strict",
                    validationAction="error",
                )
                return
            # The collection does not exist; create
            # it with the validator inline so the
            # first ``create()`` does not have to
            # back-fill the validator.
            self._db.create_collection(
                self._collection.name,
                validator=MANAGED_RULES_VALIDATOR,
                validationLevel="strict",
                validationAction="error",
            )
        except PyMongoError as exc:
            raise RulePersistenceError(
                safe_message="could not apply managed_rules schema validator",
                internal_detail=f"{type(exc).__name__}: {exc}",
            ) from exc

    def ensure_indexes(self) -> None:
        """Create the documented index set (idempotent)."""
        for spec in INDEX_SPECS:
            try:
                self._collection.create_index(
                    spec["key"],
                    name=spec["name"],
                    unique=spec.get("unique", False),
                )
            except PyMongoError as exc:
                raise RulePersistenceError(
                    safe_message=(
                        f"could not create index {spec['name']!r}"
                    ),
                    internal_detail=f"{type(exc).__name__}: {exc}",
                ) from exc



    # ------------------------------------------------------------------- create
    def create(self, definition: RuleDefinition) -> RuleDefinition:
        """Persist a new :class:`RuleDefinition`."""
        if not isinstance(definition, RuleDefinition):
            raise ValidationError(
                safe_message="invalid rule definition",
                internal_detail=(
                    f"expected RuleDefinition, got {type(definition).__name__}"
                ),
            )
        doc = definition.to_canonical_dict()
        try:
            self._collection.insert_one(doc)
        except DuplicateKeyError as exc:
            raise DuplicateManagedRuleError(
                safe_message=(
                    f"rule {definition.rule_id!r} v{definition.version} "
                    "is already registered"
                ),
                internal_detail=(
                    f"rule_id={definition.rule_id!r} "
                    f"version={definition.version}"
                ),
            ) from exc
        except PyMongoError as exc:
            raise RulePersistenceError(
                safe_message="could not persist rule definition",
                internal_detail=f"{type(exc).__name__}: {exc}",
            ) from exc
        return definition

    # ------------------------------------------------------------------- read
    def get(
        self,
        rule_id: str,
        version: Optional[int] = None,
    ) -> Optional[RuleDefinition]:
        """Fetch a single rule definition by ``(rule_id, version)``."""
        if not isinstance(rule_id, str) or not rule_id:
            raise ValidationError(
                safe_message="invalid rule_id",
                internal_detail=(
                    f"rule_id must be a non-empty str, got {type(rule_id).__name__}"
                ),
            )
        query: Dict[str, Any] = {"rule_id": rule_id}
        if version is not None:
            if not isinstance(version, int) or isinstance(version, bool):
                raise ValidationError(
                    safe_message="invalid version",
                    internal_detail=(
                        f"version must be an int, got {type(version).__name__}"
                    ),
                )
            query["version"] = version
        try:
            if version is None:
                doc = self._collection.find_one(
                    query, sort=[("version", DESCENDING)]
                )
            else:
                doc = self._collection.find_one(query)
        except PyMongoError as exc:
            raise RulePersistenceError(
                safe_message="could not read rule definition",
                internal_detail=f"{type(exc).__name__}: {exc}",
            ) from exc
        if doc is None:
            return None
        return _document_to_definition(doc)



    def find_latest_versions(
        self, *, state: Optional[RuleState] = None
    ) -> List[RuleDefinition]:
        """Return the latest version of every ``rule_id``."""
        query: Dict[str, Any] = {}
        if state is not None:
            query["state"] = state.value
        try:
            pipeline: List[Dict[str, Any]] = []
            if query:
                pipeline.append({"$match": query})
            pipeline.extend(
                [
                    {"$sort": {"rule_id": 1, "version": -1}},
                    {
                        "$group": {
                            "_id": "$rule_id",
                            "doc": {"$first": "$$ROOT"},
                        }
                    },
                    {"$replaceRoot": {"newRoot": "$doc"}},
                    {"$sort": {"rule_id": 1}},
                ]
            )
            docs = list(self._collection.aggregate(pipeline))
        except PyMongoError as exc:
            raise RulePersistenceError(
                safe_message="could not read latest rule definitions",
                internal_detail=f"{type(exc).__name__}: {exc}",
            ) from exc
        return [
            d for d in (_document_to_definition(doc) for doc in docs) if d is not None
        ]

    def find_all(
        self, *, state: Optional[RuleState] = None
    ) -> List[RuleDefinition]:
        """Return every persisted rule, optionally filtered by ``state``."""
        query: Dict[str, Any] = {}
        if state is not None:
            query["state"] = state.value
        try:
            cursor = self._collection.find(query).sort(
                [("rule_id", ASCENDING), ("version", ASCENDING)]
            )
            docs = list(cursor)
        except PyMongoError as exc:
            raise RulePersistenceError(
                safe_message="could not read rule definitions",
                internal_detail=f"{type(exc).__name__}: {exc}",
            ) from exc
        return [
            d for d in (_document_to_definition(doc) for doc in docs) if d is not None
        ]



    # ------------------------------------------------------------------ update
    def update(self, definition: RuleDefinition) -> RuleDefinition:
        """Replace the persisted copy of ``(rule_id, version)``."""
        if not isinstance(definition, RuleDefinition):
            raise ValidationError(
                safe_message="invalid rule definition",
                internal_detail=(
                    f"expected RuleDefinition, got {type(definition).__name__}"
                ),
            )
        doc = definition.to_canonical_dict()
        try:
            result = self._collection.replace_one(
                {"rule_id": definition.rule_id, "version": definition.version},
                doc,
                upsert=False,
            )
        except PyMongoError as exc:
            raise RulePersistenceError(
                safe_message="could not update rule definition",
                internal_detail=f"{type(exc).__name__}: {exc}",
            ) from exc
        if result.matched_count == 0:
            raise RulePersistenceError(
                safe_message="rule definition not found for update",
                internal_detail=(
                    f"rule_id={definition.rule_id!r} "
                    f"version={definition.version}"
                ),
            )
        return definition

    def set_state_field(
        self, rule_id: str, version: int, new_state: str
    ) -> None:
        """Update the ``state`` field directly in MongoDB."""
        if not isinstance(rule_id, str) or not rule_id:
            raise ValidationError(
                safe_message="invalid rule_id",
                internal_detail=(
                    f"rule_id must be a non-empty str, got {type(rule_id).__name__}"
                ),
            )
        if not isinstance(version, int) or isinstance(version, bool) or version < 1:
            raise ValidationError(
                safe_message="invalid version",
                internal_detail=f"got {version!r}",
            )
        if not isinstance(new_state, str) or new_state not in (
            "candidate",
            "approved",
            "retired",
        ):
            raise ValidationError(
                safe_message="invalid state",
                internal_detail=f"got {new_state!r}",
            )
        try:
            self._collection.update_one(
                {"rule_id": rule_id, "version": version},
                {"$set": {"state": new_state}},
            )
        except PyMongoError as exc:
            raise RulePersistenceError(
                safe_message="could not update rule state",
                internal_detail=f"{type(exc).__name__}: {exc}",
            ) from exc

    def set_enabled_field(
        self, rule_id: str, version: int, enabled: bool
    ) -> None:
        """Update the ``enabled`` flag directly in MongoDB."""
        if not isinstance(rule_id, str) or not rule_id:
            raise ValidationError(
                safe_message="invalid rule_id",
                internal_detail=(
                    f"rule_id must be a non-empty str, got {type(rule_id).__name__}"
                ),
            )
        if not isinstance(version, int) or isinstance(version, bool) or version < 1:
            raise ValidationError(
                safe_message="invalid version",
                internal_detail=f"got {version!r}",
            )
        if not isinstance(enabled, bool):
            raise ValidationError(
                safe_message="invalid enabled",
                internal_detail=f"got {type(enabled).__name__}",
            )
        try:
            self._collection.update_one(
                {"rule_id": rule_id, "version": version},
                {"$set": {"enabled": bool(enabled)}},
            )
        except PyMongoError as exc:
            raise RulePersistenceError(
                safe_message="could not update rule enabled",
                internal_detail=f"{type(exc).__name__}: {exc}",
            ) from exc



    # ---------------------------------------------------------------- delete
    def set_capability_id_if_missing(
        self, rule_id: str, version: int, capability_id: str
    ) -> bool:
        """Fill a **missing** capability owner on an existing rule row.

        Returns ``True`` when a row was updated. This is a bounded,
        non-destructive backfill used by the managed-rule seeding
        reconciliation (2026-09-18 audit): a ``managed_rules`` row created
        before the shipped library rules declared their capability owner keeps
        ``capability_id: null`` forever, because seeding is insert-only. The
        persisted catalogue then contradicts the live registry (the Rules page
        truthfully reports "no capability owner" while the detector knows
        ``cap-nginx``), which breaks the verifiability of capability ownership.

        Safety rules:
        * only a **missing / null** owner is filled — an owner that is already
          present (operator-set or previously backfilled) is never overwritten;
        * ``capability_id`` must be a non-empty string matching the capability
          id contract, so a malformed value can never be persisted;
        * the update is a single conditional ``update_one`` filtered on the
          null/absent owner, so concurrent callers cannot race a value in.
        """
        if not isinstance(rule_id, str) or not rule_id:
            raise ValidationError(
                safe_message="invalid rule_id",
                internal_detail=(
                    f"rule_id must be a non-empty str, got {type(rule_id).__name__}"
                ),
            )
        if not isinstance(version, int) or isinstance(version, bool) or version < 1:
            raise ValidationError(
                safe_message="invalid version",
                internal_detail=f"got {version!r}",
            )
        if not isinstance(capability_id, str) or not capability_id:
            raise ValidationError(
                safe_message="invalid capability_id",
                internal_detail=(
                    f"capability_id must be a non-empty str, got "
                    f"{type(capability_id).__name__}"
                ),
            )
        if not CAPABILITY_ID_RE.match(capability_id):
            raise ValidationError(
                safe_message="invalid capability_id",
                internal_detail=f"capability_id={capability_id!r}",
            )
        try:
            result = self._collection.update_one(
                {
                    "rule_id": rule_id,
                    "version": version,
                    "capability_id": None,
                },
                {"$set": {"capability_id": capability_id}},
            )
        except PyMongoError as exc:
            raise RulePersistenceError(
                safe_message="could not backfill the rule capability owner",
                internal_detail=f"{type(exc).__name__}: {exc}",
            ) from exc
        return bool(getattr(result, "modified_count", 0))

    def soft_delete(
        self, rule_id: str, version: int
    ) -> None:
        """Mark a rule as RETIRED (soft-delete)."""
        if not isinstance(rule_id, str) or not rule_id:
            raise ValidationError(
                safe_message="invalid rule_id",
                internal_detail=(
                    f"rule_id must be a non-empty str, got {type(rule_id).__name__}"
                ),
            )
        if not isinstance(version, int) or isinstance(version, bool) or version < 1:
            raise ValidationError(
                safe_message="invalid version",
                internal_detail=f"got {version!r}",
            )
        try:
            self._collection.update_one(
                {"rule_id": rule_id, "version": version},
                {"$set": {"state": "retired", "enabled": False}},
            )
        except PyMongoError as exc:
            raise RulePersistenceError(
                safe_message="could not retire rule",
                internal_detail=f"{type(exc).__name__}: {exc}",
            ) from exc

    def count(self) -> int:
        try:
            return int(self._collection.count_documents({}))
        except PyMongoError as exc:
            raise RulePersistenceError(
                safe_message="could not count rules",
                internal_detail=f"{type(exc).__name__}: {exc}",
            ) from exc


# ----------------------------------------------------------------- helpers
def _document_to_definition(
    doc: Dict[str, Any],
) -> Optional[RuleDefinition]:
    """Convert a MongoDB document back into a :class:`RuleDefinition`.

    Returns ``None`` (with a structured warning logged) when the
    document cannot be validated as a :class:`RuleDefinition`. The
    caller (``find_latest_versions`` / ``find_all``) filters out
    ``None`` entries so a single poisoned document never aborts the
    registry reload.

    This is the runtime backstop for the BSON ``$jsonSchema``
    validator. The model layer is the source of truth; the
    function is total: every shape that reaches here is either
    a valid :class:`RuleDefinition` or ``None``.
    """
    cleaned = {k: v for k, v in doc.items() if k != "_id"}
    try:
        cond = cleaned.get("conditions")
        if cond is not None and isinstance(cond, dict):
            cleaned["conditions"] = _rebuild_expression(cond)
        return RuleDefinition.model_validate(cleaned)
    except (PydanticValidationError, ValueError, TypeError) as exc:
        _log.warning(
            "rule_repository.document_quarantined",
            extra={
                "rule_id": cleaned.get("rule_id"),
                "version": cleaned.get("version"),
                "error_type": type(exc).__name__,
                "error": str(exc)[:512],
            },
        )
        return None


def _rebuild_expression(node: Dict[str, Any]) -> Any:
    """Recursively rebuild an :class:`Expression` from a Mongo document."""
    from ..rules.management.conditions import (
        Atom,
        Expression,
        Group,
    )

    if not isinstance(node, dict):
        raise ValueError(f"conditions node must be a dict, got {type(node).__name__}")
    kind = node.get("kind")
    if kind == "atom":
        return Expression.from_atom(Atom.model_validate(node.get("atom", {})))
    if kind == "group":
        group_doc = dict(node.get("group", {}))
        group_doc["children"] = [
            _rebuild_expression(c) for c in group_doc.get("children", [])
        ]
        return Expression.from_group(Group.model_validate(group_doc))
    raise ValueError(f"unknown expression kind {kind!r}")


__all__ = [
    "INDEX_SPECS",
    "MANAGED_RULES_VALIDATOR",
    "RuleRepository",
    "managed_rule_collection_name",
]

