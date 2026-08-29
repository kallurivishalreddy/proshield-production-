"""MongoDB $jsonSchema validator for the security_events collection.

The application performs the primary validation (Pydantic model, schema
Section 13), and the database applies a complementary structural
validator.  This is the documented defense-in-depth posture
(docs/PHASE 2/SECURITY_EVENT_SCHEMA.md, Section 22).

The validator below mirrors the canonical contract. We intentionally
keep it permissive on ``details`` (object-with-properties) and strict
on the documented required fields and their types.
"""
from __future__ import annotations

from typing import Any, Dict


SECURITY_EVENTS_VALIDATOR: Dict[str, Any] = {
    "$jsonSchema": {
        "bsonType": "object",
        "required": [
            "event_id",
            "event_time",
            "ingested_at",
            "source",
            "event_type",
            "provenance",
            "schema_version",
        ],
        # MongoDB always adds an ``_id`` field.  We explicitly allow it
        # here and rely on the ``properties`` block to forbid any other
        # unexpected keys.  We do not validate ``_id`` here because
        # pymongo controls its shape; it is a server-managed ObjectId.
        "properties": {
            "_id": {
                "bsonType": "objectId",
            },
            "event_id": {
                "bsonType": "string",
                "minLength": 1,
                "maxLength": 64,
                "description": "Globally unique UUIDv7 (RFC 9562).",
            },
            "event_time": {
                "bsonType": "date",
                "description": "UTC timestamp observed at the source.",
            },
            "ingested_at": {
                "bsonType": "date",
                "description": "UTC timestamp when ProShield received the event.",
            },
            "source": {
                "bsonType": "string",
                "minLength": 1,
                "maxLength": 64,
                "pattern": "^[a-z0-9_\\-]+$",
            },
            "event_type": {
                "bsonType": "string",
                "minLength": 1,
                "maxLength": 64,
                "pattern": "^[a-z0-9_]+$",
            },
            "source_ip": {
                "bsonType": ["string", "null"],
                "maxLength": 64,
            },
            "destination": {
                "bsonType": ["string", "null"],
                "maxLength": 256,
            },
            "endpoint": {
                "bsonType": ["string", "null"],
                "maxLength": 512,
            },
            "asset": {
                "bsonType": ["string", "null"],
                "maxLength": 128,
            },
            "account": {
                "bsonType": ["object", "null"],
            },
            "device": {
                "bsonType": ["object", "null"],
            },
            "details": {
                "bsonType": "object",
            },
            "provenance": {
                "bsonType": "object",
                "required": ["collector", "source_event_id"],
                "additionalProperties": False,
                "properties": {
                    "collector": {
                        "bsonType": "string",
                        "minLength": 1,
                        "maxLength": 64,
                    },
                    "source_event_id": {
                        "bsonType": "string",
                        "minLength": 1,
                        "maxLength": 256,
                    },
                },
            },
            "schema_version": {
                "bsonType": "string",
                "minLength": 1,
                "maxLength": 16,
                "pattern": "^\\d+\\.\\d+$",
            },
        },
    }
}
