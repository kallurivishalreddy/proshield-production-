"""Unit tests for the safe-error contract on DomainError.

Reference: docs/PHASE 3/SECURE_FOUNDATION.md, Section 30
(Secure Error Handling): the client-facing error must not expose
stack traces, internal paths, MongoDB error bodies, or secrets.
The internal detail may carry diagnostics but MUST NOT be returned
to a client.
"""
from __future__ import annotations

from app.domain.errors import (
    AuthorizationError,
    ConflictEventError,
    DomainError,
    DuplicateEventError,
    IngestionError,
    NotFoundError,
    PersistenceError,
    ValidationError,
)


def test_validation_error_carries_safe_and_internal() -> None:
    e = ValidationError(
        safe_message="bad input",
        internal_detail="field=foo value=bar",
        field="foo",
    )
    assert e.safe_message == "bad input"
    assert e.internal_detail == "field=foo value=bar"
    assert e.field == "foo"
    assert e.code == "validation_error"
    assert e.http_status == 400


def test_duplicate_event_error_is_status_200() -> None:
    # Duplicate is a successful no-op for the caller.
    e = DuplicateEventError(safe_message="dup")
    assert e.http_status == 200


def test_conflict_event_error_is_status_409() -> None:
    e = ConflictEventError(safe_message="conflict")
    assert e.http_status == 409


def test_authorization_error_is_status_403() -> None:
    e = AuthorizationError(safe_message="forbidden")
    assert e.http_status == 403


def test_not_found_error_is_status_404() -> None:
    e = NotFoundError(safe_message="not found")
    assert e.http_status == 404


def test_persistence_error_is_status_503() -> None:
    e = PersistenceError(safe_message="db unavailable")
    assert e.http_status == 503


def test_persistence_error_must_not_leak_driver_message() -> None:
    # The internal_detail is the diagnostic; the safe_message is
    # what callers (e.g., API) are allowed to surface.
    e = PersistenceError(
        safe_message="database is unavailable",
        internal_detail="pymongo.errors.ServerSelectionTimeoutError: ...",
    )
    assert "pymongo" not in e.safe_message
    assert "pymongo" in e.internal_detail


def test_all_domain_errors_inherit_from_domain_error() -> None:
    for cls in (
        ValidationError,
        DuplicateEventError,
        ConflictEventError,
        AuthorizationError,
        NotFoundError,
        PersistenceError,
        IngestionError,
    ):
        assert issubclass(cls, DomainError)
