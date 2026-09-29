"""Signed update manifest: schema, canonical serialisation and verification.

Trust model
-----------
A downloaded executable is **never** installed on its own authority.  The
updater requires two independent facts to agree:

1. **Hash** - the SHA-256 of the downloaded artefact must equal the SHA-256
   recorded in the manifest.  This defeats a corrupted or swapped package.
2. **Signature** - the manifest is signed with an Ed25519 private key.  The
   signature covers the *canonical* manifest payload, which contains the
   artefact hash, so the hash is authenticated transitively.

**Only the public key ships inside ProShield**
(``deploy/proshield-update.pub.pem``).  The private signing key is never
packaged, never installed and never present on a customer machine - see
``deploy/build_windows.py``.

Swapping channels
-----------------
The manifest declares its own ``channel`` and the ``update_manifest_url``
(``PROSHIELD_UPDATE_URL`` / ``proshield.json``) selects which manifest to read,
so the *same* updater serves the ``testing`` channel today and a
``stable``/``production`` channel later with no code change - only a different
endpoint and a differently signed manifest.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

MANIFEST_SCHEMA_VERSION = 1
SIGNATURE_FIELD = "signature"
PUBLIC_KEY_FILENAME = "proshield-update.pub.pem"

#: Channels a manifest may legitimately declare.
KNOWN_CHANNELS = ("testing", "beta", "stable", "production", "development")

#: Platform key inside ``artifacts``.
WINDOWS_PLATFORM = "windows-x64"


class ManifestError(Exception):
    """Raised when a manifest is missing, malformed or untrusted."""


# ------------------------------------------------------------------- hashing


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ------------------------------------------------------- canonical serialise


def canonical_payload(data: Dict[str, Any]) -> bytes:
    """The exact bytes that get signed / verified.

    Both the publisher (``packaging/build_windows.py``) and this verifier call
    this function, so the two can never drift apart.
    """
    payload = {key: value for key, value in data.items() if key != SIGNATURE_FIELD}
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


# ---------------------------------------------------------------------- keys


def load_public_key(path: Path):
    """Load the Ed25519 public key. Returns ``None`` when absent."""
    if not path.is_file():
        return None
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key  # type: ignore
    except Exception as exc:  # pragma: no cover
        raise ManifestError(f"cryptography is unavailable: {exc}") from exc
    try:
        key = load_pem_public_key(path.read_bytes())
    except Exception as exc:
        raise ManifestError(f"public key {path} is unreadable: {exc}") from exc
    return key


def verify_signature(payload: bytes, signature_b64: str, public_key) -> bool:
    """Verify a base64 Ed25519 signature over ``payload``."""
    try:
        from cryptography.exceptions import InvalidSignature  # type: ignore
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # type: ignore
            Ed25519PublicKey,
        )
    except Exception as exc:  # pragma: no cover
        raise ManifestError(f"cryptography is unavailable: {exc}") from exc

    if not isinstance(public_key, Ed25519PublicKey):
        raise ManifestError("update public key is not an Ed25519 key")
    try:
        raw = base64.b64decode(signature_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ManifestError(f"signature is not valid base64: {exc}") from exc
    try:
        public_key.verify(raw, payload)
        return True
    except InvalidSignature:
        return False


# ------------------------------------------------------------------ manifest


@dataclass(frozen=True)
class Artifact:
    """One downloadable package (per platform)."""

    url: str
    sha256: str
    size: int = 0
    filename: str = ""
    kind: str = "installer"
    signature: str = ""

    @property
    def name(self) -> str:
        return self.filename or self.url.rsplit("/", 1)[-1] or "ProShieldSetup.exe"

    def as_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "sha256": self.sha256,
            "size": self.size,
            "filename": self.name,
            "kind": self.kind,
        }


@dataclass(frozen=True)
class UpdateManifest:
    """A parsed, signature-verified update manifest."""

    manifest_schema: int = MANIFEST_SCHEMA_VERSION
    channel: str = "testing"
    version: str = "0.0.0"
    min_version: str = "0.0.0"
    released_at: str = ""
    notes: str = ""
    signature: str = ""
    artifacts: Dict[str, Artifact] = field(default_factory=dict)
    raw: Dict[str, Any] = field(default_factory=dict)
    verified: bool = False
    verify_detail: str = ""

    # ------------------------------------------------------------------ api
    def artifact_for(self, platform: str = WINDOWS_PLATFORM) -> Optional[Artifact]:
        return self.artifacts.get(platform)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "manifest_schema": self.manifest_schema,
            "channel": self.channel,
            "version": self.version,
            "min_version": self.min_version,
            "released_at": self.released_at,
            "notes": self.notes,
            "artifacts": {k: v.as_dict() for k, v in self.artifacts.items()},
            "verified": self.verified,
        }


def parse_manifest(raw_bytes: bytes) -> UpdateManifest:
    """Parse manifest bytes into an :class:`UpdateManifest` (no verification)."""
    try:
        data = json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ManifestError(f"manifest is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ManifestError("manifest root must be a JSON object")

    version = str(data.get("version") or "").strip()
    if not version:
        raise ManifestError("manifest is missing 'version'")

    channel = str(data.get("channel") or "testing").strip().lower()

    artifacts: Dict[str, Artifact] = {}
    raw_artifacts = data.get("artifacts")
    if isinstance(raw_artifacts, dict):
        for platform, entry in raw_artifacts.items():
            if not isinstance(entry, dict):
                continue
            url = str(entry.get("url") or "").strip()
            digest = str(entry.get("sha256") or "").strip().lower()
            if not url or not digest:
                continue
            artifacts[str(platform)] = Artifact(
                url=url,
                sha256=digest,
                size=int(entry.get("size") or 0),
                filename=str(entry.get("filename") or ""),
                kind=str(entry.get("kind") or "installer"),
                signature=str(entry.get("signature") or ""),
            )

    return UpdateManifest(
        manifest_schema=int(data.get("manifest_schema") or MANIFEST_SCHEMA_VERSION),
        channel=channel,
        version=version,
        min_version=str(data.get("min_version") or "0.0.0"),
        released_at=str(data.get("released_at") or ""),
        notes=str(data.get("notes") or ""),
        signature=str(data.get(SIGNATURE_FIELD) or ""),
        artifacts=artifacts,
        raw=data,
    )


def verify_manifest(
    manifest: UpdateManifest,
    public_key,
    allow_unsigned: bool = False,
    expected_channel: Optional[str] = None,
) -> UpdateManifest:
    """Return a verified copy of ``manifest`` or raise :class:`ManifestError`."""
    if expected_channel and manifest.channel != expected_channel:
        # 'stable' manifests are always acceptable: moving a testing install
        # onto the stable channel is a legitimate, deliberate promotion.
        if not (manifest.channel == "stable" and expected_channel == "testing"):
            raise ManifestError(
                f"manifest channel {manifest.channel!r} does not match "
                f"configured channel {expected_channel!r}"
            )

    if manifest.channel not in KNOWN_CHANNELS:
        raise ManifestError(f"unknown manifest channel {manifest.channel!r}")

    if not manifest.signature:
        if allow_unsigned:
            return _with_verification(
                manifest,
                True,
                "UNSIGNED manifest accepted - update_allow_unsigned is enabled "
                "(test only, never for production)",
            )
        raise ManifestError(
            "manifest carries no signature; refusing to trust it "
            "(set update_allow_unsigned only for isolated testing)"
        )

    if public_key is None:
        if allow_unsigned:
            return _with_verification(
                manifest, True, "signature present but no public key installed"
            )
        raise ManifestError(
            "no update public key installed "
            f"({PUBLIC_KEY_FILENAME}) - cannot verify the update"
        )

    payload = canonical_payload(manifest.raw)
    if not verify_signature(payload, manifest.signature, public_key):
        raise ManifestError("manifest signature verification FAILED")

    return _with_verification(
        manifest, True, f"signature ok (sha256={sha256_bytes(payload)[:16]}...)"
    )


def _with_verification(
    manifest: UpdateManifest, ok: bool, detail: str
) -> UpdateManifest:
    return UpdateManifest(
        manifest_schema=manifest.manifest_schema,
        channel=manifest.channel,
        version=manifest.version,
        min_version=manifest.min_version,
        released_at=manifest.released_at,
        notes=manifest.notes,
        signature=manifest.signature,
        artifacts=manifest.artifacts,
        raw=manifest.raw,
        verified=ok,
        verify_detail=detail,
    )


def verify_artifact(artifact: Artifact, path: Path) -> Tuple[bool, str]:
    """Check size (when declared) and SHA-256 of a downloaded artefact."""
    if not path.is_file():
        return False, f"artefact {path} does not exist"
    if artifact.size:
        actual_size = path.stat().st_size
        if actual_size != artifact.size:
            return False, (
                f"size mismatch: expected {artifact.size} bytes, got {actual_size}"
            )
    digest = sha256_file(path)
    if digest.lower() != artifact.sha256.lower():
        return False, (
            f"hash mismatch: expected {artifact.sha256}, computed {digest}"
        )
    return True, f"hash verified ({digest})"


def build_signed_manifest(
    *,
    version: str,
    channel: str,
    artifacts: Dict[str, Dict[str, Any]],
    private_key_path: Path,
    min_version: str = "0.0.0",
    released_at: str = "",
    notes: str = "",
) -> Dict[str, Any]:
    """Build a signed manifest document (release-time tool, see build script).

    The private key is read from ``private_key_path`` at *build* time only and
    is never copied into any artefact.
    """
    from cryptography.hazmat.primitives.serialization import (  # type: ignore
        load_pem_private_key,
    )

    payload: Dict[str, Any] = {
        "manifest_schema": MANIFEST_SCHEMA_VERSION,
        "channel": channel,
        "version": version,
        "min_version": min_version,
        "released_at": released_at,
        "notes": notes,
        "artifacts": artifacts,
    }
    key = load_pem_private_key(private_key_path.read_bytes(), password=None)
    signature = key.sign(canonical_payload(payload))
    payload[SIGNATURE_FIELD] = base64.b64encode(signature).decode("ascii")
    return payload