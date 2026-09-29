"""Serve a ProShield release directory as the testing update channel.

This is the *publisher* side of the automatic-update design: it exposes
``dist/windows/<version>/`` (manifest.json, the installer and the checksums)
over loopback HTTP so an existing installation can detect, verify and apply the
release through exactly the production code path.

Usage::

    # serve the newest built release on port 8099
    python -m scripts.publish_update_channel --port 8099

    # serve a specific release and also publish deliberately untrusted
    # manifests, for negative testing of the trust chain
    python -m scripts.publish_update_channel --version 1.0.1 --port 8099 --forge

Contains no security logic: it only copies bytes out of the release directory.
"""
from __future__ import annotations

import argparse
import json
import sys
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import List, Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

RELEASE_ROOT = ROOT / "dist" / "windows"
PRIVATE_KEY_FILE = ROOT / "deploy" / "signing" / "proshield-update-private.pem"


def latest_release() -> Optional[Path]:
    if not RELEASE_ROOT.is_dir():
        return None
    candidates = sorted(
        (p for p in RELEASE_ROOT.iterdir() if p.is_dir() and p.name[0].isdigit()),
        key=lambda p: [int(part) for part in p.name.split(".") if part.isdigit()] or [0],
    )
    return candidates[-1] if candidates else None


def forge_untrusted_manifests(release: Path) -> List[str]:
    """Publish manifests that MUST be rejected, for live negative testing.

    * ``manifest-forged.json``   - signed with a different (attacker) key
    * ``manifest-badhash.json``  - signed with the real key but describing a
      package whose SHA-256 does not match the bytes on disk
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
    )

    from service import update_manifest

    real = json.loads((release / "manifest.json").read_text(encoding="utf-8"))
    artifact = real["artifacts"]["windows-x64"]
    written: List[str] = []

    attacker_key = Ed25519PrivateKey.generate()
    attacker_path = release / "_attacker.key"
    attacker_path.write_bytes(
        attacker_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    try:
        forged = update_manifest.build_signed_manifest(
            version=str(real["version"]) + ".1",
            channel=real.get("channel", "testing"),
            artifacts={"windows-x64": dict(artifact)},
            private_key_path=attacker_path,
            notes="forged manifest (negative test)",
        )
    finally:
        attacker_path.unlink(missing_ok=True)
    (release / "manifest-forged.json").write_text(
        json.dumps(forged, indent=2, sort_keys=True), encoding="utf-8"
    )
    written.append("manifest-forged.json")

    if PRIVATE_KEY_FILE.is_file():
        tampered = dict(artifact)
        tampered["sha256"] = "0" * 64
        bad_hash = update_manifest.build_signed_manifest(
            version=str(real["version"]),
            channel=real.get("channel", "testing"),
            artifacts={"windows-x64": tampered},
            private_key_path=PRIVATE_KEY_FILE,
            notes="hash mismatch (negative test)",
        )
        (release / "manifest-badhash.json").write_text(
            json.dumps(bad_hash, indent=2, sort_keys=True), encoding="utf-8"
        )
        written.append("manifest-badhash.json")

    return written


class _QuietHandler(SimpleHTTPRequestHandler):
    """Directory server that logs only what ProShield actually fetched."""

    def log_message(self, fmt, *args):  # noqa: D102
        sys.stderr.write(f"[channel] {self.address_string()} {fmt % args}\n")

    def end_headers(self):  # noqa: D102
        self.send_header("Cache-Control", "no-store")
        super().end_headers()


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Serve a ProShield release directory as the testing update channel."
    )
    parser.add_argument("--version", default="", help="release version to serve")
    parser.add_argument("--port", type=int, default=8099)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument(
        "--forge",
        action="store_true",
        help="also publish manifests that must be REJECTED (negative testing)",
    )
    parser.add_argument(
        "--duration", type=float, default=0.0, help="stop after N seconds (0 = forever)"
    )
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    release = (RELEASE_ROOT / args.version) if args.version else latest_release()
    if release is None or not release.is_dir():
        print(f"no release directory found under {RELEASE_ROOT}")
        return 2

    manifest = release / "manifest.json"
    if not manifest.is_file():
        print(f"{release} has no manifest.json - build a release first")
        return 2

    if args.forge:
        for name in forge_untrusted_manifests(release):
            print(f"negative-test manifest written: {name}")

    document = json.loads(manifest.read_text(encoding="utf-8"))
    artifact = document.get("artifacts", {}).get("windows-x64", {})

    def handler(*a, **kw):
        return _QuietHandler(*a, directory=str(release), **kw)

    server = ThreadingHTTPServer((args.host, args.port), handler)
    base = f"http://{args.host}:{args.port}"

    print("=" * 72)
    print("ProShield testing update channel")
    print("=" * 72)
    print(f"  release   : {release}")
    print(f"  channel   : {document.get('channel')}  version {document.get('version')}")
    print(f"  signed    : {'signature' in document}")
    print(f"  artefact  : {artifact.get('filename')}  ({artifact.get('size')} bytes)")
    print()
    print("  point an installation at this channel with:")
    print(f'    "update_manifest_url": "{base}/manifest.json"')
    print('    "update_mode": "automatic"')
    print(f"    or PROSHIELD_UPDATE_URL={base}/manifest.json")
    if args.forge:
        print()
        print("  negative endpoints:")
        print(f"    untrusted signature : {base}/manifest-forged.json")
        print(f"    hash mismatch       : {base}/manifest-badhash.json")
    print()

    if args.duration:
        timer = threading.Timer(args.duration, server.shutdown)
        timer.daemon = True
        timer.start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[channel] stopped")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
