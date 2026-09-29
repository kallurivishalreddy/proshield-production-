"""Generate the ProShield update-signing Ed25519 key pair.

Run this **once** per release channel, on a trusted machine::

    python -m deploy.signing.generate_keys --channel testing

Outputs:

    deploy/signing/proshield-update-private.pem      NEVER committed, NEVER packaged
    deploy/proshield-update.pub.pem                  shipped inside every install

The private key is the root of trust for the update channel.  Keep it in a
secret store (or an offline build machine).  ``deploy/build_windows.py``
reads it only to sign ``manifest.json``; it is never copied into
``dist/windows/<version>/`` and never reaches a customer machine.
"""
from __future__ import annotations

import argparse
import os
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SIGNING_DIR = ROOT / "deploy" / "signing"
PRIVATE_KEY_FILE = SIGNING_DIR / "proshield-update-private.pem"
PUBLIC_KEY_FILE = ROOT / "deploy" / "proshield-update.pub.pem"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Generate ProShield update signing keys.")
    parser.add_argument("--channel", default="testing", help="documentation only")
    parser.add_argument("--force", action="store_true", help="overwrite an existing private key")
    parser.add_argument(
        "--print-public",
        action="store_true",
        help="only print the existing public key fingerprint",
    )
    args = parser.parse_args(argv)

    if args.print_public:
        if not PUBLIC_KEY_FILE.is_file():
            print(f"no public key at {PUBLIC_KEY_FILE}")
            return 1
        print(PUBLIC_KEY_FILE.read_text(encoding="utf-8"))
        return 0

    if PRIVATE_KEY_FILE.is_file() and not args.force:
        print(
            f"refusing to overwrite the existing private key at {PRIVATE_KEY_FILE}.\n"
            "Overwriting it invalidates every previously published manifest.\n"
            "Re-run with --force only if you intend to rotate the channel key."
        )
        return 2

    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
            PublicFormat,
        )
    except ImportError as exc:
        print(f"cryptography is required: {exc}")
        return 3

    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    )
    public_pem = private_key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    )

    SIGNING_DIR.mkdir(parents=True, exist_ok=True)
    PRIVATE_KEY_FILE.write_bytes(private_pem)
    try:
        os.chmod(PRIVATE_KEY_FILE, stat.S_IREAD | stat.S_IWRITE)
    except OSError:
        pass
    PUBLIC_KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    PUBLIC_KEY_FILE.write_bytes(public_pem)

    print(f"channel          : {args.channel}")
    print(f"private key      : {PRIVATE_KEY_FILE}   (never commit, never package)")
    print(f"public key       : {PUBLIC_KEY_FILE}   (shipped to customers)")
    print()
    print("Add the private key to your secret store and keep "
          "deploy/signing/proshield-update-private.pem out of Git.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
