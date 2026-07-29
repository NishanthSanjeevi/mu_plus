#!/usr/bin/env python3
"""Decrypt an AdvancedFileLogger encrypted log using its AdvLogger_<nonce>.bin bundle.

Each firmware build produces a unique key pair and a matching decryption bundle
(AdvLogger_<nonce>.bin) in the build output directory, where the product's build
pipeline archives it. Every encrypted log file starts with a short plaintext header
that prints the same nonce, so you can pick the right bundle for a captured log.

Usage:
    python3 DecryptAdvLoggerLogs.py <UEFI_LogN.txt> <AdvLogger_<nonce>.bin> [output.txt]

The bundle (AdvLogger_<nonce>.bin) container format (v2, little-endian):
    Magic[8]  = b"ADVLOGB2"
    u32 Version = 2
    Nonce[16]                       (hex == printed nonce and bundle file name)
    u32 PrivLen + PrivKey[PrivLen]  (RSA private key, PKCS#8 DER)
"""

from __future__ import annotations

import argparse
import re
import struct
import sys
from pathlib import Path

# Reuse the vetted envelope/AES-CTR/HMAC logic from the sibling core decryptor.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import decrypt_advlogger as core  # noqa: E402

BUNDLE_MAGIC = b"ADVLOGB2"
BUNDLE_VERSION = 2
NONCE_LEN = 16
_PRINTED_NONCE_RE = re.compile(rb"Nonce\s*:\s*([0-9A-Fa-f]+)")


def parse_bundle(path: Path):
    """Parse and validate an AdvLogger_<nonce>.bin bundle. Returns (nonce_bytes, priv_der)."""
    data = path.read_bytes()
    header = len(BUNDLE_MAGIC) + 4 + NONCE_LEN + 4
    if len(data) < header:
        raise ValueError("bundle is too small to be valid")
    if data[:len(BUNDLE_MAGIC)] != BUNDLE_MAGIC:
        raise ValueError("not an AdvLogger bundle (bad magic)")

    off = len(BUNDLE_MAGIC)
    (version,) = struct.unpack_from("<I", data, off)
    off += 4
    if version != BUNDLE_VERSION:
        raise ValueError(f"unsupported bundle version {version}")

    nonce = data[off:off + NONCE_LEN]
    off += NONCE_LEN

    (priv_len,) = struct.unpack_from("<I", data, off)
    off += 4
    if priv_len == 0 or off + priv_len > len(data):
        raise ValueError("bundle private key length is invalid")
    priv_der = data[off:off + priv_len]
    off += priv_len

    if off != len(data):
        raise ValueError("bundle has unexpected trailing data")

    return nonce, priv_der


def load_private_key(priv_der: bytes):
    from cryptography.hazmat.primitives.serialization import load_der_private_key

    private_key = load_der_private_key(priv_der, password=None)
    if getattr(private_key, "key_size", 0) != 4096:
        raise ValueError(f"unexpected RSA key size {getattr(private_key, 'key_size', 0)} (expected 4096)")
    return private_key


def read_printed_nonce(blob: bytes) -> str | None:
    match = _PRINTED_NONCE_RE.search(blob, 0, min(len(blob), 1024))
    if match is None:
        return None
    return match.group(1).decode("ascii").upper()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Decrypt an AdvancedFileLogger log using its AdvLogger_<nonce>.bin bundle."
    )
    parser.add_argument("log_file", type=Path, help="encrypted UEFI_LogN.txt input")
    parser.add_argument("bundle", type=Path, help="AdvLogger_<nonce>.bin bundle for the matching build")
    parser.add_argument("output", type=Path, nargs="?", help="decrypted output path (default: <log>.decrypted.txt)")
    parser.add_argument("--force", action="store_true", help="decrypt even if the nonce does not match")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    nonce, priv_der = parse_bundle(args.bundle)
    nonce_hex = nonce.hex().upper()
    private_key = load_private_key(priv_der)

    blob = args.log_file.read_bytes()
    printed_nonce = read_printed_nonce(blob)
    if printed_nonce is not None and printed_nonce != nonce_hex:
        message = (
            f"Nonce mismatch: '{args.log_file.name}' was produced by build {printed_nonce}, "
            f"but this bundle is for build {nonce_hex}. Use AdvLogger_{printed_nonce}.bin instead."
        )
        if not args.force:
            raise SystemExit(f"error: {message}\n(use --force to decrypt anyway)")
        print(f"warning: {message}", file=sys.stderr)

    try:
        offset = core.find_envelope_offset(blob)
    except ValueError as ex:
        raise SystemExit(f"error: {ex}")

    try:
        plaintext = core.decrypt_envelope(private_key, blob, offset)
    except ValueError as ex:
        raise SystemExit(f"error: {ex}")

    out_path = args.output or args.log_file.with_suffix(args.log_file.suffix + ".decrypted.txt")
    out_path.write_bytes(plaintext)
    print(f"Decrypted {len(plaintext)} bytes (nonce {nonce_hex}) -> {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
