#!/usr/bin/env python3
"""Decrypt AdvancedFileLogger encrypted UEFI_LogN.txt files (envelope v2, SFLOGE2).

This module is the low-level envelope reader. For the user-facing workflow that takes
an ``AdvLogger_<nonce>.bin`` bundle, use ``DecryptAdvLoggerLogs.py`` (which imports this).

Envelope layout, written at file offset ``PrefixLen`` (all integers little-endian):
  0x00  Magic[8]       b"SFLOGE2\0"
  0x08  Version        UINT32 = 2
  0x0c  Flags          UINT32 = 0
  0x10  IV[16]         AES-256-CTR initial counter block (random per boot)
  0x20  WrappedKeyLen  UINT32 = 512 (RSA-4096)
  0x24  PlaintextLen   UINT32, number of ciphertext bytes after WrappedKey
  0x28  Mac[32]        HMAC-SHA256 tag (encrypt-then-MAC)
  0x48  WrappedKey     RSA-OAEP(SHA-256, MGF1/SHA-256, empty label) of a 32-byte MasterSecret
  0x48+WrappedKeyLen   Ciphertext[PlaintextLen]

Key material: RSA-OAEP wraps a 64-byte blob = AesKey[32] || MacKey[32] (two
independent random keys). Body uses AES-256-CTR(AesKey, IV). The MAC is
HMAC-SHA256(MacKey, Magic||Version||Flags||IV||WrappedKeyLen||WrappedKey||Ciphertext)
and is verified (constant-time) before decryption (encrypt-then-MAC).

A short human-readable ASCII prefix may precede the envelope (offset 0..PrefixLen)
printing "Nonce : <hex>" so a captured log can be matched to its AdvLogger_<hex>.bin.
The AES-CTR counter is relative to the envelope plaintext, so the prefix never shifts it.

AES-256-CTR: the 16-byte IV is a 128-bit big-endian counter; block for plaintext byte
offset P is IV + P//16, and byte P uses keystream offset P % 16.
"""

from __future__ import annotations

import argparse
import getpass
import hmac as _hmac
import struct
import sys
from pathlib import Path

MAGIC = b"SFLOGE2\0"
VERSION = 2
FLAGS = 0
IV_SIZE = 16
MAC_SIZE = 32
WRAPPED_KEY_SIZE = 512                 # RSA-4096 OAEP wrapped MasterSecret
WRAPPED_KEY_LEN_OFFSET = 32
PLAINTEXT_LEN_OFFSET = 36
MAC_OFFSET = 40
WRAPPED_KEY_OFFSET = 72
HEADER_SIZE = 72                       # Magic..Mac inclusive; WrappedKey starts here
WRAPPED_SECRET_SIZE = 64               # AesKey[32] || MacKey[32]

# AES self-test reference (pure Python, AES-256 encryption + CTR).
_SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]
_RCON = [0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d]


def _xtime(x: int) -> int:
    return ((x << 1) & 0xFF) ^ (0x1B if x & 0x80 else 0)


def _mul(x: int, y: int) -> int:
    result = 0
    while y:
        if y & 1:
            result ^= x
        x = _xtime(x)
        y >>= 1
    return result


def _expand_key_256(key: bytes) -> list[int]:
    if len(key) != 32:
        raise ValueError("AES-256 key must be 32 bytes")
    words = [list(key[i:i + 4]) for i in range(0, 32, 4)]
    for i in range(8, 4 * (14 + 1)):
        temp = words[i - 1].copy()
        if i % 8 == 0:
            temp = [_SBOX[temp[1]] ^ _RCON[i // 8], _SBOX[temp[2]], _SBOX[temp[3]], _SBOX[temp[0]]]
        elif i % 8 == 4:
            temp = [_SBOX[b] for b in temp]
        words.append([words[i - 8][j] ^ temp[j] for j in range(4)])
    return [b for word in words for b in word]


def _add_round_key(state: list[list[int]], round_key: list[int], rnd: int) -> None:
    base = rnd * 16
    for c in range(4):
        for r in range(4):
            state[r][c] ^= round_key[base + c * 4 + r]


def _sub_bytes(state: list[list[int]]) -> None:
    for r in range(4):
        for c in range(4):
            state[r][c] = _SBOX[state[r][c]]


def _shift_rows(state: list[list[int]]) -> None:
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]


def _mix_columns(state: list[list[int]]) -> None:
    for c in range(4):
        a, b, d, e = state[0][c], state[1][c], state[2][c], state[3][c]
        state[0][c] = _mul(a, 2) ^ _mul(b, 3) ^ d ^ e
        state[1][c] = a ^ _mul(b, 2) ^ _mul(d, 3) ^ e
        state[2][c] = a ^ b ^ _mul(d, 2) ^ _mul(e, 3)
        state[3][c] = _mul(a, 3) ^ b ^ d ^ _mul(e, 2)


def _aes256_encrypt_block(key: bytes, block: bytes) -> bytes:
    if len(block) != 16:
        raise ValueError("AES block must be 16 bytes")
    round_key = _expand_key_256(key)
    state = [[block[c * 4 + r] for c in range(4)] for r in range(4)]
    _add_round_key(state, round_key, 0)
    for rnd in range(1, 14):
        _sub_bytes(state)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, round_key, rnd)
    _sub_bytes(state)
    _shift_rows(state)
    _add_round_key(state, round_key, 14)
    return bytes(state[r][c] for c in range(4) for r in range(4))


def aes256_ctr_crypt_reference(key: bytes, nonce: bytes, data: bytes, offset: int = 0) -> bytes:
    if len(nonce) != 16:
        raise ValueError("CTR nonce must be 16 bytes")
    nonce_int = int.from_bytes(nonce, "big")
    out = bytearray()
    block_index = offset // 16
    byte_index = offset % 16
    pos = 0
    while pos < len(data):
        counter = ((nonce_int + block_index) & ((1 << 128) - 1)).to_bytes(16, "big")
        stream = _aes256_encrypt_block(key, counter)
        while byte_index < 16 and pos < len(data):
            out.append(data[pos] ^ stream[byte_index])
            pos += 1
            byte_index += 1
        block_index += 1
        byte_index = 0
    return bytes(out)


def run_selftest() -> None:
    # NIST SP 800-38A F.5.5 AES-256 CTR test vector.
    key = bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
    nonce = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    plaintext = bytes.fromhex(
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52ef"
        "f69f2445df4f9b17ad2b417be66c3710"
    )
    expected = bytes.fromhex(
        "601ec313775789a5b7a7f504bbf3d228"
        "f443e3ca4d62b59aca84e990cacaf5c5"
        "2b0930daa23de94ce87017ba2d84988d"
        "dfc9c58db67aada613c2dd08457941a6"
    )
    ciphertext = aes256_ctr_crypt_reference(key, nonce, plaintext)
    if ciphertext != expected:
        raise AssertionError("AES-256-CTR encryption self-test failed")
    decrypted = aes256_ctr_crypt_reference(key, nonce, ciphertext)
    if decrypted != plaintext:
        raise AssertionError("AES-256-CTR decryption self-test failed")
    split = aes256_ctr_crypt_reference(key, nonce, plaintext[:17]) + aes256_ctr_crypt_reference(key, nonce, plaintext[17:], 17)
    if split != expected:
        raise AssertionError("AES-256-CTR offset self-test failed")
    print("selftest: AES-256-CTR NIST vector passed")


def _load_private_key(path: Path, password: str | None):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import pkcs12

    data = path.read_bytes()
    password_bytes = password.encode("utf-8") if password else None
    if path.suffix.lower() in {".pfx", ".p12"}:
        key, _cert, _cas = pkcs12.load_key_and_certificates(data, password_bytes)
        if key is None:
            raise ValueError("PKCS#12 file does not contain a private key")
        return key
    try:
        return serialization.load_pem_private_key(data, password_bytes)
    except ValueError:
        return serialization.load_der_private_key(data, password_bytes)


def find_envelope_offset(blob: bytes, max_scan: int = 4096) -> int:
    """Return the offset of the SFLOGE2 envelope, tolerating a plaintext prefix.

    Encrypted logs may begin with a short human-readable Nonce prefix ahead of the
    binary envelope. Scan only a bounded region so a corrupt file cannot cause an
    unbounded search or match arbitrary trailing data.
    """
    limit = min(len(blob), max_scan + len(MAGIC))
    idx = blob.find(MAGIC, 0, limit)
    if idx < 0:
        raise ValueError("no SFLOGE2 envelope found in the first %d bytes" % max_scan)
    return idx


def decrypt_envelope(private_key, blob: bytes, offset: int = 0) -> bytes:
    """Verify and decrypt a single SFLOGE2 envelope located at ``offset``."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes

    if len(blob) - offset < WRAPPED_KEY_OFFSET:
        raise ValueError("input is too small to contain an AdvancedFileLogger envelope")
    if blob[offset:offset + 8] != MAGIC:
        raise ValueError("invalid magic; input is not an encrypted AdvancedFileLogger file")
    version, flags = struct.unpack_from("<II", blob, offset + 8)
    if version != VERSION:
        raise ValueError(f"unsupported envelope version {version}")
    if flags != FLAGS:
        raise ValueError(f"unsupported envelope flags 0x{flags:x}")
    iv = blob[offset + 16:offset + 32]
    wrapped_key_len, plaintext_len = struct.unpack_from("<II", blob, offset + WRAPPED_KEY_LEN_OFFSET)
    if wrapped_key_len != WRAPPED_KEY_SIZE:
        raise ValueError(f"unexpected wrapped key length {wrapped_key_len} (expected RSA-4096)")
    mac = blob[offset + MAC_OFFSET:offset + MAC_OFFSET + MAC_SIZE]
    start = offset + WRAPPED_KEY_OFFSET + wrapped_key_len
    end = start + plaintext_len
    if start > len(blob) or end > len(blob):
        raise ValueError("invalid wrapped key or plaintext length")
    wrapped_key = blob[offset + WRAPPED_KEY_OFFSET:start]
    ciphertext = blob[start:end]

    secret = private_key.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    if len(secret) != WRAPPED_SECRET_SIZE:
        raise ValueError(f"unexpected wrapped secret length {len(secret)}")
    aes_key, mac_key = secret[:32], secret[32:]

    # Encrypt-then-MAC: authenticate Magic||Version||Flags||IV||WrappedKeyLen||WrappedKey||Ciphertext.
    auth_header = blob[offset:offset + WRAPPED_KEY_LEN_OFFSET + 4] + wrapped_key
    expected_mac = _hmac_sha256(mac_key, auth_header + ciphertext)
    if not _hmac.compare_digest(expected_mac, mac):
        raise ValueError("MAC verification failed: the log is corrupt, truncated, or tampered")

    decryptor = Cipher(algorithms.AES(aes_key), modes.CTR(iv)).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def _hmac_sha256(key: bytes, data: bytes) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.hmac import HMAC

    mac = HMAC(key, hashes.SHA256())
    mac.update(data)
    return mac.finalize()


def decrypt_file(key_path: Path, in_path: Path, out_path: Path, password: str | None) -> None:
    blob = in_path.read_bytes()
    private_key = _load_private_key(key_path, password)
    offset = find_envelope_offset(blob)
    plaintext = decrypt_envelope(private_key, blob, offset)
    out_path.write_bytes(plaintext)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Decrypt encrypted AdvancedFileLogger logs (envelope v2)")
    parser.add_argument("--key", type=Path, help="RSA private key in PEM/DER or PKCS#12/PFX format")
    parser.add_argument("--in", dest="in_file", type=Path, help="encrypted UEFI_LogN.txt input")
    parser.add_argument("--out", dest="out_file", type=Path, help="plaintext output path")
    parser.add_argument("--password", help="private-key/PFX password; prompts when set to '-' ")
    parser.add_argument("--selftest", action="store_true", help="run AES-256-CTR NIST vector self-test")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.selftest:
        run_selftest()
        return 0
    if not args.key or not args.in_file or not args.out_file:
        raise SystemExit("--key, --in, and --out are required unless --selftest is used")
    password = getpass.getpass("Private key password: ") if args.password == "-" else args.password
    decrypt_file(args.key, args.in_file, args.out_file, password)
    return 0


if __name__ == "__main__":
    sys.exit(main())
