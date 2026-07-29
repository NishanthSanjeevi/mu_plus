#!/usr/bin/env python3
"""Host-side interop + tamper tests for AdvancedFileLogger envelope v2 (SFLOGE2).

The firmware encryptor cannot be run off-target, so this test builds an envelope whose
byte layout exactly mirrors LogEncryptor.c (Common/MU/AdvLoggerPkg/AdvancedFileLogger)
and verifies that decrypt_advlogger / DecryptAdvLoggerLogs decrypt it, that tampering is
detected (encrypt-then-MAC), and that mismatched keys / bundles are rejected.

AES-256-CTR, HMAC-SHA256 and RSA-OAEP(SHA-256) are standardized, so matching the layout
here guarantees interop with the BaseCryptLib implementations used by the firmware.

Run: python3 test_advlogger_crypto.py
"""

from __future__ import annotations

import io
import struct
import subprocess
import sys
import tempfile
from contextlib import redirect_stdout
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS_DIR))

import decrypt_advlogger as core  # noqa: E402
import DecryptAdvLoggerLogs as wrapper  # noqa: E402

from cryptography.hazmat.primitives import hashes, hmac  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding, rsa  # noqa: E402
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa: E402
from cryptography.hazmat.primitives.serialization import (  # noqa: E402
    Encoding,
    NoEncryption,
    PrivateFormat,
)

MAGIC = b"SFLOGE2\0"


def _oaep():
    return padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def build_firmware_envelope(public_key, plaintext: bytes, *, aes_key: bytes, mac_key: bytes, iv: bytes,
                            prefix: bytes = b"") -> bytes:
    """Reproduce LogEncryptor.c's exact on-disk bytes for a single envelope."""
    wrapped_key = public_key.encrypt(aes_key + mac_key, _oaep())
    assert len(wrapped_key) == core.WRAPPED_KEY_SIZE

    ciphertext = Cipher(algorithms.AES(aes_key), modes.CTR(iv)).encryptor().update(plaintext)

    header = bytearray(core.HEADER_SIZE)
    header[0:8] = MAGIC
    struct.pack_into("<I", header, 8, core.VERSION)
    struct.pack_into("<I", header, 12, core.FLAGS)
    header[16:32] = iv
    struct.pack_into("<I", header, core.WRAPPED_KEY_LEN_OFFSET, core.WRAPPED_KEY_SIZE)
    struct.pack_into("<I", header, core.PLAINTEXT_LEN_OFFSET, len(ciphertext))

    # Running HMAC over header[0:36] || wrapped_key || ciphertext (encrypt-then-MAC).
    mac = hmac.HMAC(mac_key, hashes.SHA256())
    mac.update(bytes(header[:core.PLAINTEXT_LEN_OFFSET]))
    mac.update(wrapped_key)
    mac.update(ciphertext)
    header[core.MAC_OFFSET:core.MAC_OFFSET + core.MAC_SIZE] = mac.finalize()

    return prefix + bytes(header) + wrapped_key + ciphertext


def _fresh_material():
    import os
    return os.urandom(32), os.urandom(32), os.urandom(16)


def _keypair():
    priv = rsa.generate_private_key(public_exponent=0x10001, key_size=4096)
    return priv, priv.public_key()


def test_roundtrip():
    priv, pub = _keypair()
    aes_key, mac_key, iv = _fresh_material()
    plaintext = b"UEFI PEI phase log line 1\nline 2 with binary \x00\x01\x02\xff\n" * 200
    blob = build_firmware_envelope(pub, plaintext, aes_key=aes_key, mac_key=mac_key, iv=iv)
    out = core.decrypt_envelope(priv, blob, core.find_envelope_offset(blob))
    assert out == plaintext, "round-trip plaintext mismatch"
    print("PASS: envelope v2 round-trip")


def test_roundtrip_with_prefix():
    priv, pub = _keypair()
    aes_key, mac_key, iv = _fresh_material()
    plaintext = b"prefixed log body\n" * 50
    prefix = b"====== AdvancedFileLogger Encrypted Log ======\nNonce  : ABCDEF\n...\n"
    blob = build_firmware_envelope(pub, plaintext, aes_key=aes_key, mac_key=mac_key, iv=iv, prefix=prefix)
    off = core.find_envelope_offset(blob)
    assert off == len(prefix), "envelope offset should equal prefix length"
    out = core.decrypt_envelope(priv, blob, off)
    assert out == plaintext
    print("PASS: envelope v2 round-trip with plaintext prefix")


def test_tamper_ciphertext():
    priv, pub = _keypair()
    aes_key, mac_key, iv = _fresh_material()
    blob = bytearray(build_firmware_envelope(pub, b"secret log data" * 30, aes_key=aes_key, mac_key=mac_key, iv=iv))
    body = core.find_envelope_offset(blob) + core.WRAPPED_KEY_OFFSET + core.WRAPPED_KEY_SIZE
    blob[body] ^= 0x01  # flip one ciphertext bit
    try:
        core.decrypt_envelope(priv, bytes(blob), core.find_envelope_offset(blob))
    except ValueError as ex:
        assert "MAC" in str(ex)
        print("PASS: ciphertext tamper rejected by MAC")
        return
    raise AssertionError("tampered ciphertext was not rejected")


def test_tamper_mac():
    priv, pub = _keypair()
    aes_key, mac_key, iv = _fresh_material()
    blob = bytearray(build_firmware_envelope(pub, b"data" * 100, aes_key=aes_key, mac_key=mac_key, iv=iv))
    off = core.find_envelope_offset(blob)
    blob[off + core.MAC_OFFSET] ^= 0x80  # corrupt the stored tag
    try:
        core.decrypt_envelope(priv, bytes(blob), off)
    except ValueError as ex:
        assert "MAC" in str(ex)
        print("PASS: MAC tag tamper rejected")
        return
    raise AssertionError("tampered MAC tag was not rejected")


def test_wrong_key():
    _, pub = _keypair()
    wrong_priv, _ = _keypair()
    aes_key, mac_key, iv = _fresh_material()
    blob = build_firmware_envelope(pub, b"data" * 100, aes_key=aes_key, mac_key=mac_key, iv=iv)
    try:
        core.decrypt_envelope(wrong_priv, blob, core.find_envelope_offset(blob))
    except ValueError:
        print("PASS: wrong private key rejected")
        return
    raise AssertionError("wrong private key was not rejected")


def _build_bundle(nonce: bytes, priv) -> bytes:
    priv_der = priv.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
    return b"ADVLOGB2" + struct.pack("<I", 2) + nonce + struct.pack("<I", len(priv_der)) + priv_der


def test_wrapper_end_to_end():
    import os
    priv, pub = _keypair()
    aes_key, mac_key, iv = _fresh_material()
    nonce = os.urandom(16)
    nonce_hex = nonce.hex().upper()
    plaintext = b"end to end wrapper log\n" * 40
    prefix = (f"====== AdvancedFileLogger Encrypted Log ======\n"
              f"Nonce  : {nonce_hex}\n"
              f"Encrypted content follows this header.\n").encode()
    blob = build_firmware_envelope(pub, plaintext, aes_key=aes_key, mac_key=mac_key, iv=iv, prefix=prefix)

    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        log = td / "UEFI_Log1.txt"
        log.write_bytes(blob)
        bundle = td / f"AdvLogger_{nonce_hex}.bin"
        bundle.write_bytes(_build_bundle(nonce, priv))
        out = td / "decrypted.txt"
        rc = subprocess.run(
            [sys.executable, str(TOOLS_DIR / "DecryptAdvLoggerLogs.py"), str(log), str(bundle), str(out)],
            capture_output=True, text=True,
        )
        assert rc.returncode == 0, f"wrapper failed: {rc.stderr}"
        assert out.read_bytes() == plaintext, "wrapper decrypted output mismatch"

        # parse_bundle sanity
        parsed_nonce, _ = wrapper.parse_bundle(bundle)
        assert parsed_nonce == nonce
        print("PASS: DecryptAdvLoggerLogs bundle-v2 end-to-end")


def test_nonce_mismatch_guard():
    import os
    priv, pub = _keypair()
    aes_key, mac_key, iv = _fresh_material()
    bundle_nonce = os.urandom(16)
    other_nonce = os.urandom(16)
    prefix = (f"Nonce  : {other_nonce.hex().upper()}\n").encode()
    blob = build_firmware_envelope(pub, b"x" * 64, aes_key=aes_key, mac_key=mac_key, iv=iv, prefix=prefix)
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        log = td / "UEFI_Log1.txt"
        log.write_bytes(blob)
        bundle = td / "AdvLogger_x.bin"
        bundle.write_bytes(_build_bundle(bundle_nonce, priv))
        rc = subprocess.run(
            [sys.executable, str(TOOLS_DIR / "DecryptAdvLoggerLogs.py"), str(log), str(bundle)],
            capture_output=True, text=True,
        )
        assert rc.returncode != 0 and "mismatch" in rc.stderr.lower(), rc.stderr
        # --force should succeed
        rc2 = subprocess.run(
            [sys.executable, str(TOOLS_DIR / "DecryptAdvLoggerLogs.py"), str(log), str(bundle), "--force"],
            capture_output=True, text=True,
        )
        assert rc2.returncode == 0, rc2.stderr
        print("PASS: nonce mismatch guarded (and --force override works)")


def test_bad_bundles():
    import os
    priv, _ = _keypair()
    good = _build_bundle(os.urandom(16), priv)
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        cases = {
            "bad magic": b"XXXXXXXX" + good[8:],
            "bad version": good[:8] + struct.pack("<I", 99) + good[12:],
            "trailing data": good + b"\x00",
            "too small": b"ADVLOGB2",
        }
        for name, data in cases.items():
            p = td / "b.bin"
            p.write_bytes(data)
            try:
                wrapper.parse_bundle(p)
            except ValueError:
                continue
            raise AssertionError(f"bad bundle not rejected: {name}")
    print("PASS: malformed bundles rejected")


def main() -> int:
    core.run_selftest()
    test_roundtrip()
    test_roundtrip_with_prefix()
    test_tamper_ciphertext()
    test_tamper_mac()
    test_wrong_key()
    test_wrapper_end_to_end()
    test_nonce_mismatch_guard()
    test_bad_bundles()
    print("\nALL TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
