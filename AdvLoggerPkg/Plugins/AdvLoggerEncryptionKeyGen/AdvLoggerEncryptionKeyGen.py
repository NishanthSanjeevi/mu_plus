##
# AdvLoggerEncryptionKeyGen build plugin.
#
# Generates a UNIQUE RSA-4096 log-encryption key pair and a UNIQUE random nonce on
# every build, entirely from within AdvLoggerPkg, so platforms consume the encrypted
# AdvancedFileLogger feature with ZERO platform build-code changes.
#
#   * do_pre_build  - When the active platform enables AdvancedFileLogger encryption on
#                     a DEBUG build, generates the key pair and a random nonce, and emits
#                     a generated C header (AdvLoggerEncryptionKeyGen.h) into the
#                     AdvancedFileLogger module so the firmware embeds THIS build's public
#                     certificate and prints THIS build's nonce. Otherwise removes any
#                     stale generated header so it can never be silently reused.
#   * do_post_build - Verifies the generated certificate is embedded in the freshly built
#                     AdvancedFileLogger driver (and the private key is NOT), then publishes
#                     an AdvLogger_<nonce>.bin bundle (nonce + private key) into the build
#                     output directory, where the product's build pipeline archives it.
#
# The firmware encrypts logs with the PUBLIC key only; the published PRIVATE key is the
# host-side decryption key. Only logs produced by this exact build can be decrypted with
# this build's bundle. Nothing here signs firmware. Key publication is gated to DEBUG
# builds so a private key is never emitted for a RELEASE/production image.
#
# Authorization model: there is no central key vault. The per-build private key ships as
# a build-output artifact; access to the product's build pipeline (which archives the
# artifact) IS the product boundary. The nonce printed in each log is the human-readable
# join key that points a captured log at its AdvLogger_<nonce>.bin.
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause-Patent
##

import logging
import os
import re
import secrets
import shutil
import stat
import struct
from pathlib import Path

from edk2toolext.environment.plugintypes.uefi_build_plugin import IUefiBuildPlugin
from edk2toolext.environment.uefi_build import UefiBuilder

# AdvLogger decryption bundle (AdvLogger_<nonce>.bin) container format (v2):
#   Magic[8]      = b"ADVLOGB2"
#   Version  u32  (little endian) = 2
#   Nonce[16]     random per-build nonce (hex of these bytes == printed nonce / file name)
#   PrivLen  u32  (little endian) + PrivKey[PrivLen]   (RSA private key, PKCS#8 DER)
# followed by no trailing bytes. The nonce comes first, then the private key, per the
# locked design ("first part of the bin is the nonce and then the key").
ADVLOGGER_BIN_MAGIC = b"ADVLOGB2"
ADVLOGGER_BUNDLE_VERSION = 2
ADVLOGGER_NONCE_LEN = 16

# Name of the generated header consumed by LogEncryptor.c (git-ignored, per build).
GENERATED_HEADER_NAME = "AdvLoggerEncryptionKeyGen.h"

# Matches a platform enabling the feature: PcdAdvancedFileLoggerEncryptionEnable|TRUE
_ENCRYPTION_ENABLE_RE = re.compile(
    r"PcdAdvancedFileLoggerEncryptionEnable\s*\|\s*TRUE", re.IGNORECASE
)


class AdvLoggerEncryptionKeyGen(IUefiBuildPlugin):
    """Generates and publishes per-build AdvancedFileLogger log encryption material."""

    def __init__(self) -> None:
        self._module_dir = None
        self._nonce = None        # hex string (uppercase)
        self._nonce_bytes = None
        self._cert_der = None
        self._priv_der = None

    # --- discovery / gating helpers ---------------------------------------------

    def _find_module_dir(self):
        """Locate the AdvancedFileLogger module directory relative to this plugin."""
        # .../AdvLoggerPkg/Plugins/AdvLoggerEncryptionKeyGen/<thisfile>
        advlogger_pkg = Path(__file__).resolve().parents[2]
        module_dir = advlogger_pkg / "AdvancedFileLogger"
        if not (module_dir / "LogEncryptor.c").is_file():
            return None
        return module_dir

    def _generated_header_path(self, module_dir: Path) -> Path:
        return module_dir / GENERATED_HEADER_NAME

    def _remove_stale_header(self, module_dir: Path) -> None:
        header = self._generated_header_path(module_dir)
        if header.exists():
            try:
                header.unlink()
                logging.info(f"AdvLoggerEncryptionKeyGen: removed stale {header}")
            except OSError as ex:
                logging.warning(f"AdvLoggerEncryptionKeyGen: could not remove {header}: {ex}")

    def _resolve_active_platform(self, thebuilder: UefiBuilder):
        """Resolve ACTIVE_PLATFORM (a WORKSPACE/PACKAGES_PATH-relative DSC path) to a file.

        ACTIVE_PLATFORM is stored relative to a packages path (e.g. "Msft3562WinPkg/
        Project.dsc"), so it must be resolved against WORKSPACE and every PACKAGES_PATH
        entry rather than the current directory.
        """
        active_platform = thebuilder.env.GetValue("ACTIVE_PLATFORM")
        if not active_platform:
            return None

        candidate = Path(active_platform)
        if candidate.is_absolute() and candidate.is_file():
            return candidate.resolve()

        roots = []
        workspace = thebuilder.env.GetValue("WORKSPACE")
        if workspace:
            roots.append(workspace)
        packages_path = thebuilder.env.GetValue("PACKAGES_PATH") or ""
        roots.extend(p for p in packages_path.split(os.pathsep) if p)

        for root in roots:
            resolved = Path(root) / active_platform
            if resolved.is_file():
                return resolved.resolve()
        return None

    def _encryption_requested(self, thebuilder: UefiBuilder) -> bool:
        """True only for DEBUG builds whose active platform enables log encryption.

        Gating on DEBUG keeps the private key out of RELEASE/production artifacts, and
        gating on the platform's PcdAdvancedFileLoggerEncryptionEnable|TRUE avoids
        touching platforms that do not use the feature - all without platform code.
        """
        target = (thebuilder.env.GetValue("TARGET") or "").upper()
        if target != "DEBUG":
            return False

        active_platform = self._resolve_active_platform(thebuilder)
        if active_platform is None:
            return False

        platform_dir = active_platform.parent
        for suffix in ("*.dsc", "*.dsc.inc", "*.inc"):
            for dsc in platform_dir.rglob(suffix):
                try:
                    if _ENCRYPTION_ENABLE_RE.search(dsc.read_text(errors="ignore")):
                        return True
                except OSError:
                    continue
        return False

    # --- generation helpers ------------------------------------------------------

    @staticmethod
    def _format_c_array(name: str, data: bytes) -> str:
        lines = [f"STATIC CONST UINT8  {name}[] = {{"]
        for i in range(0, len(data), 12):
            chunk = ", ".join(f"0x{b:02X}" for b in data[i:i + 12])
            lines.append(f"  {chunk},")
        lines.append("};")
        return "\n".join(lines)

    def _write_generated_header(self, module_dir: Path) -> None:
        header_path = self._generated_header_path(module_dir)
        cert_array = self._format_c_array("mAdvLoggerGenEncryptionCert", self._cert_der)
        content = (
            "/** @file\n"
            "  AUTO-GENERATED per build by the AdvLoggerEncryptionKeyGen build plugin.\n"
            "  DO NOT EDIT and DO NOT COMMIT - this file is regenerated on every build\n"
            "  and is intentionally git-ignored. It embeds this build's unique\n"
            "  AdvancedFileLogger log-encryption certificate and nonce.\n"
            "**/\n\n"
            "#ifndef ADV_LOGGER_ENCRYPTION_KEY_GEN_H_\n"
            "#define ADV_LOGGER_ENCRYPTION_KEY_GEN_H_\n\n"
            "#define ADV_LOGGER_GEN_ENCRYPTION_CERT  1\n"
            f'#define ADV_LOGGER_BUILD_NONCE_STRING  "{self._nonce}"\n\n'
            f"{cert_array}\n\n"
            "#endif // ADV_LOGGER_ENCRYPTION_KEY_GEN_H_\n"
        )
        # Atomic replace so a partial write can never be consumed by the compiler.
        tmp_path = header_path.with_suffix(".h.tmp")
        tmp_path.write_text(content)
        os.replace(tmp_path, header_path)
        logging.info(f"AdvLoggerEncryptionKeyGen: generated {header_path} (nonce {self._nonce})")

    def _force_module_rebuild(self, thebuilder: UefiBuilder) -> None:
        """Force the AdvancedFileLogger module to recompile so THIS build's key is embedded.

        The generated header is pulled in via __has_include, so an incremental build does
        not know to recompile LogEncryptor.c when the header is (re)generated. Because a
        fresh key is generated on every build, the module must be rebuilt every build;
        otherwise the firmware would embed a stale certificate that no longer matches the
        published private key. Deleting the module's stale build output guarantees a
        recompile + relink, and edk2 then regenerates the firmware volume automatically.
        """
        roots = []
        for key in ("BUILD_OUTPUT_BASE", "OUTPUT_DIRECTORY"):
            value = thebuilder.env.GetValue(key)
            if value:
                candidate = Path(value)
                if not candidate.is_absolute():
                    workspace = thebuilder.env.GetValue("WORKSPACE")
                    if workspace:
                        candidate = Path(workspace) / candidate
                roots.append(candidate)
        workspace = thebuilder.env.GetValue("WORKSPACE")
        if workspace:
            roots.append(Path(workspace) / "Build")

        seen = set()
        for root in roots:
            root = root.resolve()
            if root in seen or not root.is_dir():
                continue
            seen.add(root)
            for module_dir in root.rglob("AdvLoggerPkg/AdvancedFileLogger/AdvancedFileLogger"):
                if module_dir.is_dir():
                    shutil.rmtree(module_dir, ignore_errors=True)
                    logging.info(
                        f"AdvLoggerEncryptionKeyGen: cleared stale module build output {module_dir}"
                    )
            for pattern in ("AdvancedFileLogger.efi", "AdvancedFileLogger.dll"):
                for stray in root.rglob(pattern):
                    try:
                        stray.unlink()
                    except OSError:
                        pass

    def _build_bundle_bytes(self) -> bytes:
        return (
            ADVLOGGER_BIN_MAGIC
            + struct.pack("<I", ADVLOGGER_BUNDLE_VERSION)
            + self._nonce_bytes
            + struct.pack("<I", len(self._priv_der)) + self._priv_der
        )

    def _find_module_binary(self, build_output_base: str):
        base = Path(build_output_base)
        if not base.is_dir():
            return None
        for pattern in ("AdvancedFileLogger.efi", "AdvancedFileLogger.dll"):
            found = next(base.rglob(pattern), None)
            if found is not None:
                return found
        return None

    @staticmethod
    def _write_private_file(path: Path, data: bytes) -> None:
        # Create with owner-only permissions before writing key material.
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
        try:
            os.write(fd, data)
        finally:
            os.close(fd)

    # --- build hooks -------------------------------------------------------------

    def do_pre_build(self, thebuilder: UefiBuilder) -> int:
        """Generate this build's key pair + nonce and emit the generated header."""
        module_dir = self._find_module_dir()
        if module_dir is None:
            return 0  # AdvancedFileLogger not present in this workspace.

        if not self._encryption_requested(thebuilder):
            # Not a DEBUG build with encryption enabled: never leave a stale header
            # that a later build could silently consume.
            self._remove_stale_header(module_dir)
            return 0

        try:
            import datetime

            from cryptography import x509
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.x509.oid import NameOID
        except ImportError as ex:
            # Encryption was explicitly requested; fail the build with actionable guidance
            # rather than silently shipping an image whose logs cannot be decrypted.
            logging.error(
                "AdvLoggerEncryptionKeyGen: AdvancedFileLogger encryption is enabled but the "
                f"Python 'cryptography' package is unavailable ({ex}). Install it (pip install "
                "cryptography) or disable PcdAdvancedFileLoggerEncryptionEnable."
            )
            self._remove_stale_header(module_dir)
            return -1

        self._module_dir = module_dir

        # Unique random nonce per build (CSPRNG). This is the human-readable join key
        # printed in the log and used as the bundle file name; it is independent of the
        # key material so it never leaks anything about the key.
        self._nonce_bytes = secrets.token_bytes(ADVLOGGER_NONCE_LEN)
        self._nonce = self._nonce_bytes.hex().upper()

        private_key = rsa.generate_private_key(public_exponent=0x10001, key_size=4096)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AdvLoggerPkg"),
            x509.NameAttribute(
                NameOID.COMMON_NAME,
                "AdvancedFileLogger Per-Build Log Encryption NON-PRODUCTION",
            ),
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=20 * 365))
            .sign(private_key, hashes.SHA256())
        )

        self._cert_der = certificate.public_bytes(serialization.Encoding.DER)
        self._priv_der = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        self._write_generated_header(module_dir)
        self._force_module_rebuild(thebuilder)
        return 0

    def do_post_build(self, thebuilder: UefiBuilder) -> int:
        """Verify firmware embedding, then publish the decryption bundle + tools."""
        if self._nonce is None:
            return 0  # Generation did not run this build.

        build_output_base = thebuilder.env.GetValue("BUILD_OUTPUT_BASE")
        if not build_output_base:
            logging.error("AdvLoggerEncryptionKeyGen: BUILD_OUTPUT_BASE not set; cannot verify/publish.")
            return -1

        module_binary = self._find_module_binary(build_output_base)
        if module_binary is None:
            # Encryption was requested but the driver was not produced this build.
            logging.error(
                "AdvLoggerEncryptionKeyGen: AdvancedFileLogger driver binary not found under "
                f"{build_output_base}; cannot confirm the encryption key was embedded."
            )
            return -1

        binary_bytes = module_binary.read_bytes()
        if self._cert_der not in binary_bytes:
            logging.error(
                "AdvLoggerEncryptionKeyGen: the generated encryption certificate is NOT present "
                f"in {module_binary}. The firmware and the published key would not match - failing "
                "the build to avoid producing undecryptable logs."
            )
            return -1
        if self._priv_der in binary_bytes:
            # Must never happen: the private key must stay host-side only.
            logging.error(
                "AdvLoggerEncryptionKeyGen: the PRIVATE key was found inside the firmware binary "
                f"{module_binary}. Aborting to avoid shipping the decryption key."
            )
            return -1

        # Publish directly into the build output directory. The product's build pipeline
        # archives this directory, so the archived AdvLogger_<nonce>.bin is reachable only
        # by those with access to that pipeline (the product boundary).
        out_dir = Path(build_output_base)
        out_dir.mkdir(parents=True, exist_ok=True)

        bundle_path = out_dir / f"AdvLogger_{self._nonce}.bin"
        self._write_private_file(bundle_path, self._build_bundle_bytes())

        # Copy the host decrypt tools next to the bundle so it is a self-contained kit.
        tools_dir = self._module_dir / "Tools"
        for tool in ("DecryptAdvLoggerLogs.py", "decrypt_advlogger.py"):
            src = tools_dir / tool
            if src.is_file():
                shutil.copy2(src, out_dir / tool)
            else:
                logging.warning(f"AdvLoggerEncryptionKeyGen: decrypt tool missing: {src}")

        build_id = thebuilder.env.GetValue("BUILDID_STRING") or "unknown"
        target = thebuilder.env.GetValue("TARGET") or "unknown"
        (out_dir / "AdvLogger_README.txt").write_text(
            "AdvancedFileLogger encrypted-log decryption bundle\n"
            "==================================================\n\n"
            f"Nonce    : {self._nonce}\n"
            f"Build ID : {build_id}\n"
            f"Target   : {target}\n\n"
            "The UEFI Advanced Logger logs produced by THIS build are encrypted with a\n"
            "unique RSA-4096 key pair generated for this build only. Each encrypted log\n"
            "file begins with a short plaintext header that prints the same nonce shown\n"
            "above, so you can match a captured log to this bundle.\n\n"
            f"Bundle file: AdvLogger_{self._nonce}.bin  (nonce + private key)\n\n"
            "Decrypt a captured log with:\n\n"
            f"    python3 DecryptAdvLoggerLogs.py UEFI_Log1.txt AdvLogger_{self._nonce}.bin\n\n"
            "The log body is encrypted with AES-256-CTR and authenticated with an\n"
            "HMAC-SHA256 tag (encrypt-then-MAC), so tampering or corruption is detected\n"
            "at decryption time. SECURITY: the private key in the .bin is a build\n"
            "artifact protected by the build pipeline's access control, not a repository\n"
            "secret. Keep the build output directory protected and never commit it.\n"
        )

        logging.info(
            f"AdvLoggerEncryptionKeyGen: verified embedding and published "
            f"AdvLogger_{self._nonce}.bin to {out_dir}"
        )
        return 0
