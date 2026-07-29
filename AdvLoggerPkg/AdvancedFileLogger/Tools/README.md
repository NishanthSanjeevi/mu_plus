# AdvancedFileLogger encrypted logs

The AdvancedFileLogger feature can encrypt every `UEFI_LogN.txt` it writes to the logs
partition so that only the holder of a per-build private key can read them. Everything
needed lives in `Common/MU/AdvLoggerPkg` — a platform enables the feature with a single
`FeaturePcd`, with **zero** platform build-code changes.

## How it works

* **Per build, unique material.** On every DEBUG build with the feature enabled, the
  `AdvLoggerEncryptionKeyGen` build plugin generates a fresh RSA-4096 key pair and a
  random 128-bit **nonce**. The firmware embeds only the **public** certificate.
* **Envelope (`SFLOGE2`).** Each log file starts with a short plaintext header printing
  the build's nonce, followed by the binary envelope:
  * A 64-byte secret `AesKey || MacKey` (two independent random keys) is wrapped with
    **RSA-OAEP** (SHA-256, MGF1/SHA-256) to the embedded public key.
  * The log body is encrypted with **AES-256-CTR** (`AesKey`, random IV) — size
    preserving and seekable, matching the streaming write model.
  * The whole thing is authenticated with **HMAC-SHA256** over
    `Magic || Version || Flags || IV || WrappedKeyLen || WrappedKey || Ciphertext`
    (encrypt-then-MAC), so tampering or corruption is detected at decryption.
* **Decryption bundle.** The plugin publishes `AdvLogger_<nonce>.bin` (the nonce followed
  by the PKCS#8 private key) into the build output directory
  (e.g. `Build/<Platform>_INT/DEBUG_GCC/`).

## Authorization model (no central vault)

There is no key server. The per-build private key ships as a **build-output artifact**;
the product's build pipeline archives that directory, so access to the pipeline *is* the
product boundary. A dev with access to product X's pipeline can decrypt product X's logs,
and nothing else — no cross-product vault to maintain.

## Pipeline integration

Have the build pipeline archive the bundle produced next to the firmware:

```
**/AdvLogger_*.bin
```

The file name encodes the nonce, so each archived bundle is traceable to the exact UEFI
build it decrypts.

## Decrypting a captured log

Grab the `AdvLogger_<nonce>.bin` whose nonce matches the one printed at the top of the
captured log (the header shows `Nonce  : <hex>`), then:

```bash
python3 DecryptAdvLoggerLogs.py UEFI_Log1.txt AdvLogger_<nonce>.bin [output.txt]
```

The script reads the nonce from the bundle, checks it against the nonce printed in the
log (use `--force` to override a mismatch), verifies the HMAC, and decrypts. If you hand
it the wrong bundle it fails cleanly (RSA-OAEP unwrap or MAC verification fails).

### Low-level tool

`decrypt_advlogger.py` is the underlying envelope reader if you already have a raw private
key (PEM/DER/PKCS#12):

```bash
python3 decrypt_advlogger.py --key private_key.pem --in UEFI_Log1.txt --out UEFI_Log1.decoded
python3 decrypt_advlogger.py --selftest   # AES-256-CTR NIST SP 800-38A vector check
```

## Security properties and limitations

What this feature **does** provide:

* **Confidentiality.** Log contents are AES-256-CTR encrypted with a per-build key that
  never leaves the build output. Only the holder of the per-build private key (i.e.
  someone with access to the product's build pipeline artifacts) can read them.
* **Tamper / corruption detection of a captured file.** The HMAC-SHA256 tag
  (encrypt-then-MAC) detects any in-place modification, truncation, or bit-rot of a
  captured envelope. Decryption fails closed on any mismatch, and no plaintext is emitted
  before the MAC is verified.

What it deliberately does **not** provide (and why):

* **Not origin authenticity / forgery resistance.** The firmware embeds only the *public*
  key, which is extractable from the image. Anyone can therefore fabricate a brand-new,
  fully valid envelope. The MAC proves a captured file was not altered *after the fact* —
  it does not prove the file was produced by genuine firmware. Treat these logs as
  private diagnostic data, not as signed evidence.
* **Not rollback / replay proof.** An attacker with write access to the flash/partition
  could restore an earlier valid `(length, MAC)` checkpoint. Detecting that would require
  an external monotonic anchor, which is out of scope for a boot-time debug log.
* **Crash atomicity.** The length and MAC of the final flush are written separately, so a
  reset or power loss during the last flush can leave the *most recent* log unverifiable
  (it fails closed). Previously flushed logs are unaffected.

Key-artifact boundary: the private key in `AdvLogger_<nonce>.bin` is a build artifact
protected by the build pipeline's access control, **not** a repository secret. It is never
embedded in firmware (the post-build step fails the build if the private key is found in
the image, or if the public cert is missing). One leaked bundle exposes every log from
that one build. The feature is gated to DEBUG builds so no private key is ever emitted for
a RELEASE/production image.

## Requirements

* Python 3.9+ with the [`cryptography`](https://pypi.org/project/cryptography/) package.

## Tests

`test_advlogger_crypto.py` builds an envelope whose byte layout exactly mirrors the
firmware (`LogEncryptor.c`) and verifies round-trip decryption, tamper detection
(ciphertext and MAC), wrong-key rejection, the end-to-end bundle workflow, the nonce
mismatch guard, and malformed-bundle handling:

```bash
python3 test_advlogger_crypto.py
```
