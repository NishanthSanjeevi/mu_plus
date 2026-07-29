/** @file LogEncryptor.h

  AdvancedFileLogger hybrid encryption envelope helpers (envelope v2, "SFLOGE2").

  When a per-build nonce is available (see AdvLoggerEncryptionKeyGen.h, produced by
  the AdvLoggerEncryptionKeyGen build plugin), a short human-readable ASCII prefix is
  written at file offset 0 so an operator can correlate a captured log with the
  matching AdvLogger_<nonce>.bin decryption bundle. The binary envelope described
  below follows that prefix (its length is Context->PrefixLen; 0 when no prefix).

  Log files use little-endian multi-byte fields in the plaintext envelope header.
  The envelope, written at file offset Context->PrefixLen, is:

    Magic[8]="SFLOGE2\0" | UINT32 Version=2 | UINT32 Flags=0 | Iv[16] |
    UINT32 WrappedKeyLen=512 | UINT32 PlaintextLen | Mac[32] |
    WrappedKey[WrappedKeyLen] | AES-256-CTR ciphertext[PlaintextLen]

  WrappedKey is RSA-OAEP (SHA-256, MGF1/SHA-256, empty label) over a 64-byte blob
  AesKey[32] || MacKey[32] (two independent random keys). The body is
  AES-256-CTR(AesKey, Iv). Mac is HMAC-SHA256(MacKey, Magic||Version||Flags||Iv||
  WrappedKeyLen||WrappedKey||ciphertext) computed as a running HMAC across flushes
  (encrypt-then-MAC) for tamper-evidence.

  The AES-256-CTR keystream offset is relative to the envelope plaintext, so the
  optional plaintext prefix never affects the cipher counter math.

  Copyright (C) Microsoft Corporation. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __LOG_ENCRYPTOR_H__
#define __LOG_ENCRYPTOR_H__

#include <Base.h>
#include <Protocol/SimpleFileSystem.h>

#include "AesCtr.h"

#define ADV_LOG_ENCRYPTION_MAGIC                 "SFLOGE2"
#define ADV_LOG_ENCRYPTION_MAGIC_SIZE            8
#define ADV_LOG_ENCRYPTION_VERSION               2
#define ADV_LOG_ENCRYPTION_FLAGS                 0
#define ADV_LOG_ENCRYPTION_HEADER_SIZE           72
#define ADV_LOG_ENCRYPTION_PLAINTEXT_LEN_OFFSET  36
#define ADV_LOG_ENCRYPTION_MAC_OFFSET            40
#define ADV_LOG_ENCRYPTION_MAC_SIZE              32
#define ADV_LOG_ENCRYPTION_WRAPPED_KEY_SIZE      512
#define ADV_LOG_ENCRYPTION_WRAPPED_SECRET_SIZE   64

typedef struct {
  BOOLEAN           Initialized;
  UINT8             AesKey[AES256_KEY_SIZE];
  UINT8             MacKey[ADV_LOG_ENCRYPTION_MAC_SIZE];
  UINT8             Iv[AES_BLOCK_SIZE];
  UINT8             WrappedKey[ADV_LOG_ENCRYPTION_WRAPPED_KEY_SIZE];
  UINT32            WrappedKeyLen;
  UINT32            PrefixLen;
  UINT64            DataOffset;
  UINT64            HmacFedLen;
  VOID              *HmacContext;
  AES256_CONTEXT    AesContext;
} ADVANCED_FILE_LOGGER_ENCRYPTION_CONTEXT;

EFI_STATUS
LogEncryptorEnsureInitialized (
  IN OUT ADVANCED_FILE_LOGGER_ENCRYPTION_CONTEXT  *Context,
  IN     EFI_FILE                                 *File
  );

EFI_STATUS
LogEncryptorWrite (
  IN     EFI_FILE                                 *File,
  IN     ADVANCED_FILE_LOGGER_ENCRYPTION_CONTEXT  *Context,
  IN     UINT64                                   PlaintextOffset,
  IN     CONST VOID                               *Plaintext,
  IN OUT UINTN                                    *PlaintextSize
  );

EFI_STATUS
LogEncryptorUpdatePlaintextLen (
  IN EFI_FILE                                 *File,
  IN ADVANCED_FILE_LOGGER_ENCRYPTION_CONTEXT  *Context,
  IN UINT64                                   PlaintextLen
  );

VOID
LogEncryptorReset (
  IN OUT ADVANCED_FILE_LOGGER_ENCRYPTION_CONTEXT  *Context
  );

#endif // __LOG_ENCRYPTOR_H__
