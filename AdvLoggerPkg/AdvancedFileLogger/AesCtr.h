/** @file AesCtr.h

  AES-256 CTR helper for AdvancedFileLogger encryption.

  Copyright (C) Microsoft Corporation. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __AES_CTR_H__
#define __AES_CTR_H__

#ifdef AES_CTR_STANDALONE
#include <stddef.h>
#include <stdint.h>
typedef uint8_t  UINT8;
typedef uint16_t UINT16;
typedef uint64_t UINT64;
typedef size_t   UINTN;
typedef intptr_t  INTN;
#define IN
#define OUT
#define CONST  const
#define VOID   void
#define STATIC static
#else
#include <Base.h>
#endif

#define AES256_KEY_SIZE    32
#define AES_BLOCK_SIZE     16
#define AES256_ROUND_KEYS  240

typedef struct {
  UINT8    RoundKey[AES256_ROUND_KEYS];
} AES256_CONTEXT;

VOID
Aes256Init (
  OUT AES256_CONTEXT  *Context,
  IN  CONST UINT8     Key[AES256_KEY_SIZE]
  );

VOID
Aes256CtrCrypt (
  IN  CONST AES256_CONTEXT  *Context,
  IN  CONST UINT8           Nonce[AES_BLOCK_SIZE],
  IN  UINT64                Offset,
  IN  CONST UINT8           *Input,
  OUT UINT8                 *Output,
  IN  UINTN                 Length
  );

#endif // __AES_CTR_H__
