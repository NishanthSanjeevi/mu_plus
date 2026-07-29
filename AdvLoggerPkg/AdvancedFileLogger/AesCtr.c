/** @file AesCtr.c

  AES-256 ECB core and CTR wrapper for AdvancedFileLogger encryption.

  This is a small AES-256-only port derived from tiny-AES-c
  (https://github.com/kokke/tiny-AES-c), which is released under The Unlicense
  (public domain dedication). Only the AES-256 key schedule/cipher path and a
  straightforward big-endian CTR mode wrapper are included here.

  Copyright (C) Microsoft Corporation. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "AesCtr.h"

#define AES_NB  4
#define AES_NK  8
#define AES_NR  14

STATIC CONST UINT8  mSbox[256] = {
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

STATIC CONST UINT8  mRcon[15] = {
  0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
  0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d
};

STATIC
UINT8
Xtime (
  IN UINT8  X
  )
{
  return (UINT8)((X << 1) ^ (((X >> 7) & 1) * 0x1b));
}

STATIC
UINT8
Multiply (
  IN UINT8  X,
  IN UINT8  Y
  )
{
  return (UINT8)((((Y & 1) * X) ^ (((Y >> 1) & 1) * Xtime (X)) ^ (((Y >> 2) & 1) * Xtime (Xtime (X))) ^
                  (((Y >> 3) & 1) * Xtime (Xtime (Xtime (X)))) ^ (((Y >> 4) & 1) * Xtime (Xtime (Xtime (Xtime (X)))))));
}

STATIC
VOID
KeyExpansion (
  OUT UINT8        *RoundKey,
  IN  CONST UINT8  *Key
  )
{
  UINTN  I;
  UINT8  Temp[4];
  UINT8  K;

  for (I = 0; I < AES_NK * 4; ++I) {
    RoundKey[I] = Key[I];
  }

  for (I = AES_NK; I < AES_NB * (AES_NR + 1); ++I) {
    Temp[0] = RoundKey[(I - 1) * 4 + 0];
    Temp[1] = RoundKey[(I - 1) * 4 + 1];
    Temp[2] = RoundKey[(I - 1) * 4 + 2];
    Temp[3] = RoundKey[(I - 1) * 4 + 3];

    if ((I % AES_NK) == 0) {
      K       = Temp[0];
      Temp[0] = (UINT8)(mSbox[Temp[1]] ^ mRcon[I / AES_NK]);
      Temp[1] = mSbox[Temp[2]];
      Temp[2] = mSbox[Temp[3]];
      Temp[3] = mSbox[K];
    } else if ((I % AES_NK) == 4) {
      Temp[0] = mSbox[Temp[0]];
      Temp[1] = mSbox[Temp[1]];
      Temp[2] = mSbox[Temp[2]];
      Temp[3] = mSbox[Temp[3]];
    }

    RoundKey[I * 4 + 0] = (UINT8)(RoundKey[(I - AES_NK) * 4 + 0] ^ Temp[0]);
    RoundKey[I * 4 + 1] = (UINT8)(RoundKey[(I - AES_NK) * 4 + 1] ^ Temp[1]);
    RoundKey[I * 4 + 2] = (UINT8)(RoundKey[(I - AES_NK) * 4 + 2] ^ Temp[2]);
    RoundKey[I * 4 + 3] = (UINT8)(RoundKey[(I - AES_NK) * 4 + 3] ^ Temp[3]);
  }
}

STATIC
VOID
AddRoundKey (
  IN UINT8        Round,
  IN OUT UINT8    State[4][4],
  IN CONST UINT8  *RoundKey
  )
{
  UINT8  I;
  UINT8  J;

  for (I = 0; I < 4; ++I) {
    for (J = 0; J < 4; ++J) {
      State[J][I] ^= RoundKey[(Round * AES_NB * 4) + (I * AES_NB) + J];
    }
  }
}

STATIC
VOID
SubBytes (
  IN OUT UINT8  State[4][4]
  )
{
  UINT8  I;
  UINT8  J;

  for (I = 0; I < 4; ++I) {
    for (J = 0; J < 4; ++J) {
      State[I][J] = mSbox[State[I][J]];
    }
  }
}

STATIC
VOID
ShiftRows (
  IN OUT UINT8  State[4][4]
  )
{
  UINT8  Temp;

  Temp        = State[1][0];
  State[1][0] = State[1][1];
  State[1][1] = State[1][2];
  State[1][2] = State[1][3];
  State[1][3] = Temp;

  Temp        = State[2][0];
  State[2][0] = State[2][2];
  State[2][2] = Temp;
  Temp        = State[2][1];
  State[2][1] = State[2][3];
  State[2][3] = Temp;

  Temp        = State[3][0];
  State[3][0] = State[3][3];
  State[3][3] = State[3][2];
  State[3][2] = State[3][1];
  State[3][1] = Temp;
}

STATIC
VOID
MixColumns (
  IN OUT UINT8  State[4][4]
  )
{
  UINT8  I;
  UINT8  A;
  UINT8  B;
  UINT8  C;
  UINT8  D;

  for (I = 0; I < 4; ++I) {
    A           = State[0][I];
    B           = State[1][I];
    C           = State[2][I];
    D           = State[3][I];
    State[0][I] = (UINT8)(Multiply (A, 2) ^ Multiply (B, 3) ^ C ^ D);
    State[1][I] = (UINT8)(A ^ Multiply (B, 2) ^ Multiply (C, 3) ^ D);
    State[2][I] = (UINT8)(A ^ B ^ Multiply (C, 2) ^ Multiply (D, 3));
    State[3][I] = (UINT8)(Multiply (A, 3) ^ B ^ C ^ Multiply (D, 2));
  }
}

STATIC
VOID
CipherBlock (
  IN OUT UINT8    *Buffer,
  IN CONST UINT8  *RoundKey
  )
{
  UINT8  State[4][4];
  UINT8  I;
  UINT8  J;
  UINT8  Round;

  for (I = 0; I < 4; ++I) {
    for (J = 0; J < 4; ++J) {
      State[J][I] = Buffer[(I * 4) + J];
    }
  }

  AddRoundKey (0, State, RoundKey);

  for (Round = 1; Round < AES_NR; ++Round) {
    SubBytes (State);
    ShiftRows (State);
    MixColumns (State);
    AddRoundKey (Round, State, RoundKey);
  }

  SubBytes (State);
  ShiftRows (State);
  AddRoundKey (AES_NR, State, RoundKey);

  for (I = 0; I < 4; ++I) {
    for (J = 0; J < 4; ++J) {
      Buffer[(I * 4) + J] = State[J][I];
    }
  }
}

STATIC
VOID
BuildCounterBlock (
  IN  CONST UINT8  Nonce[AES_BLOCK_SIZE],
  IN  UINT64       BlockNumber,
  OUT UINT8        Counter[AES_BLOCK_SIZE]
  )
{
  INTN    Index;
  UINT16  Sum;
  UINT8   Carry;

  for (Index = 0; Index < AES_BLOCK_SIZE; ++Index) {
    Counter[Index] = Nonce[Index];
  }

  Carry = 0;
  for (Index = AES_BLOCK_SIZE - 1; Index >= 0; --Index) {
    Sum            = (UINT16)(Counter[Index] + (UINT8)BlockNumber + Carry);
    Counter[Index] = (UINT8)Sum;
    Carry          = (UINT8)(Sum >> 8);
    BlockNumber  >>= 8;
    if ((BlockNumber == 0) && (Carry == 0)) {
      break;
    }
  }
}

VOID
Aes256Init (
  OUT AES256_CONTEXT  *Context,
  IN  CONST UINT8     Key[AES256_KEY_SIZE]
  )
{
  KeyExpansion (Context->RoundKey, Key);
}

VOID
Aes256CtrCrypt (
  IN  CONST AES256_CONTEXT  *Context,
  IN  CONST UINT8           Nonce[AES_BLOCK_SIZE],
  IN  UINT64                Offset,
  IN  CONST UINT8           *Input,
  OUT UINT8                 *Output,
  IN  UINTN                 Length
  )
{
  UINT64  BlockNumber;
  UINTN   ByteInBlock;
  UINTN   Index;
  UINT8   Stream[AES_BLOCK_SIZE];

  BlockNumber = Offset / AES_BLOCK_SIZE;
  ByteInBlock = (UINTN)(Offset % AES_BLOCK_SIZE);

  while (Length > 0) {
    BuildCounterBlock (Nonce, BlockNumber, Stream);
    CipherBlock (Stream, Context->RoundKey);

    for (Index = ByteInBlock; (Index < AES_BLOCK_SIZE) && (Length > 0); ++Index) {
      *Output = (UINT8)(*Input ^ Stream[Index]);
      ++Input;
      ++Output;
      --Length;
    }

    ++BlockNumber;
    ByteInBlock = 0;
  }
}
