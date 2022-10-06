/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Implements the cryptographic functions by calling RIOT.

--*/

#include "platform_internal.h"

void CxPlatHashFree(CXPLAT_HASH *Hash) { UNREFERENCED_PARAMETER(Hash); }

void CxPlatKeyFree(CXPLAT_KEY *Key) { UNREFERENCED_PARAMETER(Key); }

QUIC_STATUS
CxPlatKeyCreate(CXPLAT_AEAD_TYPE AeadType, const uint8_t *const RawKey,
                CXPLAT_KEY **NewKey) {
  UNREFERENCED_PARAMETER(AeadType);
  UNREFERENCED_PARAMETER(RawKey);
  UNREFERENCED_PARAMETER(NewKey);

  return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
CxPlatHashCreate(CXPLAT_HASH_TYPE HashType, const uint8_t *const Salt,
                 uint32_t SaltLength, CXPLAT_HASH **NewHash) {
  UNREFERENCED_PARAMETER(HashType);
  UNREFERENCED_PARAMETER(Salt);
  UNREFERENCED_PARAMETER(SaltLength);
  UNREFERENCED_PARAMETER(NewHash);

  return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
CxPlatHashCompute(CXPLAT_HASH *Hash, const uint8_t *const Input,
                  uint32_t InputLength, uint32_t OutputLength,
                  uint8_t *const Output) {
  UNREFERENCED_PARAMETER(Hash);
  UNREFERENCED_PARAMETER(Input);
  UNREFERENCED_PARAMETER(InputLength);
  UNREFERENCED_PARAMETER(OutputLength);
  UNREFERENCED_PARAMETER(Output);

  return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
CxPlatDecrypt(CXPLAT_KEY *Key, const uint8_t *const Iv, uint16_t AuthDataLength,
              const uint8_t *const AuthData, uint16_t BufferLength,
              uint8_t *Buffer) {
  UNREFERENCED_PARAMETER(Key);
  UNREFERENCED_PARAMETER(Iv);
  UNREFERENCED_PARAMETER(AuthDataLength);
  UNREFERENCED_PARAMETER(AuthData);
  UNREFERENCED_PARAMETER(BufferLength);
  UNREFERENCED_PARAMETER(Buffer);

  CXPLAT_DBG_ASSERT(CXPLAT_ENCRYPTION_OVERHEAD <= BufferLength);

  return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
CxPlatHpComputeMask(CXPLAT_HP_KEY *Key, uint8_t BatchSize,
                    const uint8_t *const Cipher, uint8_t *Mask) {
  UNREFERENCED_PARAMETER(Key);
  UNREFERENCED_PARAMETER(BatchSize);
  UNREFERENCED_PARAMETER(Cipher);
  UNREFERENCED_PARAMETER(Mask);

  return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
CxPlatEncrypt(CXPLAT_KEY *Key, const uint8_t *const Iv, uint16_t AuthDataLength,
              const uint8_t *const AuthData, uint16_t BufferLength,
              uint8_t *Buffer) {
  UNREFERENCED_PARAMETER(Key);
  UNREFERENCED_PARAMETER(Iv);
  UNREFERENCED_PARAMETER(AuthDataLength);
  UNREFERENCED_PARAMETER(AuthData);
  UNREFERENCED_PARAMETER(BufferLength);
  UNREFERENCED_PARAMETER(Buffer);

  CXPLAT_DBG_ASSERT(CXPLAT_ENCRYPTION_OVERHEAD <= BufferLength);
  return QUIC_STATUS_SUCCESS;
}

void CxPlatHpKeyFree(CXPLAT_HP_KEY *Key) { UNREFERENCED_PARAMETER(Key); }

QUIC_STATUS
CxPlatHpKeyCreate(CXPLAT_AEAD_TYPE AeadType, const uint8_t *const RawKey,
                  CXPLAT_HP_KEY **NewKey) {
  UNREFERENCED_PARAMETER(AeadType);
  UNREFERENCED_PARAMETER(RawKey);
  UNREFERENCED_PARAMETER(NewKey);

  return QUIC_STATUS_SUCCESS;
}
