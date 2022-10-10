/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Implements the cryptographic functions by calling RIOT.

--*/

#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/wc_port.h>

#include "platform_internal.h"

typedef struct CXPLAT_HASH {
    struct Hmac Mac;
} CXPLAT_HASH;

QUIC_STATUS
CxPlatCryptInitialize(void)
{
    if (wolfCrypt_Init() != 0) {
        QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.",
                       "wolfCrypt_Init failed");
        return QUIC_STATUS_TLS_ERROR;
    }
    return QUIC_STATUS_SUCCESS;
}

void CxPlatCryptUninitialize(void)
{
    if (wolfCrypt_Cleanup() != 0) {
        QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.",
                       "wolfCrypt_Cleanup failed");
    }
}

void CxPlatHashFree(CXPLAT_HASH * Hash)
{
    if (Hash) {
        CXPLAT_FREE(Hash, QUIC_POOL_TLS_HASH);
    }
}

void CxPlatKeyFree(CXPLAT_KEY * Key)
{
    UNREFERENCED_PARAMETER(Key);
}

QUIC_STATUS
CxPlatKeyCreate(CXPLAT_AEAD_TYPE AeadType,
                const uint8_t * const RawKey,
                CXPLAT_KEY ** NewKey)
{
    UNREFERENCED_PARAMETER(AeadType);
    UNREFERENCED_PARAMETER(RawKey);
    UNREFERENCED_PARAMETER(NewKey);

    puts("TODO CxPlatKeyCreate");
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
CxPlatHashCreate(CXPLAT_HASH_TYPE HashType,
                 const uint8_t * const Salt,
                 uint32_t SaltLength,
                 CXPLAT_HASH ** NewHash)
{
    puts("CxPlatHashCreate");

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    CXPLAT_HASH * Hash =
        CXPLAT_ALLOC_NONPAGED(sizeof(CXPLAT_HASH), QUIC_POOL_TLS_HASH);
    if (Hash == NULL) {
        QuicTraceEvent(AllocFailure, "Allocation of '%s' failed. (%llu bytes)",
                       "Crypt Hash Context", sizeof(Hash));
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }
    CxPlatZeroMemory(Hash, sizeof(CXPLAT_HASH));

    int type;
    switch (HashType) {
    case CXPLAT_HASH_SHA256:
        type = WC_SHA256;
        break;
    case CXPLAT_HASH_SHA384:
        type = WC_SHA384;
        break;
    case CXPLAT_HASH_SHA512:
        type = WC_SHA512;
        break;
    default:
        Status = QUIC_STATUS_NOT_SUPPORTED;
        goto Exit;
    }

    const int err = wc_HmacSetKey(&Hash->Mac, type, Salt, SaltLength);
    if (err != 0) {
        QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.",
                       wc_GetErrorString(err));
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    *NewHash = Hash;
    Hash = NULL;

Exit:

    CxPlatHashFree(Hash);

    return Status;
}

QUIC_STATUS
CxPlatHashCompute(CXPLAT_HASH * Hash,
                  const uint8_t * const Input,
                  uint32_t InputLength,
                  uint32_t OutputLength,
                  uint8_t * const Output)
{
    puts("CxPlatHashCompute");

    int err = wc_HmacUpdate(&Hash->Mac, Input, InputLength);
    if (!err) {
        QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.",
                       wc_GetErrorString(err));
        return QUIC_STATUS_INTERNAL_ERROR;
    }

    err = wc_HmacFinal(&Hash->Mac, Output);
    if (!err) {
        QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.",
                       wc_GetErrorString(err));
        return QUIC_STATUS_INTERNAL_ERROR;
    }

    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
CxPlatDecrypt(CXPLAT_KEY * Key,
              const uint8_t * const Iv,
              uint16_t AuthDataLength,
              const uint8_t * const AuthData,
              uint16_t BufferLength,
              uint8_t * Buffer)
{
    UNREFERENCED_PARAMETER(Key);
    UNREFERENCED_PARAMETER(Iv);
    UNREFERENCED_PARAMETER(AuthDataLength);
    UNREFERENCED_PARAMETER(AuthData);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);

    CXPLAT_DBG_ASSERT(CXPLAT_ENCRYPTION_OVERHEAD <= BufferLength);

    puts("TODO CxPlatDecrypt");
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
CxPlatHpComputeMask(CXPLAT_HP_KEY * Key,
                    uint8_t BatchSize,
                    const uint8_t * const Cipher,
                    uint8_t * Mask)
{
    UNREFERENCED_PARAMETER(Key);
    UNREFERENCED_PARAMETER(BatchSize);
    UNREFERENCED_PARAMETER(Cipher);
    UNREFERENCED_PARAMETER(Mask);

    puts("TODO CxPlatHpComputeMask");
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
CxPlatEncrypt(CXPLAT_KEY * Key,
              const uint8_t * const Iv,
              uint16_t AuthDataLength,
              const uint8_t * const AuthData,
              uint16_t BufferLength,
              uint8_t * Buffer)
{
    UNREFERENCED_PARAMETER(Key);
    UNREFERENCED_PARAMETER(Iv);
    UNREFERENCED_PARAMETER(AuthDataLength);
    UNREFERENCED_PARAMETER(AuthData);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);

    CXPLAT_DBG_ASSERT(CXPLAT_ENCRYPTION_OVERHEAD <= BufferLength);
    puts("TODO CxPlatEncrypt");
    return QUIC_STATUS_SUCCESS;
}

void CxPlatHpKeyFree(CXPLAT_HP_KEY * Key)
{
    UNREFERENCED_PARAMETER(Key);
}

QUIC_STATUS
CxPlatHpKeyCreate(CXPLAT_AEAD_TYPE AeadType,
                  const uint8_t * const RawKey,
                  CXPLAT_HP_KEY ** NewKey)
{
    UNREFERENCED_PARAMETER(AeadType);
    UNREFERENCED_PARAMETER(RawKey);
    UNREFERENCED_PARAMETER(NewKey);

    puts("TODO CxPlatHpKeyCreate");
    return QUIC_STATUS_SUCCESS;
}
