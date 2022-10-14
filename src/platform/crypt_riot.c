/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Implements the cryptographic functions by calling RIOT.

--*/

#include "platform_internal.h"

#include <wolfssl/wolfcrypt/settings.h>

#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/sha512.h>
// #include <wolfssl/wolfcrypt/wc_port.h>


QUIC_STATUS CxPlatCryptInitialize(void)
{
    if (wolfCrypt_Init()) {
        QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.",
                       "wolfCrypt_Init failed");
        return QUIC_STATUS_TLS_ERROR;
    }
    return QUIC_STATUS_SUCCESS;
}


void CxPlatCryptUninitialize(void)
{
    if (wolfCrypt_Cleanup()) {
        QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.",
                       "wolfCrypt_Cleanup failed");
    }
}


void CxPlatKeyFree(CXPLAT_KEY * Key)
{
    free(Key);
}


QUIC_STATUS CxPlatKeyCreate(CXPLAT_AEAD_TYPE AeadType,
                            const uint8_t * const RawKey,
                            CXPLAT_KEY ** NewKey)
{
    // puts("CxPlatKeyCreate");

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    struct Aes * enc = malloc(sizeof(*enc));
    if (enc == 0) {
        QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.", "malloc failed");
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    word32 len;
    switch (AeadType) {
    case CXPLAT_AEAD_AES_128_GCM:
        len = 16;
        break;
    case CXPLAT_AEAD_AES_256_GCM:
        len = 32;
        break;
    case CXPLAT_AEAD_CHACHA20_POLY1305:
    default:
        Status = QUIC_STATUS_NOT_SUPPORTED;
        goto Exit;
    }

    if (wc_AesGcmSetKey(enc, RawKey, len)) {
        QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.",
                       "wc_AesGcmSetKey failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    *NewKey = (CXPLAT_KEY *)enc;
    enc = 0;

Exit:
    free(enc);
    return Status;
}


void CxPlatHashFree(CXPLAT_HASH * Hash)
{
    free(Hash);
}


QUIC_STATUS CxPlatHashCreate(CXPLAT_HASH_TYPE HashType,
                             const uint8_t * const Salt,
                             uint32_t SaltLength,
                             CXPLAT_HASH ** NewHash)
{
    // puts("CxPlatHashCreate");

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    struct Hmac * Hash = malloc(sizeof(*Hash));
    if (Hash == 0) {
        QuicTraceEvent(AllocFailure, "Allocation of '%s' failed. (%zu bytes)",
                       "Crypt Hash Context", sizeof(Hash));
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

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

    const int err = wc_HmacSetKey(Hash, type, Salt, SaltLength);
    if (err) {
        QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.",
                       wc_GetErrorString(err));
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    *NewHash = (CXPLAT_HASH *)Hash;
    Hash = 0;

Exit:

    free(Hash);

    return Status;
}

QUIC_STATUS CxPlatHashCompute(CXPLAT_HASH * Hash,
                              const uint8_t * const Input,
                              uint32_t InputLength,
                              uint32_t OutputLength,
                              uint8_t * const Output)
{
    UNREFERENCED_PARAMETER(OutputLength);

    // puts("CxPlatHashCompute");

    int err = wc_HmacUpdate((struct Hmac *)Hash, Input, InputLength);
    if (err) {
        QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.",
                       wc_GetErrorString(err));
        return QUIC_STATUS_INTERNAL_ERROR;
    }

    err = wc_HmacFinal((struct Hmac *)Hash, Output);
    if (err) {
        QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.",
                       wc_GetErrorString(err));
        return QUIC_STATUS_INTERNAL_ERROR;
    }

    return QUIC_STATUS_SUCCESS;
}


QUIC_STATUS CxPlatDecrypt(CXPLAT_KEY * Key,
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


QUIC_STATUS CxPlatHpComputeMask(CXPLAT_HP_KEY * Key,
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


QUIC_STATUS CxPlatEncrypt(CXPLAT_KEY * Key,
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
    free(Key);
}


QUIC_STATUS CxPlatHpKeyCreate(CXPLAT_AEAD_TYPE AeadType,
                              const uint8_t * const RawKey,
                              CXPLAT_HP_KEY ** NewKey)
{
    // puts("CxPlatHpKeyCreate");

    return CxPlatKeyCreate(AeadType, RawKey, (CXPLAT_KEY **)NewKey);
}
