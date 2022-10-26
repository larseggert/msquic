/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Implements the cryptographic functions by calling OpenSSL.

--*/

#include "platform_internal.h"

#include <wolfssl/options.h>

// force openssl compatibility off
#undef HAVE_OPENSSL_CMD
#undef OPENSSL_ALL
#undef WOLFSSL_ERROR_CODE_OPENSSL
#undef OPENSSL_EXTRA

#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/wc_port.h>


typedef struct CXPLAT_KEY {
    union {
        struct Aes aes;
        byte chacha20_poly1305[CHACHA20_POLY1305_AEAD_KEYSIZE];
    } cipher;
    CXPLAT_AEAD_TYPE aead;
} CXPLAT_KEY;


QUIC_STATUS CxPlatCryptInitialize(void)
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


QUIC_STATUS CxPlatKeyCreate(CXPLAT_AEAD_TYPE AeadType,
                            const uint8_t * const RawKey,
                            CXPLAT_KEY ** NewKey)
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    CXPLAT_KEY * key = CXPLAT_ALLOC_NONPAGED(sizeof(*key), QUIC_POOL_TLS_KEY);
    if (key == 0) {
        QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.",
                       "CXPLAT_ALLOC_NONPAGED failed");
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    if (AeadType == CXPLAT_AEAD_CHACHA20_POLY1305) {
        memcpy(key->cipher.chacha20_poly1305, RawKey,
               CHACHA20_POLY1305_AEAD_KEYSIZE);

    } else {
        word32 len;
        if (AeadType == CXPLAT_AEAD_AES_128_GCM) {
            len = 16;
        } else if (AeadType == CXPLAT_AEAD_AES_256_GCM) {
            len = 32;
        } else {
            Status = QUIC_STATUS_NOT_SUPPORTED;
            goto Exit;
        }

        if (wc_AesGcmSetKey(&key->cipher.aes, RawKey, len)) {
            QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.",
                           "wc_AesGcmSetKey failed");
            Status = QUIC_STATUS_TLS_ERROR;
            goto Exit;
        }
    }
    *NewKey = key;
    key = 0;

Exit:
    CXPLAT_FREE(key, QUIC_POOL_TLS_KEY);
    return Status;
}


void CxPlatKeyFree(CXPLAT_KEY * Key)
{
    CXPLAT_FREE(Key, QUIC_POOL_TLS_KEY);
}


QUIC_STATUS CxPlatEncrypt(CXPLAT_KEY * Key,
                          const uint8_t * const Iv,
                          uint16_t AuthDataLength,
                          const uint8_t * const AuthData,
                          uint16_t BufferLength,
                          uint8_t * Buffer)
{
    CXPLAT_DBG_ASSERT(CXPLAT_ENCRYPTION_OVERHEAD <= BufferLength);

    const uint16_t PlainTextLength = BufferLength - CXPLAT_ENCRYPTION_OVERHEAD;
    uint8_t * Tag = Buffer + PlainTextLength;

    if (Key->aead == CXPLAT_AEAD_CHACHA20_POLY1305) {
        if (wc_ChaCha20Poly1305_Encrypt(Key->cipher.chacha20_poly1305, Iv,
                                        AuthData, AuthDataLength, Buffer,
                                        PlainTextLength, Buffer, Tag) != 0) {
            QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.",
                           "wc_ChaCha20Poly1305_Encrypt failed");
            return QUIC_STATUS_TLS_ERROR;
        }

    } else {
        if (wc_AesGcmEncrypt(&Key->cipher.aes, Buffer, Buffer, PlainTextLength,
                             Iv, 16, // FIXME
                             Tag, BufferLength - PlainTextLength, AuthData,
                             AuthDataLength) != 0) {
            QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.",
                           "wc_ChaCha20Poly1305_Encrypt failed");
            return QUIC_STATUS_TLS_ERROR;
        }
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
    CXPLAT_DBG_ASSERT(CXPLAT_ENCRYPTION_OVERHEAD <= BufferLength);

    const uint16_t CipherTextLength = BufferLength - CXPLAT_ENCRYPTION_OVERHEAD;
    uint8_t * Tag = Buffer + CipherTextLength;

    if (Key->aead == CXPLAT_AEAD_CHACHA20_POLY1305) {
        if (wc_ChaCha20Poly1305_Decrypt(Key->cipher.chacha20_poly1305, Iv,
                                        AuthData, AuthDataLength, Buffer,
                                        CipherTextLength, Tag, Buffer) != 0) {
            QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.",
                           "wc_ChaCha20Poly1305_Decrypt failed");
            return QUIC_STATUS_TLS_ERROR;
        }

    } else {
        if (wc_AesGcmDecrypt(&Key->cipher.aes, Buffer, Buffer, CipherTextLength,
                             Iv, 16, // FIXME
                             Tag, BufferLength - CipherTextLength, AuthData,
                             AuthDataLength) != 0) {
            QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.",
                           "wc_ChaCha20Poly1305_Decrypt failed");
            return QUIC_STATUS_TLS_ERROR;
        }
    }

    return QUIC_STATUS_SUCCESS;
}


typedef struct CXPLAT_HP_KEY {
    union {
        struct Aes aes;
        byte chacha20_poly1305[CHACHA20_POLY1305_AEAD_KEYSIZE];
    } cipher;
    CXPLAT_AEAD_TYPE aead;
} CXPLAT_HP_KEY;


QUIC_STATUS CxPlatHpKeyCreate(CXPLAT_AEAD_TYPE AeadType,
                              const uint8_t * const RawKey,
                              CXPLAT_HP_KEY ** NewKey)
{
    return CxPlatKeyCreate(AeadType, RawKey, (CXPLAT_KEY **)NewKey);
}


void CxPlatHpKeyFree(CXPLAT_HP_KEY * Key)
{
    CxPlatKeyFree((CXPLAT_KEY *)Key);
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
#if 0
    int OutLen = 0;
    if (Key->aead == CXPLAT_AEAD_CHACHA20_POLY1305) {
        static const uint8_t Zero[] = {0, 0, 0, 0, 0};
        for (uint32_t i = 0, Offset = 0; i < BatchSize;
             ++i, Offset += CXPLAT_HP_SAMPLE_LENGTH) {
            if (EVP_EncryptInit_ex(Key->CipherCtx, NULL, NULL, NULL,
                                   Cipher + Offset) != 1) {
                QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.",
                               "EVP_EncryptInit_ex (hp) failed");
                return QUIC_STATUS_TLS_ERROR;
            }
            if (EVP_EncryptUpdate(Key->CipherCtx, Mask + Offset, &OutLen, Zero,
                                  sizeof(Zero)) != 1) {
                QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.",
                               "EVP_EncryptUpdate (hp) failed");
                return QUIC_STATUS_TLS_ERROR;
            }
        }
    } else {
        if (EVP_EncryptUpdate(Key->CipherCtx, Mask, &OutLen, Cipher,
                              CXPLAT_HP_SAMPLE_LENGTH * BatchSize) != 1) {
            QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.",
                           "EVP_EncryptUpdate failed");
            return QUIC_STATUS_TLS_ERROR;
        }
    }
#endif
    return QUIC_STATUS_SUCCESS;
}

//
// Hash abstraction
//

QUIC_STATUS CxPlatHashCreate(CXPLAT_HASH_TYPE HashType,
                             const uint8_t * const Salt,
                             uint32_t SaltLength,
                             CXPLAT_HASH ** NewHash)
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    struct Hmac * Hash =
        CXPLAT_ALLOC_NONPAGED(sizeof(*Hash), QUIC_POOL_TLS_HASH);
    if (Hash == 0) {
        QuicTraceEvent(AllocFailure, "Allocation of '%s' failed. (%zu bytes)",
                       "Crypt Hash Context", sizeof(*Hash));
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
    CXPLAT_FREE(Hash, QUIC_POOL_TLS_HASH);
    return Status;
}


void CxPlatHashFree(CXPLAT_HASH * Hash)
{
    CXPLAT_FREE(Hash, QUIC_POOL_TLS_HASH);
}


QUIC_STATUS CxPlatHashCompute(CXPLAT_HASH * Hash,
                              const uint8_t * const Input,
                              uint32_t InputLength,
                              uint32_t OutputLength,
                              uint8_t * const Output)
{
    UNREFERENCED_PARAMETER(OutputLength);

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
