/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Implements the cryptographic functions by calling WolfSSL.

--*/

#include "platform_internal.h"

#include <wolfssl/options.h>

// force openssl compatibility off
#undef HAVE_OPENSSL_CMD
#undef OPENSSL_ALL
#undef WOLFSSL_ERROR_CODE_OPENSSL
// #undef OPENSSL_EXTRA


#include <wolfssl/openssl/evp.h>
#include <wolfssl/ssl.h>

#include <wolfssl/quic.h>


typedef struct CXPLAT_KEY {
    WOLFSSL_EVP_CIPHER_CTX * cipher_ctx;
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

    const WOLFSSL_EVP_CIPHER * cipher;
    switch (AeadType) {
    case CXPLAT_AEAD_AES_128_GCM:
        cipher = wolfSSL_EVP_aes_128_gcm();
        break;
    case CXPLAT_AEAD_AES_256_GCM:
        cipher = wolfSSL_EVP_aes_256_gcm();
        break;
    case CXPLAT_AEAD_CHACHA20_POLY1305:
        cipher = wolfSSL_EVP_chacha20_poly1305();
        break;
    default:
        QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.", "unknown AeadType");
        Status = QUIC_STATUS_NOT_SUPPORTED;
        goto Exit;
    }

    key->cipher_ctx = wolfSSL_quic_crypt_new(cipher, RawKey, 0, 1);
    if (key->cipher_ctx == 0) {
        QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.",
                       "wolfSSL_quic_crypt_new failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
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
    if (wolfSSL_quic_aead_encrypt(Buffer, Key->cipher_ctx, Buffer,
                                  PlainTextLength, Iv, AuthData,
                                  AuthDataLength) != WOLFSSL_SUCCESS) {
        QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.",
                       "wolfSSL_quic_aead_encrypt failed");
        return QUIC_STATUS_TLS_ERROR;
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

    if (wolfSSL_quic_aead_decrypt(Buffer, Key->cipher_ctx, Buffer, BufferLength,
                                  Iv, AuthData,
                                  AuthDataLength) != WOLFSSL_SUCCESS) {
        QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.",
                       "wolfSSL_quic_aead_decrypt failed");
        return QUIC_STATUS_TLS_ERROR;
    }

    return QUIC_STATUS_SUCCESS;
}


typedef struct CXPLAT_HP_KEY {
    WOLFSSL_EVP_CIPHER_CTX * cipher_ctx;
} CXPLAT_HP_KEY;


QUIC_STATUS CxPlatHpKeyCreate(CXPLAT_AEAD_TYPE AeadType,
                              const uint8_t * const RawKey,
                              CXPLAT_HP_KEY ** NewKey)
{
    UNREFERENCED_PARAMETER(AeadType);

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    CXPLAT_HP_KEY * key =
        CXPLAT_ALLOC_NONPAGED(sizeof(*key), QUIC_POOL_TLS_KEY);
    if (key == 0) {
        QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.",
                       "CXPLAT_ALLOC_NONPAGED failed");
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    const WOLFSSL_EVP_CIPHER * cipher;
    switch (AeadType) {
    case CXPLAT_AEAD_AES_128_GCM:
        cipher = wolfSSL_EVP_aes_128_ctr();
        break;
    case CXPLAT_AEAD_AES_256_GCM:
        cipher = wolfSSL_EVP_aes_256_ctr();
        break;
    case CXPLAT_AEAD_CHACHA20_POLY1305:
        cipher = wolfSSL_EVP_chacha20();
        break;
    default:
        QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.", "unknown AeadType");
        Status = QUIC_STATUS_NOT_SUPPORTED;
        goto Exit;
    }

    key->cipher_ctx = wolfSSL_quic_crypt_new(cipher, RawKey, 0, 1);
    if (key->cipher_ctx == 0) {
        QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.",
                       "wolfSSL_quic_crypt_new failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    *NewKey = key;
    key = 0;

Exit:
    CXPLAT_FREE(key, QUIC_POOL_TLS_KEY);
    return Status;
}


void CxPlatHpKeyFree(CXPLAT_HP_KEY * Key)
{
    CXPLAT_FREE(Key, QUIC_POOL_TLS_KEY);
}


QUIC_STATUS CxPlatHpComputeMask(CXPLAT_HP_KEY * Key,
                                uint8_t BatchSize,
                                const uint8_t * const Cipher,
                                uint8_t * Mask)
{
    static const uint8_t zero[5] = {0};
    int len;
    for (size_t Offset = 0; Offset < BatchSize * CXPLAT_HP_SAMPLE_LENGTH;
         Offset += CXPLAT_HP_SAMPLE_LENGTH) {

        if (wolfSSL_EVP_EncryptInit_ex(Key->cipher_ctx, 0, 0, 0,
                                       Cipher + Offset) != WOLFSSL_SUCCESS) {
            QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.",
                           "wolfSSL_EVP_EncryptInit_ex failed");
            return QUIC_STATUS_TLS_ERROR;
        }

        if (wolfSSL_EVP_CipherUpdate(Key->cipher_ctx, Mask + Offset, &len, zero,
                                     sizeof(zero)) != WOLFSSL_SUCCESS) {
            QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.",
                           "wolfSSL_EVP_CipherUpdate failed");
            return QUIC_STATUS_TLS_ERROR;
        }

        // if (wolfSSL_EVP_EncryptFinal_ex(Key->cipher_ctx,
        //                                 Mask + Offset + sizeof(zero),
        //                                 &len) != WOLFSSL_SUCCESS) {
        //     QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.",
        //                    "wolfSSL_EVP_EncryptFinal_ex failed");
        //     return QUIC_STATUS_TLS_ERROR;
        // }
    }
    return QUIC_STATUS_SUCCESS;
}


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
