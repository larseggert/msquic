/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Implements the TLS functions by calling WolfSSL.

--*/

#include "platform_internal.h"

#include <wolfssl/options.h>

// force openssl compatibility off
#undef HAVE_OPENSSL_CMD
// #undef OPENSSL_ALL
#undef WOLFSSL_ERROR_CODE_OPENSSL
#undef OPENSSL_EXTRA

#include <wolfssl/ssl.h> // must come before wolfssl/quic.h

#include <wolfssl/quic.h>
#include <wolfssl/wolfcrypt/pkcs12.h>

#ifdef QUIC_CLOG
#include "tls_wolfssl.c.clog.h"
#endif

uint16_t CxPlatTlsTPHeaderSize = 0;

#define SSL_AD_INTERNAL_ERROR 80
#define EVP_MAX_IV_LENGTH 16
// #define STACK_OF(x) WOLFSSL_STACK

static WOLFSSL_EVP_CIPHER * CXPLAT_AES_256_CBC_ALG_HANDLE;

#define SSL_TLSEXT_ERR_OK 0
#define X509_V_OK 0
#define X509_V_ERR_OUT_OF_MEM 17
#define X509_R_NO_CERT_SET_FOR_US_TO_VERIFY 105

#define PFX_PASSWORD_LENGTH 33


// The QUIC sec config object. Created once per listener on server side and
// once per connection on client side.

typedef struct CXPLAT_SEC_CONFIG {
    // The SSL context associated with the sec config.
    WOLFSSL_CTX * SSLCtx;

    // Optional ticket key provided by the app.
    QUIC_TICKET_KEY_CONFIG * TicketKey;

    // Callbacks for TLS.
    CXPLAT_TLS_CALLBACKS Callbacks;

    // The application supplied credential flags.
    QUIC_CREDENTIAL_FLAGS Flags;

    // Internal TLS credential flags.
    CXPLAT_TLS_CREDENTIAL_FLAGS TlsFlags;

} CXPLAT_SEC_CONFIG;


// A TLS context associated per connection.

typedef struct CXPLAT_TLS {
    // The TLS configuration information and credentials.
    CXPLAT_SEC_CONFIG * SecConfig;

    // Labels for deriving key material.
    const QUIC_HKDF_LABELS * HkdfLabels;

    // Indicates if this context belongs to server side or client side
    // connection.
    BOOLEAN IsServer : 1;

    // Indicates if the peer sent a certificate.
    BOOLEAN PeerCertReceived : 1;

    // Indicates whether the peer's TP has been received.
    BOOLEAN PeerTPReceived : 1;

    // The TLS extension type for the QUIC transport parameters.
    uint16_t QuicTpExtType;

    // The ALPN buffer.
    uint16_t AlpnBufferLength;
    const uint8_t * AlpnBuffer;

    // On client side stores a 0 terminated SNI.
    const char * SNI;

    // Ssl - A SSL object associated with the connection.
    WOLFSSL * Ssl;

    // State - The TLS state associated with the connection.
    CXPLAT_TLS_PROCESS_STATE * State;

    // ResultFlags - Stores the result of the TLS data processing operation.
    CXPLAT_TLS_RESULT_FLAGS ResultFlags;

    // Callback context and handler for QUIC TP.
    QUIC_CONNECTION * Connection;

    // Optional struct to log TLS traffic secrets.
    // Only non-0 when the connection is configured to log these.
    QUIC_TLS_SECRETS * TlsSecrets;

} CXPLAT_TLS;


// Default list of Cipher used.
#define CXPLAT_TLS_DEFAULT_SSL_CIPHERS                                         \
    "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_"     \
    "SHA256"

#define CXPLAT_TLS_AES_128_GCM_SHA256 "TLS_AES_128_GCM_SHA256"
#define CXPLAT_TLS_AES_256_GCM_SHA384 "TLS_AES_256_GCM_SHA384"
#define CXPLAT_TLS_CHACHA20_POLY1305_SHA256 "TLS_CHACHA20_POLY1305_SHA256"

// Default cert verify depth.
#define CXPLAT_TLS_DEFAULT_VERIFY_DEPTH 10

#define X509_V_ERR_CERT_HAS_EXPIRED 10
#define X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT 18
#define X509_V_ERR_CERT_REVOKED 23
#define X509_V_ERR_CERT_UNTRUSTED 27
#define X509_V_ERR_CERT_REJECTED 28


static QUIC_STATUS CxPlatTlsMapWolfSSLErrorToQuicStatus(int WolfSSLError)
{
    switch (WolfSSLError) {
    case X509_V_ERR_CERT_REJECTED:
        return QUIC_STATUS_BAD_CERTIFICATE;
    case X509_V_ERR_CERT_REVOKED:
        return QUIC_STATUS_REVOKED_CERTIFICATE;
    case X509_V_ERR_CERT_HAS_EXPIRED:
        return QUIC_STATUS_CERT_EXPIRED;
    case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
        __fallthrough;
    case X509_V_ERR_CERT_UNTRUSTED:
        return QUIC_STATUS_CERT_UNTRUSTED_ROOT;
    default:
        return QUIC_STATUS_TLS_ERROR;
    }
}


static int CxPlatTlsAlpnSelectCallback(WOLFSSL * Ssl,
                                       const unsigned char ** Out,
                                       unsigned char * OutLen,
                                       const unsigned char * In,
                                       unsigned int InLen,
                                       void * Arg)
{
    UNREFERENCED_PARAMETER(In);
    UNREFERENCED_PARAMETER(InLen);
    UNREFERENCED_PARAMETER(Arg);

    CXPLAT_TLS * TlsContext = wolfSSL_get_app_data(Ssl);

    // QUIC already parsed and picked the ALPN to use and set it in the
    // NegotiatedAlpn variable.
    CXPLAT_DBG_ASSERT(TlsContext->State->NegotiatedAlpn != 0);
    *OutLen = TlsContext->State->NegotiatedAlpn[0];
    *Out = TlsContext->State->NegotiatedAlpn + 1;

    return SSL_TLSEXT_ERR_OK;
}


static int CxPlatTlsCertificateVerifyCallback(int x,
                                              WOLFSSL_X509_STORE_CTX * x509_ctx)
{
    // puts("CxPlatTlsCertificateVerifyCallback");
    UNREFERENCED_PARAMETER(x);

    int CertificateVerified = 0;
    int status = TRUE;
    unsigned char * WolfSSLCertBuffer = 0;
    QUIC_BUFFER PortableCertificate = {0, 0};
    QUIC_BUFFER PortableChain = {0, 0};
    WOLFSSL_X509 * Cert = wolfSSL_X509_STORE_CTX_get0_cert(x509_ctx);
    WOLFSSL * Ssl = wolfSSL_X509_STORE_CTX_get_ex_data(
        x509_ctx, wolfSSL_get_ex_data_X509_STORE_CTX_idx());
    CXPLAT_TLS * TlsContext = wolfSSL_get_app_data(Ssl);
    int ValidationResult = X509_V_OK;
    BOOLEAN IsDeferredValidationOrClientAuth =
        (TlsContext->SecConfig->Flags &
             QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION ||
         TlsContext->SecConfig->Flags &
             QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION);

    TlsContext->PeerCertReceived = (Cert != 0);

    if ((TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_CLIENT ||
         IsDeferredValidationOrClientAuth) &&
        !(TlsContext->SecConfig->Flags &
          QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION)) {
        if (!(TlsContext->SecConfig->Flags &
              QUIC_CREDENTIAL_FLAG_USE_TLS_BUILTIN_CERTIFICATE_VALIDATION)) {
            if (Cert == 0) {
                QuicTraceEvent(TlsError, "[ tls][%p] ERROR, %s.",
                               TlsContext->Connection, "No certificate passed");
                wolfSSL_X509_STORE_CTX_set_error(
                    x509_ctx, X509_R_NO_CERT_SET_FOR_US_TO_VERIFY);
                return FALSE;
            }

            int WolfSSLCertLength = wolfSSL_i2d_X509(Cert, &WolfSSLCertBuffer);
            if (WolfSSLCertLength <= 0) {
                QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.",
                               "wolfSSL_i2d_X509 failed");
                CertificateVerified = FALSE;
            } else {
                CertificateVerified = CxPlatCertVerifyRawCertificate(
                    WolfSSLCertBuffer, WolfSSLCertLength, TlsContext->SNI,
                    TlsContext->SecConfig->Flags,
                    IsDeferredValidationOrClientAuth
                        ? (uint32_t *)&ValidationResult
                        : 0);
            }

            if (WolfSSLCertBuffer != 0) {
                free(WolfSSLCertBuffer);
            }

            if (!CertificateVerified) {
                wolfSSL_X509_STORE_CTX_set_error(x509_ctx,
                                                 X509_V_ERR_CERT_REJECTED);
            }
        } else {
            CertificateVerified = wolfSSL_X509_verify_cert(x509_ctx);

            if (IsDeferredValidationOrClientAuth && CertificateVerified <= 0) {
                ValidationResult = (int)CxPlatTlsMapWolfSSLErrorToQuicStatus(
                    wolfSSL_X509_STORE_CTX_get_error(x509_ctx));
            }
        }
    } else if ((TlsContext->SecConfig->Flags &
                QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED) &&
               (TlsContext->SecConfig->Flags &
                QUIC_CREDENTIAL_FLAG_USE_PORTABLE_CERTIFICATES)) {
        // We need to get certificates provided by peer if we going to pass them
        // via Callbacks.CertificateReceived. We don't really care about
        // validation status but without calling wolfSSL_X509_verify_cert()
        // x509_ctx has no certificates attached to it and that impacts
        // validation of custom certificate chains.
        //
        // WolfSSL 3 has X509_build_chain() to build just the chain.
        // We may do something similar here for WolfSsl 1.1
        wolfSSL_X509_verify_cert(x509_ctx);
    }

    if (!(TlsContext->SecConfig->Flags &
          QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION) &&
        !(TlsContext->SecConfig->Flags &
          QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION) &&
        !CertificateVerified) {
        QuicTraceEvent(TlsError, "[ tls][%p] ERROR, %s.",
                       TlsContext->Connection,
                       "Internal certificate validation failed");
        return FALSE;
    }

    if (TlsContext->SecConfig->Flags &
        QUIC_CREDENTIAL_FLAG_USE_PORTABLE_CERTIFICATES) {
        if (Cert) {
            PortableCertificate.Length =
                wolfSSL_i2d_X509(Cert, &PortableCertificate.Buffer);
            if (!PortableCertificate.Buffer) {
                QuicTraceEvent(TlsError, "[ tls][%p] ERROR, %s.",
                               TlsContext->Connection,
                               "Failed to serialize certificate context");
                wolfSSL_X509_STORE_CTX_set_error(x509_ctx,
                                                 X509_V_ERR_OUT_OF_MEM);
                return FALSE;
            }
        }
        if (x509_ctx) {
            puts("TODO x509_ctx");
#if 0
            int ChainCount;
            STACK_OF(X509) * Chain =
                wolfSSL_X509_STORE_CTX_get0_chain(x509_ctx);
            if ((ChainCount = wolfSSL_sk_X509_num(Chain)) > 0) {
                PKCS7 * p7 = wc_PKCS7_new();
                if (p7) {
                    PKCS7_set_type(p7, NID_pkcs7_signed);
                    PKCS7_content_new(p7, NID_pkcs7_data);

                    for (int i = 0; i < ChainCount; i++) {
                        PKCS7_add_certificate(p7, sk_X509_value(Chain, i));
                    }
                    PortableChain.Length = wolfSSL_i2d_PKCS7(p7, &PortableChain.Buffer);
                    PKCS7_free(p7);
                } else {
                    QuicTraceEvent(TlsError, "[ tls][%p] ERROR, %s.",
                                   TlsContext->Connection,
                                   "Failed to allocate PKCS7 context");
                }
            }
#endif
        }
    }

    if ((TlsContext->SecConfig->Flags &
         QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED) &&
        !TlsContext->SecConfig->Callbacks.CertificateReceived(
            TlsContext->Connection,
            (TlsContext->SecConfig->Flags &
             QUIC_CREDENTIAL_FLAG_USE_PORTABLE_CERTIFICATES)
                ? (QUIC_CERTIFICATE *)&PortableCertificate
                : (QUIC_CERTIFICATE *)Cert,
            (TlsContext->SecConfig->Flags &
             QUIC_CREDENTIAL_FLAG_USE_PORTABLE_CERTIFICATES)
                ? (QUIC_CERTIFICATE_CHAIN *)&PortableChain
                : (QUIC_CERTIFICATE_CHAIN *)x509_ctx,
            0, ValidationResult)) {
        QuicTraceEvent(TlsError, "[ tls][%p] ERROR, %s.",
                       TlsContext->Connection,
                       "Indicate certificate received failed");
        wolfSSL_X509_STORE_CTX_set_error(x509_ctx, X509_V_ERR_CERT_REJECTED);
        status = FALSE;
    }

    if (PortableCertificate.Buffer) {
        free(PortableCertificate.Buffer);
    }
    if (PortableChain.Buffer) {
        free(PortableChain.Buffer);
    }

    return status;
}


CXPLAT_STATIC_ASSERT((int)wolfssl_encryption_initial ==
                         (int)QUIC_PACKET_KEY_INITIAL,
                     "Code assumes exact match!");
CXPLAT_STATIC_ASSERT((int)wolfssl_encryption_early_data ==
                         (int)QUIC_PACKET_KEY_0_RTT,
                     "Code assumes exact match!");
CXPLAT_STATIC_ASSERT((int)wolfssl_encryption_handshake ==
                         (int)QUIC_PACKET_KEY_HANDSHAKE,
                     "Code assumes exact match!");
CXPLAT_STATIC_ASSERT((int)wolfssl_encryption_application ==
                         (int)QUIC_PACKET_KEY_1_RTT,
                     "Code assumes exact match!");


void CxPlatTlsNegotiatedCiphers(CXPLAT_TLS * TlsContext,
                                CXPLAT_AEAD_TYPE * AeadType,
                                CXPLAT_HASH_TYPE * HashType)
{
    switch (
        wolfSSL_CIPHER_get_id(wolfSSL_get_current_cipher(TlsContext->Ssl))) {
    case 0x1301U: // TLS_AES_128_GCM_SHA256
        *AeadType = CXPLAT_AEAD_AES_128_GCM;
        *HashType = CXPLAT_HASH_SHA256;
        break;
    case 0x1302U: // TLS_AES_256_GCM_SHA384
        *AeadType = CXPLAT_AEAD_AES_256_GCM;
        *HashType = CXPLAT_HASH_SHA384;
        break;
    case 0x1303U: // TLS_CHACHA20_POLY1305_SHA256
        *AeadType = CXPLAT_AEAD_CHACHA20_POLY1305;
        *HashType = CXPLAT_HASH_SHA256;
        break;
    default:
        CXPLAT_FRE_ASSERT(FALSE);
    }
}


int CxPlatTlsSetEncryptionSecretsCallback(WOLFSSL * Ssl,
                                          WOLFSSL_ENCRYPTION_LEVEL Level,
                                          const uint8_t * ReadSecret,
                                          const uint8_t * WriteSecret,
                                          size_t SecretLen)
{
    CXPLAT_TLS * TlsContext = wolfSSL_get_app_data(Ssl);
    CXPLAT_TLS_PROCESS_STATE * TlsState = TlsContext->State;
    QUIC_PACKET_KEY_TYPE KeyType = (QUIC_PACKET_KEY_TYPE)Level;
    QUIC_STATUS Status;

    QuicTraceLogConnVerbose(WolfSslNewEncryptionSecrets, TlsContext->Connection,
                            "New encryption secrets (Level = %u)",
                            (uint32_t)Level);

    CXPLAT_SECRET Secret;
    CxPlatTlsNegotiatedCiphers(TlsContext, &Secret.Aead, &Secret.Hash);

    if (WriteSecret) {
        CxPlatCopyMemory(Secret.Secret, WriteSecret, SecretLen);
        CXPLAT_DBG_ASSERT(TlsState->WriteKeys[KeyType] == 0);
        Status = QuicPacketKeyDerive(KeyType, TlsContext->HkdfLabels, &Secret,
                                     "write secret", TRUE,
                                     &TlsState->WriteKeys[KeyType]);
        if (QUIC_FAILED(Status)) {
            TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
            return -1;
        }

        TlsState->WriteKey = KeyType;
        TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_WRITE_KEY_UPDATED;

        if (TlsContext->IsServer && KeyType == QUIC_PACKET_KEY_0_RTT) {
            TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_EARLY_DATA_ACCEPT;
            TlsContext->State->EarlyDataState = CXPLAT_TLS_EARLY_DATA_ACCEPTED;
        }
    }

    if (ReadSecret) {
        CxPlatCopyMemory(Secret.Secret, ReadSecret, SecretLen);
        CXPLAT_DBG_ASSERT(TlsState->ReadKeys[KeyType] == 0);
        Status = QuicPacketKeyDerive(KeyType, TlsContext->HkdfLabels, &Secret,
                                     "read secret", TRUE,
                                     &TlsState->ReadKeys[KeyType]);
        if (QUIC_FAILED(Status)) {
            TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
            return -1;
        }

        if (TlsContext->IsServer && KeyType == QUIC_PACKET_KEY_1_RTT) {
            // The 1-RTT read keys aren't actually allowed to be used until
            // the handshake completes.
        } else {
            TlsState->ReadKey = KeyType;
            TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_READ_KEY_UPDATED;
        }
    }

    if (TlsContext->TlsSecrets != 0) {
        TlsContext->TlsSecrets->SecretLength = (uint8_t)SecretLen;
        switch (KeyType) {
        case QUIC_PACKET_KEY_HANDSHAKE:
            CXPLAT_FRE_ASSERT(ReadSecret != 0 && WriteSecret != 0);
            if (TlsContext->IsServer) {
                memcpy(TlsContext->TlsSecrets->ClientHandshakeTrafficSecret,
                       ReadSecret, SecretLen);
                memcpy(TlsContext->TlsSecrets->ServerHandshakeTrafficSecret,
                       WriteSecret, SecretLen);
            } else {
                memcpy(TlsContext->TlsSecrets->ClientHandshakeTrafficSecret,
                       WriteSecret, SecretLen);
                memcpy(TlsContext->TlsSecrets->ServerHandshakeTrafficSecret,
                       ReadSecret, SecretLen);
            }
            TlsContext->TlsSecrets->IsSet.ClientHandshakeTrafficSecret = TRUE;
            TlsContext->TlsSecrets->IsSet.ServerHandshakeTrafficSecret = TRUE;
            break;
        case QUIC_PACKET_KEY_1_RTT:
            CXPLAT_FRE_ASSERT(ReadSecret != 0 && WriteSecret != 0);
            if (TlsContext->IsServer) {
                memcpy(TlsContext->TlsSecrets->ClientTrafficSecret0, ReadSecret,
                       SecretLen);
                memcpy(TlsContext->TlsSecrets->ServerTrafficSecret0,
                       WriteSecret, SecretLen);
            } else {
                memcpy(TlsContext->TlsSecrets->ClientTrafficSecret0,
                       WriteSecret, SecretLen);
                memcpy(TlsContext->TlsSecrets->ServerTrafficSecret0, ReadSecret,
                       SecretLen);
            }
            TlsContext->TlsSecrets->IsSet.ClientTrafficSecret0 = TRUE;
            TlsContext->TlsSecrets->IsSet.ServerTrafficSecret0 = TRUE;
            // We're done with the TlsSecrets.
            TlsContext->TlsSecrets = 0;
            break;
        case QUIC_PACKET_KEY_0_RTT:
            if (!TlsContext->IsServer) {
                CXPLAT_FRE_ASSERT(WriteSecret != 0);
                memcpy(TlsContext->TlsSecrets->ClientEarlyTrafficSecret,
                       WriteSecret, SecretLen);
                TlsContext->TlsSecrets->IsSet.ClientEarlyTrafficSecret = TRUE;
            }
            break;
        default:
            break;
        }
    }

    return 1;
}


int CxPlatTlsAddHandshakeDataCallback(WOLFSSL * Ssl,
                                      WOLFSSL_ENCRYPTION_LEVEL Level,
                                      const uint8_t * Data,
                                      size_t Length)
{
    CXPLAT_TLS * TlsContext = wolfSSL_get_app_data(Ssl);
    CXPLAT_TLS_PROCESS_STATE * TlsState = TlsContext->State;

    QUIC_PACKET_KEY_TYPE KeyType = (QUIC_PACKET_KEY_TYPE)Level;
    if (TlsContext->ResultFlags & CXPLAT_TLS_RESULT_ERROR) {
        CXPLAT_DBG_ASSERT(CxPlatIsRandomMemoryFailureEnabled());
        return -1;
    }
    CXPLAT_DBG_ASSERT(KeyType == 0 || TlsState->WriteKeys[KeyType] != 0);

    QuicTraceLogConnVerbose(WolfSslAddHandshakeData, TlsContext->Connection,
                            "Sending %llu handshake bytes (Level = %u)",
                            (uint64_t)Length, (uint32_t)Level);

    if (Length + TlsState->BufferLength > 0xF000) {
        QuicTraceEvent(TlsError, "[ tls][%p] ERROR, %s.",
                       TlsContext->Connection, "Too much handshake data");
        TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
        return -1;
    }

    if (Length + TlsState->BufferLength > (size_t)TlsState->BufferAllocLength) {
        // Double the allocated buffer length until there's enough room for
        // the new data.
        uint16_t NewBufferAllocLength = TlsState->BufferAllocLength;
        while (Length + TlsState->BufferLength > (size_t)NewBufferAllocLength) {
            NewBufferAllocLength <<= 1;
        }

        uint8_t * NewBuffer =
            CXPLAT_ALLOC_NONPAGED(NewBufferAllocLength, QUIC_POOL_TLS_BUFFER);
        if (NewBuffer == 0) {
            QuicTraceEvent(AllocFailure,
                           "Allocation of '%s' failed. (%llu bytes)",
                           "New crypto buffer", NewBufferAllocLength);
            TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
            return -1;
        }

        CxPlatCopyMemory(NewBuffer, TlsState->Buffer, TlsState->BufferLength);
        CXPLAT_FREE(TlsState->Buffer, QUIC_POOL_TLS_BUFFER);
        TlsState->Buffer = NewBuffer;
        TlsState->BufferAllocLength = NewBufferAllocLength;
    }

    switch (KeyType) {
    case QUIC_PACKET_KEY_HANDSHAKE:
        if (TlsState->BufferOffsetHandshake == 0) {
            TlsState->BufferOffsetHandshake = TlsState->BufferTotalLength;
            QuicTraceLogConnInfo(WolfSslHandshakeDataStart,
                                 TlsContext->Connection,
                                 "Writing Handshake data starts at %u",
                                 TlsState->BufferOffsetHandshake);
        }
        break;
    case QUIC_PACKET_KEY_1_RTT:
        if (TlsState->BufferOffset1Rtt == 0) {
            TlsState->BufferOffset1Rtt = TlsState->BufferTotalLength;
            QuicTraceLogConnInfo(WolfSsl1RttDataStart, TlsContext->Connection,
                                 "Writing 1-RTT data starts at %u",
                                 TlsState->BufferOffset1Rtt);
        }
        break;
    default:
        break;
    }

    CxPlatCopyMemory(TlsState->Buffer + TlsState->BufferLength, Data, Length);
    TlsState->BufferLength += (uint16_t)Length;
    TlsState->BufferTotalLength += (uint16_t)Length;

    TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_DATA;

    return 1;
}


int CxPlatTlsFlushFlightCallback(WOLFSSL * Ssl)
{
    UNREFERENCED_PARAMETER(Ssl);
    return 1;
}


int CxPlatTlsSendAlertCallback(WOLFSSL * Ssl,
                               enum wolfssl_encryption_level_t Level,
                               uint8_t Alert)
{
    puts("CxPlatTlsSendAlertCallback");
    UNREFERENCED_PARAMETER(Level);

    CXPLAT_TLS * TlsContext = wolfSSL_get_app_data(Ssl);

    QuicTraceLogConnError(WolfSslAlert, TlsContext->Connection,
                          "Send alert = %u (Level = %u)", Alert,
                          (uint32_t)Level);

    TlsContext->State->AlertCode = Alert;
    TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;

    return 1;
}


int CxPlatTlsClientHelloCallback(WOLFSSL * Ssl, int * Alert, void * arg)
{
    UNREFERENCED_PARAMETER(arg);
    CXPLAT_TLS * TlsContext = wolfSSL_get_app_data(Ssl);

    const uint8_t * TransportParams;
    size_t TransportParamLen;

    // if (!
    wolfSSL_get_peer_quic_transport_params(Ssl, // TlsContext->QuicTpExtType,
                                           &TransportParams,
                                           &TransportParamLen); //) {
    if (TransportParamLen == 0) {
        TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
        *Alert = SSL_AD_INTERNAL_ERROR;
        return WOLFSSL_FAILURE;
    }

    return WOLFSSL_SUCCESS;
}


int CxPlatTlsOnClientSessionTicketReceived(WOLFSSL * Ssl,
                                           WOLFSSL_SESSION * Session)
{
    // puts("CxPlatTlsOnClientSessionTicketReceived");
    UNREFERENCED_PARAMETER(Session);

    CXPLAT_TLS * TlsContext = wolfSSL_get_app_data(Ssl);

    int ret = wolfSSL_i2d_SSL_SESSION(Session, 0);
    if (ret > 0) {
        uint8_t * Data = 0;
        long Length = wolfSSL_i2d_SSL_SESSION(Session, &Data);
        if (Length < UINT16_MAX) {
            QuicTraceLogConnInfo(WolfSslOnRecvTicket, TlsContext->Connection,
                                 "Received session ticket, %u bytes",
                                 (uint32_t)Length);
            TlsContext->SecConfig->Callbacks.ReceiveTicket(
                TlsContext->Connection, (uint32_t)Length, Data);
        } else {
            QuicTraceEvent(TlsError, "[ tls][%p] ERROR, %s.",
                           TlsContext->Connection, "Session data too big");
        }
    } else {
        QuicTraceEvent(TlsErrorStatus, "[ tls][%p] ERROR, %u, %s.",
                       TlsContext->Connection, wolfSSL_ERR_get_error(),
                       "wolfSSL_i2d_SSL_SESSION failed");
    }

    // We always return a "fail" response so that the session gets freed
    // again because we haven't used the reference.
    return 0;
}


int CxPlatTlsOnSessionTicketKeyNeeded(WOLFSSL * Ssl,
                                      unsigned char key_name[16],
                                      unsigned char iv[EVP_MAX_IV_LENGTH],
                                      WOLFSSL_EVP_CIPHER_CTX * ctx,
                                      WOLFSSL_HMAC_CTX * hctx,
                                      int enc // Encryption or decryption
)
{
    CXPLAT_TLS * TlsContext = wolfSSL_get_app_data(Ssl);
    QUIC_TICKET_KEY_CONFIG * TicketKey = TlsContext->SecConfig->TicketKey;

    CXPLAT_DBG_ASSERT(TicketKey != 0);
    if (TicketKey == 0) {
        return -1;
    }

    CXPLAT_STATIC_ASSERT(sizeof(TicketKey->Id) == 16,
                         "key_name and TicketKey->Id are the same size");

    if (enc) {
        if (QUIC_FAILED(CxPlatRandom(EVP_MAX_IV_LENGTH, iv))) {
            QuicTraceEvent(TlsError, "[ tls][%p] ERROR, %s.",
                           TlsContext->Connection,
                           "Failed to generate ticket IV");
            return -1; // Insufficient random
        }
        CxPlatCopyMemory(key_name, TicketKey->Id, 16);
        wolfSSL_EVP_CipherInit(ctx, CXPLAT_AES_256_CBC_ALG_HANDLE,
                               TicketKey->Material, iv, enc);

        wolfSSL_HMAC_Init(hctx, TicketKey->Material, 32, wolfSSL_EVP_sha256());
    } else {
        if (memcmp(key_name, TicketKey->Id, 16) != 0) {
            QuicTraceEvent(TlsError, "[ tls][%p] ERROR, %s.",
                           TlsContext->Connection, "Ticket key_name mismatch");
            return 0; // No match
        }
        wolfSSL_HMAC_Init(hctx, TicketKey->Material, 32, wolfSSL_EVP_sha256());
        wolfSSL_EVP_CipherInit(ctx, CXPLAT_AES_256_CBC_ALG_HANDLE,
                               TicketKey->Material, iv, enc);
    }

    return 1; // This indicates that the ctx and hctx have been set and the
              // session can continue on those parameters.
}


int CxPlatTlsOnServerSessionTicketGenerated(WOLFSSL * Ssl, void * arg)
{
    puts("TODO CxPlatTlsOnServerSessionTicketGenerated");
    UNREFERENCED_PARAMETER(arg);
    UNREFERENCED_PARAMETER(Ssl);

    // CXPLAT_TLS * TlsContext = wolfSSL_get_app_data(Ssl);
    return 1;
}


#if 0
int CxPlatTlsOnServerSessionTicketDecrypted(
    WOLFSSL * Ssl,
    byte key_name[WOLFSSL_TICKET_NAME_SZ],
    byte iv[WOLFSSL_TICKET_IV_SZ],
    byte mac[WOLFSSL_TICKET_MAC_SZ],
    int enc,
    byte * ticket,
    int inLen,
    int * outLen,
    void * userCtx)
{
    puts("TODO CxPlatTlsOnServerSessionTicketDecrypted");

    // UNREFERENCED_PARAMETER(ssl);
    UNREFERENCED_PARAMETER(key_name);
    UNREFERENCED_PARAMETER(iv);
    UNREFERENCED_PARAMETER(mac);
    UNREFERENCED_PARAMETER(enc);
    UNREFERENCED_PARAMETER(ticket);
    UNREFERENCED_PARAMETER(inLen);
    UNREFERENCED_PARAMETER(outLen);
    UNREFERENCED_PARAMETER(userCtx);

    CXPLAT_TLS * TlsContext = SSL_get_app_data(Ssl);

    QuicTraceLogConnVerbose(OpenSslTickedDecrypted, TlsContext->Connection,
                            "Session ticket decrypted");

    SSL_TICKET_RETURN Result;
    if (status == SSL_TICKET_SUCCESS) {
        Result = SSL_TICKET_RETURN_USE;
    } else if (status == SSL_TICKET_SUCCESS_RENEW) {
        Result = SSL_TICKET_RETURN_USE_RENEW;
    } else {
        Result = SSL_TICKET_RETURN_IGNORE_RENEW;
    }

    uint8_t * Buffer = NULL;
    size_t Length = 0;
    if (Session != NULL &&
        SSL_SESSION_get0_ticket_appdata(Session, (void **)&Buffer, &Length)) {

        QuicTraceLogConnVerbose(OpenSslRecvTicketData, TlsContext->Connection,
                                "Received ticket data, %u bytes",
                                (uint32_t)Length);

        if (!TlsContext->SecConfig->Callbacks.ReceiveTicket(
                TlsContext->Connection, (uint32_t)Length, Buffer)) {
            QuicTraceEvent(TlsError, "[ tls][%p] ERROR, %s.",
                           TlsContext->Connection, "ReceiveTicket failed");
            if (status == SSL_TICKET_SUCCESS_RENEW) {
                Result = SSL_TICKET_RETURN_IGNORE_RENEW;
            } else {
                Result = SSL_TICKET_RETURN_IGNORE;
            }
        }
    }

    return Result;
}
#endif

WOLFSSL_QUIC_METHOD WolfQuicCallbacks = {
    CxPlatTlsSetEncryptionSecretsCallback, CxPlatTlsAddHandshakeDataCallback,
    CxPlatTlsFlushFlightCallback, CxPlatTlsSendAlertCallback};


CXPLAT_STATIC_ASSERT(FIELD_OFFSET(QUIC_CERTIFICATE_FILE, PrivateKeyFile) ==
                         FIELD_OFFSET(QUIC_CERTIFICATE_FILE_PROTECTED,
                                      PrivateKeyFile),
                     "Mismatch (private key) in certificate file structs");

CXPLAT_STATIC_ASSERT(FIELD_OFFSET(QUIC_CERTIFICATE_FILE, CertificateFile) ==
                         FIELD_OFFSET(QUIC_CERTIFICATE_FILE_PROTECTED,
                                      CertificateFile),
                     "Mismatch (certificate file) in certificate file structs");


QUIC_TLS_PROVIDER CxPlatTlsGetProvider(void)
{
    return QUIC_TLS_PROVIDER_WOLFSSL;
}


QUIC_STATUS CxPlatTlsSecConfigCreate(
    const QUIC_CREDENTIAL_CONFIG * CredConfig,
    CXPLAT_TLS_CREDENTIAL_FLAGS TlsCredFlags,
    const CXPLAT_TLS_CALLBACKS * TlsCallbacks,
    void * Context,
    CXPLAT_SEC_CONFIG_CREATE_COMPLETE_HANDLER CompletionHandler)
{
    QUIC_CREDENTIAL_FLAGS CredConfigFlags = CredConfig->Flags;

    if (CredConfigFlags & QUIC_CREDENTIAL_FLAG_LOAD_ASYNCHRONOUS &&
        CredConfig->AsyncHandler == 0) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    if (CredConfigFlags & QUIC_CREDENTIAL_FLAG_ENABLE_OCSP ||
        CredConfigFlags & QUIC_CREDENTIAL_FLAG_USE_SUPPLIED_CREDENTIALS ||
        CredConfigFlags & QUIC_CREDENTIAL_FLAG_USE_SYSTEM_MAPPER ||
        CredConfigFlags & QUIC_CREDENTIAL_FLAG_INPROC_PEER_CERTIFICATE) {
        return QUIC_STATUS_NOT_SUPPORTED; // Not supported by this TLS
                                          // implementation
    }

#ifdef CX_PLATFORM_USES_TLS_BUILTIN_CERTIFICATE
    CredConfigFlags |=
        QUIC_CREDENTIAL_FLAG_USE_TLS_BUILTIN_CERTIFICATE_VALIDATION;
#endif

    if ((CredConfigFlags & QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION) &&
        !(CredConfigFlags &
          QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED)) {
        return QUIC_STATUS_INVALID_PARAMETER; // Defer validation without
                                              // indication doesn't make
                                              // sense.
    }

    if ((CredConfigFlags &
         QUIC_CREDENTIAL_FLAG_USE_TLS_BUILTIN_CERTIFICATE_VALIDATION) &&
        (CredConfigFlags & QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_END_CERT ||
         CredConfigFlags & QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_CHAIN ||
         CredConfigFlags &
             QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT ||
         CredConfigFlags & QUIC_CREDENTIAL_FLAG_IGNORE_NO_REVOCATION_CHECK ||
         CredConfigFlags & QUIC_CREDENTIAL_FLAG_IGNORE_REVOCATION_OFFLINE ||
         CredConfigFlags & QUIC_CREDENTIAL_FLAG_CACHE_ONLY_URL_RETRIEVAL ||
         CredConfigFlags & QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_CACHE_ONLY)) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    if (CredConfig->Reserved != 0) {
        return QUIC_STATUS_INVALID_PARAMETER; // Not currently used and
                                              // should be 0.
    }

    if (CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE) {
        if (CredConfig->CertificateFile == 0 ||
            CredConfig->CertificateFile->CertificateFile == 0 ||
            CredConfig->CertificateFile->PrivateKeyFile == 0) {
            return QUIC_STATUS_INVALID_PARAMETER;
        }
    } else if (CredConfig->Type ==
               QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED) {
        if (CredConfig->CertificateFileProtected == 0 ||
            CredConfig->CertificateFileProtected->CertificateFile == 0 ||
            CredConfig->CertificateFileProtected->PrivateKeyFile == 0 ||
            CredConfig->CertificateFileProtected->PrivateKeyPassword == 0) {
            return QUIC_STATUS_INVALID_PARAMETER;
        }
    } else if (CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12) {
        if (CredConfig->CertificatePkcs12 == 0 ||
            CredConfig->CertificatePkcs12->Asn1Blob == 0 ||
            CredConfig->CertificatePkcs12->Asn1BlobLength == 0) {
            return QUIC_STATUS_INVALID_PARAMETER;
        }
    } else if (
        CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH ||
        CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE ||
        CredConfig->Type ==
            QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT) { // NOLINT
                                                        // bugprone-branch-clone
#ifndef _WIN32
        return QUIC_STATUS_NOT_SUPPORTED; // Only supported on windows.
#endif
        // Windows parameters checked later
    } else if (CredConfig->Type == QUIC_CREDENTIAL_TYPE_NONE) {
        if (!(CredConfigFlags & QUIC_CREDENTIAL_FLAG_CLIENT)) {
            return QUIC_STATUS_INVALID_PARAMETER; // Required for server
        }
    } else {
        return QUIC_STATUS_NOT_SUPPORTED;
    }

    if (CredConfigFlags & QUIC_CREDENTIAL_FLAG_SET_ALLOWED_CIPHER_SUITES &&
        ((CredConfig->AllowedCipherSuites &
          (QUIC_ALLOWED_CIPHER_SUITE_AES_128_GCM_SHA256 |
           QUIC_ALLOWED_CIPHER_SUITE_AES_256_GCM_SHA384 |
           QUIC_ALLOWED_CIPHER_SUITE_CHACHA20_POLY1305_SHA256)) == 0)) {
        QuicTraceEvent(LibraryErrorStatus, "[ lib] ERROR, %u, %s.",
                       CredConfig->AllowedCipherSuites,
                       "No valid cipher suites presented");
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    int Ret = 0;
    CXPLAT_SEC_CONFIG * SecurityConfig = 0;
    WOLFSSL_X509 * X509Cert = 0;
    WOLFSSL_EVP_PKEY * PrivateKey = 0;
    char * CipherSuiteString = 0;
    WC_PKCS12 * Pkcs12 = 0;

    // Create a security config.
    SecurityConfig =
        CXPLAT_ALLOC_NONPAGED(sizeof(CXPLAT_SEC_CONFIG), QUIC_POOL_TLS_SECCONF);
    if (SecurityConfig == 0) {
        QuicTraceEvent(AllocFailure, "Allocation of '%s' failed. (%llu bytes)",
                       "CXPLAT_SEC_CONFIG", sizeof(CXPLAT_SEC_CONFIG));
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    CxPlatZeroMemory(SecurityConfig, sizeof(CXPLAT_SEC_CONFIG));
    SecurityConfig->Callbacks = *TlsCallbacks;
    SecurityConfig->Flags = CredConfigFlags;
    SecurityConfig->TlsFlags = TlsCredFlags;

    // Create the a SSL context for the security config.
    SecurityConfig->SSLCtx = wolfSSL_CTX_new(wolfTLSv1_3_method());
    if (SecurityConfig->SSLCtx == 0) {
        QuicTraceEvent(LibraryErrorStatus, "[ lib] ERROR, %u, %s.",
                       wolfSSL_ERR_get_error(), "wolfSSL_CTX_new failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    // Configure the SSL context with the defaults.
    Ret = wolfSSL_CTX_set_min_proto_version(SecurityConfig->SSLCtx,
                                            TLS1_3_VERSION);
    if (Ret != 1) {
        QuicTraceEvent(LibraryErrorStatus, "[ lib] ERROR, %u, %s.",
                       wolfSSL_ERR_get_error(),
                       "wolfSSL_CTX_set_min_proto_version failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret = wolfSSL_CTX_UseSessionTicket(SecurityConfig->SSLCtx);
    if (Ret != 1) {
        QuicTraceEvent(LibraryErrorStatus, "[ lib] ERROR, %u, %s.",
                       wolfSSL_ERR_get_error(),
                       "wolfSSL_CTX_UseSessionTicket failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret = wolfSSL_CTX_set_max_proto_version(SecurityConfig->SSLCtx,
                                            TLS1_3_VERSION);
    if (Ret != 1) {
        QuicTraceEvent(LibraryErrorStatus, "[ lib] ERROR, %u, %s.",
                       wolfSSL_ERR_get_error(),
                       "wolfSSL_CTX_set_max_proto_version failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    char * CipherSuites = CXPLAT_TLS_DEFAULT_SSL_CIPHERS;
    if (CredConfigFlags & QUIC_CREDENTIAL_FLAG_SET_ALLOWED_CIPHER_SUITES) {
        // Calculate allowed cipher suite string length.
        uint8_t CipherSuiteStringLength = 0;
        uint8_t AllowedCipherSuitesCount = 0;
        if (CredConfig->AllowedCipherSuites &
            QUIC_ALLOWED_CIPHER_SUITE_AES_128_GCM_SHA256) {
            CipherSuiteStringLength +=
                (uint8_t)sizeof(CXPLAT_TLS_AES_128_GCM_SHA256);
            AllowedCipherSuitesCount++;
        }
        if (CredConfig->AllowedCipherSuites &
            QUIC_ALLOWED_CIPHER_SUITE_AES_256_GCM_SHA384) {
            CipherSuiteStringLength +=
                (uint8_t)sizeof(CXPLAT_TLS_AES_256_GCM_SHA384);
            AllowedCipherSuitesCount++;
        }
        if (CredConfig->AllowedCipherSuites &
            QUIC_ALLOWED_CIPHER_SUITE_CHACHA20_POLY1305_SHA256) {
            CipherSuiteStringLength +=
                (uint8_t)sizeof(CXPLAT_TLS_CHACHA20_POLY1305_SHA256);
            AllowedCipherSuitesCount++;
        }

        CipherSuiteString = CXPLAT_ALLOC_NONPAGED(
            CipherSuiteStringLength, QUIC_POOL_TLS_CIPHER_SUITE_STRING);
        if (CipherSuiteString == 0) {
            QuicTraceEvent(AllocFailure,
                           "Allocation of '%s' failed. (%llu bytes)",
                           "CipherSuiteString", CipherSuiteStringLength);
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            goto Exit;
        }

        // Order of if-statements matters here because WolfSSL uses the
        // order of cipher suites to indicate preference. Below, we use the
        // default order of preference for TLS 1.3 cipher suites.
        //
        uint8_t CipherSuiteStringCursor = 0;
        if (CredConfig->AllowedCipherSuites &
            QUIC_ALLOWED_CIPHER_SUITE_AES_256_GCM_SHA384) {
            CxPlatCopyMemory(&CipherSuiteString[CipherSuiteStringCursor],
                             CXPLAT_TLS_AES_256_GCM_SHA384,
                             sizeof(CXPLAT_TLS_AES_256_GCM_SHA384));
            CipherSuiteStringCursor +=
                (uint8_t)sizeof(CXPLAT_TLS_AES_256_GCM_SHA384);
            if (--AllowedCipherSuitesCount > 0) {
                CipherSuiteString[CipherSuiteStringCursor - 1] = ':';
            }
        }
        if (CredConfig->AllowedCipherSuites &
            QUIC_ALLOWED_CIPHER_SUITE_CHACHA20_POLY1305_SHA256) {
            CxPlatCopyMemory(&CipherSuiteString[CipherSuiteStringCursor],
                             CXPLAT_TLS_CHACHA20_POLY1305_SHA256,
                             sizeof(CXPLAT_TLS_CHACHA20_POLY1305_SHA256));
            CipherSuiteStringCursor +=
                (uint8_t)sizeof(CXPLAT_TLS_CHACHA20_POLY1305_SHA256);
            if (--AllowedCipherSuitesCount > 0) {
                CipherSuiteString[CipherSuiteStringCursor - 1] = ':';
            }
        }
        if (CredConfig->AllowedCipherSuites &
            QUIC_ALLOWED_CIPHER_SUITE_AES_128_GCM_SHA256) {
            CxPlatCopyMemory(&CipherSuiteString[CipherSuiteStringCursor],
                             CXPLAT_TLS_AES_128_GCM_SHA256,
                             sizeof(CXPLAT_TLS_AES_128_GCM_SHA256));
            CipherSuiteStringCursor +=
                (uint8_t)sizeof(CXPLAT_TLS_AES_128_GCM_SHA256);
        }
        CXPLAT_DBG_ASSERT(CipherSuiteStringCursor == CipherSuiteStringLength);
        CipherSuites = CipherSuiteString;
    }

    Ret = wolfSSL_CTX_set_cipher_list(SecurityConfig->SSLCtx, CipherSuites);
    if (Ret != 1) {
        QuicTraceEvent(LibraryErrorStatus, "[ lib] ERROR, %u, %s.",
                       wolfSSL_ERR_get_error(),
                       "wolfSSL_CTX_set_cipher_list failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    if (SecurityConfig->Flags &
        QUIC_CREDENTIAL_FLAG_USE_TLS_BUILTIN_CERTIFICATE_VALIDATION) {
        Ret = wolfSSL_CTX_set_default_verify_paths(SecurityConfig->SSLCtx);
        if (Ret != 1) {
            QuicTraceEvent(LibraryErrorStatus, "[ lib] ERROR, %u, %s.",
                           wolfSSL_ERR_get_error(),
                           "wolfSSL_CTX_set_default_verify_paths failed");
            Status = QUIC_STATUS_TLS_ERROR;
            goto Exit;
        }
    }

    Ret =
        wolfSSL_CTX_set_quic_method(SecurityConfig->SSLCtx, &WolfQuicCallbacks);
    if (Ret != 1) {
        QuicTraceEvent(LibraryErrorStatus, "[ lib] ERROR, %u, %s.",
                       wolfSSL_ERR_get_error(),
                       "wolfSSL_CTX_set_quic_method failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    if ((CredConfigFlags & QUIC_CREDENTIAL_FLAG_CLIENT) &&
        !(TlsCredFlags & CXPLAT_TLS_CREDENTIAL_FLAG_DISABLE_RESUMPTION)) {
        wolfSSL_CTX_set_session_cache_mode(
            SecurityConfig->SSLCtx,
            SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
        wolfSSL_CTX_sess_set_new_cb(SecurityConfig->SSLCtx,
                                    CxPlatTlsOnClientSessionTicketReceived);
    }

    if (!(CredConfigFlags & QUIC_CREDENTIAL_FLAG_CLIENT)) {
        if (!(TlsCredFlags & CXPLAT_TLS_CREDENTIAL_FLAG_DISABLE_RESUMPTION)) {
            Ret = wolfSSL_CTX_set_max_early_data(SecurityConfig->SSLCtx,
                                                 0xFFFFFFFF);
            if (Ret != 1) {
                QuicTraceEvent(LibraryErrorStatus, "[ lib] ERROR, %u, %s.",
                               wolfSSL_ERR_get_error(),
                               "wolfSSL_CTX_set_max_early_data failed");
                Status = QUIC_STATUS_TLS_ERROR;
                goto Exit;
            }

            // Ret = wolfSSL_CTX_set_TicketEncCb(
            //     SecurityConfig->SSLCtx,
            //     CxPlatTlsOnServerSessionTicketDecrypted);
            // if (Ret != 1) {
            //     QuicTraceEvent(LibraryErrorStatus, "[ lib] ERROR, %u, %s.",
            //                    wolfSSL_ERR_get_error(),
            //                    "wolfSSL_CTX_set_TicketEncCb failed");
            //     Status = QUIC_STATUS_TLS_ERROR;
            //     goto Exit;
            // }
        }

        Ret = wolfSSL_CTX_set_num_tickets(SecurityConfig->SSLCtx, 0);
        if (Ret != 1) {
            QuicTraceEvent(LibraryErrorStatus, "[ lib] ERROR, %u, %s.",
                           wolfSSL_ERR_get_error(),
                           "wolfSSL_CTX_set_num_tickets failed");
            Status = QUIC_STATUS_TLS_ERROR;
            goto Exit;
        }
    }

    // Set the certs.
    if (CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE ||
        CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED) {

        if (CredConfig->Type ==
            QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED) {
            wolfSSL_CTX_set_default_passwd_cb_userdata(
                SecurityConfig->SSLCtx,
                (void *)
                    CredConfig->CertificateFileProtected->PrivateKeyPassword);
        }

        Ret = wolfSSL_CTX_use_PrivateKey_file(
            SecurityConfig->SSLCtx, CredConfig->CertificateFile->PrivateKeyFile,
            SSL_FILETYPE_PEM);
        if (Ret != 1) {
            QuicTraceEvent(LibraryErrorStatus, "[ lib] ERROR, %u, %s.",
                           wolfSSL_ERR_get_error(),
                           "wolfSSL_CTX_use_PrivateKey_file failed");
            Status = QUIC_STATUS_TLS_ERROR;
            goto Exit;
        }

        Ret = wolfSSL_CTX_use_certificate_file(
            SecurityConfig->SSLCtx,
            CredConfig->CertificateFile->CertificateFile, SSL_FILETYPE_PEM);
        if (Ret != 1) {
            QuicTraceEvent(LibraryErrorStatus, "[ lib] ERROR, %u, %s.",
                           wolfSSL_ERR_get_error(),
                           "wolfSSL_CTX_use_certificate_file failed");
            Status = QUIC_STATUS_TLS_ERROR;
            goto Exit;
        }
    } else if (CredConfig->Type != QUIC_CREDENTIAL_TYPE_NONE) {
        puts("TODO CredConfig->Type != QUIC_CREDENTIAL_TYPE_NONE");

        // BIO * Bio = BIO_new(BIO_s_mem());
        const char * Password = 0;
        char PasswordBuffer[PFX_PASSWORD_LENGTH];

        Pkcs12 = wc_PKCS12_new();
        if (!Pkcs12) {
            QuicTraceEvent(LibraryErrorStatus, "[ lib] ERROR, %u, %s.",
                           wolfSSL_ERR_get_error(), "wc_PKCS12_new failed");
            Status = QUIC_STATUS_TLS_ERROR;
            goto Exit;
        }

        // BIO_set_mem_eof_return(Bio, 0);

        if (CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12) {
            Password = CredConfig->CertificatePkcs12->PrivateKeyPassword;
            // Ret = BIO_write(Bio, CredConfig->CertificatePkcs12->Asn1Blob,
            //                 CredConfig->CertificatePkcs12->Asn1BlobLength);
            // if (Ret < 0) {
            //     QuicTraceEvent(LibraryErrorStatus, "[ lib] ERROR, %u, %s.",
            //                    wolfSSL_ERR_get_error(), "BIO_write failed");
            //     Status = QUIC_STATUS_TLS_ERROR;
            //     goto Exit;
            // }
        } else {
            uint8_t * PfxBlob = 0;
            uint32_t PfxSize = 0;
            CxPlatRandom(sizeof(PasswordBuffer), PasswordBuffer);

            // Fixup password to printable characters
            for (uint32_t idx = 0; idx < sizeof(PasswordBuffer); ++idx) {
                PasswordBuffer[idx] = ((uint8_t)PasswordBuffer[idx] % 94) + 32;
            }
            PasswordBuffer[PFX_PASSWORD_LENGTH - 1] = 0;
            Password = PasswordBuffer;

            Status = CxPlatCertExtractPrivateKey(CredConfig, PasswordBuffer,
                                                 &PfxBlob, &PfxSize);
            if (QUIC_FAILED(Status)) {
                goto Exit;
            }

            // Ret = BIO_write(Bio, PfxBlob, PfxSize);
            // CXPLAT_FREE(PfxBlob, QUIC_POOL_TLS_PFX);
            // if (Ret < 0) {
            //     QuicTraceEvent(LibraryErrorStatus, "[ lib] ERROR, %u, %s.",
            //                    wolfSSL_ERR_get_error(), "BIO_write failed");
            //     Status = QUIC_STATUS_TLS_ERROR;
            //     goto Exit;
            // }
        }

        wolfSSL_Debugging_ON();
        puts((char *)CredConfig->CertificatePkcs12->Asn1Blob);
        DerBuffer * der = 0;
        int keyFormat = 0;
        Ret = wc_PemToDer(CredConfig->CertificatePkcs12->Asn1Blob,
                          CredConfig->CertificatePkcs12->Asn1BlobLength,
                          CERT_TYPE, &der, 0, 0, &keyFormat);
        if (Ret) {
            QuicTraceEvent(LibraryErrorStatus, "[ lib] ERROR, %u, %s.",
                           wolfSSL_ERR_get_error(), "wc_PemToDer failed");
            Status = QUIC_STATUS_TLS_ERROR;
            goto Exit;
        }

        puts((char *)der->buffer);
        Ret = wc_d2i_PKCS12(der->buffer, der->length, Pkcs12);
        // BIO_free(Bio);
        // Bio = 0;

        wolfSSL_Debugging_OFF();
        if (Ret) {
            QuicTraceEvent(LibraryErrorStatus, "[ lib] ERROR, %u, %s.", Ret,
                           wc_GetErrorString(Ret));
            Status = QUIC_STATUS_TLS_ERROR;
            goto Exit;
        }

        STACK_OF(X509) * CaCertificates = 0;
        Ret = wolfSSL_PKCS12_parse(Pkcs12, Password, &PrivateKey, &X509Cert,
                                   &CaCertificates);
        if (CaCertificates) {
            X509 * CaCert;
            while ((CaCert = sk_X509_pop(CaCertificates)) != 0) {
                // This transfers ownership to SSLCtx and CaCert does not need
                // to be freed.
                wolfSSL_CTX_add_extra_chain_cert(SecurityConfig->SSLCtx,
                                                 CaCert);
            }
            wolfSSL_sk_X509_free(CaCertificates);
        }

        if (Password == PasswordBuffer) {
            CxPlatZeroMemory(PasswordBuffer, sizeof(PasswordBuffer));
        }

        if (Ret != 1) {
            QuicTraceEvent(LibraryErrorStatus, "[ lib] ERROR, %u, %s.",
                           wolfSSL_ERR_get_error(), "PKCS12_parse failed");
            Status = QUIC_STATUS_TLS_ERROR;
            goto Exit;
        }

        Ret = wolfSSL_CTX_use_PrivateKey(SecurityConfig->SSLCtx, PrivateKey);
        if (Ret != 1) {
            QuicTraceEvent(LibraryErrorStatus, "[ lib] ERROR, %u, %s.",
                           wolfSSL_ERR_get_error(),
                           "wolfSSL_CTX_use_PrivateKey failed");
            Status = QUIC_STATUS_TLS_ERROR;
            goto Exit;
        }

        Ret =
            (int)wolfSSL_CTX_use_certificate(SecurityConfig->SSLCtx, X509Cert);
        if (Ret != 1) {
            QuicTraceEvent(LibraryErrorStatus, "[ lib] ERROR, %u, %s.",
                           wolfSSL_ERR_get_error(),
                           "wolfSSL_CTX_use_certificate failed");
            Status = QUIC_STATUS_TLS_ERROR;
            goto Exit;
        }
    }

    if (CredConfig->Type != QUIC_CREDENTIAL_TYPE_NONE) {
        Ret = wolfSSL_CTX_check_private_key(SecurityConfig->SSLCtx);
        if (Ret != 1) {
            QuicTraceEvent(LibraryErrorStatus, "[ lib] ERROR, %u, %s.",
                           wolfSSL_ERR_get_error(),
                           "wolfSSL_CTX_check_private_key failed");
            Status = QUIC_STATUS_TLS_ERROR;
            goto Exit;
        }
    }

    if (CredConfigFlags & QUIC_CREDENTIAL_FLAG_CLIENT) {
        wolfSSL_CTX_set_verify(SecurityConfig->SSLCtx, SSL_VERIFY_PEER,
                               CxPlatTlsCertificateVerifyCallback);
        if (!(CredConfigFlags &
              (QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION |
               QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION))) {
            wolfSSL_CTX_set_verify_depth(SecurityConfig->SSLCtx,
                                         CXPLAT_TLS_DEFAULT_VERIFY_DEPTH);
        }

        // TODO - Support additional certificate validation parameters, such
        // as the location of the trusted root CAs
        // (SSL_CTX_load_verify_locations)?

    } else {
        wolfSSL_CTX_set_options(
            SecurityConfig->SSLCtx,
            (WOLFSSL_OP_ALL & ~WOLFSSL_OP_DONT_INSERT_EMPTY_FRAGMENTS) |
                WOLFSSL_OP_SINGLE_ECDH_USE |
                WOLFSSL_OP_CIPHER_SERVER_PREFERENCE);
        wolfSSL_CTX_set_mode(SecurityConfig->SSLCtx, SSL_MODE_RELEASE_BUFFERS);

        if (CredConfigFlags &
                QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED ||
            CredConfigFlags &
                QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION) {
            wolfSSL_CTX_set_verify(SecurityConfig->SSLCtx, SSL_VERIFY_PEER,
                                   CxPlatTlsCertificateVerifyCallback);
        }

        if (CredConfigFlags &
            QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION) {
            int VerifyMode = SSL_VERIFY_PEER;
            if (!(CredConfigFlags &
                  QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION)) {
                wolfSSL_CTX_set_verify_depth(SecurityConfig->SSLCtx,
                                             CXPLAT_TLS_DEFAULT_VERIFY_DEPTH);
            }
            if (!(CredConfigFlags &
                  (QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION |
                   QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION))) {
                VerifyMode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
            }
            wolfSSL_CTX_set_verify(SecurityConfig->SSLCtx, VerifyMode, 0);
        }

        wolfSSL_CTX_set_alpn_select_cb(SecurityConfig->SSLCtx,
                                       CxPlatTlsAlpnSelectCallback, 0);

        wolfSSL_CTX_set_max_early_data(SecurityConfig->SSLCtx, UINT32_MAX);
#if 0
        wolfSSL_CTX_set_client_hello_cb(SecurityConfig->SSLCtx,
                                        CxPlatTlsClientHelloCallback, 0);
#endif
    }

    // Invoke completion inline.

    CompletionHandler(CredConfig, Context, Status, SecurityConfig);
    SecurityConfig = 0;

    if (CredConfigFlags & QUIC_CREDENTIAL_FLAG_LOAD_ASYNCHRONOUS) {
        Status = QUIC_STATUS_PENDING;
    } else {
        Status = QUIC_STATUS_SUCCESS;
    }

Exit:
    if (SecurityConfig != 0) {
        CxPlatTlsSecConfigDelete(SecurityConfig);
    }

    if (CipherSuiteString != 0) {
        CxPlatFree(CipherSuiteString, QUIC_POOL_TLS_CIPHER_SUITE_STRING);
    }

    if (X509Cert != 0) {
        X509_free(X509Cert);
    }

    if (Pkcs12 != 0) {
        wc_PKCS12_free(Pkcs12);
    }

    if (PrivateKey != 0) {
        wolfSSL_EVP_PKEY_free(PrivateKey);
    }

    return Status;
}


void CxPlatTlsSecConfigDelete(CXPLAT_SEC_CONFIG * SecurityConfig)
{
    if (SecurityConfig->SSLCtx != 0) {
        wolfSSL_CTX_free(SecurityConfig->SSLCtx);
    }

    if (SecurityConfig->TicketKey != 0) {
        CXPLAT_FREE(SecurityConfig->TicketKey, QUIC_POOL_TLS_TICKET_KEY);
    }

    CXPLAT_FREE(SecurityConfig, QUIC_POOL_TLS_SECCONF);
}


QUIC_STATUS CxPlatTlsSecConfigSetTicketKeys(CXPLAT_SEC_CONFIG * SecurityConfig,
                                            QUIC_TICKET_KEY_CONFIG * KeyConfig,
                                            uint8_t KeyCount)
{
    CXPLAT_DBG_ASSERT(KeyCount >= 1); // Only support 1, ignore the rest for now
    UNREFERENCED_PARAMETER(KeyCount);

    if (SecurityConfig->Flags & QUIC_CREDENTIAL_FLAG_CLIENT) {
        return QUIC_STATUS_NOT_SUPPORTED;
    }

    if (SecurityConfig->TicketKey == 0) {
        SecurityConfig->TicketKey = CXPLAT_ALLOC_NONPAGED(
            sizeof(QUIC_TICKET_KEY_CONFIG), QUIC_POOL_TLS_TICKET_KEY);
        if (SecurityConfig->TicketKey == 0) {
            QuicTraceEvent(
                AllocFailure, "Allocation of '%s' failed. (%llu bytes)",
                "QUIC_TICKET_KEY_CONFIG", sizeof(QUIC_TICKET_KEY_CONFIG));
            return QUIC_STATUS_OUT_OF_MEMORY;
        }
    }

    CxPlatCopyMemory(SecurityConfig->TicketKey, KeyConfig,
                     sizeof(QUIC_TICKET_KEY_CONFIG));

    wolfSSL_CTX_set_tlsext_ticket_key_cb(SecurityConfig->SSLCtx,
                                         CxPlatTlsOnSessionTicketKeyNeeded);

    return QUIC_STATUS_SUCCESS;
}


QUIC_STATUS CxPlatTlsInitialize(const CXPLAT_TLS_CONFIG * Config,
                                CXPLAT_TLS_PROCESS_STATE * State,
                                CXPLAT_TLS ** NewTlsContext)
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    CXPLAT_TLS * TlsContext = 0;
    uint16_t ServerNameLength = 0;
    UNREFERENCED_PARAMETER(State);

    if (wolfSSL_Init() != SSL_SUCCESS) {
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    CXPLAT_DBG_ASSERT(Config->HkdfLabels);

    TlsContext = CXPLAT_ALLOC_NONPAGED(sizeof(CXPLAT_TLS), QUIC_POOL_TLS_CTX);
    if (TlsContext == 0) {
        QuicTraceEvent(AllocFailure, "Allocation of '%s' failed. (%llu bytes)",
                       "CXPLAT_TLS", sizeof(CXPLAT_TLS));
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    CxPlatZeroMemory(TlsContext, sizeof(CXPLAT_TLS));

    TlsContext->Connection = Config->Connection;
    TlsContext->HkdfLabels = Config->HkdfLabels;
    TlsContext->IsServer = Config->IsServer;
    TlsContext->SecConfig = Config->SecConfig;
    TlsContext->QuicTpExtType = Config->TPType;
    TlsContext->AlpnBufferLength = Config->AlpnBufferLength;
    TlsContext->AlpnBuffer = Config->AlpnBuffer;
    TlsContext->TlsSecrets = Config->TlsSecrets;

    QuicTraceLogConnVerbose(WolfSslContextCreated, TlsContext->Connection,
                            "TLS context Created");

    if (!Config->IsServer) {

        if (Config->ServerName != 0) {

            ServerNameLength =
                (uint16_t)strnlen(Config->ServerName, QUIC_MAX_SNI_LENGTH);
            if (ServerNameLength == QUIC_MAX_SNI_LENGTH) {
                QuicTraceEvent(TlsError, "[ tls][%p] ERROR, %s.",
                               TlsContext->Connection, "SNI Too Long");
                Status = QUIC_STATUS_INVALID_PARAMETER;
                goto Exit;
            }

            TlsContext->SNI =
                CXPLAT_ALLOC_NONPAGED(ServerNameLength + 1, QUIC_POOL_TLS_SNI);
            if (TlsContext->SNI == 0) {
                QuicTraceEvent(AllocFailure,
                               "Allocation of '%s' failed. (%llu bytes)", "SNI",
                               ServerNameLength + 1);
                Status = QUIC_STATUS_OUT_OF_MEMORY;
                goto Exit;
            }

            memcpy((char *)TlsContext->SNI, Config->ServerName,
                   ServerNameLength + 1);
        }
    }

    // Create a SSL object for the connection.
    TlsContext->Ssl = wolfSSL_new(Config->SecConfig->SSLCtx);
    if (TlsContext->Ssl == 0) {
        QuicTraceEvent(TlsError, "[ tls][%p] ERROR, %s.",
                       TlsContext->Connection, "wolfSSL_new failed");
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    wolfSSL_set_app_data(TlsContext->Ssl, TlsContext);

    if (Config->IsServer) {
        wolfSSL_set_accept_state(TlsContext->Ssl);
    } else {
        wolfSSL_set_connect_state(TlsContext->Ssl);
        wolfSSL_set_tlsext_host_name(TlsContext->Ssl, TlsContext->SNI);
        wolfSSL_set_alpn_protos(TlsContext->Ssl, TlsContext->AlpnBuffer,
                                TlsContext->AlpnBufferLength);
    }

    if (!(Config->SecConfig->TlsFlags &
          CXPLAT_TLS_CREDENTIAL_FLAG_DISABLE_RESUMPTION)) {

        if (Config->ResumptionTicketLength != 0) {
            CXPLAT_DBG_ASSERT(Config->ResumptionTicketBuffer != 0);

            QuicTraceLogConnInfo(WolfSslOnSetTicket, TlsContext->Connection,
                                 "TODO Setting session ticket, %u bytes",
                                 Config->ResumptionTicketLength);
            wolfSSL_Debugging_ON();

            const unsigned char * NewBuffer; // = CXPLAT_ALLOC_NONPAGED(
            //     Config->ResumptionTicketLength, QUIC_POOL_TLS_BUFFER);
            // if (NewBuffer == 0) {
            //     QuicTraceEvent(
            //         AllocFailure, "Allocation of '%s' failed. (%llu bytes)",
            //         "New ticket buffer", Config->ResumptionTicketLength);
            //     Status = QUIC_STATUS_OUT_OF_MEMORY;
            //     goto Exit;
            // }

            WOLFSSL_SESSION * Session = wolfSSL_d2i_SSL_SESSION(
                0, &NewBuffer, Config->ResumptionTicketLength);

            if (Session) {
                if (!wolfSSL_set_session(TlsContext->Ssl, Session)) {
                    QuicTraceEvent(TlsErrorStatus, "[ tls][%p] ERROR, %u, %s.",
                                   TlsContext->Connection,
                                   wolfSSL_ERR_get_error(),
                                   "wolfSSL_set_session failed");
                }
                wolfSSL_SESSION_free(Session);
            } else {
                QuicTraceEvent(TlsErrorStatus, "[ tls][%p] ERROR, %u, %s.",
                               TlsContext->Connection, wolfSSL_ERR_get_error(),
                               "wolfSSL_d2i_SSL_SESSION failed");
            }
            // CXPLAT_FREE(NewBuffer, QUIC_POOL_TLS_BUFFER);
        }

        if (Config->IsServer || (Config->ResumptionTicketLength != 0)) {
            wolfSSL_set_quic_early_data_enabled(TlsContext->Ssl, 1);
        }
    }

    wolfSSL_set_quic_use_legacy_codepoint(
        TlsContext->Ssl,
        TlsContext->QuicTpExtType ==
            TLS_EXTENSION_TYPE_QUIC_TRANSPORT_PARAMETERS_DRAFT);

    if (wolfSSL_set_quic_transport_params(TlsContext->Ssl,
                                          Config->LocalTPBuffer,
                                          Config->LocalTPLength) != 1) {
        QuicTraceEvent(TlsError, "[ tls][%p] ERROR, %s.",
                       TlsContext->Connection,
                       "wolfSSL_set_quic_transport_params failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }
    CXPLAT_FREE(Config->LocalTPBuffer, QUIC_POOL_TLS_TRANSPARAMS);
    if (Config->ResumptionTicketBuffer) {
        CXPLAT_FREE(Config->ResumptionTicketBuffer,
                    QUIC_POOL_CRYPTO_RESUMPTION_TICKET);
    }

    *NewTlsContext = TlsContext;
    TlsContext = 0;

Exit:
    if (TlsContext != 0) {
        CxPlatTlsUninitialize(TlsContext);
        TlsContext = 0;
    }

    return Status;
}


void CxPlatTlsUninitialize(CXPLAT_TLS * TlsContext)
{
    wolfSSL_Cleanup();

    if (TlsContext != 0) {
        QuicTraceLogConnVerbose(WolfSslContextCleaningUp,
                                TlsContext->Connection, "Cleaning up");

        if (TlsContext->SNI != 0) {
            CXPLAT_FREE(TlsContext->SNI, QUIC_POOL_TLS_SNI);
            TlsContext->SNI = 0;
        }

        if (TlsContext->Ssl != 0) {
            wolfSSL_free(TlsContext->Ssl);
            TlsContext->Ssl = 0;
        }

        CXPLAT_FREE(TlsContext, QUIC_POOL_TLS_CTX);
    }
}


void CxPlatTlsUpdateHkdfLabels(CXPLAT_TLS * TlsContext,
                               const QUIC_HKDF_LABELS * const Labels)
{
    TlsContext->HkdfLabels = Labels;
}


CXPLAT_TLS_RESULT_FLAGS CxPlatTlsProcessData(CXPLAT_TLS * TlsContext,
                                             CXPLAT_TLS_DATA_TYPE DataType,
                                             const uint8_t * Buffer,
                                             uint32_t * BufferLength,
                                             CXPLAT_TLS_PROCESS_STATE * State)
{
    CXPLAT_DBG_ASSERT(Buffer != 0 || *BufferLength == 0);

    TlsContext->State = State;
    TlsContext->ResultFlags = 0;

    if (DataType == CXPLAT_TLS_TICKET_DATA) {
        QuicTraceLogConnVerbose(WolfSslSendTicketData, TlsContext->Connection,
                                "Sending ticket data, %u bytes", *BufferLength);

        WOLFSSL_SESSION * Session = wolfSSL_get_session(TlsContext->Ssl);
        if (Session == 0) {
            QuicTraceEvent(TlsError, "[ tls][%p] ERROR, %s.",
                           TlsContext->Connection,
                           "wolfSSL_get_session failed");
            TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
            goto Exit;
        }

        if (!wolfSSL_set_SessionTicket(TlsContext->Ssl, Buffer,
                                       *BufferLength)) {
            QuicTraceEvent(TlsErrorStatus, "[ tls][%p] ERROR, %u, %s.",
                           TlsContext->Connection, wolfSSL_ERR_get_error(),
                           "wolfSSL_set_SessionTicket failed");
            TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
            goto Exit;
        }

        if (!wolfSSL_send_SessionTicket(TlsContext->Ssl)) {
            QuicTraceEvent(TlsErrorStatus, "[ tls][%p] ERROR, %u, %s.",
                           TlsContext->Connection, wolfSSL_ERR_get_error(),
                           "wolfSSL_send_SessionTicket failed");
            TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
            goto Exit;
        }

        int Ret = wolfSSL_SSL_do_handshake(TlsContext->Ssl);
        if (Ret != 1) {
            QuicTraceEvent(TlsErrorStatus, "[ tls][%p] ERROR, %u, %s.",
                           TlsContext->Connection,
                           wolfSSL_get_error(TlsContext->Ssl, Ret),
                           "wolfSSL_SSL_do_handshake failed");
            TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
            goto Exit;
        }

        goto Exit;
    }

    if (*BufferLength != 0) {
        QuicTraceLogConnVerbose(WolfSslProcessData, TlsContext->Connection,
                                "Processing %u received bytes", *BufferLength);

        if (wolfSSL_provide_quic_data(
                TlsContext->Ssl,
                (WOLFSSL_ENCRYPTION_LEVEL)TlsContext->State->ReadKey, Buffer,
                *BufferLength) != 1) {
            char buf[256];
            QuicTraceLogConnError(
                WolfSslQuicDataErrorStr, TlsContext->Connection,
                "wolfSSL_provide_quic_data failed: %s",
                wolfSSL_ERR_error_string(wolfSSL_ERR_get_error(), buf));
            TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
            goto Exit;
        }
    }

    if (!State->HandshakeComplete) {
        int Ret = wolfSSL_SSL_do_handshake(TlsContext->Ssl);
        if (Ret <= 0) {
            int Err = wolfSSL_get_error(TlsContext->Ssl, Ret);
            switch (Err) {
            case WOLFSSL_ERROR_WANT_READ:
            case WOLFSSL_ERROR_WANT_WRITE:
                // Best effort to get the server's transport params as early as
                // possible.
                if (!TlsContext->IsServer &&
                    TlsContext->PeerTPReceived == FALSE) {
                    const uint8_t * TransportParams;
                    size_t TransportParamLen;
                    wolfSSL_get_peer_quic_transport_params(
                        TlsContext->Ssl, &TransportParams, &TransportParamLen);
                    if (TransportParams != 0 && TransportParamLen != 0) {
                        TlsContext->PeerTPReceived = TRUE;
                        if (!TlsContext->SecConfig->Callbacks.ReceiveTP(
                                TlsContext->Connection,
                                (uint16_t)TransportParamLen, TransportParams)) {
                            TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
                            goto Exit;
                        }
                    }
                }
                goto Exit;

            case WOLFSSL_ERROR_SSL: {
                char buf[256];
                const char * file;
                int line;
                wolfSSL_ERR_error_string_n(
                    wolfSSL_ERR_get_error_line(&file, &line), buf, sizeof(buf));
                QuicTraceLogConnError(
                    WolfSslHandshakeErrorStr, TlsContext->Connection,
                    "TLS handshake error: %s, file:%s:%d", buf, file, line);
                TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
                goto Exit;
            }

            default:
                QuicTraceLogConnError(WolfSslHandshakeError,
                                      TlsContext->Connection,
                                      "TLS handshake error: %d", Err);
                TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
                goto Exit;
            }
        }

        if (!TlsContext->IsServer) {
            const uint8_t * NegotiatedAlpn;
            uint32_t NegotiatedAlpnLength;
            wolfSSL_get0_alpn_selected(TlsContext->Ssl, &NegotiatedAlpn,
                                       &NegotiatedAlpnLength);
            if (NegotiatedAlpnLength == 0) {
                QuicTraceLogConnError(WolfSslAlpnNegotiationFailure,
                                      TlsContext->Connection,
                                      "Failed to negotiate ALPN");
                TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
                goto Exit;
            }
            if (NegotiatedAlpnLength > UINT8_MAX) {
                QuicTraceLogConnError(WolfSslInvalidAlpnLength,
                                      TlsContext->Connection,
                                      "Invalid negotiated ALPN length");
                TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
                goto Exit;
            }
            TlsContext->State->NegotiatedAlpn = CxPlatTlsAlpnFindInList(
                TlsContext->AlpnBufferLength, TlsContext->AlpnBuffer,
                (uint8_t)NegotiatedAlpnLength, NegotiatedAlpn);
            if (TlsContext->State->NegotiatedAlpn == 0) {
                QuicTraceLogConnError(WolfSslNoMatchingAlpn,
                                      TlsContext->Connection,
                                      "Failed to find a matching ALPN");
                TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
                goto Exit;
            }
        } else if ((TlsContext->SecConfig->Flags &
                    QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED) &&
                   !TlsContext->PeerCertReceived) {
            QUIC_STATUS ValidationResult =
                (!(TlsContext->SecConfig->Flags &
                   QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION) &&
                 (TlsContext->SecConfig->Flags &
                      QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION ||
                  TlsContext->SecConfig->Flags &
                      QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION))
                    ? QUIC_STATUS_CERT_NO_CERT
                    : QUIC_STATUS_SUCCESS;

            if (!TlsContext->SecConfig->Callbacks.CertificateReceived(
                    TlsContext->Connection, 0, 0, 0, ValidationResult)) {
                QuicTraceEvent(TlsError, "[ tls][%p] ERROR, %s.",
                               TlsContext->Connection,
                               "Indicate 0 certificate received failed");
                TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
                TlsContext->State->AlertCode =
                    CXPLAT_TLS_ALERT_CODE_REQUIRED_CERTIFICATE;
                goto Exit;
            }
        }

        QuicTraceLogConnInfo(WolfSslHandshakeComplete, TlsContext->Connection,
                             "TLS Handshake complete");
        State->HandshakeComplete = TRUE;
        if (wolfSSL_session_reused(TlsContext->Ssl)) {
            QuicTraceLogConnInfo(WolfSslHandshakeResumed,
                                 TlsContext->Connection,
                                 "TLS Handshake resumed");
            State->SessionResumed = TRUE;
        }
        if (!TlsContext->IsServer) {
            int EarlyDataStatus =
                wolfSSL_get_early_data_status(TlsContext->Ssl);
            if (EarlyDataStatus == WOLFSSL_EARLY_DATA_ACCEPTED) {
                State->EarlyDataState = CXPLAT_TLS_EARLY_DATA_ACCEPTED;
                TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_EARLY_DATA_ACCEPT;

            } else if (EarlyDataStatus == WOLFSSL_EARLY_DATA_REJECTED) {
                State->EarlyDataState = CXPLAT_TLS_EARLY_DATA_REJECTED;
                TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_EARLY_DATA_REJECT;
            }
        }
        TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_HANDSHAKE_COMPLETE;

        if (TlsContext->IsServer) {
            TlsContext->State->ReadKey = QUIC_PACKET_KEY_1_RTT;
            TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_READ_KEY_UPDATED;
        } else if (!TlsContext->PeerTPReceived) {
            //
            // Last chance to get the server's transport params.
            //
            const uint8_t * TransportParams;
            size_t TransportParamLen;
            wolfSSL_get_peer_quic_transport_params(
                TlsContext->Ssl, &TransportParams, &TransportParamLen);
            if (TransportParams == 0 || TransportParamLen == 0) {
                QuicTraceLogConnError(WolfSslMissingTransportParameters,
                                      TlsContext->Connection,
                                      "No transport parameters received");
                TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
                goto Exit;
            }
            TlsContext->PeerTPReceived = TRUE;
            if (!TlsContext->SecConfig->Callbacks.ReceiveTP(
                    TlsContext->Connection, (uint16_t)TransportParamLen,
                    TransportParams)) {
                TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
                goto Exit;
            }
        }

    } else {
        if (wolfSSL_process_quic_post_handshake(TlsContext->Ssl) != 1) {
            QuicTraceEvent(TlsErrorStatus, "[ tls][%p] ERROR, %u, %s.",
                           TlsContext->Connection, wolfSSL_ERR_get_error(),
                           "wolfSSL_process_quic_post_handshake failed");
            TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
            goto Exit;
        }
    }

Exit:

    if (!(TlsContext->ResultFlags & CXPLAT_TLS_RESULT_ERROR)) {
        if (State->WriteKeys[QUIC_PACKET_KEY_HANDSHAKE] != 0 &&
            State->BufferOffsetHandshake == 0) {
            State->BufferOffsetHandshake = State->BufferTotalLength;
            QuicTraceLogConnInfo(WolfSslHandshakeDataStart,
                                 TlsContext->Connection,
                                 "Writing Handshake data starts at %u",
                                 State->BufferOffsetHandshake);
        }
        if (State->WriteKeys[QUIC_PACKET_KEY_1_RTT] != 0 &&
            State->BufferOffset1Rtt == 0) {
            State->BufferOffset1Rtt = State->BufferTotalLength;
            QuicTraceLogConnInfo(WolfSsl1RttDataStart, TlsContext->Connection,
                                 "Writing 1-RTT data starts at %u",
                                 State->BufferOffset1Rtt);
        }
    }

    return TlsContext->ResultFlags;
}


QUIC_STATUS
CxPlatSecConfigParamSet(CXPLAT_SEC_CONFIG * TlsContext,
                        uint32_t Param,
                        uint32_t BufferLength,
                        const void * Buffer)
{
    UNREFERENCED_PARAMETER(TlsContext);
    UNREFERENCED_PARAMETER(Param);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);
    return QUIC_STATUS_NOT_SUPPORTED;
}


QUIC_STATUS
CxPlatSecConfigParamGet(CXPLAT_SEC_CONFIG * SecConfig,
                        uint32_t Param,
                        uint32_t * BufferLength,
                        void * Buffer)
{
    UNREFERENCED_PARAMETER(SecConfig);
    UNREFERENCED_PARAMETER(Param);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);
    return QUIC_STATUS_NOT_SUPPORTED;
}


QUIC_STATUS CxPlatTlsParamSet(CXPLAT_TLS * SecConfig,
                              uint32_t Param,
                              uint32_t BufferLength,
                              const void * Buffer)
{
    UNREFERENCED_PARAMETER(SecConfig);
    UNREFERENCED_PARAMETER(Param);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);
    return QUIC_STATUS_NOT_SUPPORTED;
}


static QUIC_STATUS CxPlatMapCipherSuite(QUIC_HANDSHAKE_INFO * HandshakeInfo)
{
    // Mappings taken from the following .NET definitions.
    // https://github.com/dotnet/runtime/blob/69425a7e6198ff78131ad64f1aa3fc28202bfde8/src/libraries/Native/Unix/System.Security.Cryptography.Native/pal_ssl.c
    // https://github.com/dotnet/runtime/blob/1d9e50cb4735df46d3de0cee5791e97295eaf588/src/libraries/System.Net.Security/src/System/Net/Security/TlsCipherSuiteData.Lookup.cs
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    HandshakeInfo->KeyExchangeAlgorithm = QUIC_KEY_EXCHANGE_ALGORITHM_NONE;
    HandshakeInfo->KeyExchangeStrength = 0;
    HandshakeInfo->HashStrength = 0;

    switch (HandshakeInfo->CipherSuite) {
    case QUIC_CIPHER_SUITE_TLS_AES_128_GCM_SHA256:
        HandshakeInfo->CipherAlgorithm = QUIC_CIPHER_ALGORITHM_AES_128;
        HandshakeInfo->CipherStrength = 128;
        HandshakeInfo->Hash = QUIC_HASH_ALGORITHM_SHA_256;
        break;
    case QUIC_CIPHER_SUITE_TLS_AES_256_GCM_SHA384:
        HandshakeInfo->CipherAlgorithm = QUIC_CIPHER_ALGORITHM_AES_256;
        HandshakeInfo->CipherStrength = 256;
        HandshakeInfo->Hash = QUIC_HASH_ALGORITHM_SHA_384;
        break;
    case QUIC_CIPHER_SUITE_TLS_CHACHA20_POLY1305_SHA256:
        HandshakeInfo->CipherAlgorithm = QUIC_CIPHER_ALGORITHM_CHACHA20;
        HandshakeInfo->CipherStrength = 256; // TODO - Is this correct?
        HandshakeInfo->Hash = QUIC_HASH_ALGORITHM_SHA_256;
        break;
    default:
        Status = QUIC_STATUS_NOT_SUPPORTED;
        break;
    }

    return Status;
}


static uint32_t CxPlatMapVersion(const char * Version)
{
    if (strcmp(Version, "TLSv1.3") == 0) {
        return QUIC_TLS_PROTOCOL_1_3;
    }
    return QUIC_TLS_PROTOCOL_UNKNOWN;
}


QUIC_STATUS CxPlatTlsParamGet(CXPLAT_TLS * TlsContext,
                              uint32_t Param,
                              uint32_t * BufferLength,
                              void * Buffer)
{
    QUIC_STATUS Status;

    switch (Param) {

    case QUIC_PARAM_TLS_HANDSHAKE_INFO: {
        if (*BufferLength < sizeof(QUIC_HANDSHAKE_INFO)) {
            *BufferLength = sizeof(QUIC_HANDSHAKE_INFO);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == 0) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        QUIC_HANDSHAKE_INFO * HandshakeInfo = (QUIC_HANDSHAKE_INFO *)Buffer;
        HandshakeInfo->TlsProtocolVersion =
            CxPlatMapVersion(wolfSSL_get_version(TlsContext->Ssl));

        const WOLFSSL_CIPHER * Cipher =
            wolfSSL_get_current_cipher(TlsContext->Ssl);
        if (Cipher == 0) {
            QuicTraceEvent(TlsError, "[ tls][%p] ERROR, %s.",
                           TlsContext->Connection,
                           "Unable to get cipher suite");
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }
        HandshakeInfo->CipherSuite = wolfSSL_CIPHER_get_id(Cipher);
        Status = CxPlatMapCipherSuite(HandshakeInfo);
        break;
    }

    case QUIC_PARAM_TLS_NEGOTIATED_ALPN: {

        if (Buffer == 0) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        char * NegotiatedAlpn;
        unsigned short NegotiatedAlpnLen = 0;
        wolfSSL_ALPN_GetProtocol(TlsContext->Ssl, &NegotiatedAlpn,
                                 &NegotiatedAlpnLen);
        if (NegotiatedAlpnLen == 0) {
            QuicTraceEvent(TlsError, "[ tls][%p] ERROR, %s.",
                           TlsContext->Connection,
                           "Unable to get negotiated alpn");
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }
        if (*BufferLength < NegotiatedAlpnLen) {
            *BufferLength = NegotiatedAlpnLen;
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }
        *BufferLength = NegotiatedAlpnLen;
        CxPlatCopyMemory(Buffer, NegotiatedAlpn, NegotiatedAlpnLen);
        Status = QUIC_STATUS_SUCCESS;
        break;
    }

    default:
        Status = QUIC_STATUS_NOT_SUPPORTED;
        break;
    }

    return Status;
}
