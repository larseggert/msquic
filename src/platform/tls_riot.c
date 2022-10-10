/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Implements the TLS functions by calling RIOT.

--*/

#include "platform_internal.h"

// Default list of Cipher used.
#define CXPLAT_TLS_DEFAULT_SSL_CIPHERS                                         \
    "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_"     \
    "SHA256"
#define CXPLAT_TLS_AES_128_GCM_SHA256 "TLS_AES_128_GCM_SHA256"
#define CXPLAT_TLS_AES_256_GCM_SHA384 "TLS_AES_256_GCM_SHA384"
#define CXPLAT_TLS_CHACHA20_POLY1305_SHA256 "TLS_CHACHA20_POLY1305_SHA256"

uint16_t CxPlatTlsTPHeaderSize = 0;

typedef struct CXPLAT_SEC_CONFIG {
    // Optional ticket key provided by the app.
    QUIC_TICKET_KEY_CONFIG * TicketKey;

    // Callbacks for TLS.
    CXPLAT_TLS_CALLBACKS Callbacks;

    // The application supplied credential flags.
    QUIC_CREDENTIAL_FLAGS Flags;

    // Internal TLS credential flags.
    CXPLAT_TLS_CREDENTIAL_FLAGS TlsFlags;

} CXPLAT_SEC_CONFIG;

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

    // On client side stores a NULL terminated SNI.
    const char * SNI;

    // Ssl - A SSL object associated with the connection.
    //
    // SSL *Ssl;

    // State - The TLS state associated with the connection.
    // ResultFlags - Stores the result of the TLS data processing operation.
    CXPLAT_TLS_PROCESS_STATE * State;
    CXPLAT_TLS_RESULT_FLAGS ResultFlags;

    // Callback context and handler for QUIC TP.
    QUIC_CONNECTION * Connection;

} CXPLAT_TLS;

QUIC_TLS_PROVIDER
CxPlatTlsGetProvider(void)
{
    return QUIC_TLS_PROVIDER_RIOT;
}

QUIC_STATUS
CxPlatTlsParamSet(CXPLAT_TLS * SecConfig,
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

QUIC_STATUS
CxPlatTlsParamGet(CXPLAT_TLS * TlsContext,
                  uint32_t Param,
                  uint32_t * BufferLength,
                  void * Buffer)
{
    UNREFERENCED_PARAMETER(TlsContext);
    UNREFERENCED_PARAMETER(Param);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);

    puts("TODO CxPlatTlsParamGet");
    return QUIC_STATUS_SUCCESS;
}

void CxPlatTlsUpdateHkdfLabels(CXPLAT_TLS * TlsContext,
                               const QUIC_HKDF_LABELS * const Labels)
{
    UNREFERENCED_PARAMETER(TlsContext);
    UNREFERENCED_PARAMETER(Labels);
    puts("TODO CxPlatTlsUpdateHkdfLabels");
}

CXPLAT_TLS_RESULT_FLAGS
CxPlatTlsProcessData(CXPLAT_TLS * TlsContext,
                     CXPLAT_TLS_DATA_TYPE DataType,
                     const uint8_t * Buffer,
                     uint32_t * BufferLength,
                     CXPLAT_TLS_PROCESS_STATE * State)
{
    UNREFERENCED_PARAMETER(TlsContext);
    UNREFERENCED_PARAMETER(DataType);
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(State);

    CXPLAT_DBG_ASSERT(Buffer != NULL || *BufferLength == 0);
    puts("TODO CxPlatTlsProcessData");
    return CXPLAT_TLS_RESULT_ERROR;
}

QUIC_STATUS
CxPlatTlsInitialize(const CXPLAT_TLS_CONFIG * Config,
                    CXPLAT_TLS_PROCESS_STATE * State,
                    CXPLAT_TLS ** NewTlsContext)
{
    UNREFERENCED_PARAMETER(Config);
    UNREFERENCED_PARAMETER(State);
    UNREFERENCED_PARAMETER(NewTlsContext);

    CXPLAT_DBG_ASSERT(Config->HkdfLabels);

    puts("TODO? CxPlatTlsInitialize");

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    uint16_t ServerNameLength = 0;

    CXPLAT_TLS * TlsContext =
        CXPLAT_ALLOC_NONPAGED(sizeof(CXPLAT_TLS), QUIC_POOL_TLS_CTX);
    if (TlsContext == NULL) {
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

    QuicTraceLogConnVerbose(OpenSslContextCreated, TlsContext->Connection,
                            "TLS context Created");

    if (!Config->IsServer) {

        if (Config->ServerName != NULL) {

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
            if (TlsContext->SNI == NULL) {
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

Exit:
    if (TlsContext != NULL) {
        CxPlatTlsUninitialize(TlsContext);
        TlsContext = NULL;
    }

    return Status;
}

void CxPlatTlsUninitialize(CXPLAT_TLS * TlsContext)
{
    UNREFERENCED_PARAMETER(TlsContext);
    puts("TODO CxPlatTlsUninitialize");
}

void CxPlatTlsSecConfigDelete(CXPLAT_SEC_CONFIG * SecurityConfig)
{
    UNREFERENCED_PARAMETER(SecurityConfig);
    puts("TODO CxPlatTlsSecConfigDelete");
}

QUIC_STATUS CxPlatTlsSecConfigCreate(
    const QUIC_CREDENTIAL_CONFIG * CredConfig,
    CXPLAT_TLS_CREDENTIAL_FLAGS TlsCredFlags,
    const CXPLAT_TLS_CALLBACKS * TlsCallbacks,
    void * Context,
    CXPLAT_SEC_CONFIG_CREATE_COMPLETE_HANDLER CompletionHandler)
{
    UNREFERENCED_PARAMETER(CredConfig);
    UNREFERENCED_PARAMETER(TlsCredFlags);
    UNREFERENCED_PARAMETER(TlsCallbacks);
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(CompletionHandler);

    puts("TODO? CxPlatTlsSecConfigCreate");

    QUIC_CREDENTIAL_FLAGS CredConfigFlags = CredConfig->Flags;

    if (CredConfigFlags & QUIC_CREDENTIAL_FLAG_LOAD_ASYNCHRONOUS &&
        CredConfig->AsyncHandler == NULL) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    if (CredConfig->Reserved != NULL) {
        return QUIC_STATUS_INVALID_PARAMETER; // Not currently used and should
                                              // be NULL.
    }

    if (CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE) {
        if (CredConfig->CertificateFile == NULL ||
            CredConfig->CertificateFile->CertificateFile == NULL ||
            CredConfig->CertificateFile->PrivateKeyFile == NULL) {
            return QUIC_STATUS_INVALID_PARAMETER;
        }
    } else if (CredConfig->Type ==
               QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED) {
        if (CredConfig->CertificateFileProtected == NULL ||
            CredConfig->CertificateFileProtected->CertificateFile == NULL ||
            CredConfig->CertificateFileProtected->PrivateKeyFile == NULL ||
            CredConfig->CertificateFileProtected->PrivateKeyPassword == NULL) {
            return QUIC_STATUS_INVALID_PARAMETER;
        }
    } else if (CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12) {
        if (CredConfig->CertificatePkcs12 == NULL ||
            CredConfig->CertificatePkcs12->Asn1Blob == NULL ||
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
    CXPLAT_SEC_CONFIG * SecurityConfig = NULL;
    char * CipherSuiteString = NULL;

    // Create a security config.
    SecurityConfig =
        CXPLAT_ALLOC_NONPAGED(sizeof(CXPLAT_SEC_CONFIG), QUIC_POOL_TLS_SECCONF);
    if (SecurityConfig == NULL) {
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

    // Configure the SSL context with the defaults.

    char * CipherSuites = CXPLAT_TLS_DEFAULT_SSL_CIPHERS;
    if (CredConfigFlags & QUIC_CREDENTIAL_FLAG_SET_ALLOWED_CIPHER_SUITES) {
        //
        // Calculate allowed cipher suite string length.
        //
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
        if (CipherSuiteString == NULL) {
            QuicTraceEvent(AllocFailure,
                           "Allocation of '%s' failed. (%llu bytes)",
                           "CipherSuiteString", CipherSuiteStringLength);
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            goto Exit;
        }
    }
    // Set the certs.

    // Invoke completion inline.

    CompletionHandler(CredConfig, Context, Status, SecurityConfig);
    SecurityConfig = NULL;

    if (CredConfigFlags & QUIC_CREDENTIAL_FLAG_LOAD_ASYNCHRONOUS) {
        Status = QUIC_STATUS_PENDING;
    } else {
        Status = QUIC_STATUS_SUCCESS;
    }

Exit:

    if (SecurityConfig != NULL) {
        CxPlatTlsSecConfigDelete(SecurityConfig);
    }

    if (CipherSuiteString != NULL) {
        CxPlatFree(CipherSuiteString, QUIC_POOL_TLS_CIPHER_SUITE_STRING);
    }

    return Status;
}

QUIC_STATUS
CxPlatTlsSecConfigSetTicketKeys(CXPLAT_SEC_CONFIG * SecurityConfig,
                                QUIC_TICKET_KEY_CONFIG * KeyConfig,
                                uint8_t KeyCount)
{
    UNREFERENCED_PARAMETER(SecurityConfig);
    UNREFERENCED_PARAMETER(KeyConfig);
    UNREFERENCED_PARAMETER(KeyCount);

    CXPLAT_DBG_ASSERT(KeyCount >= 1); // Only support 1, ignore the rest for now

    return QUIC_STATUS_SUCCESS;
}
