/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Implements the TLS functions by calling RIOT.

--*/

#include "platform_internal.h"

#include <wolfssl/wolfcrypt/settings.h>

#include <wolfssl/ssl.h>

#if 0
// Default list of Cipher used.
#define CXPLAT_TLS_DEFAULT_SSL_CIPHERS                                         \
    "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_"     \
    "SHA256"
#define CXPLAT_TLS_AES_128_GCM_SHA256 "TLS_AES_128_GCM_SHA256"
#define CXPLAT_TLS_AES_256_GCM_SHA384 "TLS_AES_256_GCM_SHA384"
#define CXPLAT_TLS_CHACHA20_POLY1305_SHA256 "TLS_CHACHA20_POLY1305_SHA256"
#endif

uint16_t CxPlatTlsTPHeaderSize = 0;


typedef struct CXPLAT_SEC_CONFIG {
    // The SSL context associated with the sec config.
    WOLFSSL_CTX * SSLCtx;

    // Optional ticket key provided by the app.
    // QUIC_TICKET_KEY_CONFIG * TicketKey;

    // Callbacks for TLS.
    // CXPLAT_TLS_CALLBACKS Callbacks;

    // The application supplied credential flags.
    // QUIC_CREDENTIAL_FLAGS Flags;

    // Internal TLS credential flags.
    // CXPLAT_TLS_CREDENTIAL_FLAGS TlsFlags;

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
    // BOOLEAN PeerCertReceived : 1;

    // Indicates whether the peer's TP has been received.
    // BOOLEAN PeerTPReceived : 1;

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

} CXPLAT_TLS;


QUIC_TLS_PROVIDER CxPlatTlsGetProvider(void)
{
    return QUIC_TLS_PROVIDER_RIOT;
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


QUIC_STATUS CxPlatTlsParamGet(CXPLAT_TLS * TlsContext,
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


CXPLAT_TLS_RESULT_FLAGS CxPlatTlsProcessData(CXPLAT_TLS * TlsContext,
                                             CXPLAT_TLS_DATA_TYPE DataType,
                                             const uint8_t * Buffer,
                                             uint32_t * BufferLength,
                                             CXPLAT_TLS_PROCESS_STATE * State)
{
    puts("TODO CxPlatTlsProcessData");

    // UNREFERENCED_PARAMETER(DataType);
    // UNREFERENCED_PARAMETER(Buffer);
    // UNREFERENCED_PARAMETER(BufferLength);
    // UNREFERENCED_PARAMETER(State);
    CXPLAT_DBG_ASSERT(Buffer != NULL || *BufferLength == 0);

    TlsContext->State = State;
    TlsContext->ResultFlags = 0;

    if (DataType == CXPLAT_TLS_TICKET_DATA) {
        QuicTraceLogConnVerbose(OpenSslSendTicketData, TlsContext->Connection,
                                "Sending ticket data, %u bytes", *BufferLength);

        WOLFSSL_SESSION * Session = wolfSSL_get_session(TlsContext->Ssl);
        if (Session == NULL) {
            QuicTraceEvent(TlsError, "[ tls][%p] ERROR, %s.",
                           TlsContext->Connection,
                           "wolfSSL_get_session failed");
            TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
            goto Exit;
        }
        // int err =
        //     WOLFSSL_SESSION_set1_ticket_appdata(Session, Buffer,
        //     *BufferLength);
        // if (err) {
        //     QuicTraceEvent(TlsErrorStatus, "[ tls][%p] ERROR, %u, %s.",
        //                    TlsContext->Connection,
        //                    wolfSSL_get_error(Session, err),
        //                    "WOLFSSL_SESSION_set1_ticket_appdata failed");
        //     TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
        //     goto Exit;
        // }

        int Ret = wolfSSL_CTX_UseSessionTicket(TlsContext->SecConfig->SSLCtx);
        if (!Ret) {
            QuicTraceEvent(TlsErrorStatus, "[ tls][%p] ERROR, %u, %s.",
                           TlsContext->Connection,
                           wolfSSL_get_error(TlsContext->Ssl, Ret),
                           "wolfSSL_CTX_UseSessionTicket failed");
            TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
            goto Exit;
        }

        Ret = TlsContext->IsServer ? wolfSSL_accept_TLSv13(TlsContext->Ssl)
                                   : wolfSSL_connect_TLSv13(TlsContext->Ssl);
        if (Ret != 1) {
            QuicTraceEvent(TlsErrorStatus, "[ tls][%p] ERROR, %u, %s.",
                           TlsContext->Connection,
                           wolfSSL_get_error(TlsContext->Ssl, Ret),
                           "SSL_do_handshake failed");
            TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
            goto Exit;
        }

        goto Exit;
    }

#if 0
    if (*BufferLength != 0) {
        QuicTraceLogConnVerbose(OpenSslProcessData, TlsContext->Connection,
                                "Processing %u received bytes", *BufferLength);

        if (SSL_provide_quic_data(
                TlsContext->Ssl,
                (OSSL_ENCRYPTION_LEVEL)TlsContext->State->ReadKey, Buffer,
                *BufferLength) != 1) {
            char buf[256];
            QuicTraceLogConnError(OpenSslQuicDataErrorStr,
                                  TlsContext->Connection,
                                  "SSL_provide_quic_data failed: %s",
                                  ERR_error_string(wolfSSL_get_error(), buf));
            TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
            goto Exit;
        }
    }

    if (!State->HandshakeComplete) {
        int Ret = SSL_do_handshake(TlsContext->Ssl);
        if (Ret <= 0) {
            int Err = SSL_get_error(TlsContext->Ssl, Ret);
            switch (Err) {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                //
                // Best effort to get the server's transport params as early as
                // possible.
                //
                if (!TlsContext->IsServer &&
                    TlsContext->PeerTPReceived == FALSE) {
                    const uint8_t * TransportParams;
                    size_t TransportParamLen;
                    SSL_get_peer_quic_transport_params(
                        TlsContext->Ssl, &TransportParams, &TransportParamLen);
                    if (TransportParams != NULL && TransportParamLen != 0) {
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

            case SSL_ERROR_SSL: {
                char buf[256];
                const char * file;
                int line;
#ifdef IS_OPENSSL_3
                ERR_error_string_n(
                    wolfSSL_get_error_all(&file, &line, NULL, NULL, NULL), buf,
                    sizeof(buf));
#else
                ERR_error_string_n(wolfSSL_get_error_line(&file, &line), buf,
                                   sizeof(buf));
#endif
                QuicTraceLogConnError(
                    OpenSslHandshakeErrorStr, TlsContext->Connection,
                    "TLS handshake error: %s, file:%s:%d", buf,
                    (strlen(file) > OpenSslFilePrefixLength
                         ? file + OpenSslFilePrefixLength
                         : file),
                    line);
                TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
                goto Exit;
            }

            default:
                QuicTraceLogConnError(OpenSslHandshakeError,
                                      TlsContext->Connection,
                                      "TLS handshake error: %d", Err);
                TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
                goto Exit;
            }
        }

        if (!TlsContext->IsServer) {
            const uint8_t * NegotiatedAlpn;
            uint32_t NegotiatedAlpnLength;
            SSL_get0_alpn_selected(TlsContext->Ssl, &NegotiatedAlpn,
                                   &NegotiatedAlpnLength);
            if (NegotiatedAlpnLength == 0) {
                QuicTraceLogConnError(OpenSslAlpnNegotiationFailure,
                                      TlsContext->Connection,
                                      "Failed to negotiate ALPN");
                TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
                goto Exit;
            }
            if (NegotiatedAlpnLength > UINT8_MAX) {
                QuicTraceLogConnError(OpenSslInvalidAlpnLength,
                                      TlsContext->Connection,
                                      "Invalid negotiated ALPN length");
                TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
                goto Exit;
            }
            TlsContext->State->NegotiatedAlpn = CxPlatTlsAlpnFindInList(
                TlsContext->AlpnBufferLength, TlsContext->AlpnBuffer,
                (uint8_t)NegotiatedAlpnLength, NegotiatedAlpn);
            if (TlsContext->State->NegotiatedAlpn == NULL) {
                QuicTraceLogConnError(OpenSslNoMatchingAlpn,
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
                    TlsContext->Connection, NULL, NULL, 0, ValidationResult)) {
                QuicTraceEvent(TlsError, "[ tls][%p] ERROR, %s.",
                               TlsContext->Connection,
                               "Indicate null certificate received failed");
                TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
                TlsContext->State->AlertCode =
                    CXPLAT_TLS_ALERT_CODE_REQUIRED_CERTIFICATE;
                goto Exit;
            }
        }

        QuicTraceLogConnInfo(OpenSslHandshakeComplete, TlsContext->Connection,
                             "TLS Handshake complete");
        State->HandshakeComplete = TRUE;
        if (WOLFSSL_session_reused(TlsContext->Ssl)) {
            QuicTraceLogConnInfo(OpenSslHandshakeResumed,
                                 TlsContext->Connection,
                                 "TLS Handshake resumed");
            State->SessionResumed = TRUE;
        }
        if (!TlsContext->IsServer) {
            int EarlyDataStatus = SSL_get_early_data_status(TlsContext->Ssl);
            if (EarlyDataStatus == SSL_EARLY_DATA_ACCEPTED) {
                State->EarlyDataState = CXPLAT_TLS_EARLY_DATA_ACCEPTED;
                TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_EARLY_DATA_ACCEPT;

            } else if (EarlyDataStatus == SSL_EARLY_DATA_REJECTED) {
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
            SSL_get_peer_quic_transport_params(
                TlsContext->Ssl, &TransportParams, &TransportParamLen);
            if (TransportParams == NULL || TransportParamLen == 0) {
                QuicTraceLogConnError(OpenSslMissingTransportParameters,
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
        if (SSL_process_quic_post_handshake(TlsContext->Ssl) != 1) {
            QuicTraceEvent(TlsErrorStatus, "[ tls][%p] ERROR, %u, %s.",
                           TlsContext->Connection, wolfSSL_get_error(),
                           "SSL_process_quic_post_handshake failed");
            TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
            goto Exit;
        }
    }

#endif
Exit:

    if (!(TlsContext->ResultFlags & CXPLAT_TLS_RESULT_ERROR)) {
        if (State->WriteKeys[QUIC_PACKET_KEY_HANDSHAKE] != NULL &&
            State->BufferOffsetHandshake == 0) {
            State->BufferOffsetHandshake = State->BufferTotalLength;
            QuicTraceLogConnInfo(OpenSslHandshakeDataStart,
                                 TlsContext->Connection,
                                 "Writing Handshake data starts at %u",
                                 State->BufferOffsetHandshake);
        }
        if (State->WriteKeys[QUIC_PACKET_KEY_1_RTT] != NULL &&
            State->BufferOffset1Rtt == 0) {
            State->BufferOffset1Rtt = State->BufferTotalLength;
            QuicTraceLogConnInfo(OpenSsl1RttDataStart, TlsContext->Connection,
                                 "Writing 1-RTT data starts at %u",
                                 State->BufferOffset1Rtt);
        }
    }

    return TlsContext->ResultFlags;
}


QUIC_STATUS CxPlatTlsInitialize(const CXPLAT_TLS_CONFIG * Config,
                                CXPLAT_TLS_PROCESS_STATE * State,
                                CXPLAT_TLS ** NewTlsContext)
{
    UNREFERENCED_PARAMETER(State);

    puts("CxPlatTlsInitialize");

    CXPLAT_DBG_ASSERT(Config->HkdfLabels);

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    CXPLAT_TLS * TlsContext = malloc(sizeof(*TlsContext));
    if (TlsContext == 0) {
        QuicTraceEvent(AllocFailure, "Allocation of '%s' failed. (%zu bytes)",
                       "CXPLAT_TLS", sizeof(CXPLAT_TLS));
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    int ret = wolfSSL_Init();
    if (ret != SSL_SUCCESS) {
        QuicTraceEvent(TlsError, "[ tls][%p] ERROR, %s.", Config->Connection,
                       "wolfSSL_Init failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    // CxPlatZeroMemory(TlsContext, sizeof(CXPLAT_TLS));

    TlsContext->Connection = Config->Connection;
    TlsContext->HkdfLabels = Config->HkdfLabels;
    TlsContext->IsServer = Config->IsServer;
    TlsContext->SecConfig = Config->SecConfig;
    TlsContext->QuicTpExtType = Config->TPType;
    TlsContext->AlpnBufferLength = Config->AlpnBufferLength;
    TlsContext->AlpnBuffer = Config->AlpnBuffer;

    QuicTraceLogConnVerbose(OpenSslContextCreated, TlsContext->Connection,
                            "TLS context Created");

    uint16_t ServerNameLength = 0;
    if (!Config->IsServer && Config->ServerName) {
        uint16_t ServerNameLength =
            strnlen(Config->ServerName, QUIC_MAX_SNI_LENGTH);
        if (ServerNameLength == QUIC_MAX_SNI_LENGTH) {
            QuicTraceEvent(TlsError, "[ tls][%p] ERROR, %s.",
                           TlsContext->Connection, "SNI Too Long");
            Status = QUIC_STATUS_INVALID_PARAMETER;
            goto Exit;
        }

        TlsContext->SNI = malloc(ServerNameLength + 1);
        if (TlsContext->SNI == 0) {
            QuicTraceEvent(AllocFailure,
                           "Allocation of '%s' failed. (%zu bytes)", "SNI",
                           ServerNameLength + 1);
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            goto Exit;
        }

        memcpy((char *)TlsContext->SNI, Config->ServerName,
               ServerNameLength + 1);
    }

    // Create a SSL object for the connection.
    TlsContext->Ssl = wolfSSL_new(Config->SecConfig->SSLCtx);
    if (TlsContext->Ssl == NULL) {
        QuicTraceEvent(TlsError, "[ tls][%p] ERROR, %s.",
                       TlsContext->Connection, "wolfSSL_new failed");
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    // SSL_set_app_data(TlsContext->Ssl, TlsContext);

    if (Config->IsServer) {
        // wolfSSL_set_accept_state(TlsContext->Ssl);
    } else {
        // wolfSSL_set_connect_state(TlsContext->Ssl);
        if (Config->ServerName) {
            wolfSSL_UseSNI(TlsContext->Ssl, WOLFSSL_SNI_HOST_NAME,
                           TlsContext->SNI, ServerNameLength);
        }
        wolfSSL_UseALPN(TlsContext->Ssl, (char *)TlsContext->AlpnBuffer,
                        TlsContext->AlpnBufferLength,
                        WOLFSSL_ALPN_FAILED_ON_MISMATCH);
    }

    *NewTlsContext = TlsContext;
    TlsContext = 0;

Exit:
    if (TlsContext) {
        CxPlatTlsUninitialize(TlsContext);
        TlsContext = 0;
    }

    return Status;
}


void CxPlatTlsUninitialize(CXPLAT_TLS * TlsContext)
{
    puts("CxPlatTlsUninitialize");
    wolfSSL_free(TlsContext->Ssl);
    wolfSSL_Cleanup();
    free(TlsContext);
}


void CxPlatTlsSecConfigDelete(CXPLAT_SEC_CONFIG * SecurityConfig)
{
    wolfSSL_CTX_free(SecurityConfig->SSLCtx);
}


QUIC_STATUS CxPlatTlsSecConfigCreate(
    const QUIC_CREDENTIAL_CONFIG * CredConfig,
    CXPLAT_TLS_CREDENTIAL_FLAGS TlsCredFlags,
    const CXPLAT_TLS_CALLBACKS * TlsCallbacks,
    void * Context,
    CXPLAT_SEC_CONFIG_CREATE_COMPLETE_HANDLER CompletionHandler)
{
    // UNREFERENCED_PARAMETER(CredConfig);
    UNREFERENCED_PARAMETER(TlsCredFlags);
    UNREFERENCED_PARAMETER(TlsCallbacks);
    // UNREFERENCED_PARAMETER(Context);
    // UNREFERENCED_PARAMETER(CompletionHandler);

    puts("TODO? CxPlatTlsSecConfigCreate");

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    CXPLAT_SEC_CONFIG * SecurityConfig = 0;
    // char * CipherSuiteString = 0;

    // Create a security config.
    SecurityConfig = malloc(sizeof(*SecurityConfig));
    if (SecurityConfig == 0) {
        QuicTraceEvent(AllocFailure, "Allocation of '%s' failed. (%zu bytes)",
                       "CXPLAT_SEC_CONFIG", sizeof(CXPLAT_SEC_CONFIG));
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    // CxPlatZeroMemory(SecurityConfig, sizeof(CXPLAT_SEC_CONFIG));
    // SecurityConfig->Callbacks = *TlsCallbacks;
    // SecurityConfig->Flags = CredConfigFlags;
    // SecurityConfig->TlsFlags = TlsCredFlags;

    // Create the a SSL context for the security config.

    WOLFSSL_METHOD * method =
        wolfTLSv1_3_client_method(); // wolfTLSv1_3__method();
    if (method == 0) {
        QuicTraceEvent(AllocFailure, "Allocation of '%s' failed.",
                       "wolfTLSv1_3_method");
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    SecurityConfig->SSLCtx = wolfSSL_CTX_new(method);
    if (SecurityConfig->SSLCtx == NULL) {
        QuicTraceEvent(LibraryErrorStatus, "[ lib] ERROR. %s.",
                       "SSL_CTX_new failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    // Configure the SSL context with the defaults.


    // Set the certs.

    // Invoke completion inline.

    CompletionHandler(CredConfig, Context, Status, SecurityConfig);
    SecurityConfig = 0;

Exit:
    if (SecurityConfig) {
        CxPlatTlsSecConfigDelete(SecurityConfig);
    }

    // if (CipherSuiteString) {
    //     free(CipherSuiteString);
    // }

    return Status;
}


QUIC_STATUS CxPlatTlsSecConfigSetTicketKeys(CXPLAT_SEC_CONFIG * SecurityConfig,
                                            QUIC_TICKET_KEY_CONFIG * KeyConfig,
                                            uint8_t KeyCount)
{
    UNREFERENCED_PARAMETER(SecurityConfig);
    UNREFERENCED_PARAMETER(KeyConfig);
    UNREFERENCED_PARAMETER(KeyCount);

    CXPLAT_DBG_ASSERT(KeyCount >= 1); // Only support 1, ignore the rest for now

    return QUIC_STATUS_SUCCESS;
}
