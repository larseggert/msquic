/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Implements the TLS functions by calling RIOT.

--*/

#include "platform_internal.h"

uint16_t CxPlatTlsTPHeaderSize = 0;

QUIC_TLS_PROVIDER
CxPlatTlsGetProvider(void) { return QUIC_TLS_PROVIDER_RIOT; }

QUIC_STATUS
CxPlatTlsParamSet(CXPLAT_TLS *SecConfig, uint32_t Param, uint32_t BufferLength,
                  const void *Buffer) {
  UNREFERENCED_PARAMETER(SecConfig);
  UNREFERENCED_PARAMETER(Param);
  UNREFERENCED_PARAMETER(BufferLength);
  UNREFERENCED_PARAMETER(Buffer);

  return QUIC_STATUS_NOT_SUPPORTED;
}

QUIC_STATUS
CxPlatTlsParamGet(CXPLAT_TLS *TlsContext, uint32_t Param,
                  uint32_t *BufferLength, void *Buffer) {
  UNREFERENCED_PARAMETER(TlsContext);
  UNREFERENCED_PARAMETER(Param);
  UNREFERENCED_PARAMETER(BufferLength);
  UNREFERENCED_PARAMETER(Buffer);

  QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
  return Status;
}

void CxPlatTlsUpdateHkdfLabels(CXPLAT_TLS *TlsContext,
                               const QUIC_HKDF_LABELS *const Labels) {
  UNREFERENCED_PARAMETER(TlsContext);
  UNREFERENCED_PARAMETER(Labels);
}

CXPLAT_TLS_RESULT_FLAGS
CxPlatTlsProcessData(CXPLAT_TLS *TlsContext, CXPLAT_TLS_DATA_TYPE DataType,
                     const uint8_t *Buffer, uint32_t *BufferLength,
                     CXPLAT_TLS_PROCESS_STATE *State) {
  UNREFERENCED_PARAMETER(TlsContext);
  UNREFERENCED_PARAMETER(DataType);
  UNREFERENCED_PARAMETER(Buffer);
  UNREFERENCED_PARAMETER(BufferLength);
  UNREFERENCED_PARAMETER(State);

  CXPLAT_DBG_ASSERT(Buffer != NULL || *BufferLength == 0);
  return CXPLAT_TLS_RESULT_ERROR;
}

QUIC_STATUS
CxPlatTlsInitialize(const CXPLAT_TLS_CONFIG *Config,
                    CXPLAT_TLS_PROCESS_STATE *State,
                    CXPLAT_TLS **NewTlsContext) {
  UNREFERENCED_PARAMETER(Config);
  UNREFERENCED_PARAMETER(State);
  UNREFERENCED_PARAMETER(NewTlsContext);

  QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
  return Status;
}

void CxPlatTlsUninitialize(CXPLAT_TLS *TlsContext) {
  UNREFERENCED_PARAMETER(TlsContext);
}

void CxPlatTlsSecConfigDelete(CXPLAT_SEC_CONFIG *SecurityConfig) {
  UNREFERENCED_PARAMETER(SecurityConfig);
}

QUIC_STATUS CxPlatTlsSecConfigCreate(
    const QUIC_CREDENTIAL_CONFIG *CredConfig,
    CXPLAT_TLS_CREDENTIAL_FLAGS TlsCredFlags,
    const CXPLAT_TLS_CALLBACKS *TlsCallbacks, void *Context,
    CXPLAT_SEC_CONFIG_CREATE_COMPLETE_HANDLER CompletionHandler) {
  UNREFERENCED_PARAMETER(CredConfig);
  UNREFERENCED_PARAMETER(TlsCredFlags);
  UNREFERENCED_PARAMETER(TlsCallbacks);
  UNREFERENCED_PARAMETER(Context);
  UNREFERENCED_PARAMETER(CompletionHandler);

  QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
  return Status;
}

QUIC_STATUS
CxPlatTlsSecConfigSetTicketKeys(CXPLAT_SEC_CONFIG *SecurityConfig,
                                QUIC_TICKET_KEY_CONFIG *KeyConfig,
                                uint8_t KeyCount) {
  UNREFERENCED_PARAMETER(SecurityConfig);
  UNREFERENCED_PARAMETER(KeyConfig);
  UNREFERENCED_PARAMETER(KeyCount);

  CXPLAT_DBG_ASSERT(KeyCount >= 1); // Only support 1, ignore the rest for now

  return QUIC_STATUS_SUCCESS;
}
