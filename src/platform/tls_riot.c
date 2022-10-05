/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Implements the TLS functions by calling RIOT.

--*/

#include "platform_internal.h"

#if 0

uint16_t CxPlatTlsTPHeaderSize = 0;

_IRQL_requires_max_(DISPATCH_LEVEL) QUIC_TLS_PROVIDER
    CxPlatTlsGetProvider(void) {
  return QUIC_TLS_PROVIDER_RIOT;
}

_IRQL_requires_max_(PASSIVE_LEVEL) QUIC_STATUS
    CxPlatTlsParamSet(_In_ CXPLAT_TLS *SecConfig, _In_ uint32_t Param,
                      _In_ uint32_t BufferLength,
                      _In_reads_bytes_(BufferLength) const void *Buffer) {
  UNREFERENCED_PARAMETER(SecConfig);
  UNREFERENCED_PARAMETER(Param);
  UNREFERENCED_PARAMETER(BufferLength);
  UNREFERENCED_PARAMETER(Buffer);

  return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL) QUIC_STATUS
    CxPlatTlsParamGet(_In_ CXPLAT_TLS *TlsContext, _In_ uint32_t Param,
                      _Inout_ uint32_t *BufferLength,
                      _Inout_updates_bytes_opt_(*BufferLength) void *Buffer) {
  UNREFERENCED_PARAMETER(TlsContext);
  UNREFERENCED_PARAMETER(Param);
  UNREFERENCED_PARAMETER(BufferLength);
  UNREFERENCED_PARAMETER(Buffer);

  QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
  return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL) void CxPlatTlsUpdateHkdfLabels(
    _In_ CXPLAT_TLS *TlsContext, _In_ const QUIC_HKDF_LABELS *const Labels) {
  UNREFERENCED_PARAMETER(TlsContext);
  UNREFERENCED_PARAMETER(Labels);
}

_IRQL_requires_max_(PASSIVE_LEVEL) CXPLAT_TLS_RESULT_FLAGS
    CxPlatTlsProcessData(_In_ CXPLAT_TLS *TlsContext,
                         _In_ CXPLAT_TLS_DATA_TYPE DataType,
                         _In_reads_bytes_(*BufferLength) const uint8_t *Buffer,
                         _Inout_ uint32_t *BufferLength,
                         _Inout_ CXPLAT_TLS_PROCESS_STATE *State) {
  UNREFERENCED_PARAMETER(TlsContext);
  UNREFERENCED_PARAMETER(DataType);
  UNREFERENCED_PARAMETER(Buffer);
  UNREFERENCED_PARAMETER(BufferLength);
  UNREFERENCED_PARAMETER(State);

  CXPLAT_DBG_ASSERT(Buffer != NULL || *BufferLength == 0);
  return CXPLAT_TLS_RESULT_ERROR;
}

_IRQL_requires_max_(PASSIVE_LEVEL) QUIC_STATUS
    CxPlatTlsInitialize(_In_ const CXPLAT_TLS_CONFIG *Config,
                        _Inout_ CXPLAT_TLS_PROCESS_STATE *State,
                        _Out_ CXPLAT_TLS **NewTlsContext) {
  UNREFERENCED_PARAMETER(Config);
  UNREFERENCED_PARAMETER(State);
  UNREFERENCED_PARAMETER(NewTlsContext);

  QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
  return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL) void CxPlatTlsUninitialize(
    _In_opt_ CXPLAT_TLS *TlsContext) {
  UNREFERENCED_PARAMETER(TlsContext);
}

_IRQL_requires_max_(PASSIVE_LEVEL) void CxPlatTlsSecConfigDelete(__drv_freesMem(
    ServerConfig) _Frees_ptr_ _In_ CXPLAT_SEC_CONFIG *SecurityConfig) {
  UNREFERENCED_PARAMETER(SecurityConfig);
}

_IRQL_requires_max_(PASSIVE_LEVEL) QUIC_STATUS CxPlatTlsSecConfigCreate(
    _In_ const QUIC_CREDENTIAL_CONFIG *CredConfig,
    _In_ CXPLAT_TLS_CREDENTIAL_FLAGS TlsCredFlags,
    _In_ const CXPLAT_TLS_CALLBACKS *TlsCallbacks, _In_opt_ void *Context,
    _In_ CXPLAT_SEC_CONFIG_CREATE_COMPLETE_HANDLER CompletionHandler) {
  UNREFERENCED_PARAMETER(CredConfig);
  UNREFERENCED_PARAMETER(TlsCredFlags);
  UNREFERENCED_PARAMETER(TlsCallbacks);
  UNREFERENCED_PARAMETER(Context);
  UNREFERENCED_PARAMETER(CompletionHandler);

  QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
  return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL) QUIC_STATUS
    CxPlatTlsSecConfigSetTicketKeys(_In_ CXPLAT_SEC_CONFIG *SecurityConfig,
                                    _In_reads_(KeyCount)
                                        QUIC_TICKET_KEY_CONFIG *KeyConfig,
                                    _In_ uint8_t KeyCount) {
  UNREFERENCED_PARAMETER(SecurityConfig);
  UNREFERENCED_PARAMETER(KeyConfig);
  UNREFERENCED_PARAMETER(KeyCount);

  CXPLAT_DBG_ASSERT(KeyCount >= 1); // Only support 1, ignore the rest for now

  return QUIC_STATUS_SUCCESS;
}

#endif
