/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Platform Abstraction Layer storage interface.

Environment:

    RIOT

--*/

#include "platform_internal.h"

QUIC_STATUS
CxPlatStorageOpen(const char *Path,
                  CXPLAT_STORAGE_CHANGE_CALLBACK_HANDLER Callback,
                  void *CallbackContext, CXPLAT_STORAGE **NewStorage) {
  UNREFERENCED_PARAMETER(Path);
  UNREFERENCED_PARAMETER(Callback);
  UNREFERENCED_PARAMETER(CallbackContext);
  UNREFERENCED_PARAMETER(NewStorage);
  // TODO
  return QUIC_STATUS_NOT_SUPPORTED;
}

void CxPlatStorageClose(CXPLAT_STORAGE *Storage) {
  UNREFERENCED_PARAMETER(Storage);
  // TODO
}

QUIC_STATUS
CxPlatStorageReadValue(CXPLAT_STORAGE *Storage, const char *Name,
                       uint8_t *Buffer, uint32_t *BufferLength) {
  UNREFERENCED_PARAMETER(Storage);
  UNREFERENCED_PARAMETER(Name);
  UNREFERENCED_PARAMETER(Buffer);
  UNREFERENCED_PARAMETER(BufferLength);
  // TODO
  return QUIC_STATUS_NOT_SUPPORTED;
}
