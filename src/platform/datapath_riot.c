/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC datapath Abstraction Layer.

Environment:

    RIOT

--*/

#include "platform_internal.h"

_IRQL_requires_max_(DISPATCH_LEVEL) uint32_t
    CxPlatDataPathGetSupportedFeatures(_In_ CXPLAT_DATAPATH *Datapath) {
  UNREFERENCED_PARAMETER(Datapath);
  return 0;
}

void CxPlatDataPathUninitialize(_In_ CXPLAT_DATAPATH *Datapath) {
  UNREFERENCED_PARAMETER(Datapath);
}

QUIC_STATUS
CxPlatDataPathInitialize(
    _In_ uint32_t ClientRecvContextLength,
    _In_opt_ const CXPLAT_UDP_DATAPATH_CALLBACKS *UdpCallbacks,
    _In_opt_ const CXPLAT_TCP_DATAPATH_CALLBACKS *TcpCallbacks,
    _In_opt_ QUIC_EXECUTION_CONFIG *Config,
    _Out_ CXPLAT_DATAPATH **NewDataPath) {
  UNREFERENCED_PARAMETER(ClientRecvContextLength);
  UNREFERENCED_PARAMETER(UdpCallbacks);
  UNREFERENCED_PARAMETER(TcpCallbacks);
  UNREFERENCED_PARAMETER(Config);

  if (NewDataPath == NULL) {
    return QUIC_STATUS_INVALID_PARAMETER;
  }

  return QUIC_STATUS_SUCCESS;
}

void CxPlatRecvDataReturn(_In_opt_ CXPLAT_RECV_DATA *RecvDataChain) {
  UNREFERENCED_PARAMETER(RecvDataChain);
}

CXPLAT_RECV_PACKET *CxPlatDataPathRecvDataToRecvPacket(
    _In_ const CXPLAT_RECV_DATA *const RecvData) {
  UNREFERENCED_PARAMETER(RecvData);

  return 0;
}

uint16_t CxPlatSocketGetLocalMtu(_In_ CXPLAT_SOCKET *Socket) {
  UNREFERENCED_PARAMETER(Socket);

  CXPLAT_DBG_ASSERT(Socket != NULL);
  return 0;
}

CXPLAT_RECV_DATA *CxPlatDataPathRecvPacketToRecvData(
    _In_ const CXPLAT_RECV_PACKET *const Packet) {
  UNREFERENCED_PARAMETER(Packet);

  return 0;
}

QUIC_STATUS
CxPlatDataPathResolveAddress(_In_ CXPLAT_DATAPATH *Datapath,
                             _In_z_ const char *HostName,
                             _Inout_ QUIC_ADDR *Address) {
  UNREFERENCED_PARAMETER(Datapath);
  UNREFERENCED_PARAMETER(HostName);
  UNREFERENCED_PARAMETER(Address);

  QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
  return Status;
}

void CxPlatSocketDelete(_Inout_ CXPLAT_SOCKET *Socket) {
  UNREFERENCED_PARAMETER(Socket);

  CXPLAT_DBG_ASSERT(Socket != NULL);
}

void CxPlatSocketGetLocalAddress(_In_ CXPLAT_SOCKET *Socket,
                                 _Out_ QUIC_ADDR *Address) {
  UNREFERENCED_PARAMETER(Socket);
  UNREFERENCED_PARAMETER(Address);

  CXPLAT_DBG_ASSERT(Socket != NULL);
}

void CxPlatSocketGetRemoteAddress(_In_ CXPLAT_SOCKET *Socket,
                                  _Out_ QUIC_ADDR *Address) {
  UNREFERENCED_PARAMETER(Socket);
  UNREFERENCED_PARAMETER(Address);

  CXPLAT_DBG_ASSERT(Socket != NULL);
}

QUIC_STATUS
CxPlatSocketCreateUdp(_In_ CXPLAT_DATAPATH *Datapath,
                      _In_ const CXPLAT_UDP_CONFIG *Config,
                      _Out_ CXPLAT_SOCKET **NewBinding) {
  UNREFERENCED_PARAMETER(Datapath);
  UNREFERENCED_PARAMETER(Config);
  UNREFERENCED_PARAMETER(NewBinding);

  QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
  return Status;
}

QUIC_STATUS
CxPlatSocketSend(_In_ CXPLAT_SOCKET *Socket, _In_ const CXPLAT_ROUTE *Route,
                 _In_ CXPLAT_SEND_DATA *SendData,
                 _In_ uint16_t IdealProcessor) {
  UNREFERENCED_PARAMETER(Socket);
  UNREFERENCED_PARAMETER(Route);
  UNREFERENCED_PARAMETER(SendData);
  UNREFERENCED_PARAMETER(IdealProcessor);

  QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
  return Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
    _Success_(return != NULL) CXPLAT_SEND_DATA *CxPlatSendDataAlloc(
        _In_ CXPLAT_SOCKET *Socket, _In_ CXPLAT_ECN_TYPE ECN,
        _In_ uint16_t MaxPacketSize, _Inout_ CXPLAT_ROUTE *Route) {
  UNREFERENCED_PARAMETER(Socket);
  UNREFERENCED_PARAMETER(ECN);
  UNREFERENCED_PARAMETER(MaxPacketSize);
  UNREFERENCED_PARAMETER(Route);

  CXPLAT_DBG_ASSERT(Socket != NULL);
  return 0;
}

_IRQL_requires_max_(DISPATCH_LEVEL) _Success_(return != NULL)
    QUIC_BUFFER *CxPlatSendDataAllocBuffer(_In_ CXPLAT_SEND_DATA *SendData,
                                           _In_ uint16_t MaxBufferLength) {
  UNREFERENCED_PARAMETER(SendData);
  UNREFERENCED_PARAMETER(MaxBufferLength);

  CXPLAT_DBG_ASSERT(SendData != NULL);
  CXPLAT_DBG_ASSERT(MaxBufferLength > 0);
  return 0;
}

_IRQL_requires_max_(DISPATCH_LEVEL) void CxPlatSendDataFree(
    _In_ CXPLAT_SEND_DATA *SendData) {
  UNREFERENCED_PARAMETER(SendData);
}

_IRQL_requires_max_(DISPATCH_LEVEL) void CxPlatSendDataFreeBuffer(
    _In_ CXPLAT_SEND_DATA *SendData, _In_ QUIC_BUFFER *Buffer) {
  UNREFERENCED_PARAMETER(SendData);
  UNREFERENCED_PARAMETER(Buffer);
}

BOOLEAN
CxPlatDataPathIsPaddingPreferred(_In_ CXPLAT_DATAPATH *Datapath) {
  UNREFERENCED_PARAMETER(Datapath);

  return false;
}

_IRQL_requires_max_(DISPATCH_LEVEL) BOOLEAN
    CxPlatSendDataIsFull(_In_ CXPLAT_SEND_DATA *SendData) {
  UNREFERENCED_PARAMETER(SendData);

  return false;
}
