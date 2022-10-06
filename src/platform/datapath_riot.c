/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC datapath Abstraction Layer.

Environment:

    RIOT

--*/

#include "platform_internal.h"

uint32_t CxPlatDataPathGetSupportedFeatures(CXPLAT_DATAPATH *Datapath) {
  UNREFERENCED_PARAMETER(Datapath);
  return 0;
}

void CxPlatDataPathUninitialize(CXPLAT_DATAPATH *Datapath) {
  UNREFERENCED_PARAMETER(Datapath);
}

QUIC_STATUS
CxPlatDataPathInitialize(uint32_t ClientRecvContextLength,
                         const CXPLAT_UDP_DATAPATH_CALLBACKS *UdpCallbacks,
                         const CXPLAT_TCP_DATAPATH_CALLBACKS *TcpCallbacks,
                         QUIC_EXECUTION_CONFIG *Config,
                         CXPLAT_DATAPATH **NewDataPath) {
  UNREFERENCED_PARAMETER(ClientRecvContextLength);
  UNREFERENCED_PARAMETER(UdpCallbacks);
  UNREFERENCED_PARAMETER(TcpCallbacks);
  UNREFERENCED_PARAMETER(Config);

  if (NewDataPath == NULL) {
    return QUIC_STATUS_INVALID_PARAMETER;
  }
  return QUIC_STATUS_SUCCESS;
}

void CxPlatRecvDataReturn(CXPLAT_RECV_DATA *RecvDataChain) {
  UNREFERENCED_PARAMETER(RecvDataChain);
}

CXPLAT_RECV_PACKET *
CxPlatDataPathRecvDataToRecvPacket(const CXPLAT_RECV_DATA *const RecvData) {
  UNREFERENCED_PARAMETER(RecvData);
  return 0;
}

uint16_t CxPlatSocketGetLocalMtu(CXPLAT_SOCKET *Socket) {
  UNREFERENCED_PARAMETER(Socket);

  CXPLAT_DBG_ASSERT(Socket != NULL);
  return 0;
}

CXPLAT_RECV_DATA *
CxPlatDataPathRecvPacketToRecvData(const CXPLAT_RECV_PACKET *const Packet) {
  UNREFERENCED_PARAMETER(Packet);

  return 0;
}

QUIC_STATUS
CxPlatDataPathResolveAddress(CXPLAT_DATAPATH *Datapath, const char *HostName,
                             QUIC_ADDR *Address) {
  UNREFERENCED_PARAMETER(Datapath);
  UNREFERENCED_PARAMETER(HostName);
  UNREFERENCED_PARAMETER(Address);

  QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
  return Status;
}

BOOLEAN
CxPlatDataPathIsPaddingPreferred(CXPLAT_DATAPATH *Datapath) {
  UNREFERENCED_PARAMETER(Datapath);

  return false;
}

void CxPlatSocketDelete(CXPLAT_SOCKET *Socket) {
  UNREFERENCED_PARAMETER(Socket);

  CXPLAT_DBG_ASSERT(Socket != NULL);
}

void CxPlatSocketGetLocalAddress(CXPLAT_SOCKET *Socket, QUIC_ADDR *Address) {
  UNREFERENCED_PARAMETER(Socket);
  UNREFERENCED_PARAMETER(Address);

  CXPLAT_DBG_ASSERT(Socket != NULL);
}

void CxPlatSocketGetRemoteAddress(CXPLAT_SOCKET *Socket, QUIC_ADDR *Address) {
  UNREFERENCED_PARAMETER(Socket);
  UNREFERENCED_PARAMETER(Address);

  CXPLAT_DBG_ASSERT(Socket != NULL);
}

QUIC_STATUS
CxPlatSocketCreateUdp(CXPLAT_DATAPATH *Datapath,
                      const CXPLAT_UDP_CONFIG *Config,
                      CXPLAT_SOCKET **NewBinding) {
  UNREFERENCED_PARAMETER(Datapath);
  UNREFERENCED_PARAMETER(Config);
  UNREFERENCED_PARAMETER(NewBinding);

  QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
  return Status;
}

QUIC_STATUS
CxPlatSocketSend(CXPLAT_SOCKET *Socket, const CXPLAT_ROUTE *Route,
                 CXPLAT_SEND_DATA *SendData, uint16_t IdealProcessor) {
  UNREFERENCED_PARAMETER(Socket);
  UNREFERENCED_PARAMETER(Route);
  UNREFERENCED_PARAMETER(SendData);
  UNREFERENCED_PARAMETER(IdealProcessor);

  QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
  return Status;
}

CXPLAT_SEND_DATA *CxPlatSendDataAlloc(CXPLAT_SOCKET *Socket,
                                      CXPLAT_ECN_TYPE ECN,
                                      uint16_t MaxPacketSize,
                                      CXPLAT_ROUTE *Route) {
  UNREFERENCED_PARAMETER(Socket);
  UNREFERENCED_PARAMETER(ECN);
  UNREFERENCED_PARAMETER(MaxPacketSize);
  UNREFERENCED_PARAMETER(Route);

  CXPLAT_DBG_ASSERT(Socket != NULL);
  return 0;
}

QUIC_BUFFER *CxPlatSendDataAllocBuffer(CXPLAT_SEND_DATA *SendData,
                                       uint16_t MaxBufferLength) {
  UNREFERENCED_PARAMETER(SendData);
  UNREFERENCED_PARAMETER(MaxBufferLength);

  CXPLAT_DBG_ASSERT(SendData != NULL);
  CXPLAT_DBG_ASSERT(MaxBufferLength > 0);
  return 0;
}

void CxPlatSendDataFree(CXPLAT_SEND_DATA *SendData) {
  UNREFERENCED_PARAMETER(SendData);
}

void CxPlatSendDataFreeBuffer(CXPLAT_SEND_DATA *SendData, QUIC_BUFFER *Buffer) {
  UNREFERENCED_PARAMETER(SendData);
  UNREFERENCED_PARAMETER(Buffer);
}

BOOLEAN
CxPlatSendDataIsFull(CXPLAT_SEND_DATA *SendData) {
  UNREFERENCED_PARAMETER(SendData);
  return FALSE;
}
