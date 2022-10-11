/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC datapath Abstraction Layer.

Environment:

    RIOT

--*/

#include "platform_internal.h"

typedef struct CXPLAT_DATAPATH {
} CXPLAT_DATAPATH;

uint32_t CxPlatDataPathGetSupportedFeatures(CXPLAT_DATAPATH * Datapath)
{
    UNREFERENCED_PARAMETER(Datapath);
    puts("TODO CxPlatDataPathGetSupportedFeatures");
    return 0;
}

void CxPlatDataPathUninitialize(CXPLAT_DATAPATH * Datapath)
{
    UNREFERENCED_PARAMETER(Datapath);
    puts("TODO CxPlatDataPathUninitialize");
}

QUIC_STATUS
CxPlatDataPathInitialize(uint32_t ClientRecvContextLength,
                         const CXPLAT_UDP_DATAPATH_CALLBACKS * UdpCallbacks,
                         const CXPLAT_TCP_DATAPATH_CALLBACKS * TcpCallbacks,
                         QUIC_EXECUTION_CONFIG * Config,
                         CXPLAT_DATAPATH ** NewDataPath)
{
    UNREFERENCED_PARAMETER(ClientRecvContextLength);
    UNREFERENCED_PARAMETER(UdpCallbacks);
    UNREFERENCED_PARAMETER(TcpCallbacks);
    UNREFERENCED_PARAMETER(Config);

    puts("TODO CxPlatDataPathInitialize");

    if (NewDataPath == NULL) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    if (!CxPlatWorkersLazyStart(Config)) {
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    const size_t DatapathLength = sizeof(CXPLAT_DATAPATH);

    CXPLAT_DATAPATH * Datapath = (CXPLAT_DATAPATH *)CXPLAT_ALLOC_PAGED(
        DatapathLength, QUIC_POOL_DATAPATH);

    if (Datapath == NULL) {
        QuicTraceEvent(AllocFailure,
                       "Allocation of '%s' failed. (%" PRIu32 " bytes)",
                       "CXPLAT_DATAPATH", DatapathLength);
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    CxPlatZeroMemory(Datapath, DatapathLength);
    *NewDataPath = Datapath;

    return QUIC_STATUS_SUCCESS;
}

void CxPlatRecvDataReturn(CXPLAT_RECV_DATA * RecvDataChain)
{
    UNREFERENCED_PARAMETER(RecvDataChain);
    puts("TODO CxPlatRecvDataReturn");
}

CXPLAT_RECV_PACKET *
CxPlatDataPathRecvDataToRecvPacket(const CXPLAT_RECV_DATA * const RecvData)
{
    UNREFERENCED_PARAMETER(RecvData);
    puts("TODO CxPlatDataPathRecvDataToRecvPacket");
    return 0;
}

uint16_t CxPlatSocketGetLocalMtu(CXPLAT_SOCKET * Socket)
{
    UNREFERENCED_PARAMETER(Socket);

    CXPLAT_DBG_ASSERT(Socket != NULL);
    puts("TODO CxPlatSocketGetLocalMtu");
    return 0;
}

CXPLAT_RECV_DATA *
CxPlatDataPathRecvPacketToRecvData(const CXPLAT_RECV_PACKET * const Packet)
{
    UNREFERENCED_PARAMETER(Packet);

    puts("TODO CxPlatDataPathRecvPacketToRecvData");
    return 0;
}

QUIC_STATUS
CxPlatDataPathResolveAddress(CXPLAT_DATAPATH * Datapath,
                             const char * HostName,
                             QUIC_ADDR * Address)
{
    UNREFERENCED_PARAMETER(Datapath);
    UNREFERENCED_PARAMETER(HostName);
    UNREFERENCED_PARAMETER(Address);

    puts("TODO CxPlatDataPathResolveAddress");
    return QUIC_STATUS_SUCCESS;
}

BOOLEAN
CxPlatDataPathIsPaddingPreferred(CXPLAT_DATAPATH * Datapath)
{
    UNREFERENCED_PARAMETER(Datapath);

    puts("TODO CxPlatDataPathIsPaddingPreferred");
    return false;
}

void CxPlatSocketDelete(CXPLAT_SOCKET * Socket)
{
    UNREFERENCED_PARAMETER(Socket);

    CXPLAT_DBG_ASSERT(Socket != NULL);
    puts("TODO CxPlatSocketDelete");
}

void CxPlatSocketGetLocalAddress(CXPLAT_SOCKET * Socket, QUIC_ADDR * Address)
{
    UNREFERENCED_PARAMETER(Socket);
    UNREFERENCED_PARAMETER(Address);

    CXPLAT_DBG_ASSERT(Socket != NULL);
    puts("TODO CxPlatSocketGetLocalAddress");
}

void CxPlatSocketGetRemoteAddress(CXPLAT_SOCKET * Socket, QUIC_ADDR * Address)
{
    UNREFERENCED_PARAMETER(Socket);
    UNREFERENCED_PARAMETER(Address);

    CXPLAT_DBG_ASSERT(Socket != NULL);
    puts("TODO CxPlatSocketGetRemoteAddress");
}

QUIC_STATUS
CxPlatSocketCreateUdp(CXPLAT_DATAPATH * Datapath,
                      const CXPLAT_UDP_CONFIG * Config,
                      CXPLAT_SOCKET ** NewBinding)
{
    UNREFERENCED_PARAMETER(Datapath);
    UNREFERENCED_PARAMETER(Config);
    UNREFERENCED_PARAMETER(NewBinding);

    puts("TODO CxPlatSocketCreateUdp");
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
CxPlatSocketSend(CXPLAT_SOCKET * Socket,
                 const CXPLAT_ROUTE * Route,
                 CXPLAT_SEND_DATA * SendData,
                 uint16_t IdealProcessor)
{
    UNREFERENCED_PARAMETER(Socket);
    UNREFERENCED_PARAMETER(Route);
    UNREFERENCED_PARAMETER(SendData);
    UNREFERENCED_PARAMETER(IdealProcessor);

    puts("TODO CxPlatSocketSend");
    return QUIC_STATUS_SUCCESS;
}

CXPLAT_SEND_DATA * CxPlatSendDataAlloc(CXPLAT_SOCKET * Socket,
                                       CXPLAT_ECN_TYPE ECN,
                                       uint16_t MaxPacketSize,
                                       CXPLAT_ROUTE * Route)
{
    UNREFERENCED_PARAMETER(Socket);
    UNREFERENCED_PARAMETER(ECN);
    UNREFERENCED_PARAMETER(MaxPacketSize);
    UNREFERENCED_PARAMETER(Route);

    CXPLAT_DBG_ASSERT(Socket != NULL);
    puts("TODO CxPlatSendDataAlloc");
    return 0;
}

QUIC_BUFFER * CxPlatSendDataAllocBuffer(CXPLAT_SEND_DATA * SendData,
                                        uint16_t MaxBufferLength)
{
    UNREFERENCED_PARAMETER(SendData);
    UNREFERENCED_PARAMETER(MaxBufferLength);

    CXPLAT_DBG_ASSERT(SendData != NULL);
    CXPLAT_DBG_ASSERT(MaxBufferLength > 0);
    puts("TODO CxPlatSendDataAllocBuffer");
    return 0;
}

void CxPlatSendDataFree(CXPLAT_SEND_DATA * SendData)
{
    puts("TODO CxPlatSendDataFree");
    UNREFERENCED_PARAMETER(SendData);
}

void CxPlatSendDataFreeBuffer(CXPLAT_SEND_DATA * SendData, QUIC_BUFFER * Buffer)
{
    UNREFERENCED_PARAMETER(SendData);
    UNREFERENCED_PARAMETER(Buffer);
    puts("TODO CxPlatSendDataFreeBuffer");
}

BOOLEAN
CxPlatSendDataIsFull(CXPLAT_SEND_DATA * SendData)
{
    UNREFERENCED_PARAMETER(SendData);
    puts("TODO CxPlatSendDataIsFull");
    return FALSE;
}

void
CxPlatDataPathProcessCqe(
    _In_ CXPLAT_CQE* Cqe
    )
{
    puts("TODO CxPlatDataPathProcessCqe");
}
