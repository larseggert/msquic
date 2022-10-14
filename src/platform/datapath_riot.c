/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC datapath Abstraction Layer.

Environment:

    RIOT

--*/

#include <net/sock/dns.h>
#include <net/sock/udp.h>
#include <net/sock/util.h>

#include "platform_internal.h"


typedef struct CXPLAT_DATAPATH_PROC CXPLAT_DATAPATH_PROC;


// A receive block to receive a UDP packet over the sockets.
// typedef struct CXPLAT_DATAPATH_RECV_BLOCK {
// The pool owning this recv block.
// CXPLAT_POOL * OwningPool;

// The recv buffer used by MsQuic.
// CXPLAT_RECV_DATA RecvPacket;

// Represents the network route.
// CXPLAT_ROUTE Route;

// Buffer that actually stores the UDP payload.
// uint8_t Buffer[MAX_UDP_PAYLOAD_LENGTH];

// This follows the recv block.
// CXPLAT_RECV_PACKET RecvContext;
// } CXPLAT_DATAPATH_RECV_BLOCK;


// A per processor datapath context.
// typedef struct QUIC_CACHEALIGN CXPLAT_DATAPATH_PROC {

// A pointer to the datapath.
// CXPLAT_DATAPATH * Datapath;

// The event queue for this proc context.
// CXPLAT_EVENTQ * EventQ;

// Synchronization mechanism for cleanup.
// CXPLAT_REF_COUNT RefCount;

// The ideal processor of the context.
// uint16_t IdealProcessor;

// #if DEBUG
//     uint8_t Uninitialized : 1;
//     uint8_t Freed : 1;
// #endif

// Pool of receive packet contexts and buffers to be shared by all sockets
// on this core.
// CXPLAT_POOL RecvBlockPool;

// Pool of send buffers to be shared by all sockets on this core.
// CXPLAT_POOL SendBufferPool;

// Pool of large segmented send buffers to be shared by all sockets on this
// core.
// CXPLAT_POOL LargeSendBufferPool;

// Pool of send contexts to be shared by all sockets on this core.
// CXPLAT_POOL SendDataPool;
// } CXPLAT_DATAPATH_PROC;


// Socket context.
typedef struct QUIC_CACHEALIGN CXPLAT_SOCKET_CONTEXT {

    // The datapath binding this socket context belongs to.
    CXPLAT_SOCKET * Binding;

    // The datapath proc context this socket belongs to.
    // CXPLAT_DATAPATH_PROC * DatapathProc;

    // The socket FD used by this socket context.
    sock_udp_t SocketFd;

    // The event for the shutdown event.
    // DATAPATH_SQE ShutdownSqe;

    // The user data for the IO event.
    // uint32_t IoCqeType;

    // The I/O vector for receive datagrams.
    // struct iovec RecvIov;

    // The control buffer used in RecvMsgHdr.
    // char RecvMsgControl[CMSG_SPACE(sizeof(struct in6_pktinfo)) +
    //                     CMSG_SPACE(sizeof(struct in_pktinfo)) +
    //                     2 * CMSG_SPACE(sizeof(int))];

    // The buffer used to receive msg headers on socket.
    // struct msghdr RecvMsgHdr;

    // The receive block currently being used for receives on this socket.
    // CXPLAT_DATAPATH_RECV_BLOCK * CurrentRecvBlock;

    // The head of list containg all pending sends on this socket.
    // CXPLAT_LIST_ENTRY PendingSendDataHead;

    // Lock around the PendingSendData list.
    // CXPLAT_LOCK PendingSendDataLock;

    // Rundown for synchronizing clean up with upcalls.
    // CXPLAT_RUNDOWN_REF UpcallRundown;

    // Inidicates if the socket has started IO processing.
    // BOOLEAN IoStarted : 1;

    // #if DEBUG
    //     uint8_t Uninitialized : 1;
    //     uint8_t Freed : 1;
    // #endif
} CXPLAT_SOCKET_CONTEXT;


// Datapath binding.
typedef struct CXPLAT_SOCKET {
    // A pointer to datapath object.
    CXPLAT_DATAPATH * Datapath;

    // The client context for this binding.
    void * ClientContext;

    // The local address for the binding.
    QUIC_ADDR LocalAddress;

    //  The remote address for the binding.
    QUIC_ADDR RemoteAddress;

    // Synchronization mechanism for cleanup.
    // CXPLAT_REF_COUNT RefCount;

    // The MTU for this binding.
    uint16_t Mtu;

    // Indicates the binding connected to a remote IP address.
    // BOOLEAN Connected : 1;

    // Flag indicates the socket has a default remote destination.
    // BOOLEAN HasFixedRemoteAddress : 1;

    // Flag indicates the binding is being used for PCP.
    // BOOLEAN PcpBinding : 1;

#if DEBUG
    uint8_t Uninitialized : 1;
    uint8_t Freed : 1;
#endif

    // Set of socket contexts one per proc.
    CXPLAT_SOCKET_CONTEXT SocketContexts[];
} CXPLAT_SOCKET;


typedef struct CXPLAT_DATAPATH {
    // UDP handlers.
    // CXPLAT_UDP_DATAPATH_CALLBACKS UdpHandlers;

    // The proc count to create per proc datapath state.
    uint32_t ProcCount;

    // The per proc datapath contexts.
    // CXPLAT_DATAPATH_PROC Processors[];
} CXPLAT_DATAPATH;


static int quicaddr_to_sock_udp_ep(const QUIC_ADDR * address,
                                   sock_udp_ep_t * out)
{
    memset(out, 0, sizeof(*out));
    switch (address->Ip.sa_family) {
    case AF_INET: {
        struct sockaddr_in * in_addr = (struct sockaddr_in *)&address->Ipv4;
        out->family = AF_INET;
        out->addr.ipv4_u32 = in_addr->sin_addr.s_addr;
        out->port = ntohs(in_addr->sin_port);
        break;
    }
    case AF_INET6: {
        struct sockaddr_in6 * in6_addr = (struct sockaddr_in6 *)&address->Ipv6;
        out->family = AF_INET6;
        memcpy(&out->addr.ipv6, &in6_addr->sin6_addr, sizeof(out->addr.ipv6));
        out->port = ntohs(in6_addr->sin6_port);
        if (in6_addr->sin6_scope_id != 0) {
            out->netif = (uint16_t)in6_addr->sin6_scope_id;
        }
        break;
    }
    default:
        errno = EAFNOSUPPORT;
        return -1;
    }
    return 0;
}

#if 0
static int sock_udp_ep_to_quicaddr(const sock_udp_ep_t * ep,
                                   QUIC_ADDR * address)
{
    memset(address, 0, sizeof(*address));
    switch (ep->family) {
    case AF_INET: {
        struct sockaddr_in * in_addr = (struct sockaddr_in *)&address->Ipv4;
        in_addr->sin_family = AF_INET;
        in_addr->sin_addr.s_addr = ep->addr.ipv4_u32;
        in_addr->sin_port = htons(ep->port);
        break;
    }
    case AF_INET6: {
        struct sockaddr_in6 * in6_addr = (struct sockaddr_in6 *)&address->Ipv6;
        in6_addr->sin6_family = AF_INET6;
        memcpy(&in6_addr->sin6_addr, &ep->addr.ipv6, sizeof(ep->addr.ipv6));
        in6_addr->sin6_port = htons(ep->port);
        if (ep->netif != 0) {
            in6_addr->sin6_scope_id = ep->netif;
        }
        break;
    }
    default:
        errno = EAFNOSUPPORT;
        return -1;
    }
    return 0;
}
#endif

// Socket context interface. It abstracts a (generally per-processor) UDP
// socket and the corresponding logic/functionality like send and receive
// processing.
//

QUIC_STATUS
CxPlatSocketContextInitialize(CXPLAT_SOCKET_CONTEXT * SocketContext,
                              const QUIC_ADDR * LocalAddress,
                              const QUIC_ADDR * RemoteAddress)
{
    puts("CxPlatSocketContextInitialize");

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    // int Result = 0;
    // int Option = 0;
    // int Flags = 0;
    // QUIC_ADDR MappedAddress = {0};
    // socklen_t AssignedLocalAddressLength = 0;

    CXPLAT_SOCKET * Binding = SocketContext->Binding;

    // if (!CxPlatSqeInitialize(SocketContext->DatapathProc->EventQ,
    //                          &SocketContext->ShutdownSqe.Sqe,
    //                          &SocketContext->ShutdownSqe)) {
    //     Status = errno;
    //     QuicTraceEvent(DatapathErrorStatus, "[data][%p] ERROR, %"PRIu32",
    //     %s.",
    //                    Binding, Status, "CxPlatSqeInitialize failed");
    //     goto Exit;
    // }

    // TODO: Set DON'T FRAG socket option.

    // TODO: Set socket option to receive ancillary data about the incoming
    // packets.

    // TODO: Set socket option to receive TOS (= DSCP + ECN) information from
    // the incoming packet.

    // Create datagram socket.
    sock_udp_ep_t local = SOCK_IPV6_EP_ANY;
    if (LocalAddress && quicaddr_to_sock_udp_ep(LocalAddress, &local) < 0) {
        Status = errno;
        QuicTraceEvent(DatapathErrorStatus,
                       "[data][%p] ERROR, %" PRIu32 ", %s.", Binding, Status,
                       "quicaddr_to_sock_udp_ep local failed");
        goto Exit;
    }

    sock_udp_ep_t remote;
    if (RemoteAddress && quicaddr_to_sock_udp_ep(RemoteAddress, &remote) < 0) {
        Status = errno;
        QuicTraceEvent(DatapathErrorStatus,
                       "[data][%p] ERROR, %" PRIu32 ", %s.", Binding, Status,
                       "quicaddr_to_sock_udp_ep remote failed");
        goto Exit;
    }

    uint16_t local_port, remote_port;
    char local_str[64], remote_str[64];
    sock_udp_ep_fmt(&local, local_str, &local_port);
    sock_udp_ep_fmt(&remote, remote_str, &remote_port);
    printf("sock_udp_create %s:%d -> %s:%d\n", local_str, local_port,
           remote_str, remote_port);

    int ret = sock_udp_create(&SocketContext->SocketFd, &local,
                              RemoteAddress ? &remote : 0, 0);
    if (ret < 0) {
        Status = -ret;
        QuicTraceEvent(DatapathErrorStatus,
                       "[data][%p] ERROR, %" PRIu32 ", %s.", Binding, Status,
                       "socket() failed");
        goto Exit;
    }

    // If no specific local port was indicated, then the stack just
    // assigned this socket a port. We need to query it and use it for
    // all the other sockets we are going to create.
    ret = sock_udp_get_local(&SocketContext->SocketFd, &local);
    if (ret) {
        Status = -ret;
        QuicTraceEvent(DatapathErrorStatus,
                       "[data][%p] ERROR, %" PRIu32 ", %s.", Binding, Status,
                       "sock_udp_get_local failed");
        goto Exit;
    }
    Binding->LocalAddress.Ipv4.sin_port = local.port;
    // CxPlatConvertToMappedV6(&MappedAddress, &Binding->LocalAddress);

    if (LocalAddress && LocalAddress->Ipv4.sin_port != 0) {
        CXPLAT_DBG_ASSERT(LocalAddress->Ipv4.sin_port ==
                          Binding->LocalAddress.Ipv4.sin_port);
    }

    // if (Binding->LocalAddress.Ipv6.sin6_family == AF_INET6) {
    //     Binding->LocalAddress.Ipv6.sin6_family = QUIC_ADDRESS_FAMILY_INET6;
    // }

Exit:

    return Status;
}


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
        QuicTraceEvent(AllocFailure, "Allocation of '%s' failed. (%zu bytes)",
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
    CXPLAT_DBG_ASSERT(Socket != NULL);
    return Socket->Mtu;
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

    printf("CxPlatDataPathResolveAddress %s\n", HostName);

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    // Try numeric name first
    if (ipv6_addr_from_str((ipv6_addr_t *)&Address->Ipv6.sin6_addr, HostName)) {
        Address->Ipv6.sin6_family = AF_INET6;
        goto Exit;
    }
    if (ipv4_addr_from_str((ipv4_addr_t *)&Address->Ipv4.sin_addr, HostName)) {
        Address->Ipv4.sin_family = AF_INET;
        goto Exit;
    }

    // Try canonical host name.
    if (sock_dns_query(HostName, Address, AF_UNSPEC) >= 0) {
        goto Exit;
    }

    Status = QUIC_STATUS_UNREACHABLE;

    QuicTraceLogError(DatapathResolveHostNameFailed,
                      "[%p] Couldn't resolve hostname '%s' to an IP address",
                      Datapath, HostName);

Exit:

    if (Status == QUIC_STATUS_SUCCESS) {
        if (Address->Ip.sa_family == AF_INET) {
            puts(ipv4_addr_to_str((char[IPV4_ADDR_MAX_STR_LEN]){""},
                                  (ipv4_addr_t *)&Address->Ipv4.sin_addr,
                                  IPV4_ADDR_MAX_STR_LEN));
        } else {
            puts(ipv6_addr_to_str((char[IPV6_ADDR_MAX_STR_LEN]){""},
                                  (ipv6_addr_t *)&Address->Ipv6.sin6_addr,
                                  IPV6_ADDR_MAX_STR_LEN));
        }
    }
    return Status;
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
    CXPLAT_DBG_ASSERT(Socket != NULL);
    *Address = Socket->LocalAddress;
}

void CxPlatSocketGetRemoteAddress(CXPLAT_SOCKET * Socket, QUIC_ADDR * Address)
{
    CXPLAT_DBG_ASSERT(Socket != NULL);
    *Address = Socket->RemoteAddress;
}

CXPLAT_DATAPATH_PROC * CxPlatDataPathGetProc(CXPLAT_DATAPATH * Datapath,
                                             uint16_t Processor)
{
    UNREFERENCED_PARAMETER(Datapath);
    UNREFERENCED_PARAMETER(Processor);

    puts("TODO CxPlatDataPathGetProc");

    // for (uint32_t i = 0; i < Datapath->ProcCount; ++i) {
    //     if (Datapath->Processors[i].IdealProcessor == Processor) {
    //         return &Datapath->Processors[i];
    //     }
    // }
    CXPLAT_FRE_ASSERT(FALSE); // TODO - What now?!
    return NULL;
}


QUIC_STATUS
CxPlatSocketContextStartReceive(CXPLAT_SOCKET_CONTEXT * SocketContext)
{
    UNREFERENCED_PARAMETER(SocketContext);

    puts("TODO CxPlatSocketContextStartReceive");
    return QUIC_STATUS_SUCCESS;
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

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    BOOLEAN IsServerSocket = Config->RemoteAddress == NULL;

    // CXPLAT_DBG_ASSERT(Datapath->UdpHandlers.Receive != NULL ||
    //                   Config->Flags & CXPLAT_SOCKET_FLAG_PCP);

    uint32_t SocketCount = IsServerSocket ? Datapath->ProcCount : 1;
    // uint32_t CurrentProc = CxPlatProcCurrentNumber() % Datapath->ProcCount;
    CXPLAT_FRE_ASSERT(SocketCount > 0);
    size_t BindingLength =
        sizeof(CXPLAT_SOCKET) + SocketCount * sizeof(CXPLAT_SOCKET_CONTEXT);

    CXPLAT_SOCKET * Binding =
        (CXPLAT_SOCKET *)CXPLAT_ALLOC_PAGED(BindingLength, QUIC_POOL_SOCKET);
    if (Binding == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        QuicTraceEvent(AllocFailure, "Allocation of '%s' failed. (%zu bytes)",
                       "CXPLAT_SOCKET", BindingLength);
        goto Exit;
    }

    QuicTraceEvent(DatapathCreated,
                   "[data][%p] Created, local=%!ADDR!, remote=%!ADDR!", Binding,
                   CASTED_CLOG_BYTEARRAY(
                       Config->LocalAddress ? sizeof(*Config->LocalAddress) : 0,
                       Config->LocalAddress),
                   CASTED_CLOG_BYTEARRAY(Config->RemoteAddress
                                             ? sizeof(*Config->RemoteAddress)
                                             : 0,
                                         Config->RemoteAddress));

    CxPlatZeroMemory(Binding, BindingLength);
    Binding->Datapath = Datapath;
    Binding->ClientContext = Config->CallbackContext;
    // Binding->HasFixedRemoteAddress = (Config->RemoteAddress != NULL);
    // Binding->Mtu = CXPLAT_MAX_MTU;
    // CxPlatRefInitializeEx(&Binding->RefCount, SocketCount);
    if (Config->LocalAddress) {
        // CxPlatConvertToMappedV6(Config->LocalAddress,
        // &Binding->LocalAddress);
    } else {
        Binding->LocalAddress.Ip.sa_family = QUIC_ADDRESS_FAMILY_INET6;
    }
    for (uint32_t i = 0; i < SocketCount; i++) {
        Binding->SocketContexts[i].Binding = Binding;
        // Binding->SocketContexts[i].SocketFd = INVALID_SOCKET;
        // Binding->SocketContexts[i].ShutdownSqe.CqeType =
        //     CXPLAT_CQE_TYPE_SOCKET_SHUTDOWN;
        // Binding->SocketContexts[i].IoCqeType = CXPLAT_CQE_TYPE_SOCKET_IO;
        // Binding->SocketContexts[i].RecvIov.iov_len =
        //     Binding->Mtu - CXPLAT_MIN_IPV4_HEADER_SIZE -
        //     CXPLAT_UDP_HEADER_SIZE;
        // Binding->SocketContexts[i].DatapathProc =
        //     IsServerSocket ? &Datapath->Processors[i]
        //                    : CxPlatDataPathGetProc(Datapath, CurrentProc);
        // CxPlatRefIncrement(&Binding->SocketContexts[i].DatapathProc->RefCount);
        // CxPlatListInitializeHead(
        //     &Binding->SocketContexts[i].PendingSendDataHead);
        // CxPlatLockInitialize(&Binding->SocketContexts[i].PendingSendDataLock);
        // CxPlatRundownInitialize(&Binding->SocketContexts[i].UpcallRundown);
    }

    // if (Config->Flags & CXPLAT_SOCKET_FLAG_PCP) {
    //     Binding->PcpBinding = TRUE;
    // }

    for (uint32_t i = 0; i < SocketCount; i++) {
        Status = CxPlatSocketContextInitialize(&Binding->SocketContexts[i],
                                               Config->LocalAddress,
                                               Config->RemoteAddress);
        if (QUIC_FAILED(Status)) {
            goto Exit;
        }
    }

    // CxPlatConvertFromMappedV6(&Binding->LocalAddress,
    // &Binding->LocalAddress);
    Binding->LocalAddress.Ipv6.sin6_scope_id = 0;

    if (Config->RemoteAddress != NULL) {
        Binding->RemoteAddress = *Config->RemoteAddress;
    } else {
        Binding->RemoteAddress.Ipv4.sin_port = 0;
    }

    // Must set output pointer before starting receive path, as the receive path
    // will try to use the output.
    *NewBinding = Binding;

    for (uint32_t i = 0; i < SocketCount; i++) {
        Status = CxPlatSocketContextStartReceive(&Binding->SocketContexts[i]);
        if (QUIC_FAILED(Status)) {
            goto Exit;
        }
        // Binding->SocketContexts[i].IoStarted = TRUE;
    }

    Binding = NULL;

Exit:

    if (Binding != NULL) {
        CxPlatSocketDelete(Binding);
    }

    return Status;


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
    UNREFERENCED_PARAMETER(SendData);

    puts("TODO CxPlatSendDataFree");
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


void CxPlatDataPathProcessCqe(CXPLAT_CQE * Cqe)
{
    UNREFERENCED_PARAMETER(Cqe);

    puts("TODO CxPlatDataPathProcessCqe");
}
