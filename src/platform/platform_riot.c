/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Platform Abstraction Layer main module.

Environment:

    RIOT

--*/

// // For FreeBSD
// #if defined(__FreeBSD__)
// #include <pthread_np.h>
// #endif

#include <random.h>

#include "platform_internal.h"
#include "quic_platform.h"
#include "quic_trace.h"
// #include <dlfcn.h>
// #include <fcntl.h>
// #include <limits.h>
// #include <sched.h>
// #include <syslog.h>
// #define QUIC_VERSION_ONLY 1
// #include "msquic.ver"
// #ifdef QUIC_CLOG
// #include "platform_posix.c.clog.h"
// #endif

// #define CXPLAT_MAX_LOG_MSG_LEN        1024 // Bytes

// CX_PLATFORM CxPlatform = { NULL };
// int RandomFd = -1; // Used for reading random numbers.
QUIC_TRACE_RUNDOWN_CALLBACK *QuicTraceRundownCallback;

// #define STR_HELPER(x) #x
// #define STR(x) STR_HELPER(x)

// #define LIBRARY_VERSION STR(VER_MAJOR) "." STR(VER_MINOR) "." STR(VER_PATCH)

// static const char TpLibName[] = "libmsquic.lttng.so." LIBRARY_VERSION;

// uint32_t CxPlatProcessorCount;

uint64_t CxPlatTotalMemory;

// #if __APPLE__ || __FreeBSD__
// long CxPlatCurrentSqe = 0x80000000;
// #endif

// #ifdef __clang__
// __attribute__((noinline, noreturn, optnone))
// #else
// __attribute__((noinline, noreturn, optimize("O0")))
// #endif
// void
// quic_bugcheck(
//     _In_z_ const char* File,
//     _In_ int Line,
//     _In_z_ const char* Expr
//     )
// {
//     //
//     // Pass in the error info so it can be seen in the debugger.
//     //
//     UNREFERENCED_PARAMETER(File);
//     UNREFERENCED_PARAMETER(Line);
//     UNREFERENCED_PARAMETER(Expr);

//     //
//     // We want to prevent this routine from being inlined so that we can
//     // easily detect when our bugcheck conditions have occurred just by
//     // looking at callstack. However, even after specifying inline attribute,
//     // it is possible certain optimizations will cause inlining. asm
//     technique
//     // is the gcc documented way to prevent such optimizations.
//     //
//     asm("");

//     //
//     // abort() sends a SIGABRT signal and it triggers termination and
//     coredump.
//     //
//     abort();
// }

void CxPlatSystemLoad(void) { QuicTraceLogInfo(PosixLoaded, "[ dso] Loaded"); }

void CxPlatSystemUnload(void) {
  QuicTraceLogInfo(PosixUnloaded, "[ dso] Unloaded");
}

// uint64_t CGroupGetMemoryLimit();

QUIC_STATUS
CxPlatInitialize(void) {
  random_init(0); // FIXME: use a salt
  CxPlatWorkersInit();
  CxPlatTotalMemory = UINT64_MAX;

  QuicTraceLogInfo(PosixInitialized,
                   "[ dso] Initialized (AvailMem = %llu bytes)",
                   CxPlatTotalMemory);

  return QUIC_STATUS_SUCCESS;
}

void CxPlatUninitialize(void) {
  CxPlatWorkersUninit();
  QuicTraceLogInfo(PosixUninitialized, "[ dso] Uninitialized");
}

void *CxPlatAlloc(size_t ByteCount, uint32_t Tag) {
  UNREFERENCED_PARAMETER(Tag);
  return malloc(ByteCount);
}

void CxPlatFree(void *Mem, uint32_t Tag) {
  UNREFERENCED_PARAMETER(Tag);
  free(Mem);
}

void CxPlatRefInitialize(CXPLAT_REF_COUNT *RefCount) { *RefCount = 1; }

void CxPlatRefInitializeEx(CXPLAT_REF_COUNT *RefCount, uint32_t Initial) {
  *RefCount = (int64_t)Initial;
}

void CxPlatRefIncrement(CXPLAT_REF_COUNT *RefCount) {
  if (__atomic_add_fetch(RefCount, 1, __ATOMIC_SEQ_CST)) {
    return;
  }

  CXPLAT_FRE_ASSERT(FALSE);
}

BOOLEAN
CxPlatRefIncrementNonZero(volatile CXPLAT_REF_COUNT *RefCount, uint32_t Bias) {
  CXPLAT_REF_COUNT OldValue = *RefCount;

  for (;;) {
    CXPLAT_REF_COUNT NewValue = OldValue + Bias;

    if (NewValue > Bias) {
      if (__atomic_compare_exchange_n(RefCount, &OldValue, NewValue, false,
                                      __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
        return TRUE;
      }
      continue;
    }

    if (NewValue == Bias) {
      return FALSE;
    }

    CXPLAT_FRE_ASSERT(false);
    return FALSE;
  }
}

BOOLEAN
CxPlatRefDecrement(CXPLAT_REF_COUNT *RefCount) {
  CXPLAT_REF_COUNT NewValue = __atomic_sub_fetch(RefCount, 1, __ATOMIC_SEQ_CST);

  if (NewValue > 0) {
    return FALSE;
  }

  if (NewValue == 0) {
    return TRUE;
  }

  CXPLAT_FRE_ASSERT(FALSE);

  return FALSE;
}

// void
// CxPlatRundownInitialize(
//     _Inout_ CXPLAT_RUNDOWN_REF* Rundown
//     )
// {
//     CxPlatRefInitialize(&((Rundown)->RefCount));
//     CxPlatEventInitialize(&((Rundown)->RundownComplete), false, false);
// }

// void
// CxPlatRundownInitializeDisabled(
//     _Inout_ CXPLAT_RUNDOWN_REF* Rundown
//     )
// {
//     (Rundown)->RefCount = 0;
//     CxPlatEventInitialize(&((Rundown)->RundownComplete), false, false);
// }

// void
// CxPlatRundownReInitialize(
//     _Inout_ CXPLAT_RUNDOWN_REF* Rundown
//     )
// {
//     (Rundown)->RefCount = 1;
// }

// void
// CxPlatRundownUninitialize(
//     _Inout_ CXPLAT_RUNDOWN_REF* Rundown
//     )
// {
//     CxPlatEventUninitialize((Rundown)->RundownComplete);
// }

// BOOLEAN
// CxPlatRundownAcquire(
//     _Inout_ CXPLAT_RUNDOWN_REF* Rundown
//     )
// {
//     return CxPlatRefIncrementNonZero(&(Rundown)->RefCount, 1);
// }

// void
// CxPlatRundownRelease(
//     _Inout_ CXPLAT_RUNDOWN_REF* Rundown
//     )
// {
//     if (CxPlatRefDecrement(&(Rundown)->RefCount)) {
//         CxPlatEventSet((Rundown)->RundownComplete);
//     }
// }

// void
// CxPlatRundownReleaseAndWait(
//     _Inout_ CXPLAT_RUNDOWN_REF* Rundown
//     )
// {
//     if (!CxPlatRefDecrement(&(Rundown)->RefCount)) {
//         CxPlatEventWaitForever((Rundown)->RundownComplete);
//     }
// }

// uint64_t
// CxPlatTimespecToUs(
//     _In_ const struct timespec *Time
//     )
// {
//     return (Time->tv_sec * CXPLAT_MICROSEC_PER_SEC) + (Time->tv_nsec /
//     CXPLAT_NANOSEC_PER_MICROSEC);
// }

// uint64_t
// CxPlatGetTimerResolution(
//     void
//     )
// {
//     struct timespec Res = {0};
//     int ErrorCode = clock_getres(CLOCK_MONOTONIC, &Res);
//     CXPLAT_DBG_ASSERT(ErrorCode == 0);
//     UNREFERENCED_PARAMETER(ErrorCode);
//     return CxPlatTimespecToUs(&Res);
// }

uint64_t CxPlatTimeUs64(void) {
  return ztimer_now(ZTIMER_MSEC) * CXPLAT_MICROSEC_PER_MS;
}

// void
// CxPlatGetAbsoluteTime(
//     _In_ unsigned long DeltaMs,
//     _Out_ struct timespec *Time
//     )
// {
//     int ErrorCode = 0;

//     CxPlatZeroMemory(Time, sizeof(struct timespec));

// #if defined(CX_PLATFORM_LINUX)
//     ErrorCode = clock_gettime(CLOCK_MONOTONIC, Time);
// #elif defined(CX_PLATFORM_DARWIN)
//     //
//     // timespec_get is used on darwin, as CLOCK_MONOTONIC isn't actually
//     // monotonic according to our tests.
//     //
//     timespec_get(Time, TIME_UTC);
// #endif // CX_PLATFORM_DARWIN

//     CXPLAT_DBG_ASSERT(ErrorCode == 0);
//     UNREFERENCED_PARAMETER(ErrorCode);

//     Time->tv_sec += (DeltaMs / CXPLAT_MS_PER_SECOND);
//     Time->tv_nsec += ((DeltaMs % CXPLAT_MS_PER_SECOND) *
//     CXPLAT_NANOSEC_PER_MS);

//     if (Time->tv_nsec >= CXPLAT_NANOSEC_PER_SEC)
//     {
//         Time->tv_sec += 1;
//         Time->tv_nsec -= CXPLAT_NANOSEC_PER_SEC;
//     }

//     CXPLAT_DBG_ASSERT(Time->tv_sec >= 0);
//     CXPLAT_DBG_ASSERT(Time->tv_nsec >= 0);
//     CXPLAT_DBG_ASSERT(Time->tv_nsec < CXPLAT_NANOSEC_PER_SEC);
// }

// void
// CxPlatSleep(
//     _In_ uint32_t DurationMs
//     )
// {
//     int ErrorCode = 0;
//     struct timespec TS = {
//         .tv_sec = (DurationMs / CXPLAT_MS_PER_SECOND),
//         .tv_nsec = (CXPLAT_NANOSEC_PER_MS * (DurationMs %
//         CXPLAT_MS_PER_SECOND))
//     };

//     ErrorCode = nanosleep(&TS, &TS);
//     CXPLAT_DBG_ASSERT(ErrorCode == 0);
//     UNREFERENCED_PARAMETER(ErrorCode);
// }

// uint32_t
// CxPlatProcCurrentNumber(
//     void
//     )
// {
// #if defined(CX_PLATFORM_LINUX)
//     return (uint32_t)sched_getcpu() % CxPlatProcessorCount;
// #elif defined(CX_PLATFORM_DARWIN)
//     //
//     // arm64 macOS has no way to get the current proc, so treat as single
//     core.
//     // Intel macOS can return incorrect values for CPUID, so treat as single
//     core.
//     //
//     return 0;
// #endif // CX_PLATFORM_DARWIN
// }

QUIC_STATUS
CxPlatRandom(uint32_t BufferLen, void *Buffer) {
  random_bytes(Buffer, BufferLen);
  return QUIC_STATUS_SUCCESS;
}

// void
// CxPlatConvertToMappedV6(
//     _In_ const QUIC_ADDR* InAddr,
//     _Out_ QUIC_ADDR* OutAddr
//     )
// {
//     CXPLAT_DBG_ASSERT(!(InAddr == OutAddr));

//     CxPlatZeroMemory(OutAddr, sizeof(QUIC_ADDR));

//     if (InAddr->Ip.sa_family == QUIC_ADDRESS_FAMILY_INET) {
//         OutAddr->Ipv6.sin6_family = QUIC_ADDRESS_FAMILY_INET6;
//         OutAddr->Ipv6.sin6_port = InAddr->Ipv4.sin_port;
//         memset(&(OutAddr->Ipv6.sin6_addr.s6_addr[10]), 0xff, 2);
//         memcpy(&(OutAddr->Ipv6.sin6_addr.s6_addr[12]),
//         &InAddr->Ipv4.sin_addr.s_addr, 4);
//     } else {
//         *OutAddr = *InAddr;
//     }
// }

// void
// CxPlatConvertFromMappedV6(
//     _In_ const QUIC_ADDR* InAddr,
//     _Out_ QUIC_ADDR* OutAddr
//     )
// {
//     CXPLAT_DBG_ASSERT(InAddr->Ip.sa_family == QUIC_ADDRESS_FAMILY_INET6);

//     if (IN6_IS_ADDR_V4MAPPED(&InAddr->Ipv6.sin6_addr)) {
//         QUIC_ADDR TmpAddrS = {0};
//         QUIC_ADDR* TmpAddr = &TmpAddrS;

//         TmpAddr->Ipv4.sin_family = QUIC_ADDRESS_FAMILY_INET;
//         TmpAddr->Ipv4.sin_port = InAddr->Ipv6.sin6_port;
//         memcpy(&TmpAddr->Ipv4.sin_addr.s_addr,
//         &InAddr->Ipv6.sin6_addr.s6_addr[12], 4); *OutAddr = *TmpAddr;
//     } else if (OutAddr != InAddr) {
//         *OutAddr = *InAddr;
//     }
// }

#ifdef DEBUG
void CxPlatSetAllocFailDenominator(int32_t Value) {
  UNREFERENCED_PARAMETER(Value);
}

int32_t CxPlatGetAllocFailDenominator() { return 0; }
#endif

// #if defined(CX_PLATFORM_LINUX)

QUIC_STATUS
CxPlatThreadCreate(CXPLAT_THREAD_CONFIG *Config, CXPLAT_THREAD *Thread) {
  UNREFERENCED_PARAMETER(Config);
  UNREFERENCED_PARAMETER(Thread);
  return QUIC_STATUS_SUCCESS;
}

// QUIC_STATUS
// CxPlatSetCurrentThreadProcessorAffinity(
//     _In_ uint16_t ProcessorIndex
//     )
// {
// #ifndef __ANDROID__
//     cpu_set_t CpuSet;
//     pthread_t Thread = pthread_self();
//     CPU_ZERO(&CpuSet);
//     CPU_SET(ProcessorIndex, &CpuSet);

//     if (!pthread_setaffinity_np(Thread, sizeof(CpuSet), &CpuSet)) {
//         QuicTraceEvent(
//             LibraryError,
//             "[ lib] ERROR, %s.",
//             "pthread_setaffinity_np failed");
//     }

//     return QUIC_STATUS_SUCCESS;
// #else
//     UNREFERENCED_PARAMETER(ProcessorIndex);
//     return QUIC_STATUS_SUCCESS;
// #endif
// }

// #elif defined(CX_PLATFORM_DARWIN)

// QUIC_STATUS
// CxPlatThreadCreate(
//     _In_ CXPLAT_THREAD_CONFIG* Config,
//     _Out_ CXPLAT_THREAD* Thread
//     )
// {
//     QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
//     pthread_attr_t Attr;
//     if (pthread_attr_init(&Attr)) {
//         QuicTraceEvent(
//             LibraryErrorStatus,
//             "[ lib] ERROR, %u, %s.",
//             errno,
//             "pthread_attr_init failed");
//         return errno;
//     }

//     // XXX: Set processor affinity

//     if (Config->Flags & CXPLAT_THREAD_FLAG_HIGH_PRIORITY) {
//         struct sched_param Params;
//         Params.sched_priority = sched_get_priority_max(SCHED_FIFO);
//         if (!pthread_attr_setschedparam(&Attr, &Params)) {
//             QuicTraceEvent(
//                 LibraryErrorStatus,
//                 "[ lib] ERROR, %u, %s.",
//                 errno,
//                 "pthread_attr_setschedparam failed");
//         }
//     }

//     if (pthread_create(Thread, &Attr, Config->Callback, Config->Context)) {
//         Status = errno;
//         QuicTraceEvent(
//             LibraryErrorStatus,
//             "[ lib] ERROR, %u, %s.",
//             Status,
//             "pthread_create failed");
//     }

//     pthread_attr_destroy(&Attr);

//     return Status;
// }

// QUIC_STATUS
// CxPlatSetCurrentThreadProcessorAffinity(
//     _In_ uint16_t ProcessorIndex
//     )
// {
//     UNREFERENCED_PARAMETER(ProcessorIndex);
//     return QUIC_STATUS_SUCCESS;
// }

// #endif // CX_PLATFORM

void CxPlatThreadDelete(CXPLAT_THREAD *Thread) {
  UNREFERENCED_PARAMETER(Thread);
}

void CxPlatThreadWait(CXPLAT_THREAD *Thread) { UNREFERENCED_PARAMETER(Thread); }

// CXPLAT_THREAD_ID
// CxPlatCurThreadID(
//     void
//     )
// {

// // For FreeBSD
// #if defined(__FreeBSD__)
//     return pthread_getthreadid_np();

// #elif defined(CX_PLATFORM_LINUX)

//     CXPLAT_STATIC_ASSERT(sizeof(pid_t) <= sizeof(CXPLAT_THREAD_ID), "PID size
//     exceeds the expected size"); return syscall(SYS_gettid);

// #elif defined(CX_PLATFORM_DARWIN)
//     // cppcheck-suppress duplicateExpression
//     CXPLAT_STATIC_ASSERT(sizeof(uint32_t) == sizeof(CXPLAT_THREAD_ID), "The
//     cast depends on thread id being 32 bits"); uint64_t Tid; int Res =
//     pthread_threadid_np(NULL, &Tid); UNREFERENCED_PARAMETER(Res);
//     CXPLAT_DBG_ASSERT(Res == 0);
//     CXPLAT_DBG_ASSERT(Tid <= UINT32_MAX);
//     return (CXPLAT_THREAD_ID)Tid;

// #endif // CX_PLATFORM_DARWIN
// }

void CxPlatLogAssert(_In_z_ const char *File, _In_ int Line,
                     _In_z_ const char *Expr) {
  QuicTraceEvent(LibraryAssert, "[ lib] ASSERT, %u:%s - %s.", (uint32_t)Line,
                 File, Expr);
}

int _strnicmp(const char *s1, const char *s2, unsigned int sz) {
  for (unsigned int i = 0; i < sz; i++) {
    const unsigned char *us1 = (const unsigned char *)s1;
    const unsigned char *us2 = (const unsigned char *)s2;
    const int res = toupper(us1[i]) - toupper(us2[i]);
    if (res != 0)
      return res;
  }
  return 0;
}
