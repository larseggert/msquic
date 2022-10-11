/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    This file contains POSIX platform implementations of the
    QUIC Platform Interfaces.

Environment:

    RIOT

--*/

#pragma once

#ifndef CX_PLATFORM_TYPE
#error "Must be included from quic_platform.h"
#endif

#if !defined(CX_PLATFORM_RIOT)
#error "Incorrectly including RIOT Platform Header from unsupported platform"
#endif

// FIXME: work around various toolchain bugs - is there a better fix?
// #define _TIME_H_
#define _SYS_TIME_H_

#include <cond.h>
#include <event.h>
#include <mutex.h>
#include <stdint.h>
#include <thread.h>
#include <ztimer.h>

#include "msquic_riot.h"
#include "quic_sal_stub.h"

#if defined(__cplusplus)
extern "C" {
#endif

#ifndef NDEBUG
#define DEBUG 1
#endif

//
// Generic stuff.
//

// #define INVALID_SOCKET ((int)(-1))

// #define SOCKET_ERROR (-1)

#define ARRAYSIZE(A) (sizeof(A) / sizeof((A)[0]))

#define UNREFERENCED_PARAMETER(P) (void)(P)

#if defined(__GNUC__) && __GNUC__ >= 7
#define __fallthrough __attribute__((fallthrough))
#else
#define __fallthrough // fall through
#endif

//
// Interlocked implementations.
//

inline long InterlockedIncrement(_Interlocked_operand_ long volatile * Addend)
{
    return __sync_add_and_fetch(Addend, (long)1);
}

inline long InterlockedDecrement(_Interlocked_operand_ long volatile * Addend)
{
    return __sync_sub_and_fetch(Addend, (long)1);
}

// inline
// long
// InterlockedAnd(
//      _Interlocked_operand_ long volatile *Destination,
//      long Value
//     )
// {
//     return __sync_and_and_fetch(Destination, Value);
// }

// inline
// long
// InterlockedOr(
//      _Interlocked_operand_ long volatile *Destination,
//      long Value
//     )
// {
//     return __sync_or_and_fetch(Destination, Value);
// }

inline int64_t
InterlockedExchangeAdd64(_Interlocked_operand_ int64_t volatile * Addend,
                         int64_t Value)
{
    return __sync_fetch_and_add(Addend, Value);
}

inline short
InterlockedCompareExchange16(_Interlocked_operand_ short volatile * Destination,
                             short ExChange,
                             short Comperand)
{
    return __sync_val_compare_and_swap(Destination, Comperand, ExChange);
}

// inline
// short
// InterlockedCompareExchange(
//      _Interlocked_operand_ long volatile *Destination,
//      long ExChange,
//      long Comperand
//     )
// {
//     return __sync_val_compare_and_swap(Destination, Comperand, ExChange);
// }

inline int64_t InterlockedCompareExchange64(
    _Interlocked_operand_ int64_t volatile * Destination,
    int64_t ExChange,
    int64_t Comperand)
{
    return __sync_val_compare_and_swap(Destination, Comperand, ExChange);
}

inline BOOLEAN
InterlockedFetchAndClearBoolean(_Interlocked_operand_ BOOLEAN volatile * Target)
{
    return __sync_fetch_and_and(Target, 0);
}

inline void *
InterlockedFetchAndClearPointer(_Interlocked_operand_ void * volatile * Target)
{
    return __sync_fetch_and_and(Target, 0);
}

inline short
InterlockedIncrement16(_Interlocked_operand_ short volatile * Addend)
{
    return __sync_add_and_fetch(Addend, (short)1);
}

inline short
InterlockedDecrement16(_Interlocked_operand_ short volatile * Addend)
{
    return __sync_sub_and_fetch(Addend, (short)1);
}

inline int64_t
InterlockedIncrement64(_Interlocked_operand_ int64_t volatile * Addend)
{
    return __sync_add_and_fetch(Addend, (int64_t)1);
}

#define QuicReadPtrNoFence(p) ((void *)(*p))

//
// Assertion interfaces.
//

#define quic_bugcheck(...) abort()

void CxPlatLogAssert(const char * File, int Line, const char * Expr);

#define CXPLAT_STATIC_ASSERT(X, Y) static_assert(X, Y);
#define CXPLAT_ANALYSIS_ASSERT(X)
#define CXPLAT_ANALYSIS_ASSUME(X)
#define CXPLAT_FRE_ASSERT(exp)                                                 \
    ((exp) ? (void)0                                                           \
           : (CxPlatLogAssert(__FILE__, __LINE__, #exp),                       \
              quic_bugcheck(__FILE__, __LINE__, #exp)));
#define CXPLAT_FRE_ASSERTMSG(exp, Y) CXPLAT_FRE_ASSERT(exp)

#ifdef DEBUG
#define CXPLAT_DBG_ASSERT(exp) CXPLAT_FRE_ASSERT(exp)
#define CXPLAT_DBG_ASSERTMSG(exp, msg) CXPLAT_FRE_ASSERT(exp)
#else
#define CXPLAT_DBG_ASSERT(exp)
#define CXPLAT_DBG_ASSERTMSG(exp, msg)
#endif

#if DEBUG || QUIC_TELEMETRY_ASSERTS
#define CXPLAT_TEL_ASSERT(exp) CXPLAT_FRE_ASSERT(exp)
#define CXPLAT_TEL_ASSERTMSG(exp, Y) CXPLAT_FRE_ASSERT(exp)
#define CXPLAT_TEL_ASSERTMSG_ARGS(exp, _msg, _origin, _bucketArg1,             \
                                  _bucketArg2)                                 \
    CXPLAT_FRE_ASSERT(exp)
#else
#define CXPLAT_TEL_ASSERT(exp)
#define CXPLAT_TEL_ASSERTMSG(exp, Y)
#define CXPLAT_TEL_ASSERTMSG_ARGS(exp, _msg, _origin, _bucketArg1, _bucketArg2)
#endif

// //
// // Debugger check.
// //

// #define CxPlatDebuggerPresent() FALSE

//
// Interrupt ReQuest Level.
//

// #define CXPLAT_IRQL() 0
#define CXPLAT_PASSIVE_CODE()

//
// Memory management interfaces.
//

extern uint64_t CxPlatTotalMemory;

_Ret_maybenull_ void * CxPlatAlloc(size_t ByteCount, uint32_t Tag);

void CxPlatFree(__drv_freesMem(Mem) _Frees_ptr_ void * Mem, uint32_t Tag);

#define CXPLAT_ALLOC_PAGED(Size, Tag) malloc(Size)
#define CXPLAT_ALLOC_NONPAGED(Size, Tag) malloc(Size)
#define CXPLAT_FREE(Mem, Tag) free((void *)Mem)

#define CxPlatZeroMemory(Destination, Length) memset((Destination), 0, (Length))
#define CxPlatCopyMemory(Destination, Source, Length)                          \
    memcpy((Destination), (Source), (Length))
#define CxPlatMoveMemory(Destination, Source, Length)                          \
    memmove((Destination), (Source), (Length))
#define CxPlatSecureZeroMemory CxPlatZeroMemory // TODO - Something better?

#define CxPlatByteSwapUint16(value) __builtin_bswap16((unsigned short)(value))
#define CxPlatByteSwapUint32(value) __builtin_bswap32((value))
#define CxPlatByteSwapUint64(value) __builtin_bswap64((value))

//
// Lock interfaces.
//

//
// Represents a QUIC lock.
//

typedef struct CXPLAT_LOCK {
    mutex_t Mutex;
} CXPLAT_LOCK;

#define CxPlatLockInitialize(Lock) mutex_init(&(Lock)->Mutex)

#define CxPlatLockUninitialize(Lock)

#define CxPlatLockAcquire(Lock) mutex_lock(&(Lock)->Mutex)

#define CxPlatLockRelease(Lock) mutex_unlock(&(Lock)->Mutex)

typedef CXPLAT_LOCK CXPLAT_DISPATCH_LOCK;

#define CxPlatDispatchLockInitialize CxPlatLockInitialize

#define CxPlatDispatchLockUninitialize CxPlatLockUninitialize

#define CxPlatDispatchLockAcquire CxPlatLockAcquire

#define CxPlatDispatchLockRelease CxPlatLockRelease

//
// Represents a QUIC RW lock.
//

typedef struct CXPLAT_RW_LOCK {
    //     pthread_rwlock_t RwLock;
    uint8_t RwLock;

} CXPLAT_RW_LOCK;

#define CxPlatRwLockInitialize(Lock) ((Lock)->RwLock = 0)

#define CxPlatRwLockUninitialize(Lock) ((Lock)->RwLock = 0)

#define CxPlatRwLockAcquireShared(Lock) ((Lock)->RwLock = 0)

#define CxPlatRwLockAcquireExclusive(Lock) ((Lock)->RwLock = 0)

#define CxPlatRwLockReleaseShared(Lock) ((Lock)->RwLock = 0)

#define CxPlatRwLockReleaseExclusive(Lock) ((Lock)->RwLock = 0)

typedef CXPLAT_RW_LOCK CXPLAT_DISPATCH_RW_LOCK;

#define CxPlatDispatchRwLockInitialize CxPlatRwLockInitialize

#define CxPlatDispatchRwLockUninitialize CxPlatRwLockUninitialize

#define CxPlatDispatchRwLockAcquireShared CxPlatRwLockAcquireShared

#define CxPlatDispatchRwLockAcquireExclusive CxPlatRwLockAcquireExclusive

#define CxPlatDispatchRwLockReleaseShared CxPlatRwLockReleaseShared

#define CxPlatDispatchRwLockReleaseExclusive CxPlatRwLockReleaseExclusive

//
// Represents a QUIC memory pool used for fixed sized allocations.
// This must be below the lock definitions.
//

FORCEINLINE
void CxPlatListPushEntry(CXPLAT_SLIST_ENTRY * ListHead,
                         __drv_aliasesMem CXPLAT_SLIST_ENTRY * Entry);

FORCEINLINE
CXPLAT_SLIST_ENTRY * CxPlatListPopEntry(CXPLAT_SLIST_ENTRY * ListHead);

typedef struct CXPLAT_POOL {
    // List of free entries.
    CXPLAT_SLIST_ENTRY ListHead;

    // Number of free entries in the list.
    uint16_t ListDepth;

    // Lock to synchronize access to the List.
    // LINUX_TODO: Check how to make this lock free?
    CXPLAT_LOCK Lock;

    // Size of entries.
    uint32_t Size;

    // The memory tag to use for any allocation from this pool.
    uint32_t Tag;
} CXPLAT_POOL;

#define CXPLAT_POOL_MAXIMUM_DEPTH                                              \
    256 // Copied from EX_MAXIMUM_LOOKASIDE_DEPTH_BASE

static inline void CxPlatPoolInitialize(BOOLEAN IsPaged,
                                        uint32_t Size,
                                        uint32_t Tag,
                                        CXPLAT_POOL * Pool)
{
    Pool->Size = Size;
    Pool->Tag = Tag;
    CxPlatLockInitialize(&Pool->Lock);
    Pool->ListDepth = 0;
    CxPlatZeroMemory(&Pool->ListHead, sizeof(Pool->ListHead));
    UNREFERENCED_PARAMETER(IsPaged);
}

inline void CxPlatPoolUninitialize(CXPLAT_POOL * Pool)
{
    void * Entry;
    CxPlatLockAcquire(&Pool->Lock);
    while ((Entry = CxPlatListPopEntry(&Pool->ListHead)) != NULL) {
        CXPLAT_FRE_ASSERT(Pool->ListDepth > 0);
        Pool->ListDepth--;
        CxPlatLockRelease(&Pool->Lock);
        CxPlatFree(Entry, Pool->Tag);
        CxPlatLockAcquire(&Pool->Lock);
    }
    CxPlatLockRelease(&Pool->Lock);
    CxPlatLockUninitialize(&Pool->Lock);
}

inline void * CxPlatPoolAlloc(CXPLAT_POOL * Pool)
{
    CxPlatLockAcquire(&Pool->Lock);
    void * Entry = CxPlatListPopEntry(&Pool->ListHead);
    if (Entry != NULL) {
        CXPLAT_FRE_ASSERT(Pool->ListDepth > 0);
        Pool->ListDepth--;
    }
    CxPlatLockRelease(&Pool->Lock);
    if (Entry == NULL) {
        Entry = CxPlatAlloc(Pool->Size, Pool->Tag);
    }
    return Entry;
}

inline void CxPlatPoolFree(CXPLAT_POOL * Pool, void * Entry)
{
    if (Pool->ListDepth >= CXPLAT_POOL_MAXIMUM_DEPTH) {
        CxPlatFree(Entry, Pool->Tag);
    } else {
        CxPlatLockAcquire(&Pool->Lock);
        CxPlatListPushEntry(&Pool->ListHead, (CXPLAT_SLIST_ENTRY *)Entry);
        Pool->ListDepth++;
        CxPlatLockRelease(&Pool->Lock);
    }
}

//
// Reference Count Interface
//

typedef uint32_t CXPLAT_REF_COUNT;

void CxPlatRefInitialize(CXPLAT_REF_COUNT * RefCount);

void CxPlatRefInitializeEx(CXPLAT_REF_COUNT * RefCount, uint32_t Initial);

void CxPlatRefIncrement(CXPLAT_REF_COUNT * RefCount);

BOOLEAN
CxPlatRefIncrementNonZero(volatile CXPLAT_REF_COUNT * RefCount, uint32_t Bias);

BOOLEAN
CxPlatRefDecrement(CXPLAT_REF_COUNT * RefCount);

#define CxPlatRefUninitialize(RefCount)

//
// Time Measurement Interfaces
//

#define CXPLAT_NANOSEC_PER_MS (1000000)
#define CXPLAT_NANOSEC_PER_MICROSEC (1000)
#define CXPLAT_NANOSEC_PER_SEC (1000000000)
#define CXPLAT_MICROSEC_PER_MS (1000)
#define CXPLAT_MICROSEC_PER_SEC (1000000)
#define CXPLAT_MS_PER_SECOND (1000)

#define CxPlatGetTimerResolution(...) 0

uint64_t CxPlatTimeUs64(void);

// void
// CxPlatGetAbsoluteTime(
//      unsigned long DeltaMs,
//      struct timespec *Time
//     );

#define CxPlatTimeUs32() (uint32_t) CxPlatTimeUs64()
#define CxPlatTimeMs64() (CxPlatTimeUs64() / CXPLAT_MICROSEC_PER_MS)
#define CxPlatTimeMs32() (uint32_t) CxPlatTimeMs64()
#define CxPlatTimeUs64ToPlat(x) (x)

static inline int64_t CxPlatTimeEpochMs64(void)
{
    return ztimer_now(ZTIMER_MSEC);
}

inline uint64_t CxPlatTimeDiff64(uint64_t T1, uint64_t T2)
{
    // Assume no wrap around.
    return T2 - T1;
}

inline uint32_t QUIC_NO_SANITIZE("unsigned-integer-overflow")
    CxPlatTimeDiff32(uint32_t T1, // First time measured
                     uint32_t T2  // Second time measured
    )
{
    if (T2 > T1) {
        return T2 - T1;
    } else { // Wrap around case.
        return T2 + (0xFFFFFFFF - T1) + 1;
    }
}

inline BOOLEAN CxPlatTimeAtOrBefore64(uint64_t T1, uint64_t T2)
{
    // Assume no wrap around.
    return T1 <= T2;
}

inline BOOLEAN QUIC_NO_SANITIZE("unsigned-integer-overflow")
    CxPlatTimeAtOrBefore32(uint32_t T1, uint32_t T2)
{
    return (int32_t)(T1 - T2) <= 0;
}

// void
// CxPlatSleep(
//      uint32_t DurationMs
//     );

#define CxPlatSchedulerYield() sched_yield()

//
// Event Interfaces
//

//
// QUIC event object.
//

typedef struct CXPLAT_EVENT {
    // Mutex and condition.
    mutex_t Mutex;
    cond_t Cond;

    // Denotes if the event object is in signaled state.
    BOOLEAN Signaled;

    // Denotes if the event object should be auto reset after it's signaled.
    BOOLEAN AutoReset;
} CXPLAT_EVENT;

static inline void CxPlatEventInitialize(CXPLAT_EVENT * Event,
                                         BOOLEAN ManualReset,
                                         BOOLEAN InitialState)
{
    Event->AutoReset = !ManualReset;
    Event->Signaled = InitialState;

    mutex_init(&Event->Mutex);
    cond_init(&Event->Cond);
}

inline void CxPlatInternalEventUninitialize(CXPLAT_EVENT * Event) {}

inline void CxPlatInternalEventSet(CXPLAT_EVENT * Event)
{
    mutex_lock(&Event->Mutex);
    Event->Signaled = true;

    // Signal the condition while holding the lock for predictable scheduling,
    // better performance and removing possibility of use after free for the
    // condition.
    cond_broadcast(&Event->Cond);

    mutex_unlock(&Event->Mutex);
}

inline void CxPlatInternalEventReset(CXPLAT_EVENT * Event)
{
    mutex_lock(&Event->Mutex);
    Event->Signaled = false;
    mutex_unlock(&Event->Mutex);
}

inline void CxPlatInternalEventWaitForever(CXPLAT_EVENT * Event)
{

    mutex_lock(&Event->Mutex);

    // Spurious wake ups from cond_wait can occur. So the function needs
    // to be called in a loop until the predicate 'Signalled' is satisfied.
    while (!Event->Signaled) {
        cond_wait(&Event->Cond, &Event->Mutex);
    }

    if (Event->AutoReset) {
        Event->Signaled = false;
    }

    mutex_unlock(&Event->Mutex);
}

inline BOOLEAN CxPlatInternalEventWaitWithTimeout(CXPLAT_EVENT * Event,
                                                  uint32_t TimeoutMs)
{
    BOOLEAN WaitSatisfied = FALSE;
    // struct timespec Ts = {0, 0};

    // Get absolute time.
    // CxPlatGetAbsoluteTime(TimeoutMs, &Ts);

    mutex_lock(&Event->Mutex);

    while (!Event->Signaled) {
        // FIXME: cond_timedwait(&Event->Cond, &Event->Mutex, &Ts);
        cond_wait(&Event->Cond, &Event->Mutex);

        // if (Result == ETIMEDOUT) {
        //   WaitSatisfied = FALSE;
        //   goto Exit;
        // }
    }

    if (Event->AutoReset) {
        Event->Signaled = FALSE;
    }

    WaitSatisfied = TRUE;

    // Exit:

    mutex_unlock(&Event->Mutex);

    return WaitSatisfied;
}

#define CxPlatEventUninitialize(Event) CxPlatInternalEventUninitialize(&Event)
#define CxPlatEventSet(Event) CxPlatInternalEventSet(&Event)
#define CxPlatEventReset(Event) CxPlatInternalEventReset(&Event)
#define CxPlatEventWaitForever(Event) CxPlatInternalEventWaitForever(&Event)
#define CxPlatEventWaitWithTimeout(Event, TimeoutMs)                           \
    CxPlatInternalEventWaitWithTimeout(&Event, TimeoutMs)

//
// Event Queue Interfaces
//

#define CXPLAT_SQE int
typedef event_queue_t CXPLAT_EVENTQ;
typedef struct {
    event_t super;
    void * user_data;
} CXPLAT_CQE;

extern BOOLEAN CxPlatEventQInitialize(CXPLAT_EVENTQ * queue);

extern void CxPlatEventQCleanup(CXPLAT_EVENTQ * queue);

extern BOOLEAN
CxPlatEventQEnqueue(CXPLAT_EVENTQ * queue, CXPLAT_SQE * sqe, void * user_data);

extern uint32_t CxPlatEventQDequeue(CXPLAT_EVENTQ * queue,
                                    CXPLAT_CQE * events,
                                    uint32_t count,
                                    uint32_t wait_time // milliseconds
);

extern void CxPlatEventQReturn(CXPLAT_EVENTQ * queue, uint32_t count);

extern void * CxPlatCqeUserData(const CXPLAT_CQE * cqe);


// static inline BOOLEAN CxPlatEventQInitialize(CXPLAT_EVENTQ * queue)
// {
//     event_queue_init(queue);
//     return TRUE;
// }

// static inline void CxPlatEventQCleanup(CXPLAT_EVENTQ * queue)
// {
//     UNREFERENCED_PARAMETER(queue);
// }

// inline BOOLEAN
// CxPlatEventQEnqueue(CXPLAT_EVENTQ * queue, CXPLAT_SQE * sqe, void *
// user_data)
// {
//     UNREFERENCED_PARAMETER(sqe);

//     event_post(queue, user_data);
//     puts("TODO CxPlatEventQEnqueue");
//     return TRUE;
// }

// static inline uint32_t CxPlatEventQDequeue(CXPLAT_EVENTQ * queue,
//                                            CXPLAT_CQE * events,
//                                            uint32_t count,
//                                            uint32_t wait_time // milliseconds
// )
// {
//     UNREFERENCED_PARAMETER(count);

//     printf("TODO CxPlatEventQDequeue %" PRIu32 "\n", wait_time);
//     if (wait_time == UINT32_MAX) {
//         *events = *event_wait(queue);
//     } else {
//         *events = *event_wait_timeout_ztimer(queue, ZTIMER_MSEC, wait_time);
//     }
//     puts("CxPlatEventQDequeue done");
//     return 1;
// }

// inline void CxPlatEventQReturn(CXPLAT_EVENTQ * queue, uint32_t count)
// {
//     UNREFERENCED_PARAMETER(queue);
//     UNREFERENCED_PARAMETER(count);

//     puts("TODO CxPlatEventQReturn");
// }

// inline void * CxPlatCqeUserData(const CXPLAT_CQE * cqe)
// {
//     UNREFERENCED_PARAMETER(cqe);

//     puts("TODO CxPlatCqeUserData");
//     return 0;
// }

//
// Thread Interfaces.
//

//
// QUIC thread object.
//

typedef kernel_pid_t CXPLAT_THREAD;

#define CXPLAT_THREAD_CALLBACK(FuncName, CtxVarName)                           \
    void * FuncName(void * CtxVarName)

#define CXPLAT_THREAD_RETURN(Status) return NULL;

// typedef void * (*LPTHREAD_START_ROUTINE)(void *);

typedef struct CXPLAT_THREAD_CONFIG {
    uint16_t Flags;
    uint16_t IdealProcessor;
    const char * Name;
    thread_task_func_t Callback;
    void * Context;
} CXPLAT_THREAD_CONFIG;

QUIC_STATUS
CxPlatThreadCreate(CXPLAT_THREAD_CONFIG * Config, CXPLAT_THREAD * Thread);

void CxPlatThreadDelete(CXPLAT_THREAD * Thread);

void CxPlatThreadWait(CXPLAT_THREAD * Thread);

typedef kernel_pid_t CXPLAT_THREAD_ID;

static inline CXPLAT_THREAD_ID CxPlatCurThreadID(void)
{
    return thread_getpid();
}

//
// Processor Count and Index.
//

// extern uint32_t CxPlatProcessorCount;

#define CxPlatProcMaxCount() 1
#define CxPlatProcActiveCount() 1

inline uint32_t CxPlatProcCurrentNumber(void)
{
    return 0;
}

//
// Rundown Protection Interfaces.
//

// typedef uint8_t CXPLAT_RUNDOWN_REF;
typedef struct CXPLAT_RUNDOWN_REF {
    // The completion event.
    CXPLAT_EVENT RundownComplete;

    // The ref counter.
    CXPLAT_REF_COUNT RefCount;

} CXPLAT_RUNDOWN_REF;

void CxPlatRundownInitialize(CXPLAT_RUNDOWN_REF * Rundown);
// #define CxPlatRundownInitialize(...)

// // void
// // CxPlatRundownInitializeDisabled(
// //      CXPLAT_RUNDOWN_REF* Rundown
// //     );

// // void
// // CxPlatRundownReInitialize(
// //      CXPLAT_RUNDOWN_REF* Rundown
// //     );

void CxPlatRundownUninitialize(CXPLAT_RUNDOWN_REF * Rundown);
// #define CxPlatRundownUninitialize(...)

BOOLEAN
CxPlatRundownAcquire(CXPLAT_RUNDOWN_REF * Rundown);
// #define CxPlatRundownAcquire(...) TRUE

void CxPlatRundownRelease(CXPLAT_RUNDOWN_REF * Rundown);
// #define CxPlatRundownRelease(...)

void CxPlatRundownReleaseAndWait(CXPLAT_RUNDOWN_REF * Rundown);
// #define CxPlatRundownReleaseAndWait(...)

//
// Crypto Interfaces
//

QUIC_STATUS
CxPlatRandom(uint32_t BufferLen, void * Buffer);

//
// Tracing stuff.
//

void CxPlatConvertToMappedV6(const QUIC_ADDR * InAddr, QUIC_ADDR * OutAddr);

void CxPlatConvertFromMappedV6(const QUIC_ADDR * InAddr, QUIC_ADDR * OutAddr);

// QUIC_STATUS
// CxPlatSetCurrentThreadProcessorAffinity(
//      uint16_t ProcessorIndex
//     );

// #define CxPlatSetCurrentThreadGroupAffinity(ProcessorGroup)
// QUIC_STATUS_SUCCESS

// #define CXPLAT_CPUID(FunctionId, eax, ebx, ecx, dx)

#if defined(__cplusplus)
}
#endif
