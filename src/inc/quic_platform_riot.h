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

// #include <mutex.h>
#include <stdint.h>
// #include <thread.h>
#include <ztimer.h>

#include "msquic_riot.h"
#include "quic_sal_stub.h"

#if defined(__cplusplus)
extern "C" {
#endif

#ifndef NDEBUG
#define DEBUG 1
#endif

// #define ALIGN_DOWN(length, type)     ((unsigned long)(length) &
// ~(sizeof(type) - 1))

// #define ALIGN_UP(length, type)     (ALIGN_DOWN(((unsigned long)(length) +
// sizeof(type) - 1), type))

// //
// // Generic stuff.
// //

// #define INVALID_SOCKET ((int)(-1))

// #define SOCKET_ERROR (-1)

#define ARRAYSIZE(A) (sizeof(A) / sizeof((A)[0]))

#define UNREFERENCED_PARAMETER(P) (void)(P)

// #define QuicNetByteSwapShort(x) htons((x))

// #define SIZEOF_STRUCT_MEMBER(StructType, StructMember) sizeof(((StructType
// *)0)->StructMember) #define TYPEOF_STRUCT_MEMBER(StructType, StructMember)
// typeof(((StructType *)0)->StructMember)

#if defined(__GNUC__) && __GNUC__ >= 7
#define __fallthrough __attribute__((fallthrough))
#else
#define __fallthrough // fall through
#endif

//
// Interlocked implementations.
//

inline long InterlockedIncrement(_Interlocked_operand_ long volatile *Addend) {
  return __sync_add_and_fetch(Addend, (long)1);
}

inline long InterlockedDecrement(_Interlocked_operand_ long volatile *Addend) {
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
InterlockedExchangeAdd64(_Interlocked_operand_ int64_t volatile *Addend,
                         int64_t Value) {
  return __sync_fetch_and_add(Addend, Value);
}

inline short
InterlockedCompareExchange16(_Interlocked_operand_ short volatile *Destination,
                             short ExChange, short Comperand) {
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
    _Interlocked_operand_ int64_t volatile *Destination, int64_t ExChange,
    int64_t Comperand) {
  return __sync_val_compare_and_swap(Destination, Comperand, ExChange);
}

inline BOOLEAN InterlockedFetchAndClearBoolean(
    _Interlocked_operand_ BOOLEAN volatile *Target) {
  return __sync_fetch_and_and(Target, 0);
}

inline void *
InterlockedFetchAndClearPointer(_Interlocked_operand_ void *volatile *Target) {
  return __sync_fetch_and_and(Target, 0);
}

inline short
InterlockedIncrement16(_Interlocked_operand_ short volatile *Addend) {
  return __sync_add_and_fetch(Addend, (short)1);
}

inline short
InterlockedDecrement16(_Interlocked_operand_ short volatile *Addend) {
  return __sync_sub_and_fetch(Addend, (short)1);
}

inline int64_t
InterlockedIncrement64(_Interlocked_operand_ int64_t volatile *Addend) {
  return __sync_add_and_fetch(Addend, (int64_t)1);
}

#define QuicReadPtrNoFence(p) ((void *)(*p))

//
// Assertion interfaces.
//

// __attribute__((noinline, noreturn)) void
// quic_bugcheck(const char *File, int Line, const char *Expr);

#define quic_bugcheck(...) abort()

void CxPlatLogAssert(const char *File, int Line, const char *Expr);

#define CXPLAT_STATIC_ASSERT(X, Y) static_assert(X, Y);
#define CXPLAT_ANALYSIS_ASSERT(X)
#define CXPLAT_ANALYSIS_ASSUME(X)
#define CXPLAT_FRE_ASSERT(exp)                                                 \
  ((exp) ? (void)0                                                             \
         : (CxPlatLogAssert(__FILE__, __LINE__, #exp),                         \
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

_Ret_maybenull_ void *CxPlatAlloc(size_t ByteCount, uint32_t Tag);

void CxPlatFree(__drv_freesMem(Mem) _Frees_ptr_ void *Mem, uint32_t Tag);

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
  // mutex_t Mutex;
} CXPLAT_LOCK;

#define CxPlatLockInitialize(Lock) // mutex_init(&(Lock)->Mutex)

#define CxPlatLockUninitialize(Lock)

#define CxPlatLockAcquire(Lock) // mutex_lock(&(Lock)->Mutex)

#define CxPlatLockRelease(Lock) // mutex_unlock(&(Lock)->Mutex)

typedef CXPLAT_LOCK CXPLAT_DISPATCH_LOCK;

// #define CxPlatDispatchLockInitialize CxPlatLockInitialize

// #define CxPlatDispatchLockUninitialize CxPlatLockUninitialize

// #define CxPlatDispatchLockAcquire CxPlatLockAcquire

// #define CxPlatDispatchLockRelease CxPlatLockRelease

#define CxPlatDispatchLockInitialize(...)
#define CxPlatDispatchLockUninitialize(...)
#define CxPlatDispatchLockAcquire(...)
#define CxPlatDispatchLockRelease(...)

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
void CxPlatListPushEntry(CXPLAT_SLIST_ENTRY *ListHead,
                         __drv_aliasesMem CXPLAT_SLIST_ENTRY *Entry);

FORCEINLINE
CXPLAT_SLIST_ENTRY *CxPlatListPopEntry(CXPLAT_SLIST_ENTRY *ListHead);

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

// #if DEBUG
// typedef struct CXPLAT_POOL_ENTRY {
//     CXPLAT_SLIST_ENTRY ListHead;
//     uint64_t SpecialFlag;
// } CXPLAT_POOL_ENTRY;
// #define CXPLAT_POOL_SPECIAL_FLAG    0xAAAAAAAAAAAAAAAAull

// int32_t
// CxPlatGetAllocFailDenominator(
//     );
// #endif

inline void CxPlatPoolInitialize(BOOLEAN IsPaged, uint32_t Size, uint32_t Tag,
                                 CXPLAT_POOL *Pool) {
#if DEBUG
  CXPLAT_DBG_ASSERT(Size >= sizeof(CXPLAT_POOL_ENTRY));
#endif
  Pool->Size = Size;
  Pool->Tag = Tag;
  CxPlatLockInitialize(&Pool->Lock);
  Pool->ListDepth = 0;
  CxPlatZeroMemory(&Pool->ListHead, sizeof(Pool->ListHead));
  UNREFERENCED_PARAMETER(IsPaged);
}

inline void CxPlatPoolUninitialize(CXPLAT_POOL *Pool) {
  void *Entry;
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

inline void *CxPlatPoolAlloc(CXPLAT_POOL *Pool) {
#if DEBUG
  if (CxPlatGetAllocFailDenominator()) {
    return CxPlatAlloc(Pool->Size, Pool->Tag);
  }
#endif
  CxPlatLockAcquire(&Pool->Lock);
  void *Entry = CxPlatListPopEntry(&Pool->ListHead);
  if (Entry != NULL) {
    CXPLAT_FRE_ASSERT(Pool->ListDepth > 0);
    Pool->ListDepth--;
  }
  CxPlatLockRelease(&Pool->Lock);
  if (Entry == NULL) {
    Entry = CxPlatAlloc(Pool->Size, Pool->Tag);
  }
#if DEBUG
  if (Entry != NULL) {
    ((CXPLAT_POOL_ENTRY *)Entry)->SpecialFlag = 0;
  }
#endif
  return Entry;
}

inline void CxPlatPoolFree(CXPLAT_POOL *Pool, void *Entry) {
#if DEBUG
  if (CxPlatGetAllocFailDenominator()) {
    CxPlatFree(Entry, Pool->Tag);
    return;
  }
  CXPLAT_DBG_ASSERT(((CXPLAT_POOL_ENTRY *)Entry)->SpecialFlag !=
                    CXPLAT_POOL_SPECIAL_FLAG);
  ((CXPLAT_POOL_ENTRY *)Entry)->SpecialFlag = CXPLAT_POOL_SPECIAL_FLAG;
#endif
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

typedef int8_t CXPLAT_REF_COUNT;

void CxPlatRefInitialize(CXPLAT_REF_COUNT *RefCount);

void CxPlatRefInitializeEx(CXPLAT_REF_COUNT *RefCount, uint32_t Initial);

void CxPlatRefIncrement(CXPLAT_REF_COUNT *RefCount);
// #define CxPlatRefIncrement(RefCount) ((*RefCount)++)

BOOLEAN
CxPlatRefIncrementNonZero(volatile CXPLAT_REF_COUNT *RefCount, uint32_t Bias);

BOOLEAN
CxPlatRefDecrement(CXPLAT_REF_COUNT *RefCount);
// #define CxPlatRefDecrement(RefCount) ((*RefCount)--)

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

static inline int64_t CxPlatTimeEpochMs64(void) {
  return ztimer_now(ZTIMER_MSEC);
}

inline uint64_t CxPlatTimeDiff64(uint64_t T1, uint64_t T2) {
  //
  // Assume no wrap around.
  //

  return T2 - T1;
}

inline uint32_t QUIC_NO_SANITIZE("unsigned-integer-overflow")
    CxPlatTimeDiff32(uint32_t T1, // First time measured
                     uint32_t T2  // Second time measured
    ) {
  if (T2 > T1) {
    return T2 - T1;
  } else { // Wrap around case.
    return T2 + (0xFFFFFFFF - T1) + 1;
  }
}

inline BOOLEAN CxPlatTimeAtOrBefore64(uint64_t T1, uint64_t T2) {
  //
  // Assume no wrap around.
  //

  return T1 <= T2;
}

inline BOOLEAN QUIC_NO_SANITIZE("unsigned-integer-overflow")
    CxPlatTimeAtOrBefore32(uint32_t T1, uint32_t T2) {
  return (int32_t)(T1 - T2) <= 0;
}

// void
// CxPlatSleep(
//      uint32_t DurationMs
//     );

#define CxPlatSchedulerYield() // sched_yield()

// //
// // Event Interfaces
// //

// //
// // QUIC event object.
// //

typedef struct CXPLAT_EVENT {

  //     //
  //     // Mutex and condition. The alignas is important, as the perf tanks
  //     // if the event is not aligned.
  //     //
  //     alignas(16) pthread_mutex_t Mutex;
  //     pthread_cond_t Cond;

  //     //
  //     // Denotes if the event object is in signaled state.
  //     //

  //     BOOLEAN Signaled;

  //     //
  //     // Denotes if the event object should be auto reset after it's
  //     signaled.
  //     //

  //     BOOLEAN AutoReset;

} CXPLAT_EVENT;

inline void CxPlatEventInitialize(CXPLAT_EVENT *Event, BOOLEAN ManualReset,
                                  BOOLEAN InitialState) {
  UNREFERENCED_PARAMETER(Event);
  UNREFERENCED_PARAMETER(ManualReset);
  UNREFERENCED_PARAMETER(InitialState);

  //     pthread_condattr_t Attr;
  //     int Result;

  //     CxPlatZeroMemory(&Attr, sizeof(Attr));
  //     Event->AutoReset = !ManualReset;
  //     Event->Signaled = InitialState;

  //     Result = pthread_mutex_init(&Event->Mutex, NULL);
  //     CXPLAT_FRE_ASSERT(Result == 0);
  //     Result = pthread_condattr_init(&Attr);
  //     CXPLAT_FRE_ASSERT(Result == 0);
  // #if defined(CX_PLATFORM_LINUX)
  //     Result = pthread_condattr_setclock(&Attr, CLOCK_MONOTONIC);
  //     CXPLAT_FRE_ASSERT(Result == 0);
  // #endif // CX_PLATFORM_LINUX
  //     Result = pthread_cond_init(&Event->Cond, &Attr);
  //     CXPLAT_FRE_ASSERT(Result == 0);
  //     Result = pthread_condattr_destroy(&Attr);
  //     CXPLAT_FRE_ASSERT(Result == 0);
  // }

  // inline
  // void
  // CxPlatInternalEventUninitialize(
  //      CXPLAT_EVENT* Event
  //     )
  // {
  //     int Result;

  //     Result = pthread_cond_destroy(&Event->Cond);
  //     CXPLAT_FRE_ASSERT(Result == 0);
  //     Result = pthread_mutex_destroy(&Event->Mutex);
  //     CXPLAT_FRE_ASSERT(Result == 0);
  // }

  // inline
  // void
  // CxPlatInternalEventSet(
  //      CXPLAT_EVENT* Event
  //     )
  // {
  //     int Result;

  //     Result = pthread_mutex_lock(&Event->Mutex);
  //     CXPLAT_FRE_ASSERT(Result == 0);

  //     Event->Signaled = true;

  //     //
  //     // Signal the condition while holding the lock for predictable
  //     scheduling,
  //     // better performance and removing possibility of use after free for
  //     the
  //     // condition.
  //     //

  //     Result = pthread_cond_broadcast(&Event->Cond);
  //     CXPLAT_FRE_ASSERT(Result == 0);

  //     Result = pthread_mutex_unlock(&Event->Mutex);
  //     CXPLAT_FRE_ASSERT(Result == 0);
}

// inline
// void
// CxPlatInternalEventReset(
//      CXPLAT_EVENT* Event
//     )
// {
//     int Result;

//     Result = pthread_mutex_lock(&Event->Mutex);
//     CXPLAT_FRE_ASSERT(Result == 0);
//     Event->Signaled = false;
//     Result = pthread_mutex_unlock(&Event->Mutex);
//     CXPLAT_FRE_ASSERT(Result == 0);
// }

// inline
// void
// CxPlatInternalEventWaitForever(
//      CXPLAT_EVENT* Event
//     )
// {
//     UNREFERENCED_PARAMETER(Event);
//     int Result;

//     Result = pthread_mutex_lock(&Event->Mutex);
//     CXPLAT_FRE_ASSERT(Result == 0);

//     //
//     // Spurious wake ups from pthread_cond_wait can occur. So the
//     function needs
//     // to be called in a loop until the predicate 'Signalled' is
//     satisfied.
//     //

//     while (!Event->Signaled) {
//         Result = pthread_cond_wait(&Event->Cond, &Event->Mutex);
//         CXPLAT_FRE_ASSERT(Result == 0);
//     }

//     if(Event->AutoReset) {
//         Event->Signaled = false;
//     }

//     Result = pthread_mutex_unlock(&Event->Mutex);
//     CXPLAT_FRE_ASSERT(Result == 0);
// }

// inline
// BOOLEAN
// CxPlatInternalEventWaitWithTimeout(
//      CXPLAT_EVENT* Event,
//      uint32_t TimeoutMs
//     )
// {
//     BOOLEAN WaitSatisfied = FALSE;
//     struct timespec Ts = {0, 0};
//     int Result;

//     //
//     // Get absolute time.
//     //

//     CxPlatGetAbsoluteTime(TimeoutMs, &Ts);

//     Result = pthread_mutex_lock(&Event->Mutex);
//     CXPLAT_FRE_ASSERT(Result == 0);

//     while (!Event->Signaled) {

//         Result = pthread_cond_timedwait(&Event->Cond, &Event->Mutex,
//         &Ts);

//         if (Result == ETIMEDOUT) {
//             WaitSatisfied = FALSE;
//             goto Exit;
//         }

//         CXPLAT_DBG_ASSERT(Result == 0);
//         UNREFERENCED_PARAMETER(Result);
//     }

//     if (Event->AutoReset) {
//         Event->Signaled = FALSE;
//     }

//     WaitSatisfied = TRUE;

// Exit:

//     Result = pthread_mutex_unlock(&Event->Mutex);
//     CXPLAT_FRE_ASSERT(Result == 0);

//     return WaitSatisfied;
// }

// #define CxPlatEventUninitialize(Event)
// CxPlatInternalEventUninitialize(&Event) #define CxPlatEventSet(Event)
// CxPlatInternalEventSet(&Event) #define CxPlatEventReset(Event)
// CxPlatInternalEventReset(&Event) #define CxPlatEventWaitForever(Event)
// CxPlatInternalEventWaitForever(&Event) #define
// CxPlatEventWaitWithTimeout(Event, TimeoutMs)
// CxPlatInternalEventWaitWithTimeout(&Event, TimeoutMs)

#define CxPlatEventUninitialize(Event)
#define CxPlatEventSet(Event)
#define CxPlatEventReset(Event)
#define CxPlatEventWaitForever(Event)
#define CxPlatEventWaitWithTimeout(Event, TimeoutMs)

//
// Event Queue Interfaces
//

// typedef struct io_uring CXPLAT_EVENTQ;
// typedef struct io_uring_cqe* CXPLAT_CQE;

typedef uint8_t CXPLAT_EVENTQ;
typedef uint8_t CXPLAT_CQE;

static inline BOOLEAN CxPlatEventQInitialize(CXPLAT_EVENTQ *queue) {
  UNREFERENCED_PARAMETER(queue);

  return TRUE;
}

static inline void CxPlatEventQCleanup(CXPLAT_EVENTQ *queue) {
  UNREFERENCED_PARAMETER(queue);
}

static inline BOOLEAN _CxPlatEventQEnqueue(CXPLAT_EVENTQ *queue,
                                           void *user_data) {
  UNREFERENCED_PARAMETER(queue);
  UNREFERENCED_PARAMETER(user_data);

  return TRUE;
}

#define CxPlatEventQEnqueue(queue, sqe, user_data)                             \
  _CxPlatEventQEnqueue(queue, user_data)

static inline uint32_t CxPlatEventQDequeue(CXPLAT_EVENTQ *queue,
                                           CXPLAT_CQE *events, uint32_t count,
                                           uint32_t wait_time // milliseconds
) {
  UNREFERENCED_PARAMETER(queue);
  UNREFERENCED_PARAMETER(events);
  UNREFERENCED_PARAMETER(count);
  UNREFERENCED_PARAMETER(wait_time);

  return 0;
}

inline void CxPlatEventQReturn(CXPLAT_EVENTQ *queue, uint32_t count) {
  UNREFERENCED_PARAMETER(queue);
  UNREFERENCED_PARAMETER(count);
}

inline void *CxPlatCqeUserData(const CXPLAT_CQE *cqe) {
  UNREFERENCED_PARAMETER(cqe);

  return 0;
}

//
// Thread Interfaces.
//

//
// QUIC thread object.
//

// typedef pthread_t CXPLAT_THREAD;
// typedef thread_t CXPLAT_THREAD;
typedef uint8_t CXPLAT_THREAD;

#define CXPLAT_THREAD_CALLBACK(FuncName, CtxVarName)                           \
  void *FuncName(void *CtxVarName)

#define CXPLAT_THREAD_RETURN(Status) return NULL;

typedef void *(*LPTHREAD_START_ROUTINE)(void *);

typedef struct CXPLAT_THREAD_CONFIG {
  uint16_t Flags;
  uint16_t IdealProcessor;
  _Field_z_ const char *Name;
  LPTHREAD_START_ROUTINE Callback;
  void *Context;
} CXPLAT_THREAD_CONFIG;

// #ifdef CXPLAT_USE_CUSTOM_THREAD_CONTEXT

// //
// // Extension point that allows additional platform specific logic to be
// executed
// // for every thread created. The platform must define
// CXPLAT_USE_CUSTOM_THREAD_CONTEXT
// // and implement the CxPlatThreadCustomStart function.
// CxPlatThreadCustomStart MUST
// // call the Callback passed in. CxPlatThreadCustomStart MUST also free
// // CustomContext (via CXPLAT_FREE(CustomContext, QUIC_POOL_CUSTOM_THREAD))
// before
// // returning.
// //

// typedef struct CXPLAT_THREAD_CUSTOM_CONTEXT {
//     LPTHREAD_START_ROUTINE Callback;
//     void* Context;
// } CXPLAT_THREAD_CUSTOM_CONTEXT;

// CXPLAT_THREAD_CALLBACK(CxPlatThreadCustomStart, CustomContext); //
// CXPLAT_THREAD_CUSTOM_CONTEXT* CustomContext

// #endif // CXPLAT_USE_CUSTOM_THREAD_CONTEXT

QUIC_STATUS
CxPlatThreadCreate(CXPLAT_THREAD_CONFIG *Config, CXPLAT_THREAD *Thread);

void CxPlatThreadDelete(CXPLAT_THREAD *Thread);

void CxPlatThreadWait(CXPLAT_THREAD *Thread);

typedef uint8_t CXPLAT_THREAD_ID;

static inline CXPLAT_THREAD_ID CxPlatCurThreadID(void) { return 0; }

//
// Processor Count and Index.
//

// extern uint32_t CxPlatProcessorCount;

#define CxPlatProcMaxCount() 1
#define CxPlatProcActiveCount() 1

inline uint32_t CxPlatProcCurrentNumber(void) { return 0; }

//
// Rundown Protection Interfaces.
//

typedef uint8_t CXPLAT_RUNDOWN_REF;
// typedef struct CXPLAT_RUNDOWN_REF {

//   //     //
//   //     // The completion event.
//   //     //

//   //     CXPLAT_EVENT RundownComplete;

//   //     //
//   //     // The ref counter.
//   //     //

//   //     CXPLAT_REF_COUNT RefCount;

// } CXPLAT_RUNDOWN_REF;

// void CxPlatRundownInitialize(CXPLAT_RUNDOWN_REF *Rundown);
#define CxPlatRundownInitialize(...)

// // void
// // CxPlatRundownInitializeDisabled(
// //      CXPLAT_RUNDOWN_REF* Rundown
// //     );

// // void
// // CxPlatRundownReInitialize(
// //      CXPLAT_RUNDOWN_REF* Rundown
// //     );

// void CxPlatRundownUninitialize(CXPLAT_RUNDOWN_REF *Rundown);
#define CxPlatRundownUninitialize(...)

// BOOLEAN
// CxPlatRundownAcquire(CXPLAT_RUNDOWN_REF *Rundown);
#define CxPlatRundownAcquire(...) TRUE

// void CxPlatRundownRelease(CXPLAT_RUNDOWN_REF *Rundown);
#define CxPlatRundownRelease(...)

// void CxPlatRundownReleaseAndWait(CXPLAT_RUNDOWN_REF *Rundown);
#define CxPlatRundownReleaseAndWait(...)

//
// Crypto Interfaces
//

QUIC_STATUS
CxPlatRandom(uint32_t BufferLen, void *Buffer);

//
// Tracing stuff.
//

void CxPlatConvertToMappedV6(const QUIC_ADDR *InAddr, QUIC_ADDR *OutAddr);

void CxPlatConvertFromMappedV6(const QUIC_ADDR *InAddr, QUIC_ADDR *OutAddr);

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
