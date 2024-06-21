/*
  This file is part of libmicrohttpd
  Copyright (C) 2016-2024 Evgeny Grin (Karlson2k)

  GNU libmicrohttpd is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  GNU libmicrohttpd is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

*/

/**
 * @file src/mhd2/mhd_locks.h
 * @brief  Header for platform-independent locks abstraction
 * @author Karlson2k (Evgeny Grin)
 * @author Christian Grothoff
 *
 * Provides basic abstraction for locks/mutex.
 * Any functions can be implemented as macro on some platforms
 * unless explicitly marked otherwise.
 * Any function argument can be skipped in macro, so avoid
 * variable modification in function parameters.
 *
 * @warning Unlike pthread functions, most of functions return
 *          nonzero on success.
 */

#ifndef MHD_LOCKS_H
#define MHD_LOCKS_H 1

#include "mhd_sys_options.h"

#ifdef MHD_USE_THREADS

#if defined(MHD_USE_W32_THREADS)
#  define MHD_W32_MUTEX_ 1
#  if _WIN32_WINNT >= 0x0602 /* Win8 or later */
#    include <synchapi.h>
#  else
#    include <windows.h>
#  endif
#elif defined(HAVE_PTHREAD_H) && defined(MHD_USE_POSIX_THREADS)
#  define MHD_PTHREAD_MUTEX_ 1
#  include <pthread.h>
#  ifdef HAVE_STDDEF_H
#    include <stddef.h> /* for NULL */
#  else
#    include "sys_base_types.h"
#  endif
#else
#error No base mutex API is available.
#endif

#include "mhd_panic.h"

#if defined(MHD_PTHREAD_MUTEX_)
typedef pthread_mutex_t mhd_mutex;
#elif defined(MHD_W32_MUTEX_)
typedef CRITICAL_SECTION mhd_mutex;
#endif

#if defined(MHD_PTHREAD_MUTEX_)
/**
 * Initialise a new mutex.
 * @param pmutex the pointer to the mutex
 * @return nonzero on success, zero otherwise
 */
#  define mhd_mutex_init(pmutex) (! (pthread_mutex_init ((pmutex), NULL)))
#elif defined(MHD_W32_MUTEX_)
#  if _WIN32_WINNT < 0x0600
/* Before Vista */
/**
 * Initialise a new mutex.
 * @param pmutex the pointer to the mutex
 * @return nonzero on success, zero otherwise
 */
#    define mhd_mutex_init(pmutex) \
        (InitializeCriticalSectionAndSpinCount ((pmutex), 0))
#  else
/* The function always succeed starting from Vista */
/**
 * Initialise a new mutex.
 * @param pmutex the pointer to the mutex
 * @return nonzero on success, zero otherwise
 */
#    define mhd_mutex_init(pmutex) \
        (InitializeCriticalSection (pmutex), ! 0)
#  endif
#endif

#ifdef MHD_W32_MUTEX_
#  if _WIN32_WINNT < 0x0600
/* Before Vista */
/**
 * Initialise a new mutex for short locks.
 *
 * Initialised mutex is optimised for locks held only for very short period of
 * time. It should be used when only a single or just a few variables are
 * modified under the lock.
 *
 * @param pmutex the pointer to the mutex
 * @return nonzero on success, zero otherwise
 */
#    define mhd_mutex_init_short(pmutex) \
        (InitializeCriticalSectionAndSpinCount ((pmutex), 128))
#  else
/* The function always succeed starting from Vista */
/**
 * Initialise a new mutex for short locks.
 *
 * Initialised mutex is optimised for locks held only for very short period of
 * time. It should be used when only a single or just a few variables are
 * modified under the lock.
 *
 * @param pmutex the pointer to the mutex
 * @return nonzero on success, zero otherwise
 */
#    define mhd_mutex_init_short(pmutex) \
        ((void) InitializeCriticalSectionAndSpinCount ((pmutex), 128), ! 0)
#  endif
#endif

#ifndef mhd_mutex_init_short
#  define mhd_mutex_init_short(pmutex) mhd_mutex_init ((pmutex))
#endif

#if defined(MHD_PTHREAD_MUTEX_)
#  if defined(PTHREAD_MUTEX_INITIALIZER)
/**
 *  Define static mutex and statically initialise it.
 */
#    define MHD_MUTEX_STATIC_DEFN_INIT_(m) \
        static mhd_mutex m = PTHREAD_MUTEX_INITIALIZER
#  endif /* PTHREAD_MUTEX_INITIALIZER */
#endif

#if defined(MHD_PTHREAD_MUTEX_)
/**
 * Destroy previously initialised mutex.
 * @param pmutex the pointer to the mutex
 * @return nonzero on success, zero otherwise
 */
#  define mhd_mutex_destroy(pmutex) (! (pthread_mutex_destroy ((pmutex))))
#elif defined(MHD_W32_MUTEX_)
/**
 * Destroy previously initialised mutex.
 * @param pmutex the pointer to the mutex
 * @return Always nonzero
 */
#  define mhd_mutex_destroy(pmutex) (DeleteCriticalSection ((pmutex)), ! 0)
#endif


#if defined(MHD_PTHREAD_MUTEX_)
/**
 * Acquire a lock on previously initialised mutex.
 * If the mutex was already locked by other thread, function blocks until
 * the mutex becomes available.
 * @param pmutex the pointer to the mutex
 * @return nonzero on success, zero otherwise
 */
#  define mhd_mutex_lock(pmutex) (! (pthread_mutex_lock ((pmutex))))
#elif defined(MHD_W32_MUTEX_)
/**
 * Acquire a lock on previously initialised mutex.
 * If the mutex was already locked by other thread, function blocks until
 * the mutex becomes available.
 * @param pmutex the pointer to the mutex
 * @return nonzero on success, zero otherwise
 */
#  define mhd_mutex_lock(pmutex) (EnterCriticalSection ((pmutex)), ! 0)
#endif

#if defined(MHD_PTHREAD_MUTEX_)
/**
 * Unlock previously locked mutex.
 * @param pmutex the pointer to the mutex
 * @return nonzero on success, zero otherwise
 */
#  define mhd_mutex_unlock(pmutex) (! (pthread_mutex_unlock ((pmutex))))
#elif defined(MHD_W32_MUTEX_)
/**
 * Unlock previously initialised and locked mutex.
 * @param pmutex pointer to mutex
 * @return Always nonzero
 */
#  define mhd_mutex_unlock(pmutex) (LeaveCriticalSection ((pmutex)), ! 0)
#endif

/**
 * Destroy previously initialised mutex and abort execution if error is
 * detected.
 * @param pmutex the pointer to the mutex
 */
#define mhd_mutex_destroy_chk(pmutex) do {      \
          if (! mhd_mutex_destroy (pmutex))           \
          MHD_PANIC ("Failed to destroy mutex.\n"); \
} while (0)

/**
 * Acquire a lock on previously initialised mutex.
 * If the mutex was already locked by other thread, function blocks until
 * the mutex becomes available.
 * If error is detected, execution is aborted.
 * @param pmutex the pointer to the mutex
 */
#define mhd_mutex_lock_chk(pmutex) do {      \
          if (! mhd_mutex_lock (pmutex))           \
          MHD_PANIC ("Failed to lock mutex.\n"); \
} while (0)

/**
 * Unlock previously locked mutex.
 * If error is detected, execution is aborted.
 * @param pmutex the pointer to the mutex
 */
#define mhd_mutex_unlock_chk(pmutex) do {      \
          if (! mhd_mutex_unlock (pmutex))           \
          MHD_PANIC ("Failed to unlock mutex.\n"); \
} while (0)

#else  /* ! MHD_USE_THREADS */

#define mhd_mutex_init(ignore) (! 0)
#define mhd_mutex_destroy(ignore) (! 0)
#define mhd_mutex_destroy_chk(ignore) (void) 0
#define mhd_mutex_lock(ignore) (! 0)
#define mhd_mutex_lock_chk(ignore) (void) 0
#define mhd_mutex_unlock(ignore) (! 0)
#define mhd_mutex_unlock_chk(ignore) (void) 0

#endif /* ! MHD_USE_THREADS */

#endif /* ! MHD_LOCKS_H */
