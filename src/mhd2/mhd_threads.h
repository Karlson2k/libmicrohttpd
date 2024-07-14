/*
  This file is part of GNU libmicrohttpd
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
 * @file src/mhd2/mhd_threads.h
 * @brief  Header for platform-independent threads abstraction
 * @author Karlson2k (Evgeny Grin)
 *
 * Provides basic abstraction for threads.
 * Any functions can be implemented as macro on some platforms
 * unless explicitly marked otherwise.
 * Any function argument can be skipped in macro, so avoid
 * variable modification in function parameters.
 *
 * @warning Unlike pthread functions, most of functions return
 *          nonzero on success.
 */

#ifndef MHD_THREADS_H
#define MHD_THREADS_H 1

#include "mhd_sys_options.h"

#if defined(MHD_USE_POSIX_THREADS)
#  include <pthread.h>
#  ifndef MHD_USE_THREADS
#    define MHD_USE_THREADS 1
#  endif
#elif defined(MHD_USE_W32_THREADS)
#  include <windows.h>
#  ifndef MHD_USE_THREADS
#    define MHD_USE_THREADS 1
#  endif
#else
#  error No threading API is available.
#endif

#include "sys_bool_type.h"
#include "sys_base_types.h"
#include "sys_thread_entry_type.h"

#if defined(MHD_USE_POSIX_THREADS) && defined(MHD_USE_W32_THREADS)
#  error Both MHD_USE_POSIX_THREADS and MHD_USE_W32_THREADS are defined
#endif /* MHD_USE_POSIX_THREADS && MHD_USE_W32_THREADS */

#ifndef MHD_NO_THREAD_NAMES
#  if defined(MHD_USE_POSIX_THREADS)
#    if defined(HAVE_PTHREAD_SETNAME_NP_GNU) || \
  defined(HAVE_PTHREAD_SET_NAME_NP_FREEBSD) || \
  defined(HAVE_PTHREAD_SETNAME_NP_DARWIN) || \
  defined(HAVE_PTHREAD_SETNAME_NP_NETBSD) || \
  defined(HAVE_PTHREAD_ATTR_SETNAME_NP_NETBSD) || \
  defined(HAVE_PTHREAD_ATTR_SETNAME_NP_IBMI)
#      define MHD_USE_THREAD_NAME_
#    endif /* HAVE_PTHREAD_SETNAME_NP */
#  elif defined(MHD_USE_W32_THREADS)
#    ifdef _MSC_FULL_VER
/* Thread names only available with VC compiler */
#      define MHD_USE_THREAD_NAME_
#    endif /* _MSC_FULL_VER */
#  endif
#endif

/* ** Thread handle - used to control the thread ** */

#if defined(MHD_USE_POSIX_THREADS)
/**
 * The native type to control the thread from other threads
 */
typedef pthread_t mhd_thread_handle_native;
#elif defined(MHD_USE_W32_THREADS)
/**
 * The native type to control the thread from other threads
 */
typedef HANDLE mhd_thread_handle_native;
#endif

#if defined(MHD_USE_POSIX_THREADS)
#  if defined(__gnu_linux__) || \
  (defined(__linux__) && defined(__GLIBC__))
/* The next part of code is disabled because it relies on undocumented
   behaviour (while the thread ID cannot be zero with GNU C Library, it is
   not specified anywhere officially).
   It could be enabled for neglectable performance and size improvements. */
#  if 0 /* Disabled code */
/**
 * The native invalid value for native thread handle
 */
#    define mhd_THREAD_HANDLE_NATIVE_VALUE_INVALID \
        ((mhd_thread_handle_native) 0)
#  endif /* Disabled code */
#  endif /* __gnu_linux__ || (__linux__ && __GLIBC__) */
#elif defined(MHD_USE_W32_THREADS)
/* On W32 the invalid value for thread handle is described directly in
  the official documentation. */
/**
 * The native invalid value for native thread handle
 */
#  define mhd_THREAD_HANDLE_NATIVE_VALUE_INVALID \
        ((mhd_thread_handle_native) NULL)
#endif /* MHD_USE_W32_THREADS */

#if defined(MHD_USE_POSIX_THREADS)
/**
 * Wait until specified thread is ended and free the thread handle on success.
 * @param native_handle the handle to watch
 * @return nonzero on success, zero otherwise
 */
#  define mhd_join_thread(native_handle) \
        (! pthread_join ((native_handle), NULL))
#elif defined(MHD_USE_W32_THREADS)
/**
 * Wait until specified thread is ended and the free thread handle on success.
 * @param native_handle the handle to watch
 * @return nonzero on success, zero otherwise
 */
#  define mhd_join_thread(native_handle) \
        ( (WAIT_OBJECT_0 == WaitForSingleObject ( (native_handle), INFINITE)) ? \
          (CloseHandle ( (native_handle)), ! 0) : 0)
#endif

#if ! defined(mhd_THREAD_HANDLE_NATIVE_VALUE_INVALID)
/**
 * Structure with thread handle and validity flag
 */
struct mhd_thread_handle_struct
{
  bool valid;                       /**< true if native handle is set */
  mhd_thread_handle_native native; /**< the native thread handle */
};
/**
 * Type with thread handle that can be set to invalid value
 */
typedef struct mhd_thread_handle_struct mhd_thread_handle;

/**
 * Set variable pointed by @a handle_ptr to invalid (unset) value
 */
#  define mhd_thread_handle_set_invalid(handle_ptr) \
        ((handle_ptr)->valid = false)
/**
 * Set the native handle in the variable pointed by the @a handle_ptr
 * to the @a native_val value
 */
#  define mhd_thread_handle_set_native(handle_ptr,native_val) \
        ((handle_ptr)->valid = true, (handle_ptr)->native = native_val)
/**
 * Check whether the native handle value is set in the @a handle_var variable
 */
#  define mhd_thread_handle_is_valid(handle_var) \
        ((handle_var).valid)
/**
 * Get the native handle value from the @a handle_var variable
 */
#  define mhd_thread_handle_get_native(handle_var) \
        ((handle_var).native)
#else  /* MHD_THREAD_HANDLE_NATIVE_INVALID_ */
/**
 * Type with thread handle that can be set to invalid value
 */
typedef mhd_thread_handle_native mhd_thread_handle;

/**
 * Set the variable pointed by the @a handle_ptr to the invalid (unset) value
 */
#  define mhd_thread_handle_set_invalid(handle_ptr) \
        ((*(handle_ptr)) = mhd_THREAD_HANDLE_NATIVE_VALUE_INVALID)
/**
 * Set the native handle in the variable pointed by the @a handle_ptr
 * to the @a native_val value
 */
#  define mhd_thread_handle_set_native(handle_ptr,native_val) \
        ((*(handle_ptr)) = (native_val))
/**
 * Check whether the native handle value is set in the @a handle_var variable
 */
#  define mhd_thread_handle_is_valid(handle_var) \
        (mhd_THREAD_HANDLE_NATIVE_VALUE_INVALID != (handle_var))
/**
 * Get the native handle value from the @a handle_var variable
 */
#  define mhd_thread_handle_get_native(handle_var) \
        (handle_var)
/**
 * Get the pointer to the native handle stored the variable pointed by
 * the @a handle_ptr pointer
 * @note This macro could be not available if direct manipulation of
 *       the native handle is not possible
 */
#  define mhd_thread_handle_get_native_ptr(handle_ptr) \
        (handle_ptr)
#endif /* MHD_THREAD_HANDLE_NATIVE_INVALID_ */


/* ** Thread ID - used to check threads match ** */

#if defined(MHD_USE_POSIX_THREADS)
/**
 * The native type used to check whether the current thread matches
 * the expected thread
 */
typedef pthread_t mhd_thread_ID_native;

/**
 * Function to get the current thread native ID.
 */
#  define mhd_thread_ID_native_current pthread_self

/**
 * Check whether two native thread IDs are equal.
 * @return non-zero if equal, zero if not equal
 */
#  define mhd_thread_ID_native_equal(id1,id2) \
        (pthread_equal ((id1),(id2)))
#elif defined(MHD_USE_W32_THREADS)
/**
 * The native type used to check whether the current thread matches
 * the expected thread
 */
typedef DWORD mhd_thread_ID_native;

/**
 * Function to get the current thread native ID.
 */
#  define mhd_thread_ID_native_current GetCurrentThreadId

/**
 * Check whether two native thread IDs are equal.
 * @return non-zero if equal, zero if not equal
 */
#  define mhd_thread_ID_native_equal(id1,id2) \
        ((id1) == (id2))
#endif

/**
 * Check whether the specified thread ID matches current thread.
 * @param id the thread ID to match
 * @return nonzero on match, zero otherwise
 */
#define mhd_thread_ID_native_is_current_thread(id) \
        mhd_thread_ID_native_equal ((id), mhd_thread_ID_native_current ())


#if defined(MHD_USE_POSIX_THREADS)
#  if defined(mhd_THREAD_HANDLE_NATIVE_VALUE_INVALID)
/**
 * The native invalid value for native thread ID
 */
#    define MHD_THREAD_ID_NATIVE_VALUE_INVALID_ \
        mhd_THREAD_HANDLE_NATIVE_VALUE_INVALID
#  endif /* mhd_THREAD_HANDLE_NATIVE_VALUE_INVALID */
#elif defined(MHD_USE_W32_THREADS)
/**
 * The native invalid value for native thread ID
 */
 #  define MHD_THREAD_ID_NATIVE_VALUE_INVALID_ \
         ((mhd_thread_ID_native) 0)
#endif /* MHD_USE_W32_THREADS */

#if ! defined(MHD_THREAD_ID_NATIVE_VALUE_INVALID_)
/**
 * Structure with thread id and validity flag
 */
struct mhd_thread_ID_struct
{
  bool valid;                   /**< true if native ID is set */
  mhd_thread_ID_native native; /**< the native thread ID */
};
/**
 * Type with thread ID that can be set to the invalid value
 */
typedef struct mhd_thread_ID_struct mhd_thread_ID;

/**
 * Set variable pointed by the @a ID_ptr to the invalid (unset) value
 */
#  define mhd_thread_ID_set_invalid(ID_ptr) \
        ((ID_ptr)->valid = false)
/**
 * Set the native ID in the variable pointed by the @a ID_ptr
 * to the @a native_val value
 */
#  define mhd_thread_ID_set_native(ID_ptr,native_val) \
        ((ID_ptr)->valid = true, (ID_ptr)->native = (native_val))
/**
 * Check whether the native ID value is set in the @a ID_var variable
 */
#  define mhd_thread_ID_is_valid(ID_var) \
        ((ID_var).valid)
/**
 * Get the native ID value from the @a ID_var variable
 */
#  define mhd_thread_ID_get_native(ID_var) \
        ((ID_var).native)
/**
 * Check whether the @a ID_var variable is equal current thread
 */
#  define mhd_thread_ID_is_current_thread(ID_var) \
        (mhd_thread_ID_is_valid (ID_var) && \
         mhd_thread_ID_native_is_current_thread ((ID_var).native))
#else  /* MHD_THREAD_ID_NATIVE_INVALID_ */
/**
 * Type with thread ID that can be set to the invalid value
 */
typedef mhd_thread_ID_native mhd_thread_ID;

/**
 * Set variable pointed by the @a ID_ptr to the invalid (unset) value
 */
#  define mhd_thread_ID_set_invalid(ID_ptr) \
        ((*(ID_ptr)) = MHD_THREAD_ID_NATIVE_VALUE_INVALID_)
/**
 * Set the native ID in the variable pointed by the @a ID_ptr
 * to the @a native_val value
 */
#  define mhd_thread_ID_set_native(ID_ptr,native_val) \
        ((*(ID_ptr)) = (native_val))
/**
 * Check whether the native ID value is set in the @a ID_var variable
 */
#  define mhd_thread_ID_is_valid(ID_var) \
        (MHD_THREAD_ID_NATIVE_VALUE_INVALID_ != (ID_var))
/**
 * Get the native ID value from the @a ID_var variable
 */
#  define mhd_thread_ID_get_native(ID_var) \
        (ID_var)
/**
 * Check whether the @a ID_var variable is equal current thread
 */
#  define mhd_thread_ID_is_current_thread(ID_var) \
        mhd_thread_ID_native_is_current_thread (ID_var)
#endif /* MHD_THREAD_ID_NATIVE_INVALID_ */

/**
 * Set current thread ID in the variable pointed by the @a ID_ptr
 */
#  define mhd_thread_ID_set_current_thread(ID_ptr) \
        mhd_thread_ID_set_native ((ID_ptr),mhd_thread_ID_native_current ())


#if defined(MHD_USE_POSIX_THREADS)
#  if defined(mhd_THREAD_HANDLE_NATIVE_VALUE_INVALID) && \
  ! defined(MHD_THREAD_ID_NATIVE_VALUE_INVALID_)
#    error \
  MHD_THREAD_ID_NATIVE_VALUE_INVALID_ is defined, but MHD_THREAD_ID_NATIVE_VALUE_INVALID_ is not defined
#  elif ! defined(mhd_THREAD_HANDLE_NATIVE_VALUE_INVALID) && \
  defined(MHD_THREAD_ID_NATIVE_VALUE_INVALID_)
#    error \
  MHD_THREAD_ID_NATIVE_VALUE_INVALID_ is not defined, but MHD_THREAD_ID_NATIVE_VALUE_INVALID_ is defined
#  endif
#endif /* MHD_USE_POSIX_THREADS */

/* When staring a new thread, the kernel (and thread implementation) may
 * pause the calling (initial) thread and start the new thread.
 * If thread identifier is assigned to variable in the initial thread then
 * the value of the identifier variable will be undefined in the new thread
 * until the initial thread continue processing.
 * However, it is also possible that the new thread created, but not executed
 * for some time while the initial thread continue execution. In this case any
 * variable assigned in the new thread will be undefined for some time until
 * they really processed by the new thread.
 * To avoid data races, a special structure mhd_thread_handle_ID is used.
 * The "handle" is assigned by calling (initial) thread and should be always
 * defined when checked in the initial thread.
 * The "ID" is assigned by the new thread and should be always defined when
 * checked inside the new thread.
 */
/* Depending on implementation, pthread_create() MAY set thread ID into
 * provided pointer and after it start thread OR start thread and after
 * it set thread ID. In the latter case, to avoid data races, additional
 * pthread_self() call is required in thread routine. If some platform
 * is known for setting thread ID BEFORE starting thread macro
 * MHD_PTHREAD_CREATE__SET_ID_BEFORE_START_THREAD could be defined
 * to save some resources. */

/* #define MHD_PTHREAD_CREATE__SET_ID_BEFORE_START_THREAD 1 */

/* * handle - must be valid when other thread knows that particular thread
     is started.
   * ID     - must be valid when code is executed inside thread */
#if defined(MHD_USE_POSIX_THREADS) && \
  defined(MHD_PTHREAD_CREATE__SET_ID_BEFORE_START_THREAD) && \
  defined(mhd_THREAD_HANDLE_NATIVE_VALUE_INVALID) && \
  defined(MHD_THREAD_ID_NATIVE_VALUE_INVALID_) && \
  defined(mhd_thread_handle_get_native_ptr)
union mhd_thread_handle_ID_
{
  mhd_thread_handle handle;    /**< To be used in other threads */
  mhd_thread_ID ID;            /**< To be used in the thread itself */
};
typedef union mhd_thread_handle_ID_ mhd_thread_handle_ID;
#  define MHD_THREAD_HANDLE_ID_IS_UNION 1
#else  /* !MHD_USE_POSIX_THREADS
          || !MHD_PTHREAD_CREATE__SET_ID_BEFORE_START_THREAD
          || !mhd_THREAD_HANDLE_NATIVE_VALUE_INVALID
          || !MHD_THREAD_ID_NATIVE_VALUE_INVALID_
          || !mhd_thread_handle_get_native_ptr */
struct mhd_thread_handle_ID_
{
  mhd_thread_handle handle;    /**< To be used in other threads */
  mhd_thread_ID ID;            /**< To be used in the thread itself */
};
typedef struct mhd_thread_handle_ID_ mhd_thread_handle_ID;
#endif /* !MHD_USE_POSIX_THREADS
          || !MHD_PTHREAD_CREATE__SET_ID_BEFORE_START_THREAD
          || !mhd_THREAD_HANDLE_NATIVE_VALUE_INVALID
          || !MHD_THREAD_ID_NATIVE_VALUE_INVALID_
          || !mhd_thread_handle_get_native_ptr */

/**
 * Set the mhd_thread_handle_ID to the invalid value
 */
#define mhd_thread_handle_ID_set_invalid(hndl_id_ptr) \
        (mhd_thread_handle_set_invalid (&((hndl_id_ptr)->handle)), \
         mhd_thread_ID_set_invalid (&((hndl_id_ptr)->ID)))

/**
 * Check whether the thread handle is valid.
 * To be used in threads other then the thread specified by the @a hndl_id.
 */
#define mhd_thread_handle_ID_is_valid_handle(hndl_id) \
        mhd_thread_handle_is_valid ((hndl_id).handle)

/**
 * Set the native handle in the variable pointed by the @a hndl_id_ptr
 * to the @a native_val value
 */
#define mhd_thread_handle_ID_set_native_handle(hndl_id_ptr,native_val) \
        mhd_thread_handle_set_native (&((hndl_id_ptr)->handle),native_val)

#if defined(mhd_thread_handle_get_native_ptr)
/**
 * Get the pointer to the native handle stored the variable pointed by
 * the @a hndl_id_ptr
 * @note This macro could not available if direct manipulation of
 *       the native handle is not possible
 */
#  define mhd_thread_handle_ID_get_native_handle_ptr(hndl_id_ptr) \
        mhd_thread_handle_get_native_ptr (&((hndl_id_ptr)->handle))
#endif /* mhd_thread_handle_get_native_ptr */

/**
 * Get the native thread handle from the mhd_thread_handle_ID variable.
 */
#define mhd_thread_handle_ID_get_native_handle(hndl_id) \
        mhd_thread_handle_get_native ((hndl_id).handle)

/**
 * Check whether the thread ID is valid.
 * To be used in the thread itself.
 */
#define mhd_thread_handle_ID_is_valid_ID(hndl_id) \
        mhd_thread_ID_is_valid ((hndl_id).ID)

#if defined(MHD_THREAD_HANDLE_ID_IS_UNION)
#  if defined(MHD_USE_W32_THREADS)
#    error mhd_thread_handle_ID cannot be a union with W32 threads
#  endif /* MHD_USE_W32_THREADS */
/**
 * Set current thread ID in the variable pointed by the @a hndl_id_ptr
 */
#  define mhd_thread_handle_ID_set_current_thread_ID(hndl_id_ptr) (void) 0
#else  /* ! MHD_THREAD_HANDLE_ID_IS_UNION */
/**
 * Set current thread ID in the variable pointed by the @a hndl_id_ptr
 */
#  define mhd_thread_handle_ID_set_current_thread_ID(hndl_id_ptr) \
        mhd_thread_ID_set_current_thread (&((hndl_id_ptr)->ID))
#endif /* ! MHD_THREAD_HANDLE_ID_IS_UNION */

/**
 * Check whether provided thread ID matches current thread.
 * @param ID thread ID to match
 * @return nonzero on match, zero otherwise
 */
#define mhd_thread_handle_ID_is_current_thread(hndl_id) \
        mhd_thread_ID_is_current_thread ((hndl_id).ID)

/**
 * Wait until specified thread is ended and free thread handle on success.
 * @param hndl_id_ handle with ID to watch
 * @return nonzero on success, zero otherwise
 */
#define mhd_thread_handle_ID_join_thread(hndl_id) \
        mhd_join_thread (mhd_thread_handle_ID_get_native_handle (hndl_id))


/**
 * Create a thread and set the attributes according to our options.
 *
 * If thread is created, thread handle must be freed by mhd_join_thread().
 *
 * @param handle_id     handle to initialise
 * @param stack_size    size of stack for new thread, 0 for default
 * @param start_routine main function of thread
 * @param arg argument  for start_routine
 * @return non-zero on success; zero otherwise (with errno set)
 */
bool
mhd_create_thread (mhd_thread_handle_ID *handle_id,
                   size_t stack_size,
                   mhd_THREAD_START_ROUTINE start_routine,
                   void *arg);

#ifndef MHD_USE_THREAD_NAME_
#define mhd_create_named_thread(t,n,s,r,a) mhd_create_thread ((t),(s),(r),(a))
#else  /* MHD_USE_THREAD_NAME_ */
/**
 * Create a named thread and set the attributes according to our options.
 *
 * @param handle_id     handle to initialise
 * @param thread_name   name for new thread
 * @param stack_size    size of stack for new thread, 0 for default
 * @param start_routine main function of thread
 * @param arg argument  for start_routine
 * @return non-zero on success; zero otherwise
 */
bool
mhd_create_named_thread (mhd_thread_handle_ID *handle_id,
                         const char *thread_name,
                         size_t stack_size,
                         mhd_THREAD_START_ROUTINE start_routine,
                         void *arg);

#endif /* MHD_USE_THREAD_NAME_ */

#endif /* ! MHD_THREADS_H */
