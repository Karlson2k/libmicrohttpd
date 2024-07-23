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
 * @file microhttpd/mhd_threads.c
 * @brief  Implementation for thread functions
 * @author Karlson2k (Evgeny Grin)
 */

#include "mhd_threads.h"
#include "sys_null_macro.h"
#ifdef MHD_USE_W32_THREADS
#  include <process.h>
#endif
#if defined(MHD_USE_THREAD_NAME_)
#  if ! defined(MHD_USE_THREAD_ATTR_SETNAME)
#    include "sys_malloc.h"
#  endif
#  ifdef HAVE_PTHREAD_NP_H
#    include <pthread_np.h>
#  endif /* HAVE_PTHREAD_NP_H */
#endif /* MHD_USE_THREAD_NAME_ */
#include "sys_errno.h"
#include "mhd_assert.h"

#ifndef MHD_USE_THREAD_NAME_

#  define mhd_set_thread_name(t, n) (void)
#  define mhd_set_cur_thread_name(n) (void)

#else  /* MHD_USE_THREAD_NAME_ */

#  if defined(MHD_USE_POSIX_THREADS)
#    if defined(HAVE_PTHREAD_ATTR_SETNAME_NP_NETBSD) || \
  defined(HAVE_PTHREAD_ATTR_SETNAME_NP_IBMI)
#      define MHD_USE_THREAD_ATTR_SETNAME 1
#    endif /* HAVE_PTHREAD_ATTR_SETNAME_NP_NETBSD || \
          HAVE_PTHREAD_ATTR_SETNAME_NP_IBMI */

#    if defined(HAVE_PTHREAD_SETNAME_NP_GNU) || \
  defined(HAVE_PTHREAD_SET_NAME_NP_FREEBSD) \
  || defined(HAVE_PTHREAD_SETNAME_NP_NETBSD)

/**
 * Set thread name
 *
 * @param thread_id ID of thread
 * @param thread_name name to set
 * @return true on success, false otherwise
 */
static bool
mhd_set_thread_name (const mhd_thread_ID_native thread_id,
                     const char *thread_name)
{
  if (NULL == thread_name)
    return false;

#      if defined(HAVE_PTHREAD_SETNAME_NP_GNU)
  return 0 == pthread_setname_np (thread_id, thread_name);
#      elif defined(HAVE_PTHREAD_SET_NAME_NP_FREEBSD)
  /* FreeBSD and OpenBSD use different function name and void return type */
  pthread_set_name_np (thread_id, thread_name);
  return true;
#      elif defined(HAVE_PTHREAD_SETNAME_NP_NETBSD)
  /* NetBSD uses 3 arguments: second argument is string in printf-like format,
   *                          third argument is a single argument for printf();
   * OSF1 use 3 arguments too, but last one always must be zero (NULL).
   * MHD doesn't use '%' in thread names, so both form are used in same way.
   */
  return 0 == pthread_setname_np (thread_id, thread_name, 0);
#      endif /* HAVE_PTHREAD_SETNAME_NP_NETBSD */
}


#      ifndef __QNXNTO__
/**
 * Set current thread name
 * @param n name to set
 * @return non-zero on success, zero otherwise
 */
#        define mhd_set_cur_thread_name(n) \
        mhd_set_thread_name (pthread_self (),(n))
#      else  /* __QNXNTO__ */
/* Special case for QNX Neutrino - using zero for thread ID sets name faster. */
#        define mhd_set_cur_thread_name(n) mhd_set_thread_name (0,(n))
#      endif /* __QNXNTO__ */
#    elif defined(HAVE_PTHREAD_SETNAME_NP_DARWIN)

/**
 * Set current thread name
 * @param n name to set
 * @return non-zero on success, zero otherwise
 */
#      define mhd_set_cur_thread_name(n) (! (pthread_setname_np ((n))))
#    endif /* HAVE_PTHREAD_SETNAME_NP_DARWIN */

#  elif defined(MHD_USE_W32_THREADS)
#    ifndef _MSC_FULL_VER
#error Thread name available only for VC-compiler
#    else  /* _MSC_FULL_VER */
/**
 * Set thread name
 *
 * @param thread_id ID of thread, -1 for current thread
 * @param thread_name name to set
 * @return true on success, false otherwise
 */
static bool
mhd_set_thread_name (const mhd_thread_ID_native thread_id,
                     const char *thread_name)
{
  static const DWORD VC_SETNAME_EXC = 0x406D1388;
#pragma pack(push,8)
  struct thread_info_struct
  {
    DWORD type;   /* Must be 0x1000. */
    LPCSTR name;  /* Pointer to name (in user address space). */
    DWORD ID;     /* Thread ID (-1 = caller thread). */
    DWORD flags;  /* Reserved for future use, must be zero. */
  } thread_info;
#pragma pack(pop)

  if (NULL == thread_name)
    return false;

  thread_info.type  = 0x1000;
  thread_info.name  = thread_name;
  thread_info.ID    = thread_id;
  thread_info.flags = 0;

  __try
  { /* This exception is intercepted by debugger */
    RaiseException (VC_SETNAME_EXC,
                    0,
                    sizeof (thread_info) / sizeof(ULONG_PTR),
                    (ULONG_PTR *) &thread_info);
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {}

  return true;
}


/**
 * Set current thread name
 * @param n name to set
 * @return true on success, false otherwise
 */
#      define mhd_set_cur_thread_name(n) \
        mhd_set_thread_name ((mhd_thread_ID_native) (-1),(n))
#    endif /* _MSC_FULL_VER */
#  endif /* MHD_USE_W32_THREADS */

#endif /* MHD_USE_THREAD_NAME_ */


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
                   void *arg)
{
#if defined(MHD_USE_POSIX_THREADS)
  int res;
#  if defined(mhd_thread_handle_ID_get_native_handle_ptr)
  pthread_t *const new_tid_ptr =
    mhd_thread_handle_ID_get_native_handle_ptr (handle_id);
#  else  /* ! mhd_thread_handle_ID_get_native_handle_ptr */
  pthread_t new_tid;
  pthread_t *const new_tid_ptr = &new_tid;
#  endif /* ! mhd_thread_handle_ID_get_native_handle_ptr */

  mhd_assert (! mhd_thread_handle_ID_is_valid_handle (*handle_id));

  if (0 != stack_size)
  {
    pthread_attr_t attr;
    res = pthread_attr_init (&attr);
    if (0 == res)
    {
      res = pthread_attr_setstacksize (&attr,
                                       stack_size);
      if (0 == res)
        res = pthread_create (new_tid_ptr,
                              &attr,
                              start_routine,
                              arg);
      pthread_attr_destroy (&attr);
    }
  }
  else
    res = pthread_create (new_tid_ptr,
                          NULL,
                          start_routine,
                          arg);

  if (0 != res)
  {
    errno = res;
    mhd_thread_handle_ID_set_invalid (handle_id);
  }
#  if ! defined(mhd_thread_handle_ID_get_native_handle_ptr)
  else
    mhd_thread_handle_ID_set_native_handle (handle_id, new_tid);
#  endif /* ! mhd_thread_handle_ID_set_current_thread_ID */

  return 0 == res;
#elif defined(MHD_USE_W32_THREADS)
  uintptr_t thr_handle;
  unsigned int stack_size_w32;
#  if SIZEOF_SIZE_T != SIZEOF_UNSIGNED_INT

  mhd_assert (! mhd_thread_handle_ID_is_valid_handle (*handle_id));

  stack_size_w32 = (unsigned int) stack_size;
  if (stack_size != stack_size_w32)
  {
    errno = EINVAL;
    return false;
  }
#endif /* SIZEOF_SIZE_T != SIZEOF_UNSIGNED_INT */
  thr_handle = _beginthreadex (NULL,
                               stack_size_w32,
                               start_routine,
                               arg,
                               0,
                               NULL);
  if ((mhd_thread_handle_native) 0 == (mhd_thread_handle_native) thr_handle)
    return false;

  mhd_thread_handle_ID_set_native_handle (handle_id, \
                                          (mhd_thread_handle_native) \
                                          thr_handle);

  return true;
#endif /* MHD_USE_W32_THREADS */
}


#ifdef MHD_USE_THREAD_NAME_

#  ifndef MHD_USE_THREAD_ATTR_SETNAME
struct mhd_named_helper_param
{
  /**
   * Real thread start routine
   */
  mhd_THREAD_START_ROUTINE start_routine;

  /**
   * Argument for thread start routine
   */
  void *arg;

  /**
   * Name for thread
   */
  const char *name;
};


static mhd_THRD_RTRN_TYPE mhd_THRD_CALL_SPEC
named_thread_starter (void *data)
{
  struct mhd_named_helper_param *const param =
    (struct mhd_named_helper_param *) data;
  void *arg;
  mhd_THREAD_START_ROUTINE thr_func;

  if (NULL == data)
    return (mhd_THRD_RTRN_TYPE) 0;

  mhd_set_cur_thread_name (param->name);

  arg = param->arg;
  thr_func = param->start_routine;
  free (data);

  return thr_func (arg);
}


#  endif /* ! MHD_USE_THREAD_ATTR_SETNAME */


/**
 * Create a named thread and set the attributes according to our options.
 *
 * @param handle_id     handle to initialise
 * @param thread_name   name for new thread
 * @param stack_size    size of stack for new thread, 0 for default
 * @param start_routine main function of thread
 * @param arg argument  for start_routine
 * @return non-zero on success; zero otherwise (with errno set)
 */
bool
mhd_create_named_thread (mhd_thread_handle_ID *handle_id,
                         const char *thread_name,
                         size_t stack_size,
                         mhd_THREAD_START_ROUTINE start_routine,
                         void *arg)
{
#  if defined(MHD_USE_THREAD_ATTR_SETNAME)
  int res;
  pthread_attr_t attr;
#    if defined(mhd_thread_handle_ID_get_native_handle_ptr)
  pthread_t *const new_tid_ptr =
    mhd_thread_handle_ID_get_native_handle_ptr (handle_id);
#    else  /* ! mhd_thread_handle_ID_get_native_handle_ptr */
  pthread_t new_tid;
  pthread_t *const new_tid_ptr = &new_tid;
#    endif /* ! mhd_thread_handle_ID_get_native_handle_ptr */

  res = pthread_attr_init (&attr);
  if (0 == res)
  {
#    if defined(HAVE_PTHREAD_ATTR_SETNAME_NP_NETBSD)
    /* NetBSD uses 3 arguments: second argument is string in printf-like format,
     *                          third argument is single argument for printf;
     * OSF1 uses 3 arguments too, but last one always must be zero (NULL).
     * MHD doesn't use '%' in thread names, so both forms are used in same way.
     */
    res = pthread_attr_setname_np (&attr,
                                   thread_name,
                                   0);
#    elif defined(HAVE_PTHREAD_ATTR_SETNAME_NP_IBMI)
    res = pthread_attr_setname_np (&attr,
                                   thread_name);
#    else
#error No pthread_attr_setname_np() function.
#    endif
    if ((res == 0) && (0 != stack_size) )
      res = pthread_attr_setstacksize (&attr,
                                       stack_size);
    if (0 == res)
      res = pthread_create (new_tid_ptr,
                            &attr,
                            start_routine,
                            arg);
    pthread_attr_destroy (&attr);
  }
  if (0 != res)
  {
    errno = res;
    mhd_thread_handle_ID_set_invalid (handle_id);
  }
#    if ! defined(mhd_thread_handle_ID_get_native_handle_ptr)
  else
    mhd_thread_handle_ID_set_native_handle (handle_id, new_tid);
#    endif /* ! mhd_thread_handle_ID_set_current_thread_ID */

  return 0 == res;
#  else  /* ! MHD_USE_THREAD_ATTR_SETNAME */
  struct mhd_named_helper_param *param;

  if (NULL == thread_name)
  {
    errno = EINVAL;
    return false;
  }

  param = malloc (sizeof (struct mhd_named_helper_param));
  if (NULL == param)
    return false;

  param->start_routine = start_routine;
  param->arg = arg;
  param->name = thread_name;

  /* Set the thread name in the thread itself to avoid problems with
   * threads which terminated before the name is set in other thread.
   */
  if (! mhd_create_thread (handle_id,
                           stack_size,
                           &named_thread_starter,
                           (void *) param))
  {
    int err_num;

    err_num = errno;
    free (param);
    errno = err_num;
    return false;
  }

  return true;
#  endif /* ! MHD_USE_THREAD_ATTR_SETNAME */
}


#endif /* MHD_USE_THREAD_NAME_ */
