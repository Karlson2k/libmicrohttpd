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
 * @file src/mhd2/sys_thread_entry_type.h
 * @brief  The type of the thread start routine
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_SYS_THREAD_ENTRY_TYPE_H
#define MHD_SYS_THREAD_ENTRY_TYPE_H 1

#include "mhd_sys_options.h"

#if defined(MHD_USE_POSIX_THREADS)
#  define mhd_THRD_RTRN_TYPE void*
#  define mhd_THRD_CALL_SPEC
#elif defined(MHD_USE_W32_THREADS)
#  define mhd_THRD_RTRN_TYPE unsigned
#  define mhd_THRD_CALL_SPEC __stdcall
#endif

/**
 * Signature of the entrance function for a thread.
 *
 * @param cls the closure argument for the function
 * @return the termination code/result from the thread
 */
typedef mhd_THRD_RTRN_TYPE
(mhd_THRD_CALL_SPEC *mhd_THREAD_START_ROUTINE)(void *cls);

#endif /* ! MHD_SYS_THREAD_ENTRY_TYPE_H */
