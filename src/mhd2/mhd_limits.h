/*
  This file is part of libmicrohttpd
  Copyright (C) 2015-2024 Evgeny Grin (Karlson2k)

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
 * @file src/mhd2/mhd_limits.h
 * @brief  limits values definitions
 * @author Karlson2k (Evgeny Grin)
 *
 * This file provides maximum types values as macros. Macros may not work
 * in preprocessor expressions, while macros always work in compiler
 * expressions.
 * This file does not include <stdint.h> and other type-definitions files.
 * For best portability, make sure that this file is included after required
 * type-definitions files.
 */

#ifndef MHD_LIMITS_H
#define MHD_LIMITS_H

#include "mhd_sys_options.h"

#ifdef HAVE_LIMITS_H
#  include <limits.h>
#endif /* HAVE_LIMITS_H */

#define mhd_UNSIGNED_TYPE_MAX(type) ((type)(~((type) 0)))

/* Assume 8 bits per byte, no padding bits. */
#define mhd_SIGNED_TYPE_MAX(type) \
  ( (type) ((( ((type) 1) << (sizeof(type) * 8 - 2)) - 1) * 2 + 1) )

/* The maximum value for signed type, based on knowledge of unsigned counterpart
   type */
#define mhd_SIGNED_TYPE_MAX2(type,utype) ((type)(((utype)(~((utype)0))) >> 1))

#define mhd_IS_TYPE_SIGNED(type) (((type) 0) > ((type) - 1))

#if defined(__GNUC__) || defined(__clang__)
#  define mhd_USE_PREDEF_LIMITS
#endif

#ifndef INT_MAX
#  if defined(mhd_USE_PREDEF_LIMITS) && defined(__INT_MAX__)
#    define INT_MAX __INT_MAX__
#  else  /* ! __INT_MAX__ */
#    define INT_MAX mhd_SIGNED_TYPE_MAX2 (int, unsigned int)
#  endif /* ! __INT_MAX__ */
#endif /* ! INT_MAX */

#ifndef UINT_MAX
#  if defined(mhd_USE_PREDEF_LIMITS) && defined(__UINT_MAX__)
#    define UINT_MAX __UINT_MAX__
#  else  /* ! __UINT_MAX__ */
#    define UINT_MAX mhd_UNSIGNED_TYPE_MAX (unsigned int)
#  endif /* ! __UINT_MAX__ */
#endif /* !UINT_MAX */

#ifndef LONG_MAX
#  if defined(mhd_USE_PREDEF_LIMITS) && defined(__LONG_MAX__)
#    define LONG_MAX __LONG_MAX__
#  else  /* ! __LONG_MAX__ */
#    define LONG_MAX mhd_SIGNED_TYPE_MAX2 (long, unsigned long)
#  endif /* ! __LONG_MAX__ */
#endif /* !LONG_MAX */

#ifndef ULONG_MAX
#  if defined(mhd_USE_PREDEF_LIMITS) && defined(__ULONG_MAX__)
#    define ULONG_MAX ULONG_MAX
#  else  /* ! __ULONG_MAX__ */
#    define ULONG_MAX mhd_UNSIGNED_TYPE_MAX (unsigned long)
#  endif /* ! __ULONG_MAX__ */
#endif /* !ULONG_MAX */

#ifndef ULLONG_MAX
#  ifdef ULONGLONG_MAX
#    define ULLONG_MAX ULONGLONG_MAX
#  else  /* ! ULONGLONG_MAX */
#    define ULLONG_MAX mhd_UNSIGNED_TYPE_MAX (unsigned long long)
#  endif /* ! ULONGLONG_MAX */
#endif /* !ULLONG_MAX */

#ifndef INT32_MAX
#  if defined(mhd_USE_PREDEF_LIMITS) && defined(__INT32_MAX__)
#    define INT32_MAX __INT32_MAX__
#  else  /* ! __INT32_MAX__ */
#    define INT32_MAX ((int32_t) 0x7FFFFFFF)
#  endif /* ! __INT32_MAX__ */
#endif /* !INT32_MAX */

#ifndef UINT32_MAX
#  if defined(mhd_USE_PREDEF_LIMITS) && defined(__UINT32_MAX__)
#    define UINT32_MAX __UINT32_MAX__
#  else  /* ! __UINT32_MAX__ */
#    define UINT32_MAX ((uint32_t) 0xFFFFFFFFU)
#  endif /* ! __UINT32_MAX__ */
#endif /* !UINT32_MAX */

#ifndef INT64_MAX
#  if defined(mhd_USE_PREDEF_LIMITS) && defined(__INT64_MAX__)
#    define INT64_MAX __INT64_MAX__
#  else  /* ! __INT64_MAX__ */
#    define INT64_MAX ((int64_t) 0x7FFFFFFFFFFFFFFF)
#  endif /* ! __UINT64_MAX__ */
#endif /* !INT64_MAX */

#ifndef UINT64_MAX
#  if defined(mhd_USE_PREDEF_LIMITS) && defined(__UINT64_MAX__)
#    define UINT64_MAX __UINT64_MAX__
#  else  /* ! __UINT64_MAX__ */
#    define UINT64_MAX ((uint64_t) 0xFFFFFFFFFFFFFFFFU)
#  endif /* ! __UINT64_MAX__ */
#endif /* !UINT64_MAX */

#ifndef SIZE_MAX
#  if defined(mhd_USE_PREDEF_LIMITS) && defined(__SIZE_MAX__)
#    define SIZE_MAX __SIZE_MAX__
#  else  /* ! __SIZE_MAX__ */
#    define SIZE_MAX mhd_UNSIGNED_TYPE_MAX (size_t)
#  endif /* ! __SIZE_MAX__ */
#endif /* !SIZE_MAX */

#ifndef SSIZE_MAX
#  if defined(mhd_USE_PREDEF_LIMITS) && defined(__SSIZE_MAX__)
#    define SSIZE_MAX __SSIZE_MAX__
#  else
#    define SSIZE_MAX mhd_SIGNED_TYPE_MAX2 (ssize_t, size_t)
#  endif
#endif /* ! SSIZE_MAX */

#ifndef OFF_T_MAX
#  ifdef OFF_MAX
#    define OFF_T_MAX OFF_MAX
#  elif defined(OFFT_MAX)
#    define OFF_T_MAX OFFT_MAX
#  elif defined(__APPLE__) && defined(__MACH__)
#    define OFF_T_MAX INT64_MAX
#  else
#    define OFF_T_MAX mhd_SIGNED_TYPE_MAX (off_t)
#  endif
#endif /* !OFF_T_MAX */

#if defined(_LARGEFILE64_SOURCE) && ! defined(OFF64_T_MAX)
#  define OFF64_T_MAX mhd_SIGNED_TYPE_MAX (off64_t)
#endif /* _LARGEFILE64_SOURCE && !OFF64_T_MAX */

#ifndef TIME_T_MAX
#  define TIME_T_MAX ((time_t)                        \
                      (mhd_IS_TYPE_SIGNED (time_t) ?  \
                       mhd_SIGNED_TYPE_MAX (time_t) : \
                       mhd_UNSIGNED_TYPE_MAX (time_t)))
#endif /* !TIME_T_MAX */

#ifndef TIMEVAL_TV_SEC_MAX
#  ifndef _WIN32
#    define TIMEVAL_TV_SEC_MAX TIME_T_MAX
#  else  /* _WIN32 */
#    define TIMEVAL_TV_SEC_MAX LONG_MAX
#  endif /* _WIN32 */
#endif /* !TIMEVAL_TV_SEC_MAX */

#endif /* MHD_LIMITS_H */
