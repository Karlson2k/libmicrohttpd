/*
  This file is part of GNU libmicrohttpd
  Copyright (C) 2021-2022 Karlson2k (Evgeny Grin)

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
 * @file src/mhd2/mhd_align.h
 * @brief  types alignment macros
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_ALIGN_H
#define MHD_ALIGN_H 1

#include "mhd_sys_options.h"

#include "sys_base_types.h"

#include "sys_offsetof.h"

#ifdef HAVE_C_ALIGNOF
#  ifdef HAVE_STDALIGN_H
#    include <stdalign.h>
#  endif /* HAVE_STDALIGN_H */
#  define mhd_ALIGNOF(type) alignof(type)
#endif /* HAVE_C_ALIGNOF */

#ifndef mhd_ALIGNOF
#  if defined(_MSC_VER) && ! defined(__clang__) && _MSC_VER >= 1700
#    define mhd_ALIGNOF(type) __alignof (type)
#  endif /* _MSC_VER >= 1700 */
#endif /* !mhd_ALIGNOF */

#ifdef mhd_ALIGNOF
#  if (defined(__GNUC__) && __GNUC__ < 4 && __GNUC_MINOR__ < 9 && \
  ! defined(__clang__)) || \
  (defined(__clang__) && __clang_major__ < 8) || \
  (defined(__clang__) && __clang_major__ < 11 && \
  defined(__apple_build_version__))
/* GCC before 4.9 and clang before 8.0 have incorrect implementation of 'alignof()'
   which returns preferred alignment instead of minimal required alignment */
#    define mhd_ALIGNOF_UNRELIABLE 1
#  endif

#  if defined(_MSC_VER) && ! defined(__clang__) && _MSC_VER < 1900
/* MSVC has the same problem as old GCC versions:
   '__alignof()' may return "preferred" alignment instead of "required". */
#    define mhd_ALIGNOF_UNRELIABLE 1
#  endif /* _MSC_VER < 1900 */
#endif /* mhd_ALIGNOF */


/* Provide a limited set of alignment macros */
/* The set could be extended as needed */
#if defined(mhd_ALIGNOF) && ! defined(mhd_ALIGNOF_UNRELIABLE)
#  define mhd_UINT32_ALIGN mhd_ALIGNOF (uint32_t)
#  define mhd_UINT64_ALIGN mhd_ALIGNOF (uint64_t)
#else  /* ! mhd_ALIGNOF */
struct mhd_dummy_uint32_offset_test_
{
  char dummy;
  uint32_t ui32;
};
#  define mhd_UINT32_ALIGN \
        offsetof (struct mhd_dummy_uint32_offset_test_, ui32)

struct mhd_dummy_uint64_offset_test_
{
  char dummy;
  uint64_t ui64;
};
#  define mhd_UINT64_ALIGN \
        offsetof (struct mhd_dummy_uint64_offset_test_, ui64)
#endif /* ! mhd_ALIGNOF */

#endif /* ! MHD_ALIGN_H */
