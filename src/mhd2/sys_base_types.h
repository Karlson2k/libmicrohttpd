/*
  This file is part of GNU libmicrohttpd
  Copyright (C) 2024 Evgeny Grin (Karlson2k)

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
 * @file src/mhd2/sys_base_types.h
 * @brief  The header for basic system types and the NULL constant
 * @author Karlson2k (Evgeny Grin)
 *
 * This header should provide macros or typedefs for uint_fastXX_t, int_fastXX_t
 * size_t, ssize_t and NULL.
 */

#ifndef MHD_SYS_BASE_TYPES_H
#define MHD_SYS_BASE_TYPES_H 1

#include "mhd_sys_options.h"

#if defined(HAVE_SYS_TYPES_H)
#  include <sys/types.h> /* ssize_t */
#elif defined(HAVE_UNISTD_H)
#  include <unistd.h> /* should provide ssize_t */
#endif
#include <stdint.h> /* uint_fast_XXt, int_fast_XXt */
#if defined(HAVE_STDDEF_H)
#  include <stddef.h> /* size_t, NULL */
#elif defined(HAVE_STDLIB_H)
#  include <stdlib.h> /* should provide size_t, NULL */
#else
#  include <stdio.h> /* should provide size_t, NULL */
#endif
#ifdef HAVE_CRTDEFS_H
#  include <crtdefs.h> /* W32-specific header */
#endif
#ifdef HAVE_INTTYPES_H
#  include <inttypes.h>
#endif

#ifndef HAVE_SSIZE_T
#  if defined(HAVE_PTRDIFF_T)
typedef ptrdiff_t ssize_t;
#  elif defined(HAVE_INTPTR_T)
/* Not an ideal choice, the size of the largest allocation may be smaller
   than the total size of the addressable memory. */
typedef intptr_t ssize_t;
#  else
#    error Cannot find suitable 'ssize_t' replacement
#  endif
#  define HAVE_SSIZE_T 1
#  ifdef _WIN32
#    define _SSIZE_T_DEFINED
#  endif
#endif /* ! HAVE_SSIZE_T */

#ifndef PRIuFAST64
#  ifdef PRIu64
#    define PRIuFAST64 PRIu64
#  else
#    define PRIuFAST64 "llu"
#  endif
#endif

#endif /* ! MHD_SYS_BASE_TYPES_H */
