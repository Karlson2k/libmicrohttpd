/*
  This file is part of libmicrohttpd
  Copyright (C) 2017-2024 Evgeny Grin (Karlson2k)

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
 * @file src/mhd2/mhd_assert.h
 * @brief  macros for mhd_assert()
 * @author Karlson2k (Evgeny Grin)
 */

/* Unlike POSIX version of 'assert.h', MHD version of 'assert' header
 * does not allow multiple redefinition of 'mhd_assert' macro within single
 * source file. */
#ifndef MHD_ASSERT_H
#define MHD_ASSERT_H 1

#include "mhd_sys_options.h"

#if ! defined(_DEBUG) && ! defined(NDEBUG)
#  ifndef DEBUG /* Used by some toolchains */
#    define NDEBUG 1 /* Use NDEBUG by default */
#  else  /* DEBUG */
#    define _DEBUG 1 /* Non-standart macro */
#  endif /* DEBUG */
#endif /* !_DEBUG && !NDEBUG */

#if defined(_DEBUG) && defined(NDEBUG)
#error Both _DEBUG and NDEBUG are defined
#endif /* _DEBUG && NDEBUG */

#ifdef NDEBUG
#  define mhd_assert(ignore) ((void) 0)
#else  /* ! NDEBUG */
#  ifdef HAVE_ASSERT
#    include <assert.h>
#    define mhd_assert(CHK) assert (CHK)
#  else  /* ! HAVE_ASSERT */
#    include <stdio.h>
#    ifdef HAVE_STDLIB_H
#      include <stdlib.h>
#    elif defined(HAVE_UNISTD_H)
#      include <unistd.h>
#    endif
#    ifdef MHD_HAVE_MHD_FUNC_
#      define mhd_assert(CHK) \
        do { \
          if (! (CHK)) { \
            fprintf (stderr, \
                     "%s:%s:%u Assertion failed: %s\nProgram aborted.\n", \
                     __FILE__, MHD_FUNC_, (unsigned) __LINE__, #CHK); \
            fflush (stderr); abort (); } \
        } while (0)
#    else
#      define mhd_assert(CHK) \
        do { \
          if (! (CHK)) { \
            fprintf (stderr, "%s:%u Assertion failed: %s\nProgram aborted.\n", \
                     __FILE__, (unsigned) __LINE__, #CHK); \
            fflush (stderr); abort (); } \
        } while (0)
#    endif
#  endif /* ! HAVE_ASSERT */
#endif /* NDEBUG */

#ifdef _DEBUG
#  ifdef MHD_UNREACHABLE_
#    undef MHD_UNREACHABLE_
#  endif
#  define MHD_UNREACHABLE_ ((void) 0)
#endif

#endif /* ! MHD_ASSERT_H */
