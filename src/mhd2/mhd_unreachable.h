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
 * @file src/mhd2/mhd_unreachable.h
 * @brief  The definition of the mhd_UNREACHABLE() macro
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_UNREACHABLE_H
#define MHD_UNREACHABLE_H 1

#include "mhd_sys_options.h"

#if ! defined(NDEBUG)
#  include "mhd_assert.h"
#elif defined (MHD_UNREACHABLE_NEEDS_STDDEF_H)
#  include <stddef.h>
#endif

/**
 * mhd_UNREACHABLE() should be used in locations where it is known in advance
 * that the code must be not reachable.
 * It should give compiler a hint to exclude some code paths from the final
 * binary.
 */
#ifdef NDEBUG
#  ifdef MHD_UNREACHABLE_KEYWORD
#    define mhd_UNREACHABLE()   MHD_UNREACHABLE_KEYWORD
#  else
#    define mhd_UNREACHABLE()   ((void) 0)
#  endif
#else
#  define mhd_UNREACHABLE()     \
        mhd_assert (0 && "This code should be unreachable")
#endif

#endif /* ! MHD_UNREACHABLE_H */
