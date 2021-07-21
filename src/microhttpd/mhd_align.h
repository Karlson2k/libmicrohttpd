/*
  This file is part of libmicrohttpd
  Copyright (C) 2021 Karlson2k (Evgeny Grin)

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library.
  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @file microhttpd/mhd_align.h
 * @brief  types alignment macros
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_ALIGN_H
#define MHD_ALIGN_H 1

#include <stdint.h>
#include "mhd_options.h"
#ifdef HAVE_STDDEF_H
#include <stddef.h>
#endif

#ifdef HAVE_C_ALIGNOF

#ifdef HAVE_STDALIGN_H
#include <stdalign.h>
#endif

#define _MHD_ALIGNOF(type) alignof(type)

#endif /* HAVE_C_ALIGNOF */

#ifdef offsetof
#define _MHD_OFFSETOF(strct, membr) offsetof(strct, membr)
#else  /* ! offsetof */
#define _MHD_OFFSETOF(strct, membr) (size_t)(((char*)&(((strct*)0)->membr)) - \
                                     ((char*)((strct*)0)))
#endif /* ! offsetof */

/* Provide a limited set of alignment macros */
/* The set could be extended as needed */
#ifdef _MHD_ALIGNOF
#define _MHD_UINT32_ALIGN _MHD_ALIGNOF(uint32_t)
#define _MHD_UINT64_ALIGN _MHD_ALIGNOF(uint64_t)
#else  /* ! _MHD_ALIGNOF */
struct _mhd_dummy_uint32_offset_test
{
  char dummy;
  uint32_t ui32;
};
#define _MHD_UINT32_ALIGN \
  _MHD_OFFSETOF(struct _mhd_dummy_uint32_offset_test, ui32)

struct _mhd_dummy_uint64_offset_test
{
  char dummy;
  uint32_t ui64;
};
#define _MHD_UINT64_ALIGN \
  _MHD_OFFSETOF(struct _mhd_dummy_uint64_offset_test, ui64)
#endif /* ! _MHD_ALIGNOF */

#endif /* ! MHD_ALIGN_H */
