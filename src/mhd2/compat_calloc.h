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
 * @file src/mhd2/compat_calloc.h
 * @brief  The header for the calloc() or the calloc() replacement declarations
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_COMPAT_CALLOC_H
#define MHD_COMPAT_CALLOC_H 1

#include "mhd_sys_options.h"

#ifdef HAVE_CALLOC
#  if defined(HAVE_STDLIB_H)
#    include <stdlib.h>
#  elif defined(HAVE_MALLOC_H)
#    include <malloc.h>
#  else
/* Try some set of headers, hoping the right header is included */
#    if defined(HAVE_UNISTD_H)
#      include <unistd.h>
#    endif
#    include <stdio.h>
#    include <string.h>
#  endif

#  define mhd_calloc calloc
#else

#  include "sys_base_types.h" /* for size_t, NULL */


/**
 * Allocate memory for an array of @a nelem objects of @a elsize size and
 * initialise all bytes to zero in the allocated memory area.
 * @param nelem the number of elements to allocate
 * @param elsize the size of single element
 * @return the pointer to allocated memory area on success,
 *         the NULL pointer on failure.
 */
MHD_INTERNAL void *
mhd_calloc (size_t nelem, size_t elsize);

#endif /* ! HAVE_CALLOC */

#endif /* ! MHD_COMPAT_CALLOC_H */
