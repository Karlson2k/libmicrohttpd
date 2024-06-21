/*
  This file is part of GNU libmicrohttpd
  Copyright (C) 2014-2024 Karlson2k (Evgeny Grin)

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
 * @file src/mhd2/compat_calloc.c
 * @brief  The implementation of the calloc() replacement
 * @author Karlson2k (Evgeny Grin)
 */

#include "compat_calloc.h"
#ifndef HAVE_CALLOC

#include <string.h> /* for memset() */
#include "sys_malloc.h"


#ifdef __has_builtin
#  if __has_builtin (__builtin_mul_overflow)
#    define MHD_HAVE_MUL_OVERFLOW 1
#  endif
#elif defined(__GNUC__) && __GNUC__ + 0 >= 5
#  define MHD_HAVE_MUL_OVERFLOW 1
#endif /* __GNUC__ >= 5 */

MHD_INTERNAL void *
mhd_calloc (size_t nelem, size_t elsize)
{
  size_t alloc_size;
  void *ptr;
#ifdef MHD_HAVE_MUL_OVERFLOW
  if (__builtin_mul_overflow (nelem, elsize, &alloc_size) || (0 == alloc_size))
    return NULL;
#else  /* ! MHD_HAVE_MUL_OVERFLOW */
  alloc_size = nelem * elsize;
  if ((0 == alloc_size) || (elsize != alloc_size / nelem))
    return NULL;
#endif /* ! MHD_HAVE_MUL_OVERFLOW */
  ptr = malloc (alloc_size);
  if (NULL == ptr)
    return NULL;
  memset (ptr, 0, alloc_size);
  return ptr;
}


#endif /* ! HAVE_CALLOC */
