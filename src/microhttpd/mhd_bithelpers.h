/*
  This file is part of libmicrohttpd
  Copyright (C) 2019 Karlson2k (Evgeny Grin)

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
 * @file microhttpd/mhd_bithelpers.h
 * @brief  macros for bits manipulations
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_BITHELPERS_H
#define MHD_BITHELPERS_H 1

#include "mhd_byteorder.h"
#include <stdint.h>


#if _MHD_BYTE_ORDER == _MHD_LITTLE_ENDIAN
#define _MHD_PUT_64BIT_LE(addr, value64) \
  ((*(uint64_t*)(addr)) = (uint64_t)(value64))
#else  /* _MHD_BYTE_ORDER != _MHD_LITTLE_ENDIAN */
#define _MHD_PUT_64BIT_LE(addr, value64) do {                           \
        (uint8_t*(addr))[7] = (uint8_t)((value64) >> 56);               \
        (uint8_t*(addr))[6] = (uint8_t)((value64) >> 48);               \
        (uint8_t*(addr))[5] = (uint8_t)((value64) >> 40);               \
        (uint8_t*(addr))[4] = (uint8_t)((value64) >> 32);               \
        (uint8_t*(addr))[3] = (uint8_t)((value64) >> 24);               \
        (uint8_t*(addr))[2] = (uint8_t)((value64) >> 16);               \
        (uint8_t*(addr))[1] = (uint8_t)((value64) >> 8);                \
        (uint8_t*(addr))[0] = (uint8_t)((value64)); } while (0)
#endif /* _MHD_BYTE_ORDER != _MHD_LITTLE_ENDIAN */

#if _MHD_BYTE_ORDER == _MHD_LITTLE_ENDIAN
#define _MHD_PUT_32BIT_LE(addr, value32) \
  ((*(uint32_t*)(addr)) = (uint32_t)(value32))
#else  /* _MHD_BYTE_ORDER != _MHD_LITTLE_ENDIAN */

#define _MHD_PUT_32BIT_LE(addr, value32) do {                           \
        (uint8_t*(addr))[3] = (uint8_t)((value32) >> 24);               \
        (uint8_t*(addr))[2] = (uint8_t)((value32) >> 16);               \
        (uint8_t*(addr))[1] = (uint8_t)((value32) >> 8);                \
        (uint8_t*(addr))[0] = (uint8_t)((value32)); } while (0)
#endif /* _MHD_BYTE_ORDER != _MHD_LITTLE_ENDIAN */

#endif /* ! MHD_BITHELPERS_H */
