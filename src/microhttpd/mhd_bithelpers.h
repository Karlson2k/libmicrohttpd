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


#ifdef MHD_HAVE___BUILTIN_BSWAP32
#define _MHD_BYTES_SWAP32(value32)  \
        ((uint32_t)__builtin_bswap32((uint32_t)value32))
#else  /* ! MHD_HAVE___BUILTIN_BSWAP32 */
#define _MHD_BYTES_SWAP32(value32)                              \
   ( (((uint32_t)(value32))                           << 24) |  \
    ((((uint32_t)(value32)) & ((uint32_t)0x0000FF00)) << 8)  |  \
    ((((uint32_t)(value32)) & ((uint32_t)0x00FF0000)) >> 8)  |  \
     (((uint32_t)(value32))                           >> 24) )
#endif /* ! MHD_HAVE___BUILTIN_BSWAP32 */


#ifdef MHD_HAVE___BUILTIN_BSWAP64
#define _MHD_BYTES_SWAP64(value64) \
        ((uint64_t)__builtin_bswap64((uint64_t)value64))
#else  /* ! MHD_HAVE___BUILTIN_BSWAP64 */
#define _MHD_BYTES_SWAP64(value64)                                     \
  ( (((uint64_t)(value64))                                   << 56) |  \
   ((((uint64_t)(value64)) & ((uint64_t)0x000000000000FF00)) << 40) |  \
   ((((uint64_t)(value64)) & ((uint64_t)0x0000000000FF0000)) << 24) |  \
   ((((uint64_t)(value64)) & ((uint64_t)0x00000000FF000000)) << 8)  |  \
   ((((uint64_t)(value64)) & ((uint64_t)0x000000FF00000000)) >> 8)  |  \
   ((((uint64_t)(value64)) & ((uint64_t)0x0000FF0000000000)) >> 24) |  \
   ((((uint64_t)(value64)) & ((uint64_t)0x00FF000000000000)) >> 40) |  \
    (((uint64_t)(value64))                                   >> 56) )
#endif /* ! MHD_HAVE___BUILTIN_BSWAP64 */

/* _MHD_PUT_64BIT_LE (addr, value64)
 * put native-endian 64-bit value64 to addr
 * in little-endian mode.
 */
#if _MHD_BYTE_ORDER == _MHD_LITTLE_ENDIAN
#define _MHD_PUT_64BIT_LE(addr, value64)             \
        ((*(uint64_t*)(addr)) = (uint64_t)(value64))
#elif _MHD_BYTE_ORDER == _MHD_BIG_ENDIAN
#define _MHD_PUT_64BIT_LE(addr, value64)             \
        ((*(uint64_t*)(addr)) = _MHD_BYTES_SWAP64(value64))
#else  /* _MHD_BYTE_ORDER != _MHD_BIG_ENDIAN */
/* Endianess was not detected or non-standard like PDP-endian */
#define _MHD_PUT_64BIT_LE(addr, value64) do {                             \
        ((uint8_t*)(addr))[0] = (uint8_t)((uint64_t)(value64));           \
        ((uint8_t*)(addr))[1] = (uint8_t)(((uint64_t)(value64)) >> 8);    \
        ((uint8_t*)(addr))[2] = (uint8_t)(((uint64_t)(value64)) >> 16);   \
        ((uint8_t*)(addr))[3] = (uint8_t)(((uint64_t)(value64)) >> 24);   \
        ((uint8_t*)(addr))[4] = (uint8_t)(((uint64_t)(value64)) >> 32);   \
        ((uint8_t*)(addr))[5] = (uint8_t)(((uint64_t)(value64)) >> 40);   \
        ((uint8_t*)(addr))[6] = (uint8_t)(((uint64_t)(value64)) >> 48);   \
        ((uint8_t*)(addr))[7] = (uint8_t)(((uint64_t)(value64)) >> 56);   \
        } while (0)
#endif /* _MHD_BYTE_ORDER != _MHD_BIG_ENDIAN */

/* _MHD_PUT_32BIT_LE (addr, value32)
 * put native-endian 32-bit value32 to addr
 * in little-endian mode.
 */
#if _MHD_BYTE_ORDER == _MHD_LITTLE_ENDIAN
#define _MHD_PUT_32BIT_LE(addr,value32)             \
        ((*(uint32_t*)(addr)) = (uint32_t)(value32))
#elif _MHD_BYTE_ORDER == _MHD_BIG_ENDIAN
#define _MHD_PUT_32BIT_LE(addr, value32)            \
        ((*(uint32_t*)(addr)) = _MHD_BYTES_SWAP32(value32))
#else  /* _MHD_BYTE_ORDER != _MHD_BIG_ENDIAN */
/* Endianess was not detected or non-standard like PDP-endian */
#define _MHD_PUT_32BIT_LE(addr, value32) do {                             \
        ((uint8_t*)(addr))[0] = (uint8_t)((uint32_t)(value32));           \
        ((uint8_t*)(addr))[1] = (uint8_t)(((uint32_t)(value32)) >> 8);    \
        ((uint8_t*)(addr))[2] = (uint8_t)(((uint32_t)(value32)) >> 16);   \
        ((uint8_t*)(addr))[3] = (uint8_t)(((uint32_t)(value32)) >> 24);   \
        } while (0)
#endif /* _MHD_BYTE_ORDER != _MHD_BIG_ENDIAN */

/* _MHD_GET_32BIT_LE (addr)
 * get little-endian 32-bit value storied at addr
 * and return it in native-endian mode.
 */
#if _MHD_BYTE_ORDER == _MHD_LITTLE_ENDIAN
#define _MHD_GET_32BIT_LE(addr)             \
        (*(uint32_t*)(addr))
#elif _MHD_BYTE_ORDER == _MHD_BIG_ENDIAN
#define _MHD_GET_32BIT_LE(addr)             \
        _MHD_BYTES_SWAP32(*(uint32_t*)(addr))
#else  /* _MHD_BYTE_ORDER != _MHD_BIG_ENDIAN */
/* Endianess was not detected or non-standard like PDP-endian */
#define _MHD_GET_32BIT_LE(addr)                       \
        ( ( (uint32_t)(((uint8_t*)addr)[0]))        | \
          (((uint32_t)(((uint8_t*)addr)[1])) << 8)  | \
          (((uint32_t)(((uint8_t*)addr)[2])) << 16) | \
          (((uint32_t)(((uint8_t*)addr)[3])) << 24) )
#endif /* _MHD_BYTE_ORDER != _MHD_BIG_ENDIAN */


/* _MHD_PUT_64BIT_BE (addr, value64)
 * put native-endian 64-bit value64 to addr
 * in big-endian mode.
 */
#if _MHD_BYTE_ORDER == _MHD_BIG_ENDIAN
#define _MHD_PUT_64BIT_BE(addr, value64)             \
        ((*(uint64_t*)(addr)) = (uint64_t)(value64))
#elif _MHD_BYTE_ORDER == _MHD_LITTLE_ENDIAN
#define _MHD_PUT_64BIT_BE(addr, value64)             \
        ((*(uint64_t*)(addr)) = _MHD_BYTES_SWAP64(value64))
#else  /* _MHD_BYTE_ORDER != _MHD_LITTLE_ENDIAN */
/* Endianess was not detected or non-standard like PDP-endian */
#define _MHD_PUT_64BIT_BE(addr, value64) do {                             \
        ((uint8_t*)(addr))[7] = (uint8_t)((uint64_t)(value64));           \
        ((uint8_t*)(addr))[6] = (uint8_t)(((uint64_t)(value64)) >> 8);    \
        ((uint8_t*)(addr))[5] = (uint8_t)(((uint64_t)(value64)) >> 16);   \
        ((uint8_t*)(addr))[4] = (uint8_t)(((uint64_t)(value64)) >> 24);   \
        ((uint8_t*)(addr))[3] = (uint8_t)(((uint64_t)(value64)) >> 32);   \
        ((uint8_t*)(addr))[2] = (uint8_t)(((uint64_t)(value64)) >> 40);   \
        ((uint8_t*)(addr))[1] = (uint8_t)(((uint64_t)(value64)) >> 48);   \
        ((uint8_t*)(addr))[0] = (uint8_t)(((uint64_t)(value64)) >> 56);   \
        } while (0)
#endif /* _MHD_BYTE_ORDER != _MHD_LITTLE_ENDIAN */

/* _MHD_PUT_32BIT_BE (addr, value32)
 * put native-endian 32-bit value32 to addr
 * in big-endian mode.
 */
#if _MHD_BYTE_ORDER == _MHD_BIG_ENDIAN
#define _MHD_PUT_32BIT_BE(addr, value32)             \
        ((*(uint32_t*)(addr)) = (uint32_t)(value32))
#elif _MHD_BYTE_ORDER == _MHD_LITTLE_ENDIAN
#define _MHD_PUT_32BIT_BE(addr, value32)             \
        ((*(uint32_t*)(addr)) = _MHD_BYTES_SWAP32(value32))
#else  /* _MHD_BYTE_ORDER != _MHD_LITTLE_ENDIAN */
/* Endianess was not detected or non-standard like PDP-endian */
#define _MHD_PUT_32BIT_BE(addr, value32) do {                             \
        ((uint8_t*)(addr))[3] = (uint8_t)((uint32_t)(value32));           \
        ((uint8_t*)(addr))[2] = (uint8_t)(((uint32_t)(value32)) >> 8);    \
        ((uint8_t*)(addr))[1] = (uint8_t)(((uint32_t)(value32)) >> 16);   \
        ((uint8_t*)(addr))[0] = (uint8_t)(((uint32_t)(value32)) >> 24);   \
        } while (0)
#endif /* _MHD_BYTE_ORDER != _MHD_LITTLE_ENDIAN */

/* _MHD_GET_32BIT_BE (addr)
 * get big-endian 32-bit value storied at addr
 * and return it in native-endian mode.
 */
#if _MHD_BYTE_ORDER == _MHD_BIG_ENDIAN
#define _MHD_GET_32BIT_BE(addr)             \
        (*(uint32_t*)(addr))
#elif _MHD_BYTE_ORDER == _MHD_LITTLE_ENDIAN
#define _MHD_GET_32BIT_BE(addr)             \
        _MHD_BYTES_SWAP32(*(uint32_t*)(addr))
#else  /* _MHD_BYTE_ORDER != _MHD_LITTLE_ENDIAN */
/* Endianess was not detected or non-standard like PDP-endian */
#define _MHD_GET_32BIT_BE(addr)                       \
        ( (((uint32_t)(((uint8_t*)addr)[0])) << 24) | \
          (((uint32_t)(((uint8_t*)addr)[1])) << 16) | \
          (((uint32_t)(((uint8_t*)addr)[2])) << 8)  | \
          ((uint32_t) (((uint8_t*)addr)[3])) )
#endif /* _MHD_BYTE_ORDER != _MHD_LITTLE_ENDIAN */

/**
 * Rotate right 32-bit value by number of bits.
 * bits parameter must be more than zero and must be less than 32.
 * Defined in form which modern compiler could optimize.
 */
#define _MHD_ROTR32(value32, bits) ((value32) >> (bits) | (value32) << (32 - bits))

#endif /* ! MHD_BITHELPERS_H */
