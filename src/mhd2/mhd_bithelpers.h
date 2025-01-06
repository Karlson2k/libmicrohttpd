/*
  This file is part of GNU libmicrohttpd
  Copyright (C) 2019-2023 Karlson2k (Evgeny Grin)

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
 * @file src/mhd2/mhd_bithelpers.h
 * @brief  macros for bits manipulations
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_BITHELPERS_H
#define MHD_BITHELPERS_H 1

#include "mhd_sys_options.h"

#include "sys_base_types.h"

#if defined(_MSC_FULL_VER) && (! defined(__clang__) || (defined(__c2__) && \
  defined(__OPTIMIZE__)))
/* Declarations for VC & Clang/C2 built-ins */
#include <intrin.h>
#endif /* _MSC_FULL_VER  */
#include "mhd_byteorder.h"
#if mhd_BYTE_ORDER == mhd_LITTLE_ENDIAN || mhd_BYTE_ORDER == mhd_BIG_ENDIAN
#include "mhd_align.h"
#endif /* mhd_BYTE_ORDER == mhd_LITTLE_ENDIAN ||
          mhd_BYTE_ORDER == mhd_BIG_ENDIAN */

#ifndef __has_builtin
#  define mhd_HAS_BUILTIN(x) (0)
#else
#  define mhd_HAS_BUILTIN(x) __has_builtin (x)
#endif

mhd_DATA_TRUNCATION_RUNTIME_CHECK_DISABLE

#ifdef MHD_HAVE___BUILTIN_BSWAP32
#  define mhd_BYTES_SWAP32(value32)  \
        ((uint32_t) __builtin_bswap32 ((uint32_t) value32))
#elif defined(_MSC_FULL_VER) && (! defined(__clang__) || (defined(__c2__) && \
  defined(__OPTIMIZE__)))
/* Clang/C2 may not inline this function if optimizations are turned off. */
#  ifndef __clang__
#    pragma intrinsic(_byteswap_ulong)
#  endif /* ! __clang__ */
#  define mhd_BYTES_SWAP32(value32)  \
        ((uint32_t) _byteswap_ulong ((uint32_t) value32))
#elif \
  mhd_HAS_BUILTIN (__builtin_bswap32)
#  define mhd_BYTES_SWAP32(value32)  \
        ((uint32_t)__builtin_bswap32 ((uint32_t) value32))
#else  /* ! mhd_HAS_BUILTIN(__builtin_bswap32) */
#  define mhd_BYTES_SWAP32(value32)                                  \
        ( (((uint32_t) (value32)) << 24)                                  \
          | ((((uint32_t) (value32)) & ((uint32_t) 0x0000FF00)) << 8)     \
          | ((((uint32_t) (value32)) & ((uint32_t) 0x00FF0000)) >> 8)     \
          | (((uint32_t) (value32))                           >> 24) )
#endif /* ! mhd_HAS_BUILTIN(__builtin_bswap32) */

#ifdef MHD_HAVE___BUILTIN_BSWAP64
#  define mhd_BYTES_SWAP64(value64) \
        ((uint64_t)__builtin_bswap64 ((uint64_t) value64))
#elif defined(_MSC_FULL_VER) && (! defined(__clang__) || (defined(__c2__) && \
  defined(__OPTIMIZE__)))
/* Clang/C2 may not inline this function if optimizations are turned off. */
#  ifndef __clang__
#    pragma intrinsic(_byteswap_uint64)
#  endif /* ! __clang__ */
#  define mhd_BYTES_SWAP64(value64)  \
        ((uint64_t)_byteswap_uint64 ((uint64_t) value64))
#elif \
  mhd_HAS_BUILTIN (__builtin_bswap64)
#  define mhd_BYTES_SWAP64(value64) \
        ((uint64_t)__builtin_bswap64 ((uint64_t) value64))
#else  /* ! mhd_HAS_BUILTIN(__builtin_bswap64) */
#  define mhd_BYTES_SWAP64(value64)                                         \
        ( (((uint64_t) (value64)) << 56)                                          \
          | ((((uint64_t) (value64)) & ((uint64_t) 0x000000000000FF00)) << 40)    \
          | ((((uint64_t) (value64)) & ((uint64_t) 0x0000000000FF0000)) << 24)    \
          | ((((uint64_t) (value64)) & ((uint64_t) 0x00000000FF000000)) << 8)     \
          | ((((uint64_t) (value64)) & ((uint64_t) 0x000000FF00000000)) >> 8)     \
          | ((((uint64_t) (value64)) & ((uint64_t) 0x0000FF0000000000)) >> 24)    \
          | ((((uint64_t) (value64)) & ((uint64_t) 0x00FF000000000000)) >> 40)    \
          | (((uint64_t) (value64))                                   >> 56) )
#endif /* ! mhd_HAS_BUILTIN(__builtin_bswap64) */


/* mhd_PUT_64BIT_LE (addr, value64)
 * put native-endian 64-bit value64 to addr
 * in little-endian mode.
 */
/* Slow version that works with unaligned addr and with any bytes order */
#define mhd_PUT_64BIT_LE_SLOW(addr, value64) do {                       \
          ((uint8_t*) (addr))[0] = (uint8_t) ((uint64_t) (value64));           \
          ((uint8_t*) (addr))[1] = (uint8_t) (((uint64_t) (value64)) >> 8);    \
          ((uint8_t*) (addr))[2] = (uint8_t) (((uint64_t) (value64)) >> 16);   \
          ((uint8_t*) (addr))[3] = (uint8_t) (((uint64_t) (value64)) >> 24);   \
          ((uint8_t*) (addr))[4] = (uint8_t) (((uint64_t) (value64)) >> 32);   \
          ((uint8_t*) (addr))[5] = (uint8_t) (((uint64_t) (value64)) >> 40);   \
          ((uint8_t*) (addr))[6] = (uint8_t) (((uint64_t) (value64)) >> 48);   \
          ((uint8_t*) (addr))[7] = (uint8_t) (((uint64_t) (value64)) >> 56);   \
} while (0)
#if mhd_BYTE_ORDER == mhd_LITTLE_ENDIAN
#  define mhd_PUT_64BIT_LE(addr, value64)             \
        ((*(uint64_t*) (addr)) = (uint64_t) (value64))
#elif mhd_BYTE_ORDER == mhd_BIG_ENDIAN
#  define mhd_PUT_64BIT_LE(addr, value64)             \
        ((*(uint64_t*) (addr)) = mhd_BYTES_SWAP64 (value64))
#else  /* mhd_BYTE_ORDER != mhd_BIG_ENDIAN */
/* Endianness was not detected or non-standard like PDP-endian */
#  define mhd_PUT_64BIT_LE(addr, value64) \
        mhd_PUT_64BIT_LE_SLOW ((addr),(value64))
/* Indicate that mhd_PUT_64BIT_LE does not need aligned pointer */
#  define mhd_PUT_64BIT_LE_UNALIGNED 1
#endif /* mhd_BYTE_ORDER != mhd_BIG_ENDIAN */

/* Put result safely to unaligned address */
MHD_static_inline_ void
mhd_PUT_64BIT_LE_UNALIGN (void *dst, uint64_t value)
{
#ifndef mhd_PUT_64BIT_LE_UNALIGNED
  if (0 != ((uintptr_t) dst) % (mhd_UINT64_ALIGN))
    mhd_PUT_64BIT_LE_SLOW (dst, value);
  else
#endif /* ! mhd_PUT_64BIT_LE_UNALIGNED */
  mhd_PUT_64BIT_LE (dst, value);
}


/* mhd_PUT_32BIT_LE (addr, value32)
 * put native-endian 32-bit value32 to addr
 * in little-endian mode.
 */
/* Slow version that works with unaligned addr and with any bytes order */
#define mhd_PUT_32BIT_LE_SLOW(addr, value32) do {                            \
          ((uint8_t*) (addr))[0] = (uint8_t) ((uint32_t) (value32));           \
          ((uint8_t*) (addr))[1] = (uint8_t) (((uint32_t) (value32)) >> 8);    \
          ((uint8_t*) (addr))[2] = (uint8_t) (((uint32_t) (value32)) >> 16);   \
          ((uint8_t*) (addr))[3] = (uint8_t) (((uint32_t) (value32)) >> 24);   \
} while (0)
#if mhd_BYTE_ORDER == mhd_LITTLE_ENDIAN
#  define mhd_PUT_32BIT_LE(addr,value32)             \
        ((*(uint32_t*) (addr)) = (uint32_t) (value32))
#elif mhd_BYTE_ORDER == mhd_BIG_ENDIAN
#  define mhd_PUT_32BIT_LE(addr, value32)            \
        ((*(uint32_t*) (addr)) = mhd_BYTES_SWAP32 (value32))
#else  /* mhd_BYTE_ORDER != mhd_BIG_ENDIAN */
/* Endianness was not detected or non-standard like PDP-endian */
#  define mhd_PUT_32BIT_LE(addr, value32) \
        mhd_PUT_32BIT_LE_SLOW ((addr),(value32))
/* Indicate that mhd_PUT_32BIT_LE does not need aligned pointer */
#  define mhd_PUT_32BIT_LE_UNALIGNED 1
#endif /* mhd_BYTE_ORDER != mhd_BIG_ENDIAN */

/* Put result safely to unaligned address */
MHD_static_inline_ void
mhd_PUT_32BIT_LE_UNALIGN (void *dst, uint32_t value)
{
#ifndef mhd_PUT_32BIT_LE_UNALIGNED
  if (0 != ((uintptr_t) dst) % (mhd_UINT32_ALIGN))
    mhd_PUT_32BIT_LE_SLOW (dst, value);
  else
#endif /* ! mhd_PUT_64BIT_LE_UNALIGNED */
  mhd_PUT_32BIT_LE (dst, value);
}


/* mhd_GET_32BIT_LE (addr)
 * get little-endian 32-bit value storied at addr
 * and return it in native-endian mode.
 */
/* Slow version that works with unaligned addr and with any bytes order */
#define mhd_GET_32BIT_LE_SLOW(addr)                             \
        ( ( (uint32_t) (((const uint8_t*) addr)[0]))            \
          | (((uint32_t) (((const uint8_t*) addr)[1])) << 8)    \
          | (((uint32_t) (((const uint8_t*) addr)[2])) << 16)   \
          | (((uint32_t) (((const uint8_t*) addr)[3])) << 24) )
#if mhd_BYTE_ORDER == mhd_LITTLE_ENDIAN
#  define mhd_GET_32BIT_LE(addr)             \
        (*(const uint32_t*) (addr))
#elif mhd_BYTE_ORDER == mhd_BIG_ENDIAN
#  define mhd_GET_32BIT_LE(addr)             \
        mhd_BYTES_SWAP32 (*(const uint32_t*) (addr))
#else  /* mhd_BYTE_ORDER != mhd_BIG_ENDIAN */
/* Endianness was not detected or non-standard like PDP-endian */
#  define mhd_GET_32BIT_LE(addr)                          \
        ( ( (uint32_t) (((const uint8_t*) addr)[0]))            \
          | (((uint32_t) (((const uint8_t*) addr)[1])) << 8)    \
          | (((uint32_t) (((const uint8_t*) addr)[2])) << 16)   \
          | (((uint32_t) (((const uint8_t*) addr)[3])) << 24) )
/* Indicate that mhd_GET_32BIT_LE does not need aligned pointer */
#  define mhd_GET_32BIT_LE_UNALIGNED 1
#endif /* mhd_BYTE_ORDER != mhd_BIG_ENDIAN */

/* Get value safely from an unaligned address */
MHD_static_inline_ MHD_FN_PAR_NONNULL_ALL_ uint32_t
mhd_GET_32BIT_LE_UNALIGN (const void *addr)
{
#ifndef mhd_GET_32BIT_LE_UNALIGNED
  if (0 != ((uintptr_t) addr) % (mhd_UINT32_ALIGN))
    return mhd_GET_32BIT_LE_SLOW (addr);
  else
#endif /* ! mhd_PUT_64BIT_LE_UNALIGNED */
  return mhd_GET_32BIT_LE (addr);
}


/* mhd_PUT_64BIT_BE (addr, value64)
 * put native-endian 64-bit value64 to addr
 * in big-endian mode.
 */
/* Slow version that works with unaligned addr and with any bytes order */
#define mhd_PUT_64BIT_BE_SLOW(addr, value64) do {                       \
          ((uint8_t*) (addr))[7] = (uint8_t) ((uint64_t) (value64));           \
          ((uint8_t*) (addr))[6] = (uint8_t) (((uint64_t) (value64)) >> 8);    \
          ((uint8_t*) (addr))[5] = (uint8_t) (((uint64_t) (value64)) >> 16);   \
          ((uint8_t*) (addr))[4] = (uint8_t) (((uint64_t) (value64)) >> 24);   \
          ((uint8_t*) (addr))[3] = (uint8_t) (((uint64_t) (value64)) >> 32);   \
          ((uint8_t*) (addr))[2] = (uint8_t) (((uint64_t) (value64)) >> 40);   \
          ((uint8_t*) (addr))[1] = (uint8_t) (((uint64_t) (value64)) >> 48);   \
          ((uint8_t*) (addr))[0] = (uint8_t) (((uint64_t) (value64)) >> 56);   \
} while (0)
#if mhd_BYTE_ORDER == mhd_BIG_ENDIAN
#  define mhd_PUT_64BIT_BE(addr, value64)             \
        ((*(uint64_t*) (addr)) = (uint64_t) (value64))
#elif mhd_BYTE_ORDER == mhd_LITTLE_ENDIAN
#  define mhd_PUT_64BIT_BE(addr, value64)             \
        ((*(uint64_t*) (addr)) = mhd_BYTES_SWAP64 (value64))
#else  /* mhd_BYTE_ORDER != mhd_LITTLE_ENDIAN */
/* Endianness was not detected or non-standard like PDP-endian */
#  define mhd_PUT_64BIT_BE(addr, value64) mhd_PUT_64BIT_BE_SLOW (addr, value64)
/* Indicate that mhd_PUT_64BIT_BE does not need aligned pointer */
#  define mhd_PUT_64BIT_BE_UNALIGNED 1
#endif /* mhd_BYTE_ORDER != mhd_LITTLE_ENDIAN */

/* Put result safely to unaligned address */
MHD_static_inline_ void
mhd_PUT_64BIT_BE_UNALIGN (void *dst, uint64_t value)
{
#ifndef mhd_PUT_64BIT_BE_UNALIGNED
  if (0 != ((uintptr_t) dst) % (mhd_UINT64_ALIGN))
    mhd_PUT_64BIT_BE_SLOW (dst, value);
  else
#endif /* ! mhd_PUT_64BIT_BE_UNALIGNED */
  mhd_PUT_64BIT_BE (dst, value);
}


/* mhd_GET_64BIT_BE (addr)
 * load 64-bit value located at addr in big endian mode.
 */
#if mhd_BYTE_ORDER == mhd_BIG_ENDIAN
#  define mhd_GET_64BIT_BE(addr)             \
        (*(const uint64_t*) (addr))
#elif mhd_BYTE_ORDER == mhd_LITTLE_ENDIAN
#  define mhd_GET_64BIT_BE(addr)             \
        mhd_BYTES_SWAP64 (*(const uint64_t*) (addr))
#else  /* mhd_BYTE_ORDER != mhd_LITTLE_ENDIAN */
/* Endianness was not detected or non-standard like PDP-endian */
#  define mhd_GET_64BIT_BE(addr)                          \
        (   (((uint64_t) (((const uint8_t*) addr)[0])) << 56)   \
            | (((uint64_t) (((const uint8_t*) addr)[1])) << 48)   \
            | (((uint64_t) (((const uint8_t*) addr)[2])) << 40)   \
            | (((uint64_t) (((const uint8_t*) addr)[3])) << 32)   \
            | (((uint64_t) (((const uint8_t*) addr)[4])) << 24)   \
            | (((uint64_t) (((const uint8_t*) addr)[5])) << 16)   \
            | (((uint64_t) (((const uint8_t*) addr)[6])) << 8)    \
            | ((uint64_t)  (((const uint8_t*) addr)[7])) )
/* Indicate that mhd_GET_64BIT_BE does not need aligned pointer */
#  define mhd_GET_64BIT_BE_ALLOW_UNALIGNED 1
#endif /* mhd_BYTE_ORDER != mhd_LITTLE_ENDIAN */


/* mhd_PUT_32BIT_BE (addr, value32)
 * put native-endian 32-bit value32 to addr
 * in big-endian mode.
 */
#if mhd_BYTE_ORDER == mhd_BIG_ENDIAN
#  define mhd_PUT_32BIT_BE(addr, value32)             \
        ((*(uint32_t*) (addr)) = (uint32_t) (value32))
#elif mhd_BYTE_ORDER == mhd_LITTLE_ENDIAN
#  define mhd_PUT_32BIT_BE(addr, value32)             \
        ((*(uint32_t*) (addr)) = mhd_BYTES_SWAP32 (value32))
#else  /* mhd_BYTE_ORDER != mhd_LITTLE_ENDIAN */
/* Endianness was not detected or non-standard like PDP-endian */
#  define mhd_PUT_32BIT_BE(addr, value32) do {                           \
          ((uint8_t*) (addr))[3] = (uint8_t) ((uint32_t) (value32));           \
          ((uint8_t*) (addr))[2] = (uint8_t) (((uint32_t) (value32)) >> 8);    \
          ((uint8_t*) (addr))[1] = (uint8_t) (((uint32_t) (value32)) >> 16);   \
          ((uint8_t*) (addr))[0] = (uint8_t) (((uint32_t) (value32)) >> 24);   \
} while (0)
/* Indicate that mhd_PUT_32BIT_BE does not need aligned pointer */
#  define mhd_PUT_32BIT_BE_UNALIGNED 1
#endif /* mhd_BYTE_ORDER != mhd_LITTLE_ENDIAN */

/* mhd_GET_32BIT_BE (addr)
 * get big-endian 32-bit value storied at addr
 * and return it in native-endian mode.
 */
#if mhd_BYTE_ORDER == mhd_BIG_ENDIAN
#  define mhd_GET_32BIT_BE(addr)             \
        (*(const uint32_t*) (addr))
#elif mhd_BYTE_ORDER == mhd_LITTLE_ENDIAN
#  define mhd_GET_32BIT_BE(addr)             \
        mhd_BYTES_SWAP32 (*(const uint32_t*) (addr))
#else  /* mhd_BYTE_ORDER != mhd_LITTLE_ENDIAN */
/* Endianness was not detected or non-standard like PDP-endian */
#  define mhd_GET_32BIT_BE(addr)                          \
        ( (((uint32_t) (((const uint8_t*) addr)[0])) << 24)     \
          | (((uint32_t) (((const uint8_t*) addr)[1])) << 16)   \
          | (((uint32_t) (((const uint8_t*) addr)[2])) << 8)    \
          | ((uint32_t) (((const uint8_t*) addr)[3])) )
/* Indicate that mhd_GET_32BIT_BE does not need aligned pointer */
#  define mhd_GET_32BIT_BE_UNALIGNED 1
#endif /* mhd_BYTE_ORDER != mhd_LITTLE_ENDIAN */


/**
 * Rotate right 32-bit value by number of bits.
 * bits parameter must be more than zero and must be less than 32.
 */
#if defined(_MSC_FULL_VER) && (! defined(__clang__) || (defined(__c2__) && \
  defined(__OPTIMIZE__)))
/* Clang/C2 do not inline this function if optimizations are turned off. */
#  ifndef __clang__
#    pragma intrinsic(_rotr)
#  endif /* ! __clang__ */
#  define mhd_ROTR32(value32, bits) \
        ((uint32_t) _rotr ((uint32_t) (value32),(bits)))
#elif mhd_HAS_BUILTIN (__builtin_rotateright32)
#  define mhd_ROTR32(value32, bits) \
        ((uint32_t) __builtin_rotateright32 ((value32), (bits)))
#else  /* ! __builtin_rotateright32 */
MHD_static_inline_ uint32_t
mhd_ROTR32 (uint32_t value32, int bits)
{
  bits %= 32;
  if (0 == bits)
    return value32;
  /* Defined in form which modern compiler could optimize. */
  return (value32 >> bits) | (value32 << (32 - bits));
}


#endif /* ! __builtin_rotateright32 */


/**
 * Rotate left 32-bit value by number of bits.
 * bits parameter must be more than zero and must be less than 32.
 */
#if defined(_MSC_FULL_VER) && (! defined(__clang__) || (defined(__c2__) && \
  defined(__OPTIMIZE__)))
/* Clang/C2 do not inline this function if optimizations are turned off. */
#  ifndef __clang__
#    pragma intrinsic(_rotl)
#  endif /* ! __clang__ */
#  define mhd_ROTL32(value32, bits) \
        ((uint32_t) _rotl ((uint32_t) (value32),(bits)))
#elif mhd_HAS_BUILTIN (__builtin_rotateleft32)
#  define mhd_ROTL32(value32, bits) \
        ((uint32_t) __builtin_rotateleft32 ((value32), (bits)))
#else  /* ! __builtin_rotateleft32 */
MHD_static_inline_ uint32_t
mhd_ROTL32 (uint32_t value32, int bits)
{
  bits %= 32;
  if (0 == bits)
    return value32;
  /* Defined in form which modern compiler could optimize. */
  return (value32 << bits) | (value32 >> (32 - bits));
}


#endif /* ! __builtin_rotateleft32 */


/**
 * Rotate right 64-bit value by number of bits.
 * bits parameter must be more than zero and must be less than 64.
 */
#if defined(_MSC_FULL_VER) && (! defined(__clang__) || (defined(__c2__) && \
  defined(__OPTIMIZE__)))
/* Clang/C2 do not inline this function if optimisations are turned off. */
#  ifndef __clang__
#    pragma intrinsic(_rotr64)
#  endif /* ! __clang__ */
#  define mhd_ROTR64(value64, bits) \
        ((uint64_t) _rotr64 ((uint64_t) (value64),(bits)))
#elif mhd_HAS_BUILTIN (__builtin_rotateright64)
#  define mhd_ROTR64(value64, bits) \
        ((uint64_t) __builtin_rotateright64 ((value64), (bits)))
#else  /* ! __builtin_rotateright64 */
MHD_static_inline_ uint64_t
mhd_ROTR64 (uint64_t value64, int bits)
{
  bits %= 64;
  if (0 == bits)
    return value64;
  /* Defined in form which modern compiler could optimise. */
  return (value64 >> bits) | (value64 << (64 - bits));
}


#endif /* ! __builtin_rotateright64 */

mhd_DATA_TRUNCATION_RUNTIME_CHECK_RESTORE

#endif /* ! MHD_BITHELPERS_H */
