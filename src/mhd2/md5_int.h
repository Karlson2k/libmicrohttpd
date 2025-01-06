/*
  This file is part of GNU libmicrohttpd
  Copyright (C) 2022-2024 Evgeny Grin (Karlson2k)

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
 * @file src/mhd2/md5_int.h
 * @brief  Calculation of MD5 digest
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_MD5_INT_H
#define MHD_MD5_INT_H 1

#include "mhd_sys_options.h"

#include "sys_base_types.h"

/**
 * Number of bits in single MD5 word.
 */
#define mhd_MD5_WORD_SIZE_BITS (32)

/**
 * Number of bytes in single MD5 word.
 */
#define mhd_MD5_BYTES_IN_WORD (mhd_MD5_WORD_SIZE_BITS / 8)

/**
 * Hash is kept internally as four 32-bit words.
 * This is intermediate hash size, used during computing the final digest.
 */
#define mhd_MD5_HASH_SIZE_WORDS (4)

/**
 * Size of MD5 resulting digest in bytes.
 * This is the final digest size, not intermediate hash.
 */
#define mhd_MD5_DIGEST_SIZE_WORDS mhd_MD5_HASH_SIZE_WORDS

/**
 * Size of MD5 resulting digest in bytes
 * This is the final digest size, not intermediate hash.
 */
#define mhd_MD5_DIGEST_SIZE (mhd_MD5_DIGEST_SIZE_WORDS * mhd_MD5_BYTES_IN_WORD)

/**
 * Size of MD5 single processing block in bits.
 */
#define mhd_MD5_BLOCK_SIZE_BITS 512

/**
 * Size of MD5 single processing block in bytes.
 */
#define mhd_MD5_BLOCK_SIZE (mhd_MD5_BLOCK_SIZE_BITS / 8)

/**
 * Size of MD5 single processing block in words.
 */
#define mhd_MD5_BLOCK_SIZE_WORDS \
        (mhd_MD5_BLOCK_SIZE_BITS / mhd_MD5_WORD_SIZE_BITS)


/**
 * MD5 calculation context
 */
struct mhd_Md5CtxInt
{
  uint32_t H[mhd_MD5_HASH_SIZE_WORDS];     /**< Intermediate hash value / digest at end of calculation */
  uint32_t buffer[mhd_MD5_BLOCK_SIZE_WORDS];   /**< MD5 input data buffer */
  uint64_t count;                          /**< number of bytes, mod 2^64 */
};

/**
 * Initialise structure for MD5 calculation.
 *
 * @param ctx the calculation context
 */
MHD_INTERNAL void
mhd_MD5_init (struct mhd_Md5CtxInt *ctx)
MHD_FN_PAR_NONNULL_ALL_;


/**
 * MD5 process portion of bytes.
 *
 * @param ctx the calculation context
 * @param size number of bytes in @a data
 * @param data bytes to add to hash
 */
MHD_INTERNAL void
mhd_MD5_update (struct mhd_Md5CtxInt *restrict ctx,
                size_t size,
                const uint8_t *restrict data)
MHD_FN_PAR_NONNULL_ALL_ MHD_FN_PAR_IN_SIZE_ (3, 2);


/**
 * Finalise MD5 calculation, return digest.
 *
 * @param ctx the calculation context
 * @param[out] digest set to the hash, must be #mhd_MD5_DIGEST_SIZE bytes
 */
MHD_INTERNAL void
mhd_MD5_finish (struct mhd_Md5CtxInt *restrict ctx,
                uint8_t digest[mhd_MD5_DIGEST_SIZE])
MHD_FN_PAR_NONNULL_ALL_ MHD_FN_PAR_OUT_ (2);

/**
 * Indicates that function mhd_MD5_finish() (without context reset) is available
 */
#define mhd_MD5_HAS_FINISH 1

#endif /* MHD_MD5_INT_H */
