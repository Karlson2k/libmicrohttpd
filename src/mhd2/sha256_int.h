/*
  This file is part of GNU libmicrohttpd
  Copyright (C) 2019-2024 Evgeny Grin (Karlson2k)

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
 * @file src/mhd2/sha256.h
 * @brief  Calculation of SHA-256 digest
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_SHA256_INT_H
#define MHD_SHA256_INT_H 1

#include "mhd_sys_options.h"

#include "sys_base_types.h"


/**
 *  Digest is kept internally as 8 32-bit words.
 */
#define mhd_SHA256_DIGEST_SIZE_WORDS 8

/**
 * Number of bits in single SHA-256 word
 */
#define mhd_SHA256_WORD_SIZE_BITS 32

/**
 * Number of bytes in single SHA-256 word
 * used to process data
 */
#define mhd_SHA256_BYTES_IN_WORD (mhd_SHA256_WORD_SIZE_BITS / 8)

/**
 * Size of SHA-256 digest in bytes
 */
#define mhd_SHA256_DIGEST_SIZE \
        (mhd_SHA256_DIGEST_SIZE_WORDS * mhd_SHA256_BYTES_IN_WORD)

/**
 * Size of single processing block in bits
 */
#define mhd_SHA256_BLOCK_SIZE_BITS 512

/**
 * Size of single processing block in bytes
 */
#define mhd_SHA256_BLOCK_SIZE (mhd_SHA256_BLOCK_SIZE_BITS / 8)

/**
 * Size of single processing block in bytes
 */
#define mhd_SHA256_BLOCK_SIZE_WORDS \
        (mhd_SHA256_BLOCK_SIZE_BITS / mhd_SHA256_WORD_SIZE_BITS)


struct mhd_Sha256CtxInt
{
  uint32_t H[mhd_SHA256_DIGEST_SIZE_WORDS];     /**< Intermediate hash value / digest at end of calculation */
  uint32_t buffer[mhd_SHA256_BLOCK_SIZE_WORDS]; /**< SHA256 input data buffer */
  uint64_t count;                               /**< number of bytes, mod 2^64 */
};

/**
 * Initialise structure for SHA-256 calculation.
 *
 * @param ctx must be a `struct mhd_Sha256CtxInt *`
 */
MHD_INTERNAL void
mhd_SHA256_init (struct mhd_Sha256CtxInt *ctx)
MHD_FN_PAR_NONNULL_ALL_;


/**
 * Process portion of bytes.
 *
 * @param ctx must be a `struct mhd_Sha256CtxInt *`
 * @param size number of bytes in @a data
 * @param data bytes to add to hash
 */
MHD_INTERNAL void
mhd_SHA256_update (struct mhd_Sha256CtxInt *restrict ctx,
                   size_t size,
                   const uint8_t *restrict data)
MHD_FN_PAR_NONNULL_ALL_ MHD_FN_PAR_IN_SIZE_ (3, 2);


/**
 * Finalise SHA256 calculation, return digest.
 *
 * @param ctx must be a `struct mhd_Sha256CtxInt *`
 * @param[out] digest set to the hash, must be #mhd_SHA256_DIGEST_SIZE bytes
 */
MHD_INTERNAL void
mhd_SHA256_finish (struct mhd_Sha256CtxInt *restrict ctx,
                   uint8_t digest[mhd_SHA256_DIGEST_SIZE])
MHD_FN_PAR_NONNULL_ALL_ MHD_FN_PAR_OUT_ (2);

/**
 * Indicates that function mhd_SHA256_finish() (without context reset) is available
 */
#define mhd_SHA256_HAS_FINISH 1

#endif /* MHD_SHA256_INT_H */
