/*
     This file is part of GNU libmicrohttpd
     Copyright (C) 2022 Evgeny Grin (Karlson2k)

     GNU libmicrohttpd is free software; you can redistribute it and/or
     modify it under the terms of the GNU Lesser General Public
     License as published by the Free Software Foundation; either
     version 2.1 of the License, or (at your option) any later version.

     This library is distributed in the hope that it will be useful,
     but WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Lesser General Public License for more details.

     You should have received a copy of the GNU Lesser General Public
     License along with GNU libmicrohttpd.
     If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @file microhttpd/sha256_ext.h
 * @brief  Wrapper declarations for SHA-256 calculation performed by TLS library
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_SHA256_EXT_H
#define MHD_SHA256_EXT_H 1

#include "mhd_options.h"
#include <stdint.h>
#ifdef HAVE_STDDEF_H
#include <stddef.h>  /* for size_t */
#endif /* HAVE_STDDEF_H */

/**
 * Size of SHA-256 resulting digest in bytes
 * This is the final digest size, not intermediate hash.
 */
#define mhd_SHA256_DIGEST_SIZE (32)

/* Actual declaration is in GnuTLS lib header */
struct hash_hd_st;

/**
 * Indicates that struct mhd_Sha256CtxExt has 'ext_error'
 */
#define mhd_SHA256_HAS_EXT_ERROR 1

/**
 * SHA-256 calculation context
 */
struct mhd_Sha256CtxExt
{
  struct hash_hd_st *handle; /**< Hash calculation handle */
  int ext_error; /**< Non-zero if external error occurs during init or hashing */
};

/**
 * Indicates that mhd_SHA256_init_one_time() function is present.
 */
#define mhd_SHA256_HAS_INIT_ONE_TIME 1

/**
 * Initialise structure for SHA-256 calculation, allocate resources.
 *
 * This function must not be called more than one time for @a ctx.
 *
 * @param ctx the calculation context
 */
void
mhd_SHA256_init_one_time (struct mhd_Sha256CtxExt *ctx);


/**
 * SHA-256 process portion of bytes.
 *
 * @param ctx the calculation context
 * @param size number of bytes in @a data
 * @param data bytes to add to hash
 */
void
mhd_SHA256_update (struct mhd_Sha256CtxExt *ctx,
                   size_t size,
                   const uint8_t *data);


/**
 * Indicates that mhd_SHA256_finish_reset() function is available
 */
#define mhd_SHA256_HAS_FINISH_RESET 1

/**
 * Finalise SHA-256 calculation, return digest, reset hash calculation.
 *
 * @param ctx the calculation context
 * @param[out] digest set to the hash, must be #mhd_SHA256_DIGEST_SIZE bytes
 */
void
mhd_SHA256_finish_reset (struct mhd_Sha256CtxExt *ctx,
                         uint8_t digest[mhd_SHA256_DIGEST_SIZE]);

/**
 * Indicates that mhd_SHA256_deinit() function is present
 */
#define mhd_SHA256_HAS_DEINIT 1

/**
 * Free allocated resources.
 *
 * @param ctx the calculation context
 */
void
mhd_SHA256_deinit (struct mhd_Sha256CtxExt *ctx);

#endif /* MHD_SHA256_EXT_H */
