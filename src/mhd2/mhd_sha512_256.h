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
 * @file src/mhd2/mhd_sha512_256.h
 * @brief  Simple wrapper for selection of built-in/external SHA-512/256
 *         implementation
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_SHA512_256_H
#define MHD_SHA512_256_H 1

#include "mhd_sys_options.h"

#ifndef MHD_SUPPORT_SHA512_256
#error This file must be used only when SHA-512/256 is enabled
#endif
#ifndef MHD_SHA512_256_EXTR
#  include "sha512_256_int.h"
#else  /* MHD_SHA512_256_EXTR */
#  include "sha512_256_ext.h"
#endif /* MHD_SHA512_256_EXTR */

#ifndef mhd_SHA512_256_DIGEST_SIZE
/**
 * Size of SHA-512/256 resulting digest in bytes
 * This is the final digest size, not intermediate hash.
 */
#  define mhd_SHA512_256_DIGEST_SIZE (32)
#endif /* ! mhd_SHA512_256_DIGEST_SIZE */

#ifndef MHD_SHA512_256_EXTR
/**
 * Universal ctx type mapped for chosen implementation
 */
#  define mhd_Sha512_256Ctx mhd_Sha512_256CtxInt
#else  /* MHD_SHA512_256_EXTR */
/**
 * Universal ctx type mapped for chosen implementation
 */
#  define mhd_Sha512_256Ctx mhd_Sha512_256CtxExt
#endif /* MHD_SHA512_256_EXTR */

#ifndef mhd_SHA512_256_HAS_INIT_ONE_TIME
/**
 * Setup and prepare ctx for hash calculation
 */
#  define mhd_SHA512_256_init_one_time(ctx) mhd_SHA512_256_init (ctx)
#endif /* ! mhd_SHA512_256_HAS_INIT_ONE_TIME */

#ifndef mhd_SHA512_256_HAS_DEINIT
#  define mhd_SHA512_256_deinit(ctx) ((void) 0)
#endif /* HAVE_SHA512_256_DEINIT */

#ifndef mhd_SHA512_256_HAS_FINISH_RESET
/**
 * Re-use the same ctx for the new hashing after digest calculated
 */
#  define mhd_SHA512_256_reset(ctx) mhd_SHA512_256_init (ctx)
/**
 * Finalise hash calculation, return digest, reset hash calculation.
 */
#  define mhd_SHA512_256_finish_reset(ctx,digest) \
        (mhd_SHA512_256_finish (ctx,digest), mhd_SHA512_256_reset (ctx))
/**
 * Finalise hash calculation, return digest, de-initialise hash calculation.
 */
#  define mhd_SHA512_256_finish_deinit(ctx,digest) \
        (mhd_SHA512_256_finish (ctx,digest), mhd_SHA512_256_deinit (ctx))
#else  /* mhd_SHA512_256_HAS_FINISH_RESET */
#  define mhd_SHA512_256_reset(ctx) ((void) 0)
/**
 * Finalise hash calculation, return digest, de-initialise hash calculation.
 */
#  define mhd_SHA512_256_finish_deinit(ctx,digest) \
        (mhd_SHA512_256_finish_reset (ctx,digest), mhd_SHA512_256_deinit (ctx))
#endif /* mhd_SHA512_256_HAS_FINISH_RESET */

/* Sanity checks */

#if ! defined(mhd_SHA512_256_HAS_FINISH_RESET) && \
  ! defined(mhd_SHA512_256_HAS_FINISH)
#error Required mhd_SHA512_256_finish_reset() or mhd_SHA512_256_finish()
#endif /* ! mhd_SHA512_256_HAS_FINISH_RESET && ! mhd_SHA512_256_HAS_FINISH */

#ifdef mhd_SHA512_256_HAS_EXT_ERROR
#define mhd_SHA512_256_has_err(ctx) (0 != ((ctx)->ext_error))
#else  /* ! mhd_SHA512_256_HAS_EXT_ERROR */
#define mhd_SHA512_256_has_err(ctx) (((void) (ctx)), ! ! 0)
#endif /* ! mhd_SHA512_256_HAS_EXT_ERROR */

#endif /* MHD_SHA512_256_H */
