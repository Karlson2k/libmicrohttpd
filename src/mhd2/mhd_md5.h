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
 * @file src/mhd2/mhd_md5.h
 * @brief  Simple wrapper for selection of built-in/external MD5 implementation
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_MD5_H
#define MHD_MD5_H 1

#include "mhd_sys_options.h"

#ifndef MHD_SUPPORT_MD5
#error This file must be used only when MD5 is enabled
#endif

#ifndef MHD_MD5_EXTR
#include "md5_int.h"
#else  /* MHD_MD5_EXTR */
#include "md5_ext.h"
#endif /* MHD_MD5_EXTR */

#ifndef mhd_MD5_DIGEST_SIZE
/**
 * Size of MD5 resulting digest in bytes
 * This is the final digest size, not intermediate hash.
 */
#  define mhd_MD5_DIGEST_SIZE (16)
#endif /* ! mhd_MD5_DIGEST_SIZE */

#ifndef MHD_MD5_EXTR
/**
 * Universal ctx type mapped for chosen implementation
 */
#  define mhd_Md5Ctx mhd_Md5CtxInt
#else  /* MHD_MD5_EXTR */
/**
 * Universal ctx type mapped for chosen implementation
 */
#  define mhd_Md5Ctx mhd_Md5CtxExt
#endif /* MHD_MD5_EXTR */

#ifndef mhd_MD5_HAS_INIT_ONE_TIME
/**
 * Setup and prepare ctx for hash calculation
 */
#  define mhd_MD5_init_one_time(ctx) mhd_MD5_init (ctx)
#endif /* ! mhd_MD5_HAS_INIT_ONE_TIME */

#ifndef mhd_MD5_HAS_FINISH_RESET
/**
 * Re-use the same ctx for the new hashing after digest calculated
 */
#  define mhd_MD5_reset(ctx) mhd_MD5_init (ctx)
/**
 * Finalise MD5 calculation, return digest, reset hash calculation.
 */
#  define mhd_MD5_finish_reset(ctx,digest) \
        (mhd_MD5_finish (ctx,digest), mhd_MD5_reset (ctx))
/**
 * Finalise hash calculation, return digest, de-initialise hash calculation.
 */
#  define mhd_MD5_finish_deinit(ctx,digest) \
        (mhd_MD5_finish (ctx,digest), mhd_MD5_deinit (ctx))
#else  /* mhd_MD5_HAS_FINISH_RESET */
#  define mhd_MD5_reset(ctx) ((void) 0)
/**
 * Finalise hash calculation, return digest, de-initialise hash calculation.
 */
#  define mhd_MD5_finish_deinit(ctx,digest) \
        (mhd_MD5_finish_reset (ctx,digest), mhd_MD5_deinit (ctx))
#endif /* mhd_MD5_HAS_FINISH_RESET */

#ifndef mhd_MD5_HAS_DEINIT
#  define mhd_MD5_deinit(ctx) ((void) 0)
#endif /* HAVE_MD5_DEINIT */


#ifdef mhd_MD5_HAS_EXT_ERROR
#define mhd_MD5_has_err(ctx) (0 != ((ctx)->ext_error))
#else  /* ! mhd_MD5_HAS_EXT_ERROR */
#define mhd_MD5_has_err(ctx) (((void) (ctx)), ! ! 0)
#endif /* ! mhd_SHA512_256_HAS_EXT_ERROR */

/* Sanity checks */

#if ! defined(mhd_MD5_HAS_FINISH_RESET) && ! defined(mhd_MD5_HAS_FINISH)
#error Required at least one of mhd_MD5_finish_reset(), mhd_MD5_finish()
#endif /* ! mhd_MD5_HAS_FINISH_RESET && ! mhd_MD5_HAS_FINISH */

#endif /* MHD_MD5_H */
