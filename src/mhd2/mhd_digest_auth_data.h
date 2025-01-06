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
 * @file src/mhd2/mhd_digest_auth_data.h
 * @brief  The macros and other data for Digest Auth
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_DIGEST_AUTH_DATA_H
#define MHD_DIGEST_AUTH_DATA_H 1

#include "mhd_sys_options.h"

/**
 * The name of the Auth scheme
 */
#define mhd_AUTH_DIGEST_SCHEME "Digest"

/**
 * The size of the random part of the nonce (in bytes)
 */
#define mhd_AUTH_DIGEST_NONCE_RAND_BIN_SIZE     32
/**
 * The length of the random part of the nonce (in chars)
 */
#define mhd_AUTH_DIGEST_NONCE_RAND_LEN \
        (mhd_AUTH_DIGEST_NONCE_RAND_BIN_SIZE * 2)

/**
 * The size of the validity time part of the nonce (in bytes)
 */
#define mhd_AUTH_DIGEST_NONCE_VALD_BIN_SIZE     4
/**
 * The length of the validity time part of the nonce (in chars)
 */
#define mhd_AUTH_DIGEST_NONCE_VALD_LEN \
        (mhd_AUTH_DIGEST_NONCE_VALD_BIN_SIZE * 2)

/**
 * The total size of the binary form of the nonce (in bytes)
 */
#define mhd_AUTH_DIGEST_NONCE_BIN_SIZE \
        (mhd_AUTH_DIGEST_NONCE_RAND_BIN_SIZE \
         + mhd_AUTH_DIGEST_NONCE_VALD_BIN_SIZE)
/**
 * The total length of the nonce (in chars), without zero termination
 */
#define mhd_AUTH_DIGEST_NONCE_LEN       (mhd_AUTH_DIGEST_NONCE_BIN_SIZE * 2)

#endif /* ! MHD_DIGEST_AUTH_DATA_H */
