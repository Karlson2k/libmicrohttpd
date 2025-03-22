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
 * @file src/mhd2/auth_digest.h
 * @brief  The declaration of the Digest Authorization internal functions
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_AUTH_DIGEST_H
#define MHD_AUTH_DIGEST_H 1

#include "mhd_sys_options.h"

#if ! defined(MHD_SUPPORT_AUTH_DIGEST)
#error Digest Authorization must be enabled
#endif

#include "sys_bool_type.h"
#include "sys_base_types.h"

#include "mhd_digest_auth_data.h"

#include "mhd_public_api.h"

struct MHD_Connection; /* forward declaration */
struct MHD_Request;    /* forward declaration */

/**
 * Generate new nonce for Digest Auth, put the nonce in text form to the buffer
 * @param c the connection to use // TODO: replace with daemon object
 * @param out_buf the output buffer to put the generated nonce,
 *                NOT zero terminated
 * @return 'true' if succeed,
 *         'false' otherwise
 */
MHD_INTERNAL bool
mhd_auth_digest_get_new_nonce (struct MHD_Connection *restrict c,
                               char out_buf[mhd_AUTH_DIGEST_NONCE_LEN])
MHD_FN_PAR_NONNULL_ALL_ MHD_FN_PAR_OUT_ (2);

/**
 * Find in request and parse Digest Authentication information
 * @param req the request to use
 * @param[out] v_auth_basic_creds the pointer to set to the found data
 * @return #MHD_SC_OK on success,
 *         error code otherwise
 */
MHD_INTERNAL enum MHD_StatusCode
mhd_request_get_auth_digest_info (
  struct MHD_Request *restrict req,
  const struct MHD_AuthDigestInfo **restrict v_auth_digest_info)
MHD_FN_MUST_CHECK_RESULT_ MHD_FN_PAR_NONNULL_ALL_ MHD_FN_PAR_OUT_ (2);

#endif /* ! MHD_AUTH_DIGEST_H */
