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
 * @file src/mhd2/auth_basic.h
 * @brief  The declaration of the Basic Authorization header parser
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_AUTH_BASIC_H
#define MHD_AUTH_BASIC_H 1

#include "mhd_sys_options.h"

#if ! defined(MHD_SUPPORT_AUTH_BASIC)
#error Basic Authorization must be enabled
#endif

#include "mhd_public_api.h"

/**
 * Find in request and parse Basic Authentication information
 * @param req the request to use
 * @param[out] v_auth_basic_creds the pointer to set to the found data
 * @return #MHD_SC_OK on success,
 *         error code otherwise
 */
MHD_INTERNAL enum MHD_StatusCode
mhd_request_get_auth_basic_creds (
  struct MHD_Request *restrict req,
  const struct MHD_BasicAuthInfo **restrict v_auth_basic_creds)
MHD_FN_MUST_CHECK_RESULT_ MHD_FN_PAR_NONNULL_ALL_ MHD_FN_PAR_OUT_ (2);

#endif /* ! MHD_AUTH_BASIC_H */
