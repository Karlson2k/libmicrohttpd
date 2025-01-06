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
 * @file src/mhd2/request_auth_get.h
 * @brief  The declaration of the request Authorization header parsing helper
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_REQUEST_AUTH_GET_H
#define MHD_REQUEST_AUTH_GET_H 1

#include "mhd_sys_options.h"

#if ! defined(MHD_SUPPORT_AUTH_BASIC) && ! defined(MHD_SUPPORT_AUTH_DIGEST)
#error Authorization header parsing must be enabled
#endif

#include "sys_bool_type.h"

struct MHD_String;      /* forward declaration */
struct MHD_Request;     /* forward declaration */

/**
 * The type of Authorization header to look for
 */
enum MHD_FIXED_ENUM_ mhd_AuthHeaderKind
{
#ifdef MHD_SUPPORT_AUTH_BASIC
  mhd_AUTH_HDR_BASIC,
#endif
#ifdef MHD_SUPPORT_AUTH_DIGEST
  mhd_AUTH_HDR_DIGEST,
#endif
#ifdef MHD_ENUMS_NEED_TRAILING_VALUE
  mhd_AUTH_HDR_KIND_SENTINEL
#endif
};


/**
 * Get value of the specific Authorization header
 *
 * This function supports multiple types of the Authorization headers in
 * one request, but does not parse each header for several types of
 * Authorization. This should not be a limitation as RFC 7235 (section 4.2)
 * allows only one type of Authorization in each request.
 *
 * @param request the request to use
 * @param auth_type the type of Authorization to get
 * @param[out] header_value the value of the Authorization header, excluding
 *                          the prefix (type) and initial whitespaces
 * @return 'true' if requested header found,
 *         'false' otherwise (@a header_value not set)
 */
MHD_INTERNAL bool
mhd_request_get_auth_header_value (struct MHD_Request *restrict request,
                                   enum mhd_AuthHeaderKind auth_type,
                                   struct MHD_String *restrict header_value)
MHD_FN_MUST_CHECK_RESULT_ MHD_FN_PAR_NONNULL_ALL_ MHD_FN_PAR_OUT_ (3);

#endif /* ! MHD_REQUEST_AUTH_GET_H */
