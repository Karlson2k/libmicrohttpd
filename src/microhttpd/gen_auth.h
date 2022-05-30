/*
  This file is part of libmicrohttpd
  Copyright (C) 2022 Evgeny Grin (Karlson2k)

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library.
  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @file microhttpd/gen_auth.h
 * @brief  Declarations for HTTP authorisation general functions
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_GET_AUTH_H
#define MHD_GET_AUTH_H 1

#include "mhd_options.h"
#ifdef HAVE_STDBOOL_H
#include <stdbool.h>
#endif /* HAVE_STDBOOL_H */

struct MHD_Connection; /* Forward declaration to avoid include of the large headers */

/**
 * Type of authorisation
 */
enum MHD_AuthType
{
  MHD_AUTHTYPE_NONE = 0,/**< No authorisation */
  MHD_AUTHTYPE_BASIC,   /**< Basic Authorisation, RFC 7617  */
  MHD_AUTHTYPE_DIGEST,  /**< Digest Authorisation, RFC 7616 */
  MHD_AUTHTYPE_INVALID  /**< Wrong/Unknown/Unsupported authorisation type */
};

#ifdef BAUTH_SUPPORT
/* Forward declaration to avoid additional headers inclusion */
struct MHD_RqBAuth;
#endif /* BAUTH_SUPPORT */
#ifdef DAUTH_SUPPORT
/* Forward declaration to avoid additional headers inclusion */
struct MHD_RqDAuth;
#endif /* DAUTH_SUPPORT */

/**
 * Universal Authorisation Request parameters
 */
union MHD_AuthRqParams
{
#ifdef BAUTH_SUPPORT
  struct MHD_RqBAuth *bauth;
#endif /* BAUTH_SUPPORT */
#ifdef DAUTH_SUPPORT
  struct MHD_RqDAuth *dauth;
#endif /* DAUTH_SUPPORT */
};

/**
 * Request Authentication type and parameters
 */
struct MHD_AuthRqHeader
{
  enum MHD_AuthType auth_type;
  union MHD_AuthRqParams params;
};


/**
 * Return request's Authentication type and parameters.
 *
 * Function return result of parsing of the request's "Authorization" header or
 * returns cached parsing result if the header was already parsed for
 * the current request.
 * @param connection the connection to process
 * @return the pointer to structure with Authentication type and parameters,
 *         NULL if no memory in memory pool or if called too early (before
 *         header has been received).
 */
const struct MHD_AuthRqHeader *
MHD_get_auth_rq_params_ (struct MHD_Connection *connection);

#endif /* ! MHD_GET_AUTH_H */
