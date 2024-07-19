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
 * @file src/mhd2/request_get_value.h
 * @brief  The declaration of internal mhd_request_get_value* functions
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_REQUEST_GET_VALUE_H
#define MHD_REQUEST_GET_VALUE_H 1

#include "mhd_sys_options.h"
#include "sys_base_types.h"
#include "sys_bool_type.h"
#include "mhd_str_macros.h"

#include "mhd_public_api.h"

/**
 * Get specified field value from request
 * If multiple values match the kind, return any one of them.
 *
 * The returned pointer is valid until the response is queued.
 * If the data is needed beyond this point, it should be copied.
 *
 * @param request request to get values from
 * @param kind what kind of value are we looking for
 * @param key_len the length of the @a key string
 * @param key the header to look for, empty to lookup 'trailing' value
 *            without a key
 * @return NULL if no such item was found
 * @ingroup request
 */
MHD_INTERNAL const struct MHD_StringNullable *
mhd_request_get_value_n (struct MHD_Request *restrict request,
                         enum MHD_ValueKind kind,
                         size_t key_len,
                         const char *restrict key)
MHD_FN_PAR_NONNULL_ (1)
MHD_FN_PAR_NONNULL_ (4) MHD_FN_PAR_CSTR_ (4);

/**
 * Get specified field value from request
 * If multiple values match the kind, return any one of them.
 *
 * The returned pointer is valid until the response is queued.
 * If the data is needed beyond this point, it should be copied.
 *
 * @param request request to get values from
 * @param kind what kind of value are we looking for
 * @param key the header to look for, empty to lookup 'trailing' value
 *            without a key; must be a static string or array
 * @return NULL if no such item was found
 * @ingroup request
 */
#define mhd_request_get_value_st(r,k,str) \
        mhd_request_get_value_n ((r),(k),mhd_SSTR_LEN (str),(str))

#endif /* ! MHD_REQUEST_GET_VALUE_H */


/**
 * Check whether the request header contains particular token.
 *
 * Token could be surrounded by spaces and tabs and delimited by comma.
 * Case-insensitive match used for header names and tokens.
 * @param c          the connection to check values
 * @param header_len the length of header, not including optional
 *                   terminating null-character
 * @param header     the header name
 * @param token_len  the length of token, not including optional
 *                   terminating null-character.
 * @param token      the token to find
 * @return true if the token is found in the specified header,
 *         false otherwise
 */
MHD_INTERNAL bool
mhd_stream_has_header_token (const struct MHD_Connection *restrict c,
                             size_t header_len,
                             const char *restrict header,
                             size_t token_len,
                             const char *restrict token)
MHD_FN_PAR_NONNULL_ALL_ MHD_FN_PAR_CSTR_ (3) MHD_FN_PAR_CSTR_ (5);

/**
 * Check whether the request header contains particular token.
 *
 * Token could be surrounded by spaces and tabs and delimited by comma.
 * Case-insensitive match used for header names and tokens.
 * @param c          the connection to check values
 * @param hdr        the statically allocated header name string
 * @param token      the statically allocated string of token to find
 * @return true if the token is found in the specified header,
 *         false otherwise
 */
#define mhd_stream_has_header_token_st(c,hdr,tkn) \
        mhd_stream_has_header_token ((c), mhd_SSTR_LEN (hdr), (hdr), \
                                     mhd_SSTR_LEN (tkn), (tkn))
