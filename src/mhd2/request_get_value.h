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
#include "mhd_public_api.h"

/**
 * Get a particular header (or other kind of request data) value.
 * If multiple values match the kind, return any one of them.
 *
 * The returned pointer is valid until the response is queued.
 * If the data is needed beyond this point, it should be copied.
 *
 * @param request request to get values from
 * @param kind what kind of value are we looking for
 * @param key the header to look for, empty to lookup 'trailing' value
 *            without a key
 * @return NULL if no such item was found
 * @ingroup request
 */
MHD_INTERNAL const struct MHD_String *
mhd_request_get_value_len (struct MHD_Request *restrict request,
                           enum MHD_ValueKind kind,
                           size_t key_len,
                           const char *restrict key)
MHD_FN_PAR_NONNULL_ (1)
MHD_FN_PAR_NONNULL_ (4) MHD_FN_PAR_CSTR_ (4);

#endif /* ! MHD_REQUEST_GET_VALUE_H */
