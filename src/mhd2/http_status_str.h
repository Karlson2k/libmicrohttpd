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
 * @file src/mhd2/http_status_str.h
 * @brief  The declaration for internal HTTP status string functions
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_HTTP_STATUS_STR_H
#define MHD_HTTP_STATUS_STR_H 1

#include "mhd_sys_options.h"

#include "sys_base_types.h"
#include "mhd_str_types.h"

/**
 * Get string for provided HTTP status code.
 * Substitute a replacement string for unknown codes.
 *
 * @param code the HTTP status code
 * @return pointer to MHD_String, never NULL.
 */
MHD_INTERNAL const struct MHD_String *
mhd_HTTP_status_code_to_string_int (uint_fast16_t code)
MHD_FN_CONST_;


#endif /* ! MHD_HTTP_STATUS_STR_H */
