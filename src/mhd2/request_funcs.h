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
 * @file src/mhd2/request_funcs.h
 * @brief  The declaration of the request internal functions
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_REQUEST_FUNCS_H
#define MHD_REQUEST_FUNCS_H 1

#include "mhd_sys_options.h"
#include "sys_bool_type.h"
#include "mhd_str_types.h"
#include "mhd_public_api.h"

struct MHD_Connection; /* forward declaration */

/**
 * Add field to the request.
 * The memory allocated in the request memory pool
 *
 * @param c the connection to use
 * @param kind the kind of the field to add
 * @param name the name of the field to add, the string is not copied,
 *             only copied the pointer value
 * @param value the value of the field to add, the string is not copied,
 *              only copied the pointer value
 * @return true if succeed,
 *         false if memory cannot be allocated
 */
MHD_INTERNAL bool
mhd_stream_add_field (struct MHD_Connection *restrict c,
                      enum MHD_ValueKind kind,
                      const struct MHD_String *restrict name,
                      const struct MHD_String *restrict value)
MHD_FN_PAR_NONNULL_ALL_;

/**
 * Add field to the request.
 * The memory allocated in the request memory pool
 * The value can have NULL string ("no value").
 *
 * @param c the connection to use
 * @param kind the kind of the field to add
 * @param name the name of the field to add, the string is not copied,
 *             only copied the pointer value
 * @param value the value of the field to add, the string is not copied,
 *              only copied the pointer value
 * @return true if succeed,
 *         false if memory cannot be allocated
 */
MHD_INTERNAL bool
mhd_stream_add_field_nullable (struct MHD_Connection *restrict c,
                               enum MHD_ValueKind kind,
                               const struct MHD_String *restrict name,
                               const struct MHD_StringNullable *restrict value)
MHD_FN_PAR_NONNULL_ALL_;

#endif /* ! MHD_REQUEST_FUNCS_H */
