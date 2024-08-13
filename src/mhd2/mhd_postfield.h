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
 * @file src/mhd2/mhd_postfield.h
 * @brief  The definition of the struct MHD_PostField
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_POSTFIELD_H
#define MHD_POSTFIELD_H 1

#include "mhd_sys_options.h"

#ifndef MHD_POSTFILED_DEFINED

struct MHD_PostField
{
  /**
   * The name of the field
   */
  struct MHD_String name;
  /**
   * The field data
   * If not set or defined then to C string is NULL.
   * If set to empty string then pointer to C string not NULL,
   * but the length is zero.
   */
  struct MHD_StringNullable value;
  /**
   * The filename if provided (only for "multipart/form-data")
   * If not set or defined then to C string is NULL.
   * If set to empty string then pointer to C string not NULL,
   * but the length is zero.
   */
  struct MHD_StringNullable filename;
  /**
   * The Content-Type if provided (only for "multipart/form-data")
   * If not set or defined then to C string is NULL.
   * If set to empty string then pointer to C string not NULL,
   * but the length is zero.
   */
  struct MHD_StringNullable content_type;
  /**
   * The Transfer-Encoding if provided (only for "multipart/form-data")
   * If not set or defined then to C string is NULL.
   * If set to empty string then pointer to C string not NULL,
   * but the length is zero.
   */
  struct MHD_StringNullable transfer_encoding;
};

#define MHD_POSTFILED_DEFINED 1
#endif /* ! MHD_POSTFILED_DEFINED */

#endif /* ! MHD_POSTFIELD_H */
