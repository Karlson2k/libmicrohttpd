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
 * @file src/mhd2/mhd_str_types.h
 * @brief  The definition of the tristate type and helper macros
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_STR_TYPES_H
#define MHD_STR_TYPES_H 1

#include "mhd_sys_options.h"

#ifndef MHD_STRINGS_DEFINED
#include "sys_base_types.h"


/**
 * String with length data.
 * This type should always have valid @a cstr pointer.
 */
struct MHD_String
{
  /**
   * Number of characters in @e str, not counting 0-termination.
   */
  size_t len;

  /**
   * 0-terminated C-string.
   * Must not be NULL.
   */
  const char *cstr;
};

/**
 * String with length data.
 * This type of data may have NULL as the @a cstr pointer.
 */
struct MHD_StringNullable
{
  /**
   * Number of characters in @e str, not counting 0-termination.
   * If @a cstr is NULL, it must be zero.
   */
  size_t len;

  /**
   * 0-terminated C-string.
   * In some cases it could be NULL.
   */
  const char *cstr;
};

#define MHD_STRINGS_DEFINED 1
#endif /* ! MHD_STRINGS_DEFINED */

#endif /* ! MHD_STR_TYPES_H */
