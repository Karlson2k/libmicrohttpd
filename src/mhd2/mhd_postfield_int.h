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
 * @file src/mhd2/mhd_postfield_int.h
 * @brief  The definition of the internal struct mhd_PostFieldInt
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_POSTFIELD_INT_H
#define MHD_POSTFIELD_INT_H 1

#include "mhd_sys_options.h"

#include "sys_base_types.h"

/**
 * Position and length of a string in some buffer
 */
struct mhd_PositionAndLength
{
  /**
   * The position
   */
  size_t pos;
  /**
   * The length
   */
  size_t len;
};

struct mhd_PostFieldInt
{
  /**
   * The name of the field.
   * May start at zero position.
   */
  struct mhd_PositionAndLength name;
  /**
   * The field data
   * If not set or defined then position is zero.
   */
  struct mhd_PositionAndLength value;
  /**
   * The filename if provided (only for "multipart/form-data")
   * If not set or defined then position is zero.
   */
  struct mhd_PositionAndLength filename;
  /**
   * The Content-Type if provided (only for "multipart/form-data")
   * If not set or defined then position is zero.
   */
  struct mhd_PositionAndLength content_type;
  /**
   * The Transfer-Encoding if provided (only for "multipart/form-data")
   * If not set or defined then position is zero.
   */
  struct mhd_PositionAndLength transfer_encoding;
#if 0  // TODO: support processing in connection buffer
  /**
   * If 'true' then all strings are in the "large shared buffer".
   * If 'false' then all strings are in the stream buffer.
   */
  bool buf_is_lbuf;
#endif
};

#endif /* ! MHD_POSTFIELD_INT_H */
