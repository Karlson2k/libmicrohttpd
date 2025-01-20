/*
  This file is part of GNU libmicrohttpd
  Copyright (C) 2025 Evgeny Grin (Karlson2k)

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
 * @file src/mhd2/mhd_stream.h
 * @brief  The definition of the MHD_Stream type and helper macros
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_STREAM_H
#define MHD_STREAM_H 1

#include "mhd_sys_options.h"

/**
 * The HTTP stream data.
 * For HTTP/1.x this information held in MHD_Connection structure
 */
struct MHD_Stream
{
  /**
   * The dummy member.
   * Do not use
   */
  int place_holder;
};

#endif /* ! MHD_STREAM_H */
