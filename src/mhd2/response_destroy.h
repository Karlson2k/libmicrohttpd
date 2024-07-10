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
 * @file src/mhd2/response_destroy.h
 * @brief  The declarations of internal functions for response deletion
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_RESPONSE_DESTROY_H
#define MHD_RESPONSE_DESTROY_H 1

#include "mhd_sys_options.h"

struct MHD_Response; /* forward declaration */

/**
 * Free/destroy non-reusable response, decrement use count for reusable
 * response and free/destroy if it is not used any more.
 * @param response the response to manipulate
 */
MHD_INTERNAL void
mhd_response_dec_use_count (struct MHD_Response *restrict response);


#endif /* ! MHD_RESPONSE_DESTROY_H */
