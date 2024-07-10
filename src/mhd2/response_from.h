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
 * @file src/mhd2/response_from.h
 * @brief  The declarations of internal functions for response creation and
 *         deletion
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_RESPONSE_FROM_H
#define MHD_RESPONSE_FROM_H 1

#include "mhd_sys_options.h"

struct MHD_Response; /* forward declaration */

/**
 * Deinit / free / cleanup content data of the response
 * @param r the response to use
 */
MHD_INTERNAL void
mhd_response_deinit_content_data (struct MHD_Response *restrict r)
MHD_FN_PAR_NONNULL_ (1);


#endif /* ! MHD_RESPONSE_FROM_H */
