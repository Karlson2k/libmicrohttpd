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
 * @file src/mhd2/response_funcs.h
 * @brief  The declarations of the internal response helper functions
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_RESPONSE_FUNCS_H
#define MHD_RESPONSE_FUNCS_H 1

#include "mhd_sys_options.h"
#include "sys_bool_type.h"


struct MHD_Response; /* forward declaration */

/**
 * Make response re-usable, initialise all required data
 * @param r the response to make re-usable
 * @return 'true' if succeed, 'false' if failed
 */
MHD_INTERNAL bool
response_make_reusable (struct MHD_Response *restrict r)
MHD_FN_PAR_NONNULL_ (1);


/**
 * De-initialise re-usability data
 * @param r the response to de-initialise re-usability data
 */
MHD_INTERNAL void
mhd_response_deinit_reusable (struct MHD_Response *restrict r)
MHD_FN_PAR_NONNULL_ (1);


/**
 * Check whether response is "frozen" (modifications blocked) and "freeze"
 * it if not frozen before
 * @param response the response to manipulate
 */
MHD_INTERNAL void
mhd_response_check_frozen_freeze (struct MHD_Response *restrict r);


#endif /* ! MHD_RESPONSE_FUNCS_H */
