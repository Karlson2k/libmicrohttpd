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
 * @file src/mhd2/upgrade_proc.h
 * @brief  The declaration of functions for processing data for HTTP Upgrade
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_UPGRADE_PROC_H
#define MHD_UPGRADE_PROC_H 1

#include "mhd_sys_options.h"

#include "sys_bool_type.h"

struct MHD_Connection; /* forward declaration */

/**
 * Switch to "upgrading" state if the full upgrade headers have been sent
 * completely.
 * @param c the connection to use
 * @return 'true' if connection is switched to "upgrading" state,
 *         'false' if headers has not been sent completely yet.
 */
MHD_INTERNAL bool
mhd_upgrade_try_start_upgrading (struct MHD_Connection *restrict c)
MHD_FN_PAR_NONNULL_ (1);


/**
 * Switch connection to "upgraded" state, call application callback for
 * switching to "upgraded" state.
 * @param c the connection to use
 * @return 'true' if connection is switched to "upgraded" state,
 *         'false' if connection failed to switch (initialisation error).
 */
MHD_INTERNAL bool
mhd_upgrade_finish_switch_to_upgraded (struct MHD_Connection *restrict c)
MHD_FN_PAR_NONNULL_ (1);


/**
 * De-initialise HTTP-Upgraded-specific data
 * @param c the connection the de-initialise
 */
MHD_INTERNAL void
mhd_upgraded_deinit (struct MHD_Connection *restrict c)
MHD_FN_PAR_NONNULL_ (1);

#endif /* ! MHD_UPGRADE_PROC_H */
