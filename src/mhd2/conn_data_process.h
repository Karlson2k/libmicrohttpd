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
 * @file src/mhd2/data_process.h
 * @brief  The declarations of data processing functions for connection
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_DATA_PROCESS_H
#define MHD_DATA_PROCESS_H 1

#include "mhd_sys_options.h"
#include "sys_bool_type.h"

struct MHD_Connection; /* forward declaration */

/**
 * Perform connection receiving, sending and processing data.
 * @param c the connection to use
 * @return true if data processed successfully,
 *         false if connection needs to be closed
 */
MHD_INTERNAL bool
mhd_conn_process_recv_send_data (struct MHD_Connection *restrict c)
MHD_FN_PAR_NONNULL_ALL_;

/**
 * Update "active" state, move to the activity lists if necessary.
 * Update "event loop info"
 * @param c the connection to use
 * @return true if data processed successfully,
 *         false if connection needs to be closed
 */
MHD_INTERNAL bool
mhd_conn_update_active_state (struct MHD_Connection *restrict c)
MHD_FN_PAR_NONNULL_ALL_;

#endif /* ! MHD_DATA_PROCESS_H */
