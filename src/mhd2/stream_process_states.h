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
 * @file src/mhd2/stream_process_states.h
 * @brief  The declarations of internal functions for processing
 *         stream states
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_STREAM_PROCESS_STATES_H
#define MHD_STREAM_PROCESS_STATES_H 1

#include "mhd_sys_options.h"

#include "sys_bool_type.h"

struct MHD_Connection; /* forward declaration */

/**
 * Process states and the data for the connection
 * For HTTP/1.1 connection is equal stream
 * @param c the connection to process
 * @return true if states and data has been successfully processed,
 *         false if connection needs to be closed
 */
MHD_INTERNAL bool
mhd_conn_process_data (struct MHD_Connection *restrict c)
MHD_FN_PAR_NONNULL_ALL_;

#endif /* ! MHD_STREAM_PROCESS_STATES_H */
