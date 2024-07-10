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
 * @file src/mhd2/stream_process_request.h
 * @brief  The declarations of internal functions for requests parsing
 *         and processing
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_STREAM_PROCESS_REQUEST_H
#define MHD_STREAM_PROCESS_STATES_H 1

#include "mhd_sys_options.h"

#include "sys_bool_type.h"

struct MHD_Connection; /* forward declaration */

/**
 * Find and parse the request line.
 * @param c the connection to process
 * @return true if request line completely processed (or unrecoverable error
 *         found) and state is changed,
 *         false if not enough data yet in the receive buffer
 */
MHD_INTERNAL bool
mhd_get_request_line (struct MHD_Connection *restrict c)
MHD_FN_PAR_NONNULL_ALL_;

/**
 * Switch to request headers (field lines) processing state.
 * @param c the connection to process
 */
MHD_INTERNAL void
mhd_switch_to_rq_headers_processing (struct MHD_Connection *restrict c)
MHD_FN_PAR_NONNULL_ALL_;

/**
 * Find the end of the request headers and make basic header parsing.
 * Advance to the next state when done, handle errors.
 * @param c the connection to process
 * @param process_footers if true then footers are processed,
 *                        if false then headers are processed
 * @return true if request headers reading finished (either successfully
 *         or with error),
 *         false if not enough data yet in the receive buffer
 */
MHD_INTERNAL bool
mhd_get_req_headers (struct MHD_Connection *restrict c, bool process_footers)
MHD_FN_PAR_NONNULL_ALL_;

/**
 * Parse the various headers; figure out the size
 * of the upload and make sure the headers follow
 * the protocol.  Advance to the appropriate state.
 *
 * @param c the connection to process
 */
MHD_INTERNAL void
mhd_parse_connection_headers (struct MHD_Connection *restrict c)
MHD_FN_PAR_NONNULL_ALL_;

#endif /* ! MHD_STREAM_PROCESS_STATES_H */
