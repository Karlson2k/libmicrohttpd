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
 * @file src/mhd2/stream_process_reply.h
 * @brief  The declarations of internal functions for forming and sending
 *         replies for requests
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_STREAM_PROCESS_REPLY_H
#define MHD_STREAM_PROCESS_REPLY_H 1

#include "mhd_sys_options.h"

#include "sys_bool_type.h"

struct MHD_Connection; /* forward declaration */


/**
 * Check whether Dynamic Content Creator cleanup callback is set and
 * call it, if needed.
 * Un-set cleanup callback after calling.
 * @param c the connection to process
 */
MHD_INTERNAL void
mhd_stream_call_dcc_cleanup_if_needed (struct MHD_Connection *restrict c)
MHD_FN_PAR_NONNULL_ALL_;


/**
 * Allocate the connection's write buffer and fill it with all of the
 * headers from the response.
 * Required headers are added here.
 *
 * @param c the connection to process
 * @return 'true' if state has been update,
 *         'false' if connection is going to be aborted
 */
MHD_INTERNAL bool
mhd_stream_build_header_response (struct MHD_Connection *restrict c)
MHD_FN_PAR_NONNULL_ALL_;


/**
 * Prepare the unchunked response content of this connection for sending.
 *
 * @param c the connection
 * @return 'true' if connection new state could be processed now,
 *         'false' if no new state processing is needed.
 */
MHD_INTERNAL bool
mhd_stream_prep_unchunked_body (struct MHD_Connection *restrict c)
MHD_FN_PAR_NONNULL_ALL_;


/**
 * Prepare the chunked response content of this connection for sending.
 *
 * @return 'true' if connection new state could be processed now,
 *         'false' if no new state processing is needed.
 */
MHD_INTERNAL bool
mhd_stream_prep_chunked_body (struct MHD_Connection *restrict c)
MHD_FN_PAR_NONNULL_ALL_;


/**
 * Allocate the connection's write buffer (if necessary) and fill it
 * with response footers.
 *
 * @param c the connection
 */
MHD_INTERNAL void
mhd_stream_prep_chunked_footer (struct MHD_Connection *restrict c)
MHD_FN_PAR_NONNULL_ALL_;

#endif /* ! MHD_STREAM_PROCESS_REPLY_H */
