/*
  This file is part of GNU libmicrohttpd
  Copyright (C) 2014-2024 Evgeny Grin (Karlson2k)
  Copyright (C) 2007-2020 Daniel Pittman and Christian Grothoff

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
 *
 * Based on the MHD v0.x code by Daniel Pittman, Christian Grothoff and other
 * contributors.
 */

#ifndef MHD_STREAM_PROCESS_REQUEST_H
#define MHD_STREAM_PROCESS_REQUEST_H 1

#include "mhd_sys_options.h"

#include "sys_bool_type.h"
#include "sys_base_types.h"

#include "mhd_str_types.h"

struct MHD_Connection; /* forward declaration */

/**
 * Callback for iterating over GET parameters
 * @param cls the iterator metadata
 * @param name the name of the parameter
 * @param value the value of the parameter
 * @return bool to continue iterations,
 *         false to stop the iteration
 */
typedef bool
(MHD_FN_PAR_NONNULL_ (2) MHD_FN_PAR_NONNULL_ (3)
 *mhd_GetArgumentInter)(void *restrict cls,
                        const struct MHD_String *restrict name,
                        const struct MHD_StringNullable *restrict value);

/**
 * Parse and unescape the arguments given by the client
 * as part of the HTTP request URI.
 *
 * @param args_len the function to call on each key-value pair found
 * @param[in,out] args argument URI string (after "?" in URI),
 *        clobbered in the process!
 * @param cb function to call on each key-value pair found
 * @param cls the iterator context
 * @param[out] enc_broken the pointer to get
 * @return false on failure
 *         true on success (parsing succeeded, @a cb always returned true)
 */
MHD_INTERNAL bool
mhd_parse_get_args (size_t args_len,
                    char *restrict args,
                    mhd_GetArgumentInter cb,
                    void *restrict cls)
MHD_FN_PAR_NONNULL_ (2) MHD_FN_PAR_CSTR_ (2) MHD_FN_PAR_INOUT_ (2);


/**
 * Find and parse the request line.
 * @param c the connection to process
 * @return true if request line completely processed (or unrecoverable error
 *         found) and state is changed,
 *         false if not enough data yet in the receive buffer
 */
MHD_INTERNAL bool
mhd_stream_get_request_line (struct MHD_Connection *restrict c)
MHD_FN_PAR_NONNULL_ALL_;

/**
 * Switch to request headers (field lines) processing state.
 * @param c the connection to process
 */
MHD_INTERNAL void
mhd_stream_switch_to_rq_headers_proc (struct MHD_Connection *restrict c)
MHD_FN_PAR_NONNULL_ALL_;

/**
 * Reset request header processing state.
 *
 * This function resets the processing state before processing the header
 * (or footer) line.
 * @param c the connection to process
 */
MHD_INTERNAL void
mhd_stream_reset_rq_hdr_proc_state (struct MHD_Connection *c)
MHD_FN_PAR_NONNULL_ALL_;

/**
 * Find the end of the request GET parameters.
 * Advance to the next state when done, handle errors.
 * @param c the connection to process
 * @param process_footers if true then footers are processed,
 *                        if false then headers are processed
 * @return true if request headers reading finished (either successfully
 *         or with error),
 *         false if not enough data yet in the receive buffer
 */
MHD_INTERNAL bool
mhd_stream_get_request_headers (struct MHD_Connection *restrict c,
                                bool process_footers)
MHD_FN_PAR_NONNULL_ALL_;

/**
 * Parse the various request headers; figure out the size of the upload and
 * make sure the headers follow the protocol.
 * Advance to the appropriate state.
 *
 * @param c the connection to process
 */
MHD_INTERNAL void
mhd_stream_parse_request_headers (struct MHD_Connection *restrict c)
MHD_FN_PAR_NONNULL_ALL_;

/**
 * Call application request handling callback, process action given by app.
 * Advance to the next state when done, handle errors.
 * @param c the connection to process
 * @return true if advanced to the next state and the next state could
 *              be processes right now,
 *         false if connection is suspended or aborted or more data needed
 *         to process the next state
 */
MHD_INTERNAL bool
mhd_stream_call_app_request_cb (struct MHD_Connection *restrict c)
MHD_FN_PAR_NONNULL_ALL_;

/**
 * Process non-chunked request body or upload chunking encoding.
 * Call the upload handler of the application.
 * Advance to the next state when done, handle errors.
 *
 * @param c the connection to process
 * @return true if advanced to the next state,
 *         false if more data needed or connection is suspended or aborted
 */
MHD_INTERNAL bool
mhd_stream_process_request_body (struct MHD_Connection *restrict c)
MHD_FN_PAR_NONNULL_ALL_;

/**
 * Call application final upload callback, process action given by app.
 * Advance to the next state, handle errors.
 * @param c the connection to process
 * @return true if advanced to the next state,
 *         false if connection is suspended or aborted
 */
MHD_INTERNAL bool
mhd_stream_call_app_final_upload_cb (struct MHD_Connection *restrict c)
MHD_FN_PAR_NONNULL_ALL_;

/**
 * Process finalisation of request receiving.
 * Advance to the next state, handle errors.
 * @param c the connection to process
 * @return true if advanced to the next state,
 *         false if connection is suspended or aborted
 */
MHD_INTERNAL bool
mhd_stream_process_req_recv_finished (struct MHD_Connection *restrict c)
MHD_FN_PAR_NONNULL_ALL_;

/**
 * Check whether enough space is available in the read buffer for the next
 * operation.
 * Handles grow of the buffer if required and error conditions (when buffer
 * grow is required but not possible).
 * Must be called only when processing the event loop states and when
 * reading is required for the next phase.
 * @param c the connection to check
 * @return true if connection handled successfully and enough buffer
 *         is available,
 *         false if not enough buffer is available and the loop's states
 *         must be processed again as connection is in the error state.
 */
MHD_INTERNAL bool
mhd_stream_check_and_grow_read_buffer_space (struct MHD_Connection *restrict c)
MHD_FN_PAR_NONNULL_ALL_;

#endif /* ! MHD_STREAM_PROCESS_REQUEST_H */
