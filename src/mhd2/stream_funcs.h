/*
  This file is part of GNU libmicrohttpd
  Copyright (C) 2022-2024 Evgeny Grin (Karlson2k)

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
 * @file src/mhd2/stream_funcs.h
 * @brief  The declaration of the stream internal functions
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_STREAM_FUNCS_H
#define MHD_STREAM_FUNCS_H 1

#include "mhd_sys_options.h"
#include "sys_base_types.h"


struct MHD_Connection; /* forward declaration */


/**
 * The stage of input data processing.
 * Used for out-of-memory (in the pool) handling.
 */
enum MHD_FIXED_ENUM_ MHD_ProcRecvDataStage
{
  MHD_PROC_RECV_INIT,        /**< No data HTTP request data have been processed yet */
  MHD_PROC_RECV_METHOD,      /**< Processing/receiving the request HTTP method */
  MHD_PROC_RECV_URI,         /**< Processing/receiving the request URI */
  MHD_PROC_RECV_HTTPVER,     /**< Processing/receiving the request HTTP version string */
  MHD_PROC_RECV_HEADERS,     /**< Processing/receiving the request HTTP headers */
  MHD_PROC_RECV_COOKIE,      /**< Processing the received request cookie header */
  MHD_PROC_RECV_BODY_NORMAL, /**< Processing/receiving the request non-chunked body */
  MHD_PROC_RECV_BODY_CHUNKED,/**< Processing/receiving the request chunked body */
  MHD_PROC_RECV_FOOTERS      /**< Processing/receiving the request footers */
};

/**
 * Allocate memory from connection's memory pool.
 * If memory pool doesn't have enough free memory but read or write buffer
 * have some unused memory, the size of the buffer will be reduced as needed.
 * @param connection the connection to use
 * @param size the size of allocated memory area
 * @return pointer to allocated memory region in the pool or
 *         NULL if no memory is available
 */
MHD_INTERNAL void *
mhd_stream_alloc_memory (struct MHD_Connection *restrict connection,
                         size_t size)
MHD_FN_PAR_NONNULL_ALL_;

/**
 * Shrink stream read buffer to the zero size of free space in the buffer
 * @param c the connection whose read buffer is being manipulated
 */
MHD_INTERNAL void
mhd_stream_shrink_read_buffer (struct MHD_Connection *restrict c)
MHD_FN_PAR_NONNULL_ALL_;

/**
 * Allocate the maximum available amount of memory from MemoryPool
 * for write buffer.
 * @param c the connection whose write buffer is being manipulated
 * @return the size of the free space in the write buffer
 */
MHD_INTERNAL size_t
mhd_stream_maximize_write_buffer (struct MHD_Connection *restrict c)
MHD_FN_PAR_NONNULL_ALL_;


/**
 * Select the HTTP error status code for "out of receive buffer space" error.
 * @param c the connection to process
 * @param stage the current stage of request receiving
 * @param add_element_size the size of the @a add_element;
 *                         zero if @a add_element is NULL
 * @param add_element the optional pointer to the element failed to be processed
 *                    or added, the meaning of the element depends on
 *                    the @a stage. Could be not zero-terminated and can
 *                    contain binary zeros. Can be NULL.
 * @return the HTTP error code to use in the error reply
 */
MHD_INTERNAL unsigned int
mhd_stream_get_no_space_err_status_code (struct MHD_Connection *restrict c,
                                         enum MHD_ProcRecvDataStage stage,
                                         size_t add_element_size,
                                         const char *restrict add_element)
MHD_FN_PAR_NONNULL_ (1) MHD_FN_PAR_IN_SIZE_ (4,3);

/**
 * Switch connection from recv mode to send mode.
 *
 * Current request header or body will not be read anymore,
 * response must be assigned to connection.
 * @param c the connection to prepare for sending.
 */
MHD_INTERNAL void
mhd_stream_switch_from_recv_to_send (struct MHD_Connection *c)
MHD_FN_PAR_NONNULL_ALL_;


enum mhd_StreamAbortReason
{
  mhd_STREAM_ABORT_CLIENT_HTTP_ERR
};

/**
 * Close stream with error
 *
 * @param c the connection to close.
 */
MHD_INTERNAL void
mhd_stream_abort (struct MHD_Connection *c,
                  enum mhd_StreamAbortReason reason,
                  const char *log_msg)
MHD_FN_PAR_NONNULL_ (1) MHD_FN_PAR_CSTR_ (3);

#ifdef HAVE_LOG_FUNCTIONALITY
#  define mhd_STREAM_ABORT(c,r,m) (mhd_stream_abort ((c),(r),(m)))
#else  /* ! HAVE_LOG_FUNCTIONALITY */
#  define mhd_STREAM_ABORT(c,r,m) (mhd_stream_abort ((c),(r),NULL))
#endif /* ! HAVE_LOG_FUNCTIONALITY */

/**
 * Update last activity mark to the current time..
 * @param c the connection to update
 */
MHD_INTERNAL void
mhd_stream_update_activity_mark (struct MHD_Connection *restrict c)
MHD_FN_PAR_NONNULL_ALL_;


/**
 * Perform initial clean-up and mark for closing.
 * Set the reason to "aborted by application"
 * @param c to make
 */
MHD_INTERNAL void
mhd_conn_pre_close_app_abort (struct MHD_Connection *restrict c)
MHD_FN_PAR_NONNULL_ALL_;


/**
 * Perform initial clean-up and mark for closing.
 * Set the reason to "socket error"
 * @param c to make
 */
MHD_INTERNAL void
mhd_conn_pre_close_skt_err (struct MHD_Connection *restrict c)
MHD_FN_PAR_NONNULL_ALL_;


#endif /* ! MHD_STREAM_FUNCS_H */
