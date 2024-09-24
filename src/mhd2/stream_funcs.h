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
#include "sys_bool_type.h"


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
 * Fully deallocate write buffer, if it was allocated previously.
 * The write buffer must have no unsent data.
 * @param c the connection whose write buffer is being manipulated
 */
MHD_INTERNAL void
mhd_stream_release_write_buffer (struct MHD_Connection *restrict c)
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

/**
 * Finish request serving.
 * The stream will be re-used or closed.
 *
 * @param c the connection to use.
 */
MHD_INTERNAL void
mhd_stream_finish_req_serving (struct MHD_Connection *restrict c,
                               bool reuse)
MHD_FN_PAR_NONNULL_ALL_;

/**
 * Update last activity mark to the current time.
 * @param c the connection to update
 */
MHD_INTERNAL void
mhd_stream_update_activity_mark (struct MHD_Connection *restrict c)
MHD_FN_PAR_NONNULL_ALL_;

/**
 * Check whether connection's timeout is expired.
 * @param c the connection to update
 * @return 'true' if connection timeout expired and connection needs to be
 *         closed,
 *         'false' otherwise
 */
MHD_INTERNAL bool
mhd_stream_is_timeout_expired (struct MHD_Connection *restrict c)
MHD_FN_PAR_NONNULL_ALL_;

/**
 * The reason to close the connection
 */
enum mhd_ConnCloseReason
{
  /* Hard problem while receiving */
  /**
   * Client sent data that cannot be interpreted as HTTP data
   */
  mhd_CONN_CLOSE_CLIENT_HTTP_ERR_ABORT_CONN
  ,
  /**
   * No space in the connection pool memory for receiving or processing
   * the request
   */
  mhd_CONN_CLOSE_NO_POOL_MEM_FOR_REQUEST
  ,
  /**
   * The client shut down send before complete request sent
   */
  mhd_CONN_CLOSE_CLIENT_SHUTDOWN_EARLY
  ,

  /* Hard problem while sending */

  /**
   * No space in the connection pool memory for the reply
   */
  mhd_CONN_CLOSE_NO_POOL_MEM_FOR_REPLY
  ,
  /**
   * No memory to create error response
   */
  mhd_CONN_CLOSE_NO_MEM_FOR_ERR_RESPONSE
  ,
  /**
   * Application behaves incorrectly
   */
  mhd_CONN_CLOSE_APP_ERROR
  ,
  /**
   * Application requested about of the stream
   */
  mhd_CONN_CLOSE_APP_ABORTED
  ,

  /* Hard problem while receiving or sending */
  /**
   * MHD internal error.
   * Should never appear.
   */
  mhd_CONN_CLOSE_INT_ERROR
  ,
  /**
   * No system resources available to handle connection
   */
  mhd_CONN_CLOSE_NO_SYS_RESOURCES
  ,
  /**
   * The TCP or TLS connection is broken or aborted due to error on socket
   * or TLS
   */
  mhd_CONN_CLOSE_SOCKET_ERR
  ,
  /**
   * The daemon is being shut down, all connection must be closed
   */
  mhd_CONN_CLOSE_DAEMON_SHUTDOWN
  ,

  /* Could be hard or soft error depending on connection state */
  /**
   * Timeout detected when receiving request
   */
  mhd_CONN_CLOSE_TIMEDOUT
  ,

  /* Soft problem */
  /**
   * The connection must be closed after error response as the client
   * violates HTTP specification
   */
  mhd_CONN_CLOSE_ERR_REPLY_SENT
  ,

#ifdef MHD_UPGRADE_SUPPORT

  /* Transition to another protocol */
  /**
   * The connection stopped HTTP communication and will be used for another
   * protocol.
   * The socket is not being closed.
   */
  mhd_CONN_CLOSE_UPGRADE
  ,
#endif /* MHD_UPGRADE_SUPPORT */

  /* Graceful closing */
  /**
   * Close connection after graceful completion of HTTP communication
   */
  mhd_CONN_CLOSE_HTTP_COMPLETED

};


/**
 * Start closing of the connection.
 *
 * Application is notified about connection closing (if callback is set),
 * the socket is shut downed for sending and the connection is marked for
 * closing. The real resource deallocation and socket closing are performed
 * later.
 *
 * As no resources are deallocated by this function, it is safe to call it
 * "deep" in the code. Upon return all connection resources still could be used,
 * pointers can be dereferenced etc. The real cleanup is performed when
 * connection state is processed by #mhd_conn_process_data().
 *
 * @param c the connection for pre-closing
 * @param reason the reason for closing
 * @param log_msg the message for the log
 */
MHD_INTERNAL void
mhd_conn_start_closing (struct MHD_Connection *restrict c,
                        enum mhd_ConnCloseReason reason,
                        const char *log_msg)
MHD_FN_PAR_NONNULL_ (1) MHD_FN_PAR_CSTR_ (3);

/**
 * Abort the stream and log message
 */
#ifdef HAVE_LOG_FUNCTIONALITY
#  define mhd_STREAM_ABORT(c,r,m) (mhd_conn_start_closing ((c),(r),(m)))
#else  /* ! HAVE_LOG_FUNCTIONALITY */
#  define mhd_STREAM_ABORT(c,r,m) (mhd_conn_start_closing ((c),(r),NULL))
#endif /* ! HAVE_LOG_FUNCTIONALITY */

/**
 * Perform initial clean-up and mark for closing.
 * Set the reason to "aborted by application"
 * @param c the connection for pre-closing
 */
#define mhd_conn_start_closing_app_abort(c) \
        mhd_conn_start_closing ((c), mhd_CONN_CLOSE_APP_ABORTED, NULL)

/**
 * Perform initial clean-up and mark for closing.
 * Set the reason to "socket error"
 * @param c the connection for pre-closing
 */
#define mhd_conn_start_closing_skt_err(c) \
        mhd_conn_start_closing ((c), mhd_CONN_CLOSE_SOCKET_ERR, NULL)

/**
 * Perform initial clean-up and mark for closing.
 * Set the reason to "request finished"
 * @param c the connection for pre-closing
 */
#define mhd_conn_start_closing_req_finished(c) \
        mhd_conn_start_closing ((c), mhd_CONN_CLOSE_HTTP_COMPLETED, NULL)

/**
 * Perform initial clean-up and mark for closing.
 * Set the reason to "timed out".
 * @param c the connection for pre-closing
 */
#define mhd_conn_start_closing_timedout(c) \
        mhd_conn_start_closing ((c), mhd_CONN_CLOSE_TIMEDOUT, NULL)

/**
 * Perform initial clean-up and mark for closing.
 * Set the reason to "daemon shutdown".
 * @param c the connection for pre-closing
 */
#define mhd_conn_start_closing_d_shutdown(c) \
        mhd_conn_start_closing ((c), mhd_CONN_CLOSE_DAEMON_SHUTDOWN, NULL)

/**
 * Perform initial clean-up and mark for closing.
 * Set the reason to "no system resources".
 * @param c the connection for pre-closing
 */
#define mhd_conn_start_closing_no_sys_res(c) \
        mhd_conn_start_closing ((c), mhd_CONN_CLOSE_NO_SYS_RESOURCES, NULL)

#ifdef MHD_UPGRADE_SUPPORT
/**
 * Perform initial clean-up and prepare for HTTP Upgrade.
 * Set the reason to "upgrading".
 * @param c the connection for preparing
 */
#  define mhd_conn_pre_upgrade(c) \
        mhd_conn_start_closing ((c), mhd_CONN_CLOSE_UPGRADE, NULL)
#endif /* MHD_UPGRADE_SUPPORT */


/**
 * Perform first part of the initial connection cleanup.
 * This function is used for both standard connection cleanup and for transition
 * to HTTP-Upgraded connection.
 * This cleanup should be performed in the same thread that processes
 * the connection recv/send/data.
 * @param c the connection to perform the first part of for pre-cleaning
 */
MHD_INTERNAL void
mhd_conn_pre_clean_part1 (struct MHD_Connection *restrict c)
MHD_FN_PAR_NONNULL_ (1);

/**
 * Perform initial connection cleanup after start of the connection closing
 * procedure.
 * This cleanup should be performed in the same thread that processes
 * the connection recv/send/data.
 * @param c the connection for pre-cleaning
 */
MHD_INTERNAL void
mhd_conn_pre_clean (struct MHD_Connection *restrict c)
MHD_FN_PAR_NONNULL_ (1);

#endif /* ! MHD_STREAM_FUNCS_H */
