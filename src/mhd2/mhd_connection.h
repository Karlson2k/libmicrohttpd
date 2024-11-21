/*
  This file is part of GNU libmicrohttpd
  Copyright (C) 2014-2024 Evgeny Grin (Karlson2k)
  Copyright (C) 2007-2018 Daniel Pittman and Christian Grothoff

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
 * @file src/mhd2/mhd_connection.h
 * @brief  Definition of struct MHD_connection
 * @author Karlson2k (Evgeny Grin)
 * @author Daniel Pittman
 * @author Christian Grothoff
 *
 * @warning Imported from MHD1 with minimal changes
 * TODO: Rewrite
 */

#ifndef MHD_CONNECTION_H
#define MHD_CONNECTION_H 1

#include "mhd_sys_options.h"

#include "sys_bool_type.h"
#include "sys_base_types.h"

#include "mhd_conn_socket.h"

#include "mhd_threads.h"

#include "mhd_tristate.h"
#include "mhd_dlinked_list.h"

#include "mhd_request.h"
#include "mhd_reply.h"

#ifdef MHD_UPGRADE_SUPPORT
#  include "mhd_upgrade.h"
#endif /* MHD_UPGRADE_SUPPORT */

#include "mhd_socket_error.h"

#include "mhd_public_api.h"

#ifdef MHD_ENABLE_HTTPS
#  include "mhd_tls_choice.h" /* For the TLS struct forward declaration */
#endif

/**
 * Minimum reasonable size by which MHD tries to increment read/write buffers.
 * We usually begin with half the available pool space for the
 * IO-buffer, but if absolutely needed we additively grow by the
 * number of bytes given here (up to -- theoretically -- the full pool
 * space).
 *
 * Currently set to reasonable maximum MSS size.
 */
#define mhd_BUF_INC_SIZE 1500

/**
 * Message to transmit when http 1.1 request is received
 */
#define mdh_HTTP_1_1_100_CONTINUE_REPLY "HTTP/1.1 100 Continue\r\n\r\n"


struct MHD_Connection; /* forward declaration */

/**
 * What is this connection waiting for?
 */
enum MHD_FIXED_FLAGS_ENUM_ MHD_ConnectionEventLoopInfo
{
  /**
   * We are waiting to be able to read.
   * The same value as #mhd_SOCKET_NET_STATE_RECV_READY
   */
  MHD_EVENT_LOOP_INFO_RECV = 1 << 0
  ,
  /**
   * We are waiting to be able to write.
   * The same value as #mhd_SOCKET_NET_STATE_SEND_READY
   */
  MHD_EVENT_LOOP_INFO_SEND = 1 << 1
  ,
  /**
   * We are waiting for the application to provide data.
   */
  MHD_EVENT_LOOP_INFO_PROCESS = 1 << 4
  ,
  /**
   * We are finished and are awaiting cleanup.
   */
  MHD_EVENT_LOOP_INFO_CLEANUP = 1 << 5
#ifdef MHD_UPGRADE_SUPPORT
  ,
  /**
   * We are finished and are awaiting cleanup.
   */
  MHD_EVENT_LOOP_INFO_UPGRADED = 1 << 6
#endif /* MHD_UPGRADE_SUPPORT */
};

#define MHD_EVENT_LOOP_INFO_PROCESS_READ \
        (MHD_EVENT_LOOP_INFO_RECV | MHD_EVENT_LOOP_INFO_PROCESS)


/**
 * The reason for the connection closure
 */
enum mhd_ConnClosureReason
{
  /**
   * The socket is not closed / closing.
   */
  mhd_CONN_CLOSURE_REASON_NO_CLOSURE = 0
  ,
  /**
   * Socket has to be closed because HTTP protocol successfully finished data
   * exchange.
   */
  mhd_CONN_CLOSURE_REASON_PROTOCOL_SUCCESS
  ,
  /**
   * Socket has to be closed because remote side violated some HTTP
   * specification requirements or request processed with an error.
   * The HTTP error response should be sent.
   */
  mhd_CONN_CLOSURE_REASON_PROTOCOL_FAILURE_SOFT
  ,
  /**
   * Timeout expired
   */
  mhd_CONN_CLOSURE_REASON_TIMEOUT
  ,
  /**
   * Socket has to be closed because received data cannot be interpreted as
   * valid HTTP data.
   */
  mhd_CONN_CLOSURE_REASON_PROTOCOL_FAILURE_HARD
  ,
  /**
   * Unrecoverable TLS error
   */
  mhd_CONN_CLOSURE_REASON_TLS_ERROR
  ,
  /**
   * The remote side closed connection in abortive way
   */
  mhd_CONN_CLOSURE_REASON_REMOTE_HARD_DISCONN
  ,
  /**
   * The connection has been broken for some reason
   */
  mhd_CONN_CLOSURE_REASON_CONN_BROKEN
};

/**
 * States in a state machine for a connection.
 *
 * The main transitions are any-state to #MHD_CONNECTION_CLOSED, any
 * state to state+1, #MHD_CONNECTION_FOOTERS_SENT to
 * #MHD_CONNECTION_INIT.  #MHD_CONNECTION_CLOSED is the terminal state
 * and #MHD_CONNECTION_INIT the initial state.
 *
 * Note that transitions for *reading* happen only after the input has
 * been processed; transitions for *writing* happen after the
 * respective data has been put into the write buffer (the write does
 * not have to be completed yet).  A transition to
 * #MHD_CONNECTION_CLOSED or #MHD_CONNECTION_INIT requires the write
 * to be complete.
 */
enum MHD_FIXED_ENUM_ MHD_CONNECTION_STATE
{
  /**
   * Connection just started (no headers received).
   * Waiting for the line with the request type, URL and version.
   */
  MHD_CONNECTION_INIT = 0
  ,
  /**
   * Part of the request line was received.
   * Wait for complete line.
   */
  MHD_CONNECTION_REQ_LINE_RECEIVING
  ,
  /**
   * We got the URL (and request type and version).  Wait for a header line.
   *
   * A milestone state. No received data is processed in this state.
   */
  MHD_CONNECTION_REQ_LINE_RECEIVED
  ,
  /**
   * Receiving request headers.  Wait for the rest of the headers.
   */
  MHD_CONNECTION_REQ_HEADERS_RECEIVING
  ,
  /**
   * We got the request headers.  Process them.
   */
  MHD_CONNECTION_HEADERS_RECEIVED
  ,
  /**
   * We have processed the request headers.  Call application callback.
   */
  MHD_CONNECTION_HEADERS_PROCESSED
  ,
  /**
   * We have processed the headers and need to send 100 CONTINUE.
   */
  MHD_CONNECTION_CONTINUE_SENDING
  ,
  /**
   * We have sent 100 CONTINUE (or do not need to).  Read the message body.
   */
  MHD_CONNECTION_BODY_RECEIVING
  ,
  /**
   * We got the request body.
   *
   * A milestone state. No received data is processed in this state.
   */
  MHD_CONNECTION_BODY_RECEIVED
  ,
  /**
   * We are reading the request footers.
   */
  MHD_CONNECTION_FOOTERS_RECEIVING
  ,
  /**
   * We received the entire footer.
   *
   * A milestone state. No data is receiving in this state.
   */
  MHD_CONNECTION_FOOTERS_RECEIVED
  ,
  /**
   * We received the entire request.
   *
   * A milestone state. No data is receiving in this state.
   */
  MHD_CONNECTION_FULL_REQ_RECEIVED
  ,
  /**
   * Finished receiving request data: either complete request received or
   * MHD is going to send reply early, without getting full request.
   */
  MHD_CONNECTION_REQ_RECV_FINISHED
  ,
  /**
   * Finished reading of the request and the response is ready.
   * Switch internal logic from receiving to sending, prepare connection
   * sending the reply and build the reply header.
   */
  MHD_CONNECTION_START_REPLY
  ,
  /**
   * We have prepared the response headers in the write buffer.
   * Send the response headers.
   */
  MHD_CONNECTION_HEADERS_SENDING
  ,
  /**
   * We have sent the response headers.  Get ready to send the body.
   */
  MHD_CONNECTION_HEADERS_SENT
#ifdef MHD_UPGRADE_SUPPORT
  ,
  /**
   * Sending special HTTP "Upgrade" headers
   */
  MHD_CONNECTION_UPGRADE_HEADERS_SENDING
#endif /* MHD_UPGRADE_SUPPORT */
  ,
  /**
   * We are waiting for the client to provide more
   * data of a non-chunked body.
   */
  MHD_CONNECTION_UNCHUNKED_BODY_UNREADY
  ,
  /**
   * We are ready to send a part of a non-chunked body.  Send it.
   */
  MHD_CONNECTION_UNCHUNKED_BODY_READY
  ,
  /**
   * We are waiting for the client to provide a chunk of the body.
   */
  MHD_CONNECTION_CHUNKED_BODY_UNREADY
  ,
  /**
   * We are ready to send a chunk.
   */
  MHD_CONNECTION_CHUNKED_BODY_READY
  ,
  /**
   * We have sent the chunked response body. Prepare the footers.
   */
  MHD_CONNECTION_CHUNKED_BODY_SENT
  ,
  /**
   * We have prepared the response footer.  Send it.
   */
  MHD_CONNECTION_FOOTERS_SENDING
  ,
  /**
   * We have sent the entire reply.
   * Shutdown connection or restart processing to get a new request.
   */
  MHD_CONNECTION_FULL_REPLY_SENT
#ifdef MHD_UPGRADE_SUPPORT
  ,
  /**
   * Transition to "Upgraded" state
   */
  MHD_CONNECTION_UPGRADING
  ,
  /**
   * Sending and receiving data on HTTP-Upgraded connection channel.
   * Normal data processing and connection handling is not performed
   * by MHD anymore.
   */
  MHD_CONNECTION_UPGRADED
  ,
  /**
   * Closing HTTP-Upgraded connection
   */
  MHD_CONNECTION_UPGRADED_CLEANING
#endif /* MHD_UPGRADE_SUPPORT */
  ,
  /**
   * Finished regular connection processing.
   * Initial buffers cleanup and freeing.
   */
  MHD_CONNECTION_PRE_CLOSING
  ,
  /**
   * This connection is to be closed.
   */
  MHD_CONNECTION_CLOSED

};

struct mhd_ConnDebugData
{
  bool closing_started;
  bool pre_cleaned;
  bool removed_from_daemon;
  bool tls_inited;
};

/**
 * Ability to use same connection for next request
 */
enum MHD_FIXED_ENUM_ mhd_ConnReuse
{
  /**
   * Connection must be closed after sending response.
   */
  mhd_CONN_MUST_CLOSE = -1
  ,
  /**
   * KeepAlive state is possible
   */
  mhd_CONN_KEEPALIVE_POSSIBLE = 0
  ,
  /**
   * Connection will be upgraded
   */
  mhd_CONN_MUST_UPGRADE = 1
};

/**
 * The helper struct for the connections list
 */
mhd_DLINKEDL_LINKS_DEF (MHD_Connection);

/**
 * State kept for HTTP network connection.
 */
struct MHD_Connection
{

  /**
   * The list with all daemon's connections
   */
  mhd_DLNKDL_LINKS (MHD_Connection,all_conn);

  /**
   * The connection socket data
   */
  struct mhd_ConnSocket sk;

#ifdef MHD_ENABLE_HTTPS
  /**
   * Connection-specific TLS data.
   * NULL if TLS is not used (plain HTTP connection).
   * Allocated (and freed) together with struct MHD_Connection, cannot be
   * deallocated separately.
   */
  struct mhd_TlsConnData *tls;
#endif

  /**
   * 'true' if connection is in 'process ready' list,
   * 'false' otherwise
   */
  bool in_proc_ready;

  /**
   * The list with all daemon's connections that ready to processing
   */
  mhd_DLNKDL_LINKS (MHD_Connection,proc_ready);

  /**
   * The list of connections sorted by timeout
   */
  mhd_DLNKDL_LINKS (MHD_Connection,by_timeout);

#ifdef MHD_UPGRADE_SUPPORT
  /**
   * The data for handling HTTP-Upgraded connection
   */
  struct MHD_UpgradedHandle upgr;

  /**
   * Double-linke list of HTTP-Upgraded connections waiting for clean-up
   */
  mhd_DLNKDL_LINKS (MHD_Connection,upgr_cleanup);
#endif /* MHD_UPGRADE_SUPPORT */

  /**
   * True if connection is suspended
   */
  bool suspended;

  /**
   * True if connection is resuming
   */
  bool resuming;

  /**
   * Reference to the MHD_Daemon struct.
   */
  struct MHD_Daemon *daemon;

  /**
   * Request-specific data
   */
  struct MHD_Request rq;

  /**
   * Reply-specific data
   */
  struct MHD_Reply rp;

  /**
   * The memory pool is created whenever we first read from the TCP
   * stream and destroyed at the end of each request (and re-created
   * for the next request).  In the meantime, this pointer is NULL.
   * The pool is used for all connection-related data except for the
   * response (which maybe shared between connections) and the IP
   * address (which persists across individual requests).
   */
  struct mhd_MemoryPool *pool;

  /**
   * We allow the main application to associate some pointer with the
   * TCP connection (which may span multiple HTTP requests).  Here is
   * where we store it.  (MHD does not know or care what it is).
   * The location is given to the #MHD_NotifyConnectionCallback and
   * also accessible via #MHD_CONNECTION_INFO_SOCKET_CONTEXT.
   */
  void *socket_context;

  /**
   * Close connection after sending response?
   * Functions may change value from "KeepAlive" to "Must close",
   * but no functions reset value "Must Close" to any other value.
   */
  enum mhd_ConnReuse conn_reuse;

  /**
   * Buffer for reading requests.  Allocated in pool.  Actually one
   * byte larger than @e read_buffer_size (if non-NULL) to allow for
   * 0-termination.
   */
  char *read_buffer;

  /**
   * Buffer for writing response (headers only).  Allocated
   * in pool.
   */
  char *write_buffer;

#if defined(MHD_USE_THREADS)
  /**
   * Thread handle for this connection (if we are using
   * one thread per connection).
   */
  mhd_thread_handle_ID tid;
#endif

  /**
   * Size of @e read_buffer (in bytes).
   * This value indicates how many bytes we're willing to read
   * into the buffer.
   */
  size_t read_buffer_size;

  /**
   * Position where we currently append data in @e read_buffer (the
   * next char after the last valid position).
   */
  size_t read_buffer_offset;

  /**
   * Size of @e write_buffer (in bytes).
   */
  size_t write_buffer_size;

  /**
   * Offset where we are with sending from @e write_buffer.
   */
  size_t write_buffer_send_offset;

  /**
   * Last valid location in write_buffer (where do we
   * append and up to where is it safe to send?)
   */
  size_t write_buffer_append_offset;

  /**
   * Position in the 100 CONTINUE message that
   * we need to send when receiving http 1.1 requests.
   */
  size_t continue_message_write_offset;

  /**
   * Last time this connection had any activity
   * (reading or writing).
   */
  uint_fast64_t last_activity;

  /**
   * After how many milliseconds of inactivity should
   * this connection time out?
   * Zero for no timeout.
   */
  uint_fast64_t connection_timeout_ms;

  /**
   * Some error happens during processing the connection therefore this
   * connection must be closed.
   * The error may come from the client side (like wrong request format),
   * from the application side (like data callback returned error), or from
   * the OS side (like out-of-memory).
   */
  bool stop_with_error;

  /**
   * Response queued early, before the request is fully processed,
   * the client upload is rejected.
   * The connection cannot be reused for additional requests as the current
   * request is incompletely read and it is unclear where is the initial
   * byte of the next request.
   */
  bool discard_request;

#if defined(MHD_USE_THREADS)
  /**
   * Set to `true` if the thread has been joined.
   */
  bool thread_joined;
#endif

  /**
   * Connection is in the cleanup DL-linked list.
   */
  bool in_cleanup;

  /**
   * State in the FSM for this connection.
   */
  enum MHD_CONNECTION_STATE state;

  /**
   * What is this connection waiting for?
   */
  enum MHD_ConnectionEventLoopInfo event_loop_info;

#ifndef NDEBUG
  /**
   * Debugging data
   */
  struct mhd_ConnDebugData dbg;
#endif
};

#ifdef MHD_ENABLE_HTTPS
/**
 * Returns non-zero if connection has TLS enabled or zero otherwise
 */
#  define mhd_C_HAS_TLS(c) (((c)->tls) ? (! 0) : (0))
#else
/**
 * Returns non-zero if connection has TLS enabled or zero otherwise
 */
#  define mhd_C_HAS_TLS(c) (0)
#endif

#endif /* ! MHD_CONNECTION_H */
