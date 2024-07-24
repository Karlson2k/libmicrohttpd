/*
  This file is part of GNU libmicrohttpd
  Copyright (C) 2015-2024 Evgeny Grin (Karlson2k)
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
 * @file src/mhd2/data_process.c
 * @brief  The implementation of data receiving, sending and processing
 *         functions for connection
 * @author Karlson2k (Evgeny Grin)
 *
 * Based on the MHD v0.x code by Daniel Pittman, Christian Grothoff and other
 * contributors.
 */

#include "mhd_sys_options.h"

#include "conn_data_process.h"
#include "sys_bool_type.h"
#include "sys_base_types.h"

#include "mhd_assert.h"

#include "mhd_daemon.h"
#include "mhd_connection.h"

#include "daemon_logger.h"

#include "conn_data_recv.h"
#include "conn_data_send.h"
#include "stream_process_states.h"

MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_ bool
mhd_conn_process_recv_send_data (struct MHD_Connection *restrict c)
{
  const bool send_ready_state_known =
    ((mhd_D_IS_USING_EDGE_TRIG (c->daemon)) ||
     (0 != (MHD_EVENT_LOOP_INFO_WRITE & c->event_loop_info)));
  const bool has_sock_err =
    (0 != (mhd_SOCKET_NET_STATE_ERROR_READY & c->sk_ready));
  bool data_processed;

  data_processed = false;

  if (0 != (MHD_EVENT_LOOP_INFO_READ & c->event_loop_info))
  {
    bool use_recv;
    use_recv = (0 != (mhd_SOCKET_NET_STATE_RECV_READY & c->sk_ready));
    use_recv = use_recv ||
               (has_sock_err && c->sk_nonblck);

    if (use_recv)
    {
      mhd_conn_data_recv (c, has_sock_err);
      if (! mhd_conn_process_data (c))
        return false;
      data_processed = true;
    }
  }

  if (0 != (MHD_EVENT_LOOP_INFO_WRITE & c->event_loop_info))
  {
    bool use_send;
    /* Perform sending if:
     * + connection is ready for sending or
     * + just formed send data, connection send ready status is not known and
     *   connection socket is non-blocking
     * + detected network error on the connection, to check to the error */
    /* Assuming that after finishing receiving phase, connection send system
       buffers should have some space as sending was performed before receiving
       or has not been performed yet. */
    use_send = (0 != (mhd_SOCKET_NET_STATE_SEND_READY & c->sk_ready));
    use_send = use_send ||
               (data_processed && (! send_ready_state_known) && c->sk_nonblck);
    use_send = use_send ||
               (has_sock_err && c->sk_nonblck);

    if (use_send)
    {
      mhd_conn_data_send (c);
      if (! mhd_conn_process_data (c))
        return false;
      data_processed = true;
    }
  }
  if (! data_processed)
    return mhd_conn_process_data (c);
  return true;

#if 0 // TODO: re-implement fasttrack as a single unified buffer sending
  if (! force_close)
  {
    /* No need to check value of 'ret' here as closed connection
     * cannot be in MHD_EVENT_LOOP_INFO_WRITE state. */
    if ( (MHD_EVENT_LOOP_INFO_WRITE == c->event_loop_info) &&
         write_ready)
    {
      MHD_connection_handle_write (c);
      ret = MHD_connection_handle_idle (c);
      states_info_processed = true;
    }
  }
  else
  {
    MHD_connection_close_ (c,
                           MHD_REQUEST_TERMINATED_WITH_ERROR);
    return MHD_connection_handle_idle (c);
  }

  if (! states_info_processed)
  {   /* Connection is not read or write ready, but external conditions
       * may be changed and need to be processed. */
    ret = MHD_connection_handle_idle (c);
  }
  /* Fast track for fast connections. */
  /* If full request was read by single read_handler() invocation
     and headers were completely prepared by single MHD_connection_handle_idle()
     then try not to wait for next sockets polling and send response
     immediately.
     As writeability of socket was not checked and it may have
     some data pending in system buffers, use this optimization
     only for non-blocking sockets. */
  /* No need to check 'ret' as connection is always in
   * MHD_CONNECTION_CLOSED state if 'ret' is equal 'MHD_NO'. */
  else if (on_fasttrack && c->sk_nonblck)
  {
    if (MHD_CONNECTION_HEADERS_SENDING == c->state)
    {
      MHD_connection_handle_write (c);
      /* Always call 'MHD_connection_handle_idle()' after each read/write. */
      ret = MHD_connection_handle_idle (c);
    }
    /* If all headers were sent by single write_handler() and
     * response body is prepared by single MHD_connection_handle_idle()
     * call - continue. */
    if ((MHD_CONNECTION_UNCHUNKED_BODY_READY == c->state) ||
        (MHD_CONNECTION_CHUNKED_BODY_READY == c->state))
    {
      MHD_connection_handle_write (c);
      ret = MHD_connection_handle_idle (c);
    }
  }

  /* All connection's data and states are processed for this turn.
   * If connection already has more data to be processed - use
   * zero timeout for next select()/poll(). */
  /* Thread-per-connection do not need global zero timeout as
   * connections are processed individually. */
  /* Note: no need to check for read buffer availability for
   * TLS read-ready connection in 'read info' state as connection
   * without space in read buffer will be marked as 'info block'. */
  if ( (! c->daemon->data_already_pending) &&
       (! mhd_D_HAS_THR_PER_CONN (c->daemon)) )
  {
    if (0 != (MHD_EVENT_LOOP_INFO_PROCESS & c->event_loop_info))
      c->daemon->data_already_pending = true;
#ifdef HTTPS_SUPPORT
    else if ( (c->tls_read_ready) &&
              (0 != (MHD_EVENT_LOOP_INFO_READ & c->event_loop_info)) )
      c->daemon->data_already_pending = true;
#endif /* HTTPS_SUPPORT */
  }
  return ret;
#endif
}
