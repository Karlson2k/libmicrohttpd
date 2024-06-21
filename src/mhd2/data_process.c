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

#include "data_process.h"

#include "sys_bool_type.h"
#include "sys_base_types.h"

#include "mhd_assert.h"

#include "mhd_daemon.h"
#include "mhd_connection.h"

#include "mhd_recv.h"

#include "daemon_logger.h"

/**
 * Perform data receiving for the connection and try to detect the socket error
 * type.
 *
 * @param c the connection to use
 * @param has_err if 'true' then just check for the network error
 *        type is performed
 */
void
conn_process_recv (struct MHD_Connection restrict *c,
                   bool has_err)
{
  ssize_t bytes_read;
  uint_fast64_t dummy_buf;
  void *buf;
  size_t buf_size;
  size_t received;
  enum mhd_SocketError res;

  mhd_assert (MHD_CONNECTION_CLOSED != c->state);
  mhd_assert ((NULL != c->read_buffer) || has_err);
  mhd_assert ((c->read_buffer_size > c->read_buffer_offset) || has_err);
  mhd_assert (! has_err || \
              (0 != (c->sk_ready & mhd_SOCKET_NET_STATE_ERROR_READY)));
  mhd_assert ((0 == (c->sk_ready & mhd_SOCKET_NET_STATE_ERROR_READY)) || \
              has_err);

  // TODO: TLS support: handshake/transport layer

  if (! has_err ||
      (NULL != c->read_buffer) || (c->read_buffer_size > c->read_buffer_offset))
  {
    buf = c->read_buffer + c->read_buffer_offset;
    buf_size = c->read_buffer_size - c->read_buffer_offset;
  }
  else
  {
    buf = &dummy_buf;
    buf_size = sizeof(buf);
  }

  res = mhd_recv (c,buf_size, buf, &received);

  if ((mhd_SOCKET_ERR_NO_ERROR != res) || has_err)
  {
    /* Handle errors */
    if (! mhd_SOCKET_ERR_IS_HARD (res) && c->sk_nonblck)
    {
      /* Re-try last time to detect the error */
      res = mhd_recv (c, &dummy_buf, sizeof(dummy_buf), &received);
    }
    if (mhd_SOCKET_ERR_IS_HARD (res))
    {
      c->sk_discnt_err = res;
      c->sk_ready =
        (enum mhd_SocketNetState) (((unsigned int) c->sk_ready)
                                   | mhd_SOCKET_NET_STATE_ERROR_READY);
    }
    return;
  }

  if (0 == bytes_read)
    c->sk_rmt_shut_wr = true;

  c->read_buffer_offset += (size_t) bytes_read;
  MHD_update_last_activity_ (c); // TODO: centralise activity update
  return;
}


#if 0 // TODO: report disconnect
if ((bytes_read < 0) || socket_error)
{
  if (MHD_ERR_CONNRESET_ == bytes_read)
  {
    if ( (MHD_CONNECTION_INIT < c->state) &&
         (MHD_CONNECTION_FULL_REQ_RECEIVED > c->state) )
    {
#ifdef HAVE_MESSAGES
      MHD_DLOG (c->daemon,
                _ ("Socket has been disconnected when reading request.\n"));
#endif
      c->discard_request = true;
    }
    MHD_connection_close_ (c,
                           MHD_REQUEST_TERMINATED_READ_ERROR);
    return;
  }

#ifdef HAVE_MESSAGES
  if (MHD_CONNECTION_INIT != c->state)
    MHD_DLOG (c->daemon,
              _ ("Connection socket is closed when reading " \
                 "request due to the error: %s\n"),
              (bytes_read < 0) ? str_conn_error_ (bytes_read) :
              "detected c closure");
#endif
  CONNECTION_CLOSE_ERROR (c,
                          NULL);
  return;
}

#if 0 // TODO: handle remote shut WR
if (0 == bytes_read)
{ /* Remote side closed c. */   // FIXME: Actually NOT!
  c->sk_rmt_shut_wr = true;
  if ( (MHD_CONNECTION_INIT < c->state) &&
       (MHD_CONNECTION_FULL_REQ_RECEIVED > c->state) )
  {
#ifdef HAVE_MESSAGES
    MHD_DLOG (c->daemon,
              _ ("Connection was closed by remote side with incomplete "
                 "request.\n"));
#endif
    c->discard_request = true;
    MHD_connection_close_ (c,
                           MHD_REQUEST_TERMINATED_CLIENT_ABORT);
  }
  else if (MHD_CONNECTION_INIT == c->state)
    /* This termination code cannot be reported to the application
     * because application has not been informed yet about this request */
    MHD_connection_close_ (c,
                           MHD_REQUEST_TERMINATED_COMPLETED_OK);
  else
    MHD_connection_close_ (c,
                           MHD_REQUEST_TERMINATED_WITH_ERROR);
  return;
}
#endif
#endif

MHD_INTERNAL bool
mhd_connection_process_recv_send_data (struct MHD_Connection restrict *c)
{
  const bool send_ready_state_known =
    ((0 != (MHD_EVENT_LOOP_INFO_WRITE & c->event_loop_info)) ||
     mhd_D_IS_USING_EDGE_TRIG (c->daemon));
  const bool has_sock_err =
    (0 != (mhd_SOCKET_NET_STATE_ERROR_READY & c->sk_ready));
  bool data_processed;
  bool need_send;

  data_processed = false;

  if ( ((0 != (mhd_SOCKET_NET_STATE_RECV_READY & c->sk_ready)) &&
        ((0 != (MHD_EVENT_LOOP_INFO_READ & c->event_loop_info))
         || has_sock_err))
       || (has_sock_err && c->sk_nonblck))
  {
    conn_process_recv (c, has_sock_err);
    if (! conn_process_data (c))
      return false;
    data_processed = true;
  }
  need_send = ((0 != (mhd_SOCKET_NET_STATE_SEND_READY & c->sk_ready)) &&
               (0 != (MHD_EVENT_LOOP_INFO_WRITE & c->event_loop_info)));

  if (0 != (MHD_EVENT_LOOP_INFO_WRITE & c->event_loop_info))
  {
    /* Perform sending if:
     * + connection is ready for sending or
     * + just formed send data, connection send ready status is not known and
     *   connection socket is non-blocking */
    /* Assuming that after finishing receiving phase, connection send buffers
       should have some space as sending was performed before receiving or has
       not been performed yet. */
    if ((0 != (mhd_SOCKET_NET_STATE_SEND_READY & c->sk_ready)) ||
        ((data_processed && ! send_ready_state_known && c->sk_nonblck) ||
         (has_sock_err && c->sk_nonblck)))
    {
      conn_process_send (c, has_sock_err);
      if (! conn_process_data (c))
        return false;
      data_processed = true;
    }
  }
  if (! data_processed)
    return conn_process_data (c);
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
    if ((MHD_CONNECTION_NORMAL_BODY_READY == c->state) ||
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
       (! MHD_D_IS_USING_THREAD_PER_CONN_ (c->daemon)) )
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
