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
 * @file src/mhd2/conn_data_recv.c
 * @brief  The implementation of data receiving functions for connection
 * @author Karlson2k (Evgeny Grin)
 */

#include "conn_data_recv.h"

#include "mhd_sys_options.h"

#include "sys_bool_type.h"
#include "sys_base_types.h"

#include "mhd_assert.h"

#include "mhd_connection.h"

#include "mhd_recv.h"
#include "stream_funcs.h"

MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_ void
mhd_conn_data_recv (struct MHD_Connection *restrict c,
                    bool has_err)
{
  void *buf;
  size_t buf_size;
  size_t received;
  enum mhd_SocketError res;

  mhd_assert (MHD_CONNECTION_CLOSED != c->state);
  mhd_assert (NULL != c->read_buffer);
  mhd_assert (c->read_buffer_size > c->read_buffer_offset);
  mhd_assert (! has_err || \
              (0 != (c->sk_ready & mhd_SOCKET_NET_STATE_ERROR_READY)));
  mhd_assert ((0 == (c->sk_ready & mhd_SOCKET_NET_STATE_ERROR_READY)) || \
              has_err);

  // TODO: TLS support: handshake/transport layer

  buf = c->read_buffer + c->read_buffer_offset;
  buf_size = c->read_buffer_size - c->read_buffer_offset;

  res = mhd_recv (c,buf_size, buf, &received);

  if ((mhd_SOCKET_ERR_NO_ERROR != res) || has_err)
  {
    /* Handle errors */
    if ((mhd_SOCKET_ERR_NO_ERROR == res) && (0 == received))
    {
      c->sk_rmt_shut_wr = true;
      res = mhd_SOCKET_ERR_REMT_DISCONN;
    }
    if (has_err && ! mhd_SOCKET_ERR_IS_HARD (res) && c->sk_nonblck)
    {
      /* Re-try last time to detect the error */
      uint_fast64_t dummy_buf;
      res = mhd_recv (c, sizeof(dummy_buf), (char *) &dummy_buf, &received);
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

  if (0 == received)
    c->sk_rmt_shut_wr = true;

  c->read_buffer_offset += received;
  mhd_stream_update_activity_mark (c); // TODO: centralise activity update
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
