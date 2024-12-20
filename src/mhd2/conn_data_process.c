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
#include "mhd_unreachable.h"

#include "mhd_daemon.h"
#include "mhd_connection.h"

#include "daemon_logger.h"

#include "conn_data_recv.h"
#include "conn_data_send.h"
#include "stream_process_states.h"

#ifdef MHD_ENABLE_HTTPS
#  include "conn_tls_check.h"
#endif /* MHD_ENABLE_HTTPS */

MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_ bool
mhd_conn_process_recv_send_data (struct MHD_Connection *restrict c)
{
  bool send_ready_state_known;
  bool has_sock_err;
  bool data_processed;

#ifdef MHD_ENABLE_HTTPS
  if (mhd_C_HAS_TLS (c))
  {
    switch (mhd_conn_tls_check (c))
    {
    case mhd_CONN_TLS_CHECK_OK:
      break;        /* Process HTTP data */
    case mhd_CONN_TLS_CHECK_HANDSHAKING:
      return true;  /* TLS is not yet ready */
    case mhd_CONN_TLS_CHECK_BROKEN:
      return false; /* Connection is broken */
    default:
      mhd_assert (0 && "Impossible value");
      mhd_UNREACHABLE ();
      break;
    }
  }
#endif /* MHD_ENABLE_HTTPS */

  /* The "send-ready" state is known if system polling call is edge-triggered
     (it always checks for both send- and recv-ready) or if connection needs
     sending (therefore "send-ready" was explicitly checked by sockets polling
     call). */
  send_ready_state_known =
    ((mhd_D_IS_USING_EDGE_TRIG (c->daemon)) ||
     (0 != (MHD_EVENT_LOOP_INFO_SEND & c->event_loop_info)));
  has_sock_err =
    (0 != (mhd_SOCKET_NET_STATE_ERROR_READY & c->sk.ready));
  data_processed = false;

  if (0 != (MHD_EVENT_LOOP_INFO_RECV & c->event_loop_info))
  {
    bool use_recv;
    use_recv = (0 != (mhd_SOCKET_NET_STATE_RECV_READY
                      & (c->sk.ready | mhd_C_HAS_TLS_DATA_IN (c))));
    use_recv = use_recv ||
               (has_sock_err && c->sk.props.is_nonblck);

    if (use_recv)
    {
      mhd_conn_data_recv (c, has_sock_err);
      if (! mhd_conn_process_data (c))
        return false;
      data_processed = true;
    }
  }

  if (0 != (MHD_EVENT_LOOP_INFO_SEND & c->event_loop_info))
  {
    bool use_send;
    /* Perform sending if:
     * + connection is ready for sending or
     * + just formed send data, connection send ready status is not known and
     *   connection socket is non-blocking
     * + detected network error on the connection, to check for the error */
    /* Assuming that after finishing receiving phase, connection send system
       buffers should have some space as sending was performed before receiving
       or has not been performed yet. */
    use_send = (0 != (mhd_SOCKET_NET_STATE_SEND_READY & c->sk.ready));
    use_send = use_send ||
               (data_processed && (! send_ready_state_known)
                && c->sk.props.is_nonblck);
    use_send = use_send ||
               (has_sock_err && c->sk.props.is_nonblck);

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
}
