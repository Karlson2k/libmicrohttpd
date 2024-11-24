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
 * @file src/mhd2/conn_tls_handshake.c
 * @brief  The implementation of connection TLS handling functions
 * @author Karlson2k (Evgeny Grin)
 */

#include "mhd_sys_options.h"

#include "conn_tls_check.h"

#include "mhd_assert.h"

#include "mhd_daemon.h"
#include "mhd_connection.h"

#include "mhd_socket_error_funcs.h"
#include "daemon_logger.h"

#include "mhd_tls_funcs.h"

#include "conn_mark_ready.h"
#include "stream_funcs.h"
#include "stream_process_states.h"


MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_ enum mhd_ConnTlsCheckResult
mhd_conn_tls_check (struct MHD_Connection *restrict c)
{
  mhd_assert (mhd_C_HAS_TLS (c));
  mhd_assert (mhd_D_HAS_TLS (c->daemon));
  mhd_assert ((mhd_CONN_STATE_TLS_HANDSHAKE_RECV == c->conn_state) || \
              (mhd_CONN_STATE_TLS_HANDSHAKE_SEND == c->conn_state) || \
              (mhd_CONN_STATE_TLS_CONNECTED == c->conn_state));

  if (mhd_CONN_STATE_TLS_CONNECTED == c->conn_state)
    return mhd_CONN_TLS_CHECK_OK; /* TLS is already connected */

  if (0 != (mhd_SOCKET_NET_STATE_ERROR_READY & c->sk.ready))
  {
    /* Some socket error has been detected. Do not try to handshake. */
    if (mhd_SOCKET_ERR_NO_ERROR == c->sk.state.discnt_err)
      c->sk.state.discnt_err = mhd_socket_error_get_from_socket (c->sk.fd);
    mhd_conn_start_closing_skt_err (c);
    return mhd_CONN_TLS_CHECK_BROKEN;
  }
  /* Check whether the socket is ready for the required send/recv operation */
  if (0 == (((mhd_CONN_FLAG_RECV | mhd_CONN_FLAG_SEND)
             & ((unsigned int) c->conn_state)
             & ((unsigned int) c->sk.ready))))
    return mhd_CONN_TLS_CHECK_HANDSHAKING;

  switch (mhd_tls_conn_handshake (c->tls))
  {
  case mhd_TLS_PROCED_SUCCESS:
    c->conn_state = mhd_CONN_STATE_TLS_CONNECTED;
    if (! c->sk.props.is_nonblck)
    {
      /* The socket is blocking,
         probably all available data has been processed already. */
      c->sk.ready = (enum mhd_SocketNetState) /* Clear 'recv-ready' and 'send-ready' */
                    (((unsigned int) c->sk.ready)
                     & (~(enum mhd_SocketNetState)
                        mhd_SOCKET_NET_STATE_SEND_READY)
                     & (~(enum mhd_SocketNetState)
                        mhd_SOCKET_NET_STATE_RECV_READY));
    }
    /* TLS is connected now, set event loop state based on HTTP protocol.
       Some early application-level data could be processing in this round. */
    mhd_conn_event_loop_state_update (c);

    return mhd_CONN_TLS_CHECK_OK;
    break;
  case mhd_TLS_PROCED_RECV_MORE_NEEDED:
    c->sk.ready = (enum mhd_SocketNetState) /* Clear 'recv-ready' */
                  (((unsigned int) c->sk.ready)
                   & (~(enum mhd_SocketNetState)
                      mhd_SOCKET_NET_STATE_RECV_READY));
  /* Intentional fall-through */
  case mhd_TLS_PROCED_RECV_INTERRUPTED:
    c->conn_state = mhd_CONN_STATE_TLS_HANDSHAKE_RECV;
    c->event_loop_info = MHD_EVENT_LOOP_INFO_RECV;
    break;
  case mhd_TLS_PROCED_SEND_MORE_NEEDED:
    c->sk.ready = (enum mhd_SocketNetState) /* Clear 'send-ready' */
                  (((unsigned int) c->sk.ready)
                   & (~(enum mhd_SocketNetState)
                      mhd_SOCKET_NET_STATE_SEND_READY));
  /* Intentional fall-through */
  case mhd_TLS_PROCED_SEND_INTERRUPTED:
    c->conn_state = mhd_CONN_STATE_TLS_HANDSHAKE_SEND;
    c->event_loop_info = MHD_EVENT_LOOP_INFO_SEND;
    break;
  case mhd_TLS_PROCED_FAILED:
    c->conn_state = mhd_CONN_STATE_TLS_FAILED;
    mhd_LOG_MSG (c->daemon, \
                 MHD_SC_TLS_CONNECTION_HANDSHAKED_FAILED, \
                 "Failed to perform TLS handshake on the new connection");
    c->sk.state.discnt_err = mhd_SOCKET_ERR_TLS;
    mhd_conn_start_closing_skt_err (c);
    return mhd_CONN_TLS_CHECK_BROKEN;
    break;
  default:
    mhd_assert (0 && "Should be unreachable");
    MHD_UNREACHABLE_;
    return mhd_CONN_TLS_CHECK_BROKEN;
  }

  mhd_conn_mark_ready_update (c);
  return mhd_CONN_TLS_CHECK_HANDSHAKING;
}
