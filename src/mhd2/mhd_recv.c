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
 * @file src/mhd2/mhd_recv.c
 * @brief  The implementation of the mhd_recv() function
 * @author Karlson2k (Evgeny Grin)
 */

#include "mhd_sys_options.h"

#include "mhd_recv.h"

#include "mhd_connection.h"

#include "mhd_socket_type.h"
#include "sys_sockets_headers.h"
#include "mhd_sockets_macros.h"

#include "mhd_limits.h"

#include "mhd_assert.h"
#include "mhd_socket_error_funcs.h"

#ifdef MHD_SUPPORT_HTTPS
#  include "mhd_tls_funcs.h"
#endif

static MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_OUT_SIZE_ (3,2) MHD_FN_PAR_OUT_ (4) enum mhd_SocketError
mhd_recv_plain (struct MHD_Connection *restrict c,
                size_t buf_size,
                char buf[MHD_FN_PAR_DYN_ARR_SIZE_ (buf_size)],
                size_t *restrict received)
{
  /* Plain TCP connection */
  ssize_t res;
  enum mhd_SocketError err;

  if (MHD_SCKT_SEND_MAX_SIZE_ < buf_size)
    buf_size = MHD_SCKT_SEND_MAX_SIZE_;

  res = mhd_sys_recv (c->sk.fd, buf, buf_size);
  if (0 <= res)
  {
    *received = (size_t) res;
    if (buf_size > (size_t) res)
      c->sk.ready = (enum mhd_SocketNetState) /* Clear 'recv-ready' */
                    (((unsigned int) c->sk.ready)
                     & (~(enum mhd_SocketNetState)
                        mhd_SOCKET_NET_STATE_RECV_READY));
    return mhd_SOCKET_ERR_NO_ERROR; /* Success exit point */
  }

  err = mhd_socket_error_get_from_sys_err (mhd_SCKT_GET_LERR ());

  if (mhd_SOCKET_ERR_AGAIN == err)
    c->sk.ready = (enum mhd_SocketNetState) /* Clear 'recv-ready' */
                  (((unsigned int) c->sk.ready)
                   & (~(enum mhd_SocketNetState)
                      mhd_SOCKET_NET_STATE_RECV_READY));

  return err; /* Failure exit point */
}


#ifdef MHD_SUPPORT_HTTPS

static MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_OUT_SIZE_ (3,2) MHD_FN_PAR_OUT_ (4) enum mhd_SocketError
mhd_recv_tls (struct MHD_Connection *restrict c,
              size_t buf_size,
              char buf[MHD_FN_PAR_DYN_ARR_SIZE_ (buf_size)],
              size_t *restrict received)
{
  /* TLS connection */
  enum mhd_SocketError res;

  mhd_assert (mhd_C_HAS_TLS (c));
  mhd_assert (0 != buf_size);

  res = mhd_tls_conn_recv (c->tls,
                           buf_size,
                           buf,
                           received);
  c->tls_has_data_in = mhd_TLS_BUF_NO_DATA; /* Updated with the actual value below */

  if (mhd_SOCKET_ERR_AGAIN == res)
    c->sk.ready = (enum mhd_SocketNetState) /* Clear 'recv-ready' */
                  (((unsigned int) c->sk.ready)
                   & (~(enum mhd_SocketNetState)
                      mhd_SOCKET_NET_STATE_RECV_READY));
  else if (mhd_SOCKET_ERR_NO_ERROR == res)
  {
    if (res == buf_size)
    {
      if (mhd_tls_conn_has_data_in (c->tls))
        c->tls_has_data_in = mhd_TLS_BUF_HAS_DATA_IN;
    }
#ifndef NDEBUG
    else
      mhd_assert (! mhd_tls_conn_has_data_in (c->tls));
#endif
  }

  return res;
}


#endif /* MHD_SUPPORT_HTTPS */

MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_OUT_SIZE_ (3,2) MHD_FN_PAR_OUT_ (4) enum mhd_SocketError
mhd_recv (struct MHD_Connection *restrict c,
          size_t buf_size,
          char buf[MHD_FN_PAR_DYN_ARR_SIZE_ (buf_size)],
          size_t *restrict received)
{
  mhd_assert (MHD_INVALID_SOCKET != c->sk.fd);
  mhd_assert (mhd_HTTP_STAGE_CLOSED != c->stage);

#ifdef MHD_SUPPORT_HTTPS
  if (mhd_C_HAS_TLS (c))
    return mhd_recv_tls (c,
                         buf_size,
                         buf,
                         received);
#endif /* MHD_SUPPORT_HTTPS */

  return mhd_recv_plain (c, buf_size, buf, received);
}
