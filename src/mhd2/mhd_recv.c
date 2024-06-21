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

#include <limits.h>

#ifndef SSIZE_MAX
#  define SSIZE_MAX ((ssize_t) ((~((size_t) 0)) >> 1))
#endif


MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_OUT_SIZE_ (3,2) \
  MHD_FN_PAR_OUT_ (4) enum mhd_SocketError
mhd_recv (struct MHD_Connection *restrict c,
          size_t buf_size,
          void *restrict buf,
          size_t *restrict received)
{
  mhd_assert (MHD_INVALID_SOCKET != c->socket_fd);
  mhd_assert (MHD_CONNECTION_CLOSED != c->state);

  // TODO: implement TLS support
  if (1) /* Plain TCP connection */
  {
    ssize_t res;
    int err;

    if (MHD_SCKT_SEND_MAX_SIZE_ < buf_size)
      buf_size = MHD_SCKT_SEND_MAX_SIZE_;

    res = mhd_sys_recv (c->socket_fd, buf, buf_size);
    if (0 <= res)
    {
      *received = (size_t) res;
      if (buf_size > (size_t) res)
        c->sk_ready =
          (enum mhd_SocketNetState) (((unsigned int) c->sk_ready)
                                     & (~mhd_SOCKET_NET_STATE_RECV_READY));
      return mhd_SOCKET_ERR_NO_ERROR; /* Success exit point */
    }

    err = mhd_SCKT_GET_LERR ();

    if (mhd_SCKT_ERR_IS_EAGAIN (err))
    {
      c->sk_ready = /* Clear 'recv-ready' */
                    (enum mhd_SocketNetState)
                    (((unsigned int) c->sk_ready)
                     & (~mhd_SOCKET_NET_STATE_RECV_READY));
      return mhd_SOCKET_ERR_AGAIN;
    }
    else if (mhd_SCKT_ERR_IS_CONNRESET (err))
      return mhd_SOCKET_ERR_CONNRESET;
    else if (mhd_SCKT_ERR_IS_EINTR (err))
      return mhd_SOCKET_ERR_INTR;
    else if (mhd_SCKT_ERR_IS_CONN_BROKEN (err))
      return mhd_SOCKET_ERR_CONN_BROKEN;
    else if (mhd_SCKT_ERR_IS_NOTCONN (err))
      return mhd_SOCKET_ERR_NOTCONN;
    else if (mhd_SCKT_ERR_IS_LOW_MEM (err))
      return mhd_SOCKET_ERR_NOMEM;
    else if (mhd_SCKT_ERR_IS_BADF (err))
      return mhd_SOCKET_ERR_BADF;
    else if (mhd_SCKT_ERR_IS_EINVAL (err))
      return mhd_SOCKET_ERR_INVAL;
    else if (mhd_SCKT_ERR_IS_OPNOTSUPP (err))
      return mhd_SOCKET_ERR_OPNOTSUPP;
    else if (mhd_SCKT_ERR_IS_NOTSOCK (err))
      return mhd_SOCKET_ERR_NOTSOCK;
  }

  return mhd_SOCKET_ERR_OTHER;
}
