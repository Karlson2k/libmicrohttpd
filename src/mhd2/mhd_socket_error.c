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
 * @file src/mhd2/mhd_socket_error.c
 * @brief  The definition of mhd_SocketError-related functions
 * @author Karlson2k (Evgeny Grin)
 */

#include "mhd_sys_options.h"
#include "mhd_socket_error.h"
#include "sys_sockets_headers.h"
#include "mhd_sockets_macros.h"
#include "sys_sockets_types.h"

MHD_INTERNAL enum mhd_SocketError
mhd_socket_error_get_from_sys_err (int socket_err)
{
  if (mhd_SCKT_ERR_IS_EAGAIN (socket_err))
    return mhd_SOCKET_ERR_AGAIN;
  else if (mhd_SCKT_ERR_IS_CONNRESET (socket_err))
    return mhd_SOCKET_ERR_CONNRESET;
  else if (mhd_SCKT_ERR_IS_EINTR (socket_err))
    return mhd_SOCKET_ERR_INTR;
  else if (mhd_SCKT_ERR_IS_CONN_BROKEN (socket_err))
    return mhd_SOCKET_ERR_CONN_BROKEN;
  else if (mhd_SCKT_ERR_IS_PIPE (socket_err))
    return mhd_SOCKET_ERR_PIPE;
  else if (mhd_SCKT_ERR_IS_NOTCONN (socket_err))
    return mhd_SOCKET_ERR_NOTCONN;
  else if (mhd_SCKT_ERR_IS_LOW_MEM (socket_err))
    return mhd_SOCKET_ERR_NOMEM;
  else if (mhd_SCKT_ERR_IS_BADF (socket_err))
    return mhd_SOCKET_ERR_BADF;
  else if (mhd_SCKT_ERR_IS_EINVAL (socket_err))
    return mhd_SOCKET_ERR_INVAL;
  else if (mhd_SCKT_ERR_IS_OPNOTSUPP (socket_err))
    return mhd_SOCKET_ERR_OPNOTSUPP;
  else if (mhd_SCKT_ERR_IS_NOTSOCK (socket_err))
    return mhd_SOCKET_ERR_NOTSOCK;

  return mhd_SOCKET_ERR_OTHER;
}


MHD_INTERNAL enum mhd_SocketError
mhd_socket_error_get_from_socket (MHD_Socket fd)
{
#if defined(SOL_SOCKET) && defined(SO_ERROR)
  enum mhd_SocketError err;
  int sock_err;
  socklen_t optlen = sizeof (sock_err);

  sock_err = 0;
  if ((0 == getsockopt (fd,
                        SOL_SOCKET,
                        SO_ERROR,
                        (void *) &sock_err,
                        &optlen))
      && (sizeof(sock_err) == optlen))
    return mhd_socket_error_get_from_sys_err (sock_err);

  err = mhd_socket_error_get_from_sys_err (mhd_SCKT_GET_LERR ());
  if ((mhd_SOCKET_ERR_NOTSOCK == err) ||
      (mhd_SOCKET_ERR_BADF == err))
    return err;
#endif /* SOL_SOCKET && SO_ERROR */
  return mhd_SOCKET_ERR_NOT_CHECKED;
}
