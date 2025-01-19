/*
  This file is part of GNU libmicrohttpd
  Copyright (C) 2025 Evgeny Grin (Karlson2k)

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
 * @file src/mhd2/conn_get_info.c
 * @brief  The implementation of MHD_connection_get_info_*() functions
 * @author Karlson2k (Evgeny Grin)
 */

#include "mhd_sys_options.h"

#include "mhd_unreachable.h"

#include "mhd_connection.h"

#include "daemon_funcs.h"
#ifdef MHD_SUPPORT_HTTPS
#  include "mhd_tls_funcs.h"
#endif

#include "mhd_public_api.h"

MHD_EXTERN_
MHD_FN_PAR_NONNULL_ (1)
MHD_FN_PAR_NONNULL_ (3) MHD_FN_PAR_OUT_ (3) enum MHD_StatusCode
MHD_connection_get_info_fixed_sz (
  struct MHD_Connection *connection,
  enum MHD_ConnectionInfoFixedType info_type,
  union MHD_ConnectionInfoFixedData *output_buf,
  size_t output_buf_size)
{
  switch (info_type)
  {
  case MHD_CONNECTION_INFO_FIXED_CLIENT_ADDRESS:
    if (NULL == connection->sk.addr.data)
    {
      if (mhd_T_IS_NOT_YES (connection->sk.props.is_nonip))
        return MHD_SC_INFO_GET_TYPE_UNOBTAINABLE;
      else
        return MHD_SC_INFO_GET_TYPE_NOT_APPLICABLE;
    }
    mhd_assert (0 != connection->sk.addr.size);
    if (sizeof(output_buf->v_sa_info) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
    output_buf->v_sa_info.sa_size = connection->sk.addr.size;
    output_buf->v_sa_info.sa =
      (const struct sockaddr*) connection->sk.addr.data;
    return MHD_SC_OK;
  case MHD_CONNECTION_INFO_FIXED_CONNECTION_FD:
    if (sizeof(output_buf->v_fd) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
    mhd_assert (MHD_INVALID_SOCKET != connection->sk.fd);
    output_buf->v_fd = connection->sk.fd;
    return MHD_SC_OK;
  case MHD_CONNECTION_INFO_FIXED_DAEMON:
    if (sizeof(output_buf->v_daemon) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
    output_buf->v_daemon = mhd_daemon_get_master_daemon (connection->daemon);
    return MHD_SC_OK;

  case MHD_CONNECTION_INFO_FIXED_SENTINEL:
  default:
    break;
  }
  return MHD_SC_INFO_GET_TYPE_UNKNOWN;
}
