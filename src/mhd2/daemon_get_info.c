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
 * @file src/mhd2/daemon_get_info.c
 * @brief  The implementation of MHD_daemon_get_info_*() functions
 * @author Karlson2k (Evgeny Grin)
 */

#include "mhd_sys_options.h"

#include "sys_base_types.h"
#include "sys_sockets_types.h"

#include "mhd_socket_type.h"
#include "mhd_daemon.h"

#include "mhd_public_api.h"

MHD_EXTERN_
MHD_FN_PAR_NONNULL_ (1)
MHD_FN_PAR_NONNULL_ (3) MHD_FN_PAR_OUT_ (3) enum MHD_StatusCode
MHD_daemon_get_info_fixed_sz (struct MHD_Daemon *daemon,
                              enum MHD_DaemonInfoFixedType info_type,
                              union MHD_DaemonInfoFixedData *output_buf,
                              size_t output_buf_size)
{
  switch (info_type)
  {
  case MHD_DAEMON_INFO_FIXED_LISTEN_SOCKET:
    if (MHD_INVALID_SOCKET == daemon->net.listen.fd)
      return MHD_SC_INFO_GET_TYPE_NOT_APPLICABLE;
    if (sizeof(MHD_Socket) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
    output_buf->v_socket = daemon->net.listen.fd;
    return MHD_SC_OK;
  case MHD_DAEMON_INFO_FIXED_AGGREAGATE_FD:
#ifdef MHD_SUPPORT_EPOLL
    if (! mhd_D_IS_USING_EPOLL (daemon))
      return MHD_SC_INFO_GET_TYPE_NOT_APPLICABLE;
    if (sizeof(int) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
    output_buf->v_fd = daemon->events.data.epoll.e_fd;
    return MHD_SC_OK;
#else
    return MHD_SC_INFO_GET_TYPE_NOT_SUPP_BY_BUILD;
#endif
    break;
  case MHD_DAEMON_INFO_FIXED_BIND_PORT:
    if (MHD_INVALID_SOCKET == daemon->net.listen.fd)
      return MHD_SC_INFO_GET_TYPE_NOT_APPLICABLE;
    if (mhd_SOCKET_TYPE_UNKNOWN > daemon->net.listen.type)
      return MHD_SC_INFO_GET_TYPE_NOT_APPLICABLE;
    if (0 == daemon->net.listen.port)
    {
      if (mhd_SOCKET_TYPE_IP != daemon->net.listen.type)
        return MHD_SC_INFO_GET_TYPE_NOT_APPLICABLE;
      return MHD_SC_INFO_GET_TYPE_UNOBTAINABLE;
    }
    if (sizeof(output_buf->v_port) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
    output_buf->v_port = daemon->net.listen.port;
    return MHD_SC_OK;
  case MHD_DAEMON_INFO_FIXED_SENTINEL:
  default:
    break;
  }
  return MHD_SC_INFO_GET_TYPE_UNKNOWN;
}
