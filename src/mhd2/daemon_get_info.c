/*
  This file is part of GNU libmicrohttpd
  Copyright (C) 2024-2025 Evgeny Grin (Karlson2k)

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

#include "mhd_unreachable.h"

#include "sys_base_types.h"
#include "sys_sockets_types.h"

#include "mhd_socket_type.h"
#include "mhd_daemon.h"
#include "events_process.h"
#ifdef MHD_SUPPORT_HTTPS
#  include "mhd_tls_choice.h"
#  ifdef MHD_USE_MULTITLS
#    include "tls_multi_daemon_data.h"
#  endif
#endif

#include "mhd_public_api.h"

MHD_EXTERN_ MHD_FN_MUST_CHECK_RESULT_
MHD_FN_PAR_NONNULL_ (1)
MHD_FN_PAR_NONNULL_ (3) MHD_FN_PAR_OUT_ (3) enum MHD_StatusCode
MHD_daemon_get_info_fixed_sz (
  struct MHD_Daemon *MHD_RESTRICT daemon,
  enum MHD_DaemonInfoFixedType info_type,
  union MHD_DaemonInfoFixedData *MHD_RESTRICT output_buf,
  size_t output_buf_size)
{
  if (mhd_DAEMON_STATE_STARTED > daemon->state)
    return MHD_SC_TOO_EARLY;
  if (mhd_DAEMON_STATE_STARTED < daemon->state)
    return MHD_SC_TOO_LATE;

  switch (info_type)
  {
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
    if (sizeof(output_buf->v_bind_port_uint16) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
    output_buf->v_bind_port_uint16 = daemon->net.listen.port;
    return MHD_SC_OK;
  case MHD_DAEMON_INFO_FIXED_LISTEN_SOCKET:
    if (MHD_INVALID_SOCKET == daemon->net.listen.fd)
      return MHD_SC_INFO_GET_TYPE_NOT_APPLICABLE;
    if (sizeof(output_buf->v_listen_socket) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
    output_buf->v_listen_socket = daemon->net.listen.fd;
    return MHD_SC_OK;
  case MHD_DAEMON_INFO_FIXED_AGGREAGATE_FD:
#ifdef MHD_SUPPORT_EPOLL
    if (! mhd_D_IS_USING_EPOLL (daemon))
      return MHD_SC_INFO_GET_TYPE_NOT_APPLICABLE;
    if (sizeof(output_buf->v_aggreagate_fd) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
    output_buf->v_aggreagate_fd = daemon->events.data.epoll.e_fd;
    return MHD_SC_OK;
#else
    return MHD_SC_INFO_GET_TYPE_NOT_SUPP_BY_BUILD;
#endif
    break;
  case MHD_DAEMON_INFO_FIXED_TLS_BACKEND:
    if (sizeof(output_buf->v_tls_backend) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
    if (! mhd_D_HAS_TLS (daemon))
      output_buf->v_tls_backend = MHD_TLS_BACKEND_NONE;
    else
    {
#if ! defined(MHD_SUPPORT_HTTPS)
      mhd_UNREACHABLE ();
#elif defined(MHD_USE_MULTITLS)
      switch (daemon->tls->choice)
      {
#  ifdef MHD_SUPPORT_GNUTLS
      case mhd_TLS_MULTI_ROUTE_GNU:
        output_buf->v_tls_backend = MHD_TLS_BACKEND_GNUTLS;
        break;
#  endif
#  ifdef MHD_SUPPORT_OPENSSL
      case mhd_TLS_MULTI_ROUTE_OPEN:
        output_buf->v_tls_backend = MHD_TLS_BACKEND_OPENSSL;
        break;
#  endif
      case mhd_TLS_MULTI_ROUTE_NONE:
      default:
        mhd_UNREACHABLE ();
        break;
      }
#elif defined(MHD_SUPPORT_GNUTLS)
      output_buf->v_tls_backend = MHD_TLS_BACKEND_GNUTLS;
#elif defined(MHD_SUPPORT_OPENSSL)
      output_buf->v_tls_backend = MHD_TLS_BACKEND_OPENSSL;
#else
#error No TLS backends enabled, while TLS support is enabled
#endif
    }
    break;
    return MHD_SC_OK;

  case MHD_DAEMON_INFO_FIXED_SENTINEL:
  default:
    break;
  }
  return MHD_SC_INFO_GET_TYPE_UNKNOWN;
}


MHD_EXTERN_ MHD_FN_MUST_CHECK_RESULT_
MHD_FN_PAR_NONNULL_ (1)
MHD_FN_PAR_NONNULL_ (3) MHD_FN_PAR_OUT_ (3) enum MHD_StatusCode
MHD_daemon_get_info_dynamic_sz (
  struct MHD_Daemon *MHD_RESTRICT daemon,
  enum MHD_DaemonInfoDynamicType info_type,
  union MHD_DaemonInfoDynamicData *MHD_RESTRICT output_buf,
  size_t output_buf_size)
{
  if (mhd_DAEMON_STATE_STARTED > daemon->state)
    return MHD_SC_TOO_EARLY;
  if (mhd_DAEMON_STATE_STARTED < daemon->state)
    return MHD_SC_TOO_LATE;

  switch (info_type)
  {
  case MHD_DAEMON_INFO_DYNAMIC_MAX_TIME_TO_WAIT:
    if (mhd_WM_INT_HAS_THREADS (daemon->wmode_int))
      return MHD_SC_INFO_GET_TYPE_NOT_APPLICABLE;
    if (sizeof(output_buf->v_max_time_to_wait_uint64) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
    output_buf->v_max_time_to_wait_uint64 = mhd_daemon_get_wait_max (daemon);
    return MHD_SC_OK;
  case MHD_DAEMON_INFO_DYNAMIC_HAS_CONNECTIONS:
    if (sizeof(output_buf->v_has_connections_bool) <= output_buf_size)
    {
      enum MHD_Bool res;
      /*
         Reading number of connection from the daemon member could be non-atomic
         and may give wrong result (if it is modified in other thread), however
         test against zero/non-zero value is valid even if reading is
         non-atomic.
       */
      if (! mhd_D_HAS_WORKERS (daemon))
        res = (0 != daemon->conns.count) ? MHD_YES : MHD_NO;
      else
      {
        unsigned int i;
        res = MHD_NO;
        mhd_assert (NULL != daemon->threading.hier.pool.workers);
        for (i = 0; i < daemon->threading.hier.pool.num; ++i)
        {
          if (0 != daemon->threading.hier.pool.workers[i].conns.count)
          {
            res = MHD_YES;
            break;
          }
        }
      }
      output_buf->v_has_connections_bool = res;
      return MHD_SC_OK;
    }
    return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
  case MHD_DAEMON_INFO_DYNAMIC_SENTINEL:
  default:
    break;
  }
  return MHD_SC_INFO_GET_TYPE_UNKNOWN;
}
