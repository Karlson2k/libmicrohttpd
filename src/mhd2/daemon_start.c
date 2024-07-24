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
 * @file src/mhd2/daemon_start.c
 * @brief  The implementation of the MHD_daemon_start()
 * @author Karlson2k (Evgeny Grin)
 */

#include "mhd_sys_options.h"

#include "sys_base_types.h"
#include "sys_malloc.h"

#include <string.h>
#include "sys_sockets_types.h"
#include "sys_sockets_headers.h"
#include "mhd_sockets_macros.h"
#include "sys_ip_headers.h"

#ifdef MHD_POSIX_SOCKETS
#  include "sys_errno.h"
#endif
#ifdef MHD_USE_EPOLL
#  include <sys/epoll.h>
#endif

#ifdef MHD_POSIX_SOCKETS
#  include <fcntl.h>
#  ifdef MHD_USE_SELECT
#    ifdef HAVE_SYS_SELECT_H
#      include <sys/select.h> /* For FD_SETSIZE */
#    else
#      ifdef HAVE_SYS_TIME_H
#        include <sys/time.h>
#      endif
#      ifdef HAVE_SYS_TYPES_H
#        include <sys/types.h>
#      endif
#      ifdef HAVE_UNISTD_H
#        include <unistd.h>
#      endif
#    endif
#  endif
#endif

#include "mhd_limits.h"

#include "mhd_daemon.h"
#include "daemon_options.h"

#include "mhd_assert.h"
#include "mhd_sockets_funcs.h"
#include "daemon_logger.h"

#ifdef MHD_USE_THREADS
#  include "mhd_itc.h"
#  include "mhd_threads.h"
#  include "events_process.h"
#  include "daemon_funcs.h"
#endif

#include "mhd_public_api.h"


/**
 * The default value for fastopen queue length (currently GNU/Linux only)
 */
#define MHD_TCP_FASTOPEN_DEF_QUEUE_LEN 64

/**
 * Release any internally allocated pointers, then deallocate the settings.
 * @param s the pointer to the settings to release
 */
static void
dsettings_release (struct DaemonOptions *s)
{
  /* Release starting from the last member */
  if (NULL != s->random_entropy.v_buf)
    free (s->random_entropy.v_buf);
  if (MHD_INVALID_SOCKET != s->listen_socket)
    mhd_socket_close (s->listen_socket);
  if (NULL != s->bind_sa.v_sa)
    free (s->bind_sa.v_sa);
  free (s);
}


/**
 * Set the daemon work mode and perform some related checks.
 * @param d the daemon object
 * @param s the user settings
 * @return MHD_SC_OK on success,
 *         the error code otherwise
 */
static MHD_FN_PAR_NONNULL_ (1) MHD_FN_PAR_NONNULL_ (2)
MHD_FN_MUST_CHECK_RESULT_ enum MHD_StatusCode
daemon_set_work_mode (struct MHD_Daemon *restrict d,
                      struct DaemonOptions *restrict s)
{
  switch (s->work_mode.mode)
  {
  case MHD_WM_EXTERNAL_PERIODIC:
    d->wmode_int = mhd_WM_INT_INTERNAL_EVENTS_NO_THREADS;
    break;
  case MHD_WM_EXTERNAL_EVENT_LOOP_CB_LEVEL:
  case MHD_WM_EXTERNAL_EVENT_LOOP_CB_EDGE:
    if (MHD_SPS_AUTO != s->poll_syscall)
    {
      mhd_LOG_MSG ( \
        d, MHD_SC_SYSCALL_WORK_MODE_COMBINATION_INVALID, \
        "The requested work mode is not compatible with setting " \
        "socket polling syscall.");
      return MHD_SC_SYSCALL_WORK_MODE_COMBINATION_INVALID;
    }
    if (MHD_WM_EXTERNAL_EVENT_LOOP_CB_LEVEL == s->work_mode.mode)
      d->wmode_int = mhd_WM_INT_EXTERNAL_EVENTS_LEVEL;
    else
      d->wmode_int = mhd_WM_INT_EXTERNAL_EVENTS_EDGE;
    break;
  case MHD_WM_EXTERNAL_SINGLE_FD_WATCH:
    if ((MHD_SPS_AUTO != s->poll_syscall) &&
        (MHD_SPS_EPOLL != s->poll_syscall))
    {
      mhd_LOG_MSG ( \
        d, MHD_SC_SYSCALL_WORK_MODE_COMBINATION_INVALID, \
        "The requested work mode MHD_WM_EXTERNAL_SINGLE_FD_WATCH " \
        "is not compatible with requested socket polling syscall.");
      return MHD_SC_SYSCALL_WORK_MODE_COMBINATION_INVALID;
    }
#ifndef MHD_USE_EPOLL
    mhd_LOG_MSG ( \
      d, MHD_SC_FEATURE_DISABLED, \
      "The epoll is required for the requested work mode " \
      "MHD_WM_EXTERNAL_SINGLE_FD_WATCH, but not available on this " \
      "platform or MHD build.");
    return MHD_SC_FEATURE_DISABLED;
#else
    d->wmode_int = mhd_WM_INT_INTERNAL_EVENTS_NO_THREADS;
#endif
    break;
  case MHD_WM_THREAD_PER_CONNECTION:
    if (MHD_SPS_EPOLL == s->poll_syscall)
    {
      mhd_LOG_MSG ( \
        d, MHD_SC_SYSCALL_WORK_MODE_COMBINATION_INVALID, \
        "The requested work mode MHD_WM_THREAD_PER_CONNECTION " \
        "is not compatible with 'epoll' sockets polling.");
      return MHD_SC_SYSCALL_WORK_MODE_COMBINATION_INVALID;
    }
  /* Intentional fallthrough */
  case MHD_WM_WORKER_THREADS:
#ifndef MHD_USE_THREADS
    mhd_LOG_MSG (d, MHD_SC_FEATURE_DISABLED, \
                 "The internal threads modes are not supported by this " \
                 "build of MHD.");
    return MHD_SC_FEATURE_DISABLED;
#else  /* MHD_USE_THREADS */
    if (MHD_WM_THREAD_PER_CONNECTION == s->work_mode.mode)
      d->wmode_int = mhd_WM_INT_INTERNAL_EVENTS_THREAD_PER_CONNECTION;
    else if (1 >= s->work_mode.params.num_worker_threads)   /* && (MHD_WM_WORKER_THREADS == s->work_mode.mode) */
      d->wmode_int = mhd_WM_INT_INTERNAL_EVENTS_ONE_THREAD;
    else
      d->wmode_int = mhd_WM_INT_INTERNAL_EVENTS_THREAD_POOL;
#endif /* MHD_USE_THREADS */
    break;
  default:
    mhd_LOG_MSG (d, MHD_SC_CONFIGURATION_UNEXPECTED_WM, \
                 "Wrong requested work mode.");
    return MHD_SC_CONFIGURATION_UNEXPECTED_WM;
  }

  return MHD_SC_OK;
}


union mhd_SockaddrAny
{
  struct sockaddr sa;
  struct sockaddr_in sa_i4;
#ifdef HAVE_INET6
  struct sockaddr_in6 sa_i6;
#endif /* HAVE_INET6 */
  struct sockaddr_storage sa_stor;
};


/**
 * The type of the socket to create
 */
enum mhd_CreateSktType
{
  /**
   * Unknown address family (could be IP or not IP)
   */
  mhd_SKT_UNKNOWN = -4
  ,
  /**
   * The socket is not IP.
   */
  mhd_SKT_NON_IP = -2
  ,
  /**
   * The socket is UNIX.
   */
  mhd_SKT_UNIX = -1
  ,
  /**
   * No socket
   */
  mhd_SKT_NO_SOCKET = MHD_AF_NONE
  ,
  /**
   * IPv4 only
   */
  mhd_SKT_IP_V4_ONLY = MHD_AF_INET4
  ,
  /**
   * IPv6 only
   */
  mhd_SKT_IP_V6_ONLY = MHD_AF_INET6
  ,
  /**
   * IPv6 with dual stack enabled
   */
  mhd_SKT_IP_DUAL_REQUIRED = MHD_AF_DUAL
  ,
  /**
   * Try IPv6 with dual stack then IPv4
   */
  mhd_SKT_IP_V4_WITH_V6_OPT = MHD_AF_DUAL_v6_OPTIONAL
  ,
  /**
   * IPv6 with optional dual stack
   */
  mhd_SKT_IP_V6_WITH_V4_OPT = MHD_AF_DUAL_v4_OPTIONAL
  ,
  /**
   * Try IPv4 then IPv6 with optional dual stack
   */
  mhd_SKT_IP_V4_WITH_FALLBACK = 16
};

/**
 * Create socket, bind to the address and start listening on the socket.
 *
 * The socket is assigned to the daemon as listening FD.
 * @param d the daemon to use
 * @param s the user settings
 * @param v6_tried true if IPv6 has been tried already
 * @param force_v6_any_dual true if IPv6 is forced with dual stack either
 *                          enabled or not
 * @return #MHD_SC_OK on success,
 *         the error code otherwise
 */
static enum MHD_StatusCode
create_bind_listen_stream_socket (struct MHD_Daemon *restrict d,
                                  struct DaemonOptions *restrict s,
                                  bool v6_tried,
                                  bool force_v6_any_dual)
{
  MHD_Socket sk;
  enum mhd_CreateSktType sk_type;
  bool sk_already_listening;
  union mhd_SockaddrAny sa_all;
  const struct sockaddr *p_use_sa;
  socklen_t use_sa_size;
  uint_least16_t sk_port;
  bool is_non_block;
  bool is_non_inhr;
  enum MHD_StatusCode ret;

  sk = MHD_INVALID_SOCKET;
  sk_type = mhd_SKT_NO_SOCKET;
  sk_already_listening = false;
  p_use_sa = NULL;
  use_sa_size = 0;
  sk_port = 0;

#ifndef HAVE_INET6
  mhd_assert (! v6_tried);
  mhd_assert (! force_v6_any_dual);
#endif

  if (MHD_INVALID_SOCKET != s->listen_socket)
  {
    mhd_assert (! v6_tried);
    mhd_assert (! force_v6_any_dual);
    /* Check for options conflicts */
    if (0 != s->bind_sa.v_sa_len)
    {
      mhd_LOG_MSG (d, MHD_SC_OPTIONS_CONFLICT, \
                   "MHD_D_O_BIND_SA cannot be used together " \
                   "with MHD_D_O_LISTEN_SOCKET");
      return MHD_SC_OPTIONS_CONFLICT;
    }
    else if (MHD_AF_NONE != s->bind_port.v_af)
    {
      mhd_LOG_MSG (d, MHD_SC_OPTIONS_CONFLICT, \
                   "MHD_D_O_BIND_PORT cannot be used together " \
                   "with MHD_D_O_LISTEN_SOCKET");
      return MHD_SC_OPTIONS_CONFLICT;
    }

    /* No options conflicts */
    sk = s->listen_socket;
    s->listen_socket = MHD_INVALID_SOCKET; /* Prevent closing with settings cleanup */
    sk_type = mhd_SKT_UNKNOWN;
    sk_already_listening = true;
  }
  else if ((0 != s->bind_sa.v_sa_len) || (MHD_AF_NONE != s->bind_port.v_af))
  {
    if (0 != s->bind_sa.v_sa_len)
    {
      mhd_assert (! v6_tried);
      mhd_assert (! force_v6_any_dual);

      /* Check for options conflicts */
      if (MHD_AF_NONE != s->bind_port.v_af)
      {
        mhd_LOG_MSG (d, MHD_SC_OPTIONS_CONFLICT, \
                     "MHD_D_O_BIND_SA cannot be used together " \
                     "with MHD_D_O_BIND_PORT");
        return MHD_SC_OPTIONS_CONFLICT;
      }

      /* No options conflicts */
      switch (s->bind_sa.v_sa->sa_family)
      {
      case AF_INET:
        sk_type = mhd_SKT_IP_V4_ONLY;
        if (sizeof(sa_all.sa_i4) > s->bind_sa.v_sa_len)
        {
          mhd_LOG_MSG (d, MHD_SC_CONFIGURATION_WRONG_SA_SIZE, \
                       "The size of the provided sockaddr does not match "
                       "used address family");
          return MHD_SC_CONFIGURATION_WRONG_SA_SIZE;
        }
        memcpy (&(sa_all.sa_i4), s->bind_sa.v_sa, sizeof(sa_all.sa_i4));
        sk_port = (uint_least16_t) ntohs (sa_all.sa_i4.sin_port);
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
        sa_all.sa_i4.sin_len = (socklen_t) sizeof(sa_all.sa_i4);
#endif
        p_use_sa = (struct sockaddr *) &(sa_all.sa_i4);
        use_sa_size = (socklen_t) sizeof(sa_all.sa_i4);
        break;
#ifdef HAVE_INET6
      case AF_INET6:
        sk_type = mhd_SKT_IP_V6_ONLY;
        if (sizeof(sa_all.sa_i6) > s->bind_sa.v_sa_len)
        {
          mhd_LOG_MSG (d, MHD_SC_CONFIGURATION_WRONG_SA_SIZE, \
                       "The size of the provided sockaddr does not match "
                       "used address family");
          return MHD_SC_CONFIGURATION_WRONG_SA_SIZE;
        }
        memcpy (&(sa_all.sa_i6), s->bind_sa.v_sa, s->bind_sa.v_sa_len);
        sk_port = (uint_least16_t) ntohs (sa_all.sa_i6.sin6_port);
#ifdef HAVE_STRUCT_SOCKADDR_IN6_SIN6_LEN
        sa_all.sa_i6.sin6_len = (socklen_t) s->bind_sa.v_sa_len;
#endif
        p_use_sa = (struct sockaddr *) &(sa_all.sa_i6);
        use_sa_size = (socklen_t) sizeof(sa_all.sa_i6);
        break;
#endif /* HAVE_INET6 */
#ifdef MHD_AF_UNIX
      case MHD_AF_UNIX:
        sk_type = mhd_SKT_UNIX;
        p_use_sa = NULL; /* To be set below */
        break;
#endif /* MHD_AF_UNIX */
      default:
        sk_type = mhd_SKT_UNKNOWN;
        p_use_sa = NULL; /* To be set below */
      }

      if (s->bind_sa.v_dual)
      {
        if (mhd_SKT_IP_V6_ONLY != sk_type)
        {
          mhd_LOG_MSG (d, MHD_SC_LISTEN_DUAL_STACK_NOT_SUITABLE, \
                       "IP dual stack is not possible for provided sockaddr");
        }
#ifdef HAVE_INET6
        else
        {
#ifdef IPV6_V6ONLY // TODO: detect constants declarations in configure
          sk_type = mhd_SKT_IP_DUAL_REQUIRED;
#else  /* ! IPV6_V6ONLY */
          mhd_LOG_MSG (d, \
                       MHD_SC_LISTEN_DUAL_STACK_CONFIGURATION_NOT_SUPPORTED, \
                       "IP dual stack is not supported by this platform or " \
                       "by this MHD build");
#endif /* ! IPV6_V6ONLY */
        }
#endif /* HAVE_INET6 */
      }

      if (NULL == p_use_sa)
      {
#if defined(HAVE_STRUCT_SOCKADDR_SA_LEN) && \
        defined(HAVE_STRUCT_SOCKADDR_STORAGE_SS_LEN)
        if ((((size_t) s->bind_sa.v_sa->sa_len) != s->bind_sa.v_sa_len) &&
            (sizeof(sa_all) >= s->bind_sa.v_sa_len))
        {
          /* Fix embedded 'sa_len' member if possible */
          memcpy (&sa_all, s->bind_sa.v_sa, s->bind_sa.v_sa_len);
          sa_all.sa_stor.ss_len = (socklen_t) s->bind_sa.v_sa_len;
          p_use_sa = (const struct sockaddr *) &(sa_all.sa_stor);
        }
        else
#endif /* HAVE_STRUCT_SOCKADDR_SA_LEN && HAVE_STRUCT_SOCKADDR_STORAGE_SS_LEN */
        p_use_sa = s->bind_sa.v_sa;
        use_sa_size = (socklen_t) s->bind_sa.v_sa_len;
      }
    }
    else /* if (MHD_AF_NONE != s->bind_port.v_af) */
    {
      /* No options conflicts */
      switch (s->bind_port.v_af)
      {
      case MHD_AF_NONE:
        mhd_assert (0);
        MHD_UNREACHABLE_;
        return MHD_SC_INTERNAL_ERROR;
      case MHD_AF_AUTO:
#ifdef HAVE_INET6
#ifdef IPV6_V6ONLY // TODO: detect constants declarations in configure
        if (force_v6_any_dual)
          sk_type = mhd_SKT_IP_V6_WITH_V4_OPT;
        else if (v6_tried)
          sk_type = mhd_SKT_IP_V4_WITH_FALLBACK;
        else
          sk_type = mhd_SKT_IP_V4_WITH_V6_OPT;
#else  /* ! IPV6_V6ONLY */
        mhd_assert (! v6_tried);
        if (force_v6_any_dual)
          sk_type = mhd_SKT_IP_V6_ONLY;
        else
          sk_type = mhd_SKT_IP_V4_WITH_FALLBACK;
#endif /* ! IPV6_V6ONLY */
#else  /* ! HAVE_INET6 */
        sk_type = mhd_SKT_IP_V4_ONLY;
#endif /* ! HAVE_INET6 */
        break;
      case MHD_AF_INET4:
        mhd_assert (! v6_tried);
        mhd_assert (! force_v6_any_dual);
        sk_type = mhd_SKT_IP_V4_ONLY;
        break;
      case MHD_AF_INET6:
        mhd_assert (! v6_tried);
        mhd_assert (! force_v6_any_dual);
#ifdef HAVE_INET6
        sk_type = mhd_SKT_IP_V6_ONLY;
#else  /* ! HAVE_INET6 */
        mhd_LOG_MSG (d, MHD_SC_IPV6_NOT_SUPPORTED_BY_BUILD, \
                     "IPv6 is not supported by this MHD build or " \
                     "by this platform");
        return MHD_SC_IPV6_NOT_SUPPORTED_BY_BUILD;
#endif /* ! HAVE_INET6 */
        break;
      case MHD_AF_DUAL:
        mhd_assert (! v6_tried);
        mhd_assert (! force_v6_any_dual);
#ifdef HAVE_INET6
#ifdef IPV6_V6ONLY // TODO: detect constants declarations in configure
        sk_type = mhd_SKT_IP_DUAL_REQUIRED;
#else  /* ! IPV6_V6ONLY */
        mhd_LOG_MSG (d,
                     MHD_SC_LISTEN_DUAL_STACK_CONFIGURATION_NOT_SUPPORTED, \
                     "IP dual stack is not supported by this platform or " \
                     "by this MHD build");
        sk_type = mhd_SKT_IP_V6_ONLY;
#endif /* ! IPV6_V6ONLY */
#else  /* ! HAVE_INET6 */
        mhd_LOG_MSG (d, MHD_SC_IPV6_NOT_SUPPORTED_BY_BUILD, \
                     "IPv6 is not supported by this MHD build or " \
                     "by this platform");
        return MHD_SC_IPV6_NOT_SUPPORTED_BY_BUILD;
#endif /* ! HAVE_INET6 */
        break;
      case MHD_AF_DUAL_v4_OPTIONAL:
        mhd_assert (! v6_tried);
        mhd_assert (! force_v6_any_dual);
#ifdef HAVE_INET6
#ifdef IPV6_V6ONLY // TODO: detect constants declarations in configure
        sk_type = mhd_SKT_IP_V6_WITH_V4_OPT;
#else  /* ! IPV6_V6ONLY */
        sk_type = mhd_SKT_IP_V6_ONLY;
#endif /* ! IPV6_V6ONLY */
#else  /* ! HAVE_INET6 */
        mhd_LOG_MSG (d, MHD_SC_IPV6_NOT_SUPPORTED_BY_BUILD, \
                     "IPv6 is not supported by this MHD build or " \
                     "by this platform");
        return MHD_SC_IPV6_NOT_SUPPORTED_BY_BUILD;
#endif /* ! HAVE_INET6 */
        break;
      case MHD_AF_DUAL_v6_OPTIONAL:
        mhd_assert (! force_v6_any_dual);
#ifdef HAVE_INET6
#ifdef IPV6_V6ONLY // TODO: detect constants declarations in configure
        sk_type = (! v6_tried) ?
                  mhd_SKT_IP_V4_WITH_V6_OPT : mhd_SKT_IP_V4_ONLY;
#else  /* ! IPV6_V6ONLY */
        mhd_assert (! v6_tried);
        sk_type = mhd_SKT_IP_V4_ONLY;
#endif /* ! IPV6_V6ONLY */
#else  /* ! HAVE_INET6 */
        mhd_assert (! v6_tried);
        sk_type = mhd_SKT_IP_V4_ONLY;
#endif /* ! HAVE_INET6 */
        break;
      default:
        mhd_LOG_MSG (d, MHD_SC_AF_NOT_SUPPORTED_BY_BUILD, \
                     "Unknown address family specified");
        return MHD_SC_AF_NOT_SUPPORTED_BY_BUILD;
      }

      mhd_assert (mhd_SKT_NO_SOCKET < sk_type);

      switch (sk_type)
      {
      case mhd_SKT_IP_V4_ONLY:
      case mhd_SKT_IP_V4_WITH_FALLBACK:
        /* Zeroing is not required, but may help on exotic platforms */
        memset (&(sa_all.sa_i4), 0, sizeof(sa_all.sa_i4));
        sa_all.sa_i4.sin_family = AF_INET;
        sa_all.sa_i4.sin_port = htons (s->bind_port.v_port);
        if (0 == INADDR_ANY) /* Optimised at compile time */
          sa_all.sa_i4.sin_addr.s_addr = INADDR_ANY;
        else
          sa_all.sa_i4.sin_addr.s_addr = htonl (INADDR_ANY);
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
        sa_all.sa_i4.sin_len = sizeof (sa_all.sa_i4);
#endif
        p_use_sa = (const struct sockaddr *) &(sa_all.sa_i4);
        use_sa_size = (socklen_t) sizeof (sa_all.sa_i4);
        break;
      case mhd_SKT_IP_V6_ONLY:
      case mhd_SKT_IP_DUAL_REQUIRED:
      case mhd_SKT_IP_V4_WITH_V6_OPT:
      case mhd_SKT_IP_V6_WITH_V4_OPT:
#ifdef HAVE_INET6
        if (1)
        {
#ifdef IN6ADDR_ANY_INIT
          static const struct in6_addr static_in6any = IN6ADDR_ANY_INIT;
#endif
          /* Zeroing is required by POSIX */
          memset (&(sa_all.sa_i6), 0, sizeof(sa_all.sa_i6));
          sa_all.sa_i6.sin6_family = AF_INET6;
          sa_all.sa_i6.sin6_port = htons (s->bind_port.v_port);
#ifdef IN6ADDR_ANY_INIT /* Optional assignment at the address is all zeros anyway */
          sa_all.sa_i6.sin6_addr = static_in6any;
#endif
#ifdef HAVE_STRUCT_SOCKADDR_IN6_SIN6_LEN
          sa_all.sa_i6.sin6_len = sizeof (sa_all.sa_i6);
#endif
          p_use_sa = (const struct sockaddr *) &(sa_all.sa_i6);
          use_sa_size = (socklen_t) sizeof (sa_all.sa_i6);
        }
        break;
#endif /* HAVE_INET6 */
      case mhd_SKT_UNKNOWN:
      case mhd_SKT_NON_IP:
      case mhd_SKT_UNIX:
      case mhd_SKT_NO_SOCKET:
      default:
        mhd_assert (0);
        MHD_UNREACHABLE_;
        return MHD_SC_INTERNAL_ERROR;
      }

      sk_port = s->bind_port.v_port;

    }
  }
  else
  {
    /* No listen socket */
    d->net.listen.fd = MHD_INVALID_SOCKET;
    d->net.listen.type = mhd_SOCKET_TYPE_UNKNOWN;
    d->net.listen.non_block = false;
    d->net.listen.port = 0;

    return MHD_SC_OK;
  }

  mhd_assert (mhd_SKT_NO_SOCKET != sk_type);
  mhd_assert ((NULL != p_use_sa) || sk_already_listening);
  mhd_assert ((MHD_INVALID_SOCKET == sk) || sk_already_listening);

  if (MHD_INVALID_SOCKET == sk)
  {
    mhd_assert (NULL != p_use_sa);
#if defined(MHD_WINSOCK_SOCKETS) && defined(WSA_FLAG_NO_HANDLE_INHERIT)
    /* May fail before Win7 SP1 */
    sk = WSASocketW (p_use_sa->sa_family, SOCK_STREAM, 0,
                     NULL, 0, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);

    if (MHD_INVALID_SOCKET == sk)
#endif /* MHD_WINSOCK_SOCKETS && WSA_FLAG_NO_HANDLE_INHERIT */
    sk = socket (p_use_sa->sa_family,
                 SOCK_STREAM | mhd_SOCK_NONBLOCK
                 | mhd_SOCK_CLOEXEC | mhd_SOCK_NOSIGPIPE, 0);

    if (MHD_INVALID_SOCKET == sk)
    {
      bool is_af_err = mhd_SCKT_LERR_IS_AF ();

      if (is_af_err)
        mhd_LOG_MSG (d, MHD_SC_AF_NOT_AVAILABLE, \
                     "The requested socket address family is rejected " \
                     "by the OS");

#ifdef HAVE_INET6
      if (mhd_SKT_IP_V4_WITH_FALLBACK == sk_type)
        return create_bind_listen_stream_socket (d, s, v6_tried, true);
      if (mhd_SKT_IP_V4_WITH_V6_OPT == sk_type)
        return create_bind_listen_stream_socket (d, s, true, false);
#endif /* HAVE_INET6 */

      if (! is_af_err)
        mhd_LOG_MSG (d, MHD_SC_FAILED_TO_OPEN_LISTEN_SOCKET, \
                     "Failed to open listen socket");

      return MHD_SC_FAILED_TO_OPEN_LISTEN_SOCKET;
    }
    is_non_block = (0 != mhd_SOCK_NONBLOCK);
    is_non_inhr = (0 != mhd_SOCK_CLOEXEC);
  }
  else
  {
    is_non_block = false; /* Try to set non-block */
    is_non_inhr = false;  /* Try to set non-inheritable */
  }

  /* The listen socket must be closed if error code returned
     beyond this point */

  ret = MHD_SC_OK;

  do
  { /* The scope for automatic socket close for error returns */
    if (! mhd_FD_FITS_DAEMON (d,sk))
    {
      mhd_LOG_MSG (d, MHD_SC_LISTEN_FD_OUTSIDE_OF_SET_RANGE, \
                   "The listen FD value is higher than allowed");
      ret = MHD_SC_LISTEN_FD_OUTSIDE_OF_SET_RANGE;
      break;
    }

    if (! is_non_inhr)
    {
      if (! mhd_socket_noninheritable (sk))
        mhd_LOG_MSG (d, MHD_SC_LISTEN_SOCKET_NOINHERIT_FAILED, \
                     "OS refused to make the listen socket non-inheritable");
    }

    if (! sk_already_listening)
    {
#ifdef HAVE_INET6
#ifdef IPV6_V6ONLY // TODO: detect constants declarations in configure
      if ((mhd_SKT_IP_V6_ONLY == sk_type) ||
          (mhd_SKT_IP_DUAL_REQUIRED == sk_type) ||
          (mhd_SKT_IP_V4_WITH_V6_OPT == sk_type) ||
          (mhd_SKT_IP_V6_WITH_V4_OPT == sk_type) ||
          (mhd_SKT_UNKNOWN == sk_type))
      {
        mhd_SCKT_OPT_BOOL no_dual_to_set;
        bool use_dual;

        use_dual = ((mhd_SKT_IP_DUAL_REQUIRED == sk_type) ||
                    (mhd_SKT_IP_V4_WITH_V6_OPT == sk_type) ||
                    (mhd_SKT_IP_V6_WITH_V4_OPT == sk_type));
        no_dual_to_set = use_dual ? 0 : 1;

        if (0 != setsockopt (sk, IPPROTO_IPV6, IPV6_V6ONLY,
                             (void *) &no_dual_to_set, sizeof (no_dual_to_set)))
        {
          mhd_SCKT_OPT_BOOL no_dual_current;
          socklen_t opt_size;
          bool state_unknown;
          bool state_match;

          no_dual_current = 0;
          opt_size = sizeof(no_dual_current);

          /* Some platforms forbid setting this options, but allow
             reading. */
          if ((0 != getsockopt (sk, IPPROTO_IPV6, IPV6_V6ONLY,
                                (void*) &no_dual_current, &opt_size))
              || (((socklen_t) sizeof(no_dual_current)) < opt_size))
          {
            state_unknown = true;
            state_match = false;
          }
          else
          {
            state_unknown = false;
            state_match = ((! ! no_dual_current) == (! ! no_dual_to_set));
          }

          if (state_unknown || ! state_match)
          {
            if (mhd_SKT_IP_V4_WITH_V6_OPT == sk_type)
            {
              (void) mhd_socket_close (sk);
              return create_bind_listen_stream_socket (d, s, true, false);
            }
            if (! state_unknown)
            {
              /* The dual-stack state is definitely wrong */
              if (mhd_SKT_IP_V6_ONLY == sk_type)
              {
                mhd_LOG_MSG ( \
                  d, MHD_SC_LISTEN_DUAL_STACK_CONFIGURATION_REJECTED, \
                  "Failed to disable IP dual-stack configuration " \
                  "for the listen socket");
                ret = MHD_SC_LISTEN_DUAL_STACK_CONFIGURATION_REJECTED;
                break;
              }
              else if (mhd_SKT_UNKNOWN != sk_type)
              {
                mhd_LOG_MSG ( \
                  d, MHD_SC_LISTEN_DUAL_STACK_CONFIGURATION_REJECTED, \
                  "Cannot enable IP dual-stack configuration " \
                  "for the listen socket");
                if (mhd_SKT_IP_DUAL_REQUIRED == sk_type)
                {
                  ret = MHD_SC_LISTEN_DUAL_STACK_CONFIGURATION_REJECTED;
                  break;
                }
              }
            }
            else
            {
              /* The dual-stack state is unknown */
              if (mhd_SKT_UNKNOWN != sk_type)
                mhd_LOG_MSG (
                  d, MHD_SC_LISTEN_DUAL_STACK_CONFIGURATION_UNKNOWN, \
                  "Failed to set dual-stack (IPV6_ONLY) configuration " \
                  "for the listen socket, using system defaults");
            }
          }
        }
      }
#else  /* ! IPV6_V6ONLY */
      mhd_assert (mhd_SKT_IP_DUAL_REQUIRED != sk_type);
      mhd_assert (mhd_SKT_IP_V4_WITH_V6_OPT != sk_type);
      mhd_assert (mhd_SKT_IP_V6_WITH_V4_OPT != sk_type);
#endif /* ! IPV6_V6ONLY */
#endif /* HAVE_INET6 */

      if (MHD_FOM_AUTO <= d->settings->tcp_fastopen.v_option)
      {
#if defined(TCP_FASTOPEN)
        int fo_param;
#ifdef __linux__
        /* The parameter is the queue length */
        fo_param = (int) d->settings->tcp_fastopen.v_queue_length;
        if (0 == fo_param)
          fo_param = MHD_TCP_FASTOPEN_DEF_QUEUE_LEN;
#else  /* ! __linux__ */
        fo_param = 1; /* The parameter is on/off type of setting */
#endif /* ! __linux__ */
        if (0 != setsockopt (sk, IPPROTO_TCP, TCP_FASTOPEN,
                             (const void *) &fo_param,
                             sizeof (fo_param)))
        {
          mhd_LOG_MSG (d, MHD_SC_LISTEN_FAST_OPEN_FAILURE, \
                       "OS refused to enable TCP Fast Open on " \
                       "the listen socket");
          if (MHD_FOM_AUTO < d->settings->tcp_fastopen.v_option)
          {
            ret = MHD_SC_LISTEN_FAST_OPEN_FAILURE;
            break;
          }
        }
#else  /* ! TCP_FASTOPEN */
        if (MHD_FOM_AUTO < d->settings->tcp_fastopen.v_option)
        {
          mhd_LOG_MSG (d, MHD_SC_LISTEN_FAST_OPEN_FAILURE, \
                       "The OS does not support TCP Fast Open");
          ret = MHD_SC_LISTEN_FAST_OPEN_FAILURE;
          break;
        }
#endif
      }

      if (MHD_D_OPTION_BIND_TYPE_NOT_SHARED >= d->settings->listen_addr_reuse)
      {
#ifndef MHD_WINSOCK_SOCKETS
#ifdef SO_REUSEADDR
        mhd_SCKT_OPT_BOOL on_val1 = 1;
        if (0 != setsockopt (sk, SOL_SOCKET, SO_REUSEADDR,
                             (const void *) &on_val1, sizeof (on_val1)))
        {
          mhd_LOG_MSG (d, MHD_SC_LISTEN_PORT_REUSE_ENABLE_FAILED, \
                       "OS refused to enable address reuse on " \
                       "the listen socket");
        }
#else  /* ! SO_REUSEADDR */
        mhd_LOG_MSG (d, MHD_SC_LISTEN_ADDRESS_REUSE_ENABLE_NOT_SUPPORTED, \
                     "The OS does not support address reuse for sockets");
#endif /* ! SO_REUSEADDR */
#endif /* ! MHD_WINSOCK_SOCKETS */
        if (MHD_D_OPTION_BIND_TYPE_NOT_SHARED > d->settings->listen_addr_reuse)
        {
#if defined(SO_REUSEPORT) || defined(MHD_WINSOCK_SOCKETS)
          mhd_SCKT_OPT_BOOL on_val2 = 1;
          if (0 != setsockopt (sk, SOL_SOCKET,
#ifndef MHD_WINSOCK_SOCKETS
                               SO_REUSEPORT,
#else  /* ! MHD_WINSOCK_SOCKETS */
                               SO_REUSEADDR, /* On W32 it is the same as SO_REUSEPORT on other platforms */
#endif /* ! MHD_WINSOCK_SOCKETS */
                               (const void *) &on_val2, sizeof (on_val2)))
          {
            mhd_LOG_MSG (d, MHD_SC_LISTEN_ADDRESS_REUSE_ENABLE_FAILED, \
                         "OS refused to enable address sharing " \
                         "on the listen socket");
            ret = MHD_SC_LISTEN_ADDRESS_REUSE_ENABLE_FAILED;
            break;
          }
#else  /* ! SO_REUSEADDR && ! MHD_WINSOCK_SOCKETS */
          mhd_LOG_MSG (d, MHD_SC_LISTEN_ADDRESS_REUSE_ENABLE_NOT_SUPPORTED, \
                       "The OS does not support address sharing for sockets");
          ret = MHD_SC_LISTEN_ADDRESS_REUSE_ENABLE_NOT_SUPPORTED;
          break;
#endif /* ! SO_REUSEADDR && ! MHD_WINSOCK_SOCKETS */
        }
      }
#if defined(SO_EXCLUSIVEADDRUSE) || defined(SO_EXCLBIND)
      else if (MHD_D_OPTION_BIND_TYPE_EXCLUSIVE <=
               d->settings->listen_addr_reuse)
      {
        mhd_SCKT_OPT_BOOL on_val = 1;
        if (0 != setsockopt (sk, SOL_SOCKET,
#ifdef SO_EXCLUSIVEADDRUSE
                             SO_EXCLUSIVEADDRUSE,
#else
                             SO_EXCLBIND,
#endif
                             (const void *) &on_val, sizeof (on_val)))
        {
          mhd_LOG_MSG (d, MHD_SC_LISTEN_ADDRESS_EXCLUSIVE_ENABLE_FAILED, \
                       "OS refused to enable exclusive address use " \
                       "on the listen socket");
          ret = MHD_SC_LISTEN_ADDRESS_EXCLUSIVE_ENABLE_FAILED;
          break;
        }
      }
#endif /* SO_EXCLUSIVEADDRUSE || SO_EXCLBIND */

      mhd_assert (NULL != p_use_sa);
      mhd_assert (0 != use_sa_size);
      if (0 != bind (sk, p_use_sa, use_sa_size))
      {
#ifdef HAVE_INET6
        if (mhd_SKT_IP_V4_WITH_FALLBACK == sk_type)
        {
          (void) mhd_socket_close (sk);
          return create_bind_listen_stream_socket (d, s, v6_tried, true);
        }
        if (mhd_SKT_IP_V4_WITH_V6_OPT == sk_type)
        {
          (void) mhd_socket_close (sk);
          return create_bind_listen_stream_socket (d, s, true, false);
        }
#endif /* HAVE_INET6 */
        mhd_LOG_MSG (d, MHD_SC_LISTEN_SOCKET_BIND_FAILED, \
                     "Failed to bind the listen socket");
        ret = MHD_SC_LISTEN_SOCKET_BIND_FAILED;
        break;
      }

      if (1)
      {
        int accept_queue_len;
        accept_queue_len = (int) s->listen_backlog;
        if (0 > accept_queue_len)
          accept_queue_len = 0;
        if (0 == accept_queue_len)
        {
#ifdef SOMAXCONN
          accept_queue_len = SOMAXCONN;
#else  /* ! SOMAXCONN */
          accept_queue_len = 127; /* Should be the safe value */
#endif /* ! SOMAXCONN */
        }
        if (0 != listen (sk, accept_queue_len))
        {
#ifdef HAVE_INET6
          if (mhd_SKT_IP_V4_WITH_FALLBACK == sk_type)
          {
            (void) mhd_socket_close (sk);
            return create_bind_listen_stream_socket (d, s, v6_tried, true);
          }
          if (mhd_SKT_IP_V4_WITH_V6_OPT == sk_type)
          {
            (void) mhd_socket_close (sk);
            return create_bind_listen_stream_socket (d, s, true, false);
          }
#endif /* HAVE_INET6 */
          mhd_LOG_MSG (d, MHD_SC_LISTEN_FAILURE, \
                       "Failed to start listening on the listen socket");
          ret = MHD_SC_LISTEN_FAILURE;
          break;
        }
      }
    }
    /* A valid listening socket is ready here */

    if (! is_non_block)
    {
      is_non_block = mhd_socket_nonblocking (sk);
      if (! is_non_block)
        mhd_LOG_MSG (d, MHD_SC_LISTEN_SOCKET_NONBLOCKING_FAILURE, \
                     "OS refused to make the listen socket non-blocking");
    }

    /* Set to the daemon only when the listening socket is fully ready */
    d->net.listen.fd = sk;
    switch (sk_type)
    {
    case mhd_SKT_UNKNOWN:
      d->net.listen.type = mhd_SOCKET_TYPE_UNKNOWN;
      break;
    case mhd_SKT_NON_IP:
      d->net.listen.type = mhd_SOCKET_TYPE_NON_IP;
      break;
    case mhd_SKT_UNIX:
      d->net.listen.type = mhd_SOCKET_TYPE_UNIX;
      break;
    case mhd_SKT_IP_V4_ONLY:
    case mhd_SKT_IP_V6_ONLY:
    case mhd_SKT_IP_DUAL_REQUIRED:
    case mhd_SKT_IP_V4_WITH_V6_OPT:
    case mhd_SKT_IP_V6_WITH_V4_OPT:
    case mhd_SKT_IP_V4_WITH_FALLBACK:
      d->net.listen.type = mhd_SOCKET_TYPE_IP;
      break;
    case mhd_SKT_NO_SOCKET:
    default:
      mhd_assert (0 && "Impossible value");
      MHD_UNREACHABLE_;
      return MHD_SC_INTERNAL_ERROR;
    }
    d->net.listen.non_block = is_non_block;
    d->net.listen.port = sk_port;

    mhd_assert (ret == MHD_SC_OK);

    return MHD_SC_OK;

  } while (0);

  mhd_assert (MHD_SC_OK != ret); /* This should be only error returns here */
  mhd_assert (MHD_INVALID_SOCKET != sk);
  (void) mhd_socket_close (sk);
  return ret;
}


/**
 * Detect and set the type and port of the listening socket
 * @param d the daemon to use
 */
static MHD_FN_PAR_NONNULL_ (1) void
detect_listen_type_and_port (struct MHD_Daemon *restrict d)
{
  union mhd_SockaddrAny sa_all;
  socklen_t sa_size;
  enum mhd_SocketType declared_type;

  mhd_assert (MHD_INVALID_SOCKET != d->net.listen.fd);
  mhd_assert (0 == d->net.listen.port);
  memset (&sa_all, 0, sizeof(sa_all)); /* Actually not required */
  sa_size = (socklen_t) sizeof(sa_all);

  if (0 != getsockname (d->net.listen.fd, &(sa_all.sa), &sa_size))
  {
    if (mhd_SOCKET_TYPE_IP == d->net.listen.type)
      mhd_LOG_MSG (d, MHD_SC_LISTEN_PORT_DETECT_FAILURE, \
                   "Failed to detect the port number on the listening socket");
    return;
  }

  declared_type = d->net.listen.type;
  if (0 == sa_size)
  {
#ifndef __linux__
    /* Used on some non-Linux platforms */
    d->net.listen.type = mhd_SOCKET_TYPE_UNIX;
    d->net.listen.port = 0;
#else  /* ! __linux__ */
    (void) 0;
#endif /* ! __linux__ */
  }
  else
  {
    switch (sa_all.sa.sa_family)
    {
    case AF_INET:
      d->net.listen.type = mhd_SOCKET_TYPE_IP;
      d->net.listen.port = (uint_least16_t) ntohs (sa_all.sa_i4.sin_port);
      break;
#ifdef HAVE_INET6
    case AF_INET6:
      d->net.listen.type = mhd_SOCKET_TYPE_IP;
      d->net.listen.port = (uint_least16_t) ntohs (sa_all.sa_i6.sin6_port);
      break;
#endif /* HAVE_INET6 */
#ifdef MHD_AF_UNIX
    case MHD_AF_UNIX:
      d->net.listen.type = mhd_SOCKET_TYPE_UNIX;
      d->net.listen.port = 0;
      break;
#endif /* MHD_AF_UNIX */
    default:
      d->net.listen.type = mhd_SOCKET_TYPE_UNKNOWN;
      d->net.listen.port = 0;
      break;
    }
  }

  if ((declared_type != d->net.listen.type)
      && (mhd_SOCKET_TYPE_IP == declared_type))
    mhd_LOG_MSG (d, MHD_SC_UNEXPECTED_SOCKET_ERROR, \
                 "The type of listen socket is detected as non-IP, while " \
                 "the socket has been created as an IP socket");
}


#ifdef MHD_USE_EPOLL

/**
 * Initialise daemon's epoll FD
 */
static MHD_FN_PAR_NONNULL_ (1) enum MHD_StatusCode
init_epoll (struct MHD_Daemon *restrict d)
{
  int e_fd;
  mhd_assert (mhd_WM_INT_INTERNAL_EVENTS_THREAD_PER_CONNECTION != d->wmode_int);
  mhd_assert ((mhd_POLL_TYPE_NOT_SET_YET == d->events.poll_type) || \
              ((mhd_POLL_TYPE_EPOLL == d->events.poll_type) && \
               (mhd_WM_INT_INTERNAL_EVENTS_THREAD_POOL == d->wmode_int)));
  mhd_assert ((! d->dbg.net_inited) || \
              (mhd_WM_INT_INTERNAL_EVENTS_THREAD_POOL == d->wmode_int));
  mhd_assert ((mhd_POLL_TYPE_EPOLL != d->events.poll_type) || \
              (NULL == d->events.data.epoll.events));
  mhd_assert ((mhd_POLL_TYPE_EPOLL != d->events.poll_type) || \
              (MHD_INVALID_SOCKET == d->events.data.epoll.e_fd));
#ifdef HAVE_EPOLL_CREATE1
  e_fd = epoll_create1 (EPOLL_CLOEXEC);
#else  /* ! HAVE_EPOLL_CREATE1 */
  e_fd = epoll_create (128); /* The number is usually ignored */
  if (0 <= e_fd)
  {
    if (! mhd_socket_noninheritable (e_fd))
      mhd_LOG_MSG (d, MHD_SC_EPOLL_CTL_CONFIGURE_NOINHERIT_FAILED, \
                   "Failed to make epoll control FD non-inheritable");
  }
#endif /* ! HAVE_EPOLL_CREATE1 */
  if (0 > e_fd)
  {
    mhd_LOG_MSG (d, MHD_SC_EPOLL_CTL_CREATE_FAILED, \
                 "Failed to create epoll control FD");
    return MHD_SC_EPOLL_CTL_CREATE_FAILED; /* Failure exit point */
  }

  if (! mhd_FD_FITS_DAEMON (d, e_fd))
  {
    mhd_LOG_MSG (d, MHD_SC_EPOLL_CTL_OUTSIDE_OF_SET_RANGE, \
                 "The epoll control FD value is higher than allowed");
    (void) close (e_fd);
    return MHD_SC_EPOLL_CTL_OUTSIDE_OF_SET_RANGE; /* Failure exit point */
  }

  d->events.poll_type = mhd_POLL_TYPE_EPOLL;
  d->events.data.epoll.e_fd = e_fd;
  d->events.data.epoll.events = NULL; /* Memory allocated during event and threads init */
  d->events.data.epoll.num_elements = 0;
  return MHD_SC_OK; /* Success exit point */
}


/**
 * Deinitialise daemon's epoll FD
 */
MHD_FN_PAR_NONNULL_ (1) static void
deinit_epoll (struct MHD_Daemon *restrict d)
{
  mhd_assert (mhd_POLL_TYPE_EPOLL == d->events.poll_type);
  /* With thread pool the epoll control FD could be migrated to the
   * first worker daemon. */
  mhd_assert ((MHD_INVALID_SOCKET != d->events.data.epoll.e_fd) || \
              (mhd_WM_INT_INTERNAL_EVENTS_THREAD_POOL == d->wmode_int));
  mhd_assert ((MHD_INVALID_SOCKET != d->events.data.epoll.e_fd) || \
              (mhd_DAEMON_TYPE_MASTER_CONTROL_ONLY == d->threading.d_type));
  if (MHD_INVALID_SOCKET != d->events.data.epoll.e_fd)
    close (d->events.data.epoll.e_fd);
}


#endif /* MHD_USE_EPOLL */

/**
 * Choose sockets monitoring syscall and pre-initialise it
 * @param d the daemon object
 * @param s the user settings
 * @return #MHD_SC_OK on success,
 *         the error code otherwise
 */
static MHD_FN_PAR_NONNULL_ (1) MHD_FN_PAR_NONNULL_ (2) \
  MHD_FN_MUST_CHECK_RESULT_ enum MHD_StatusCode
daemon_choose_and_preinit_events (struct MHD_Daemon *restrict d,
                                  struct DaemonOptions *restrict s)
{
  enum mhd_IntPollType chosen_type;

  mhd_assert ((mhd_POLL_TYPE_NOT_SET_YET == d->events.poll_type) || \
              (mhd_WM_INT_EXTERNAL_EVENTS_EDGE == d->wmode_int) || \
              (mhd_WM_INT_EXTERNAL_EVENTS_LEVEL == d->wmode_int) || \
              (MHD_WM_EXTERNAL_SINGLE_FD_WATCH == s->work_mode.mode));
  mhd_assert ((mhd_POLL_TYPE_NOT_SET_YET == d->events.poll_type) || \
              (d->events.poll_type == (enum mhd_IntPollType) s->poll_syscall) \
              || ((MHD_SPS_AUTO == s->poll_syscall) && \
                  ((mhd_POLL_TYPE_EXT == d->events.poll_type) || \
                   (mhd_POLL_TYPE_EPOLL == d->events.poll_type))));

  /* Check whether the provided parameter is in the range of expected values */
  switch (s->poll_syscall)
  {
  case MHD_SPS_AUTO:
    chosen_type = mhd_POLL_TYPE_NOT_SET_YET;
    break;
  case MHD_SPS_SELECT:
    mhd_assert (! mhd_WM_INT_HAS_EXT_EVENTS (d->wmode_int));
#ifndef MHD_USE_SELECT
    mhd_LOG_MSG (d, MHD_SC_SELECT_SYSCALL_NOT_AVAILABLE, \
                 "'select()' is not supported by the platform or " \
                 "this MHD build");
    return MHD_SC_SELECT_SYSCALL_NOT_AVAILABLE;
#else  /* MHD_USE_SELECT */
    chosen_type = mhd_POLL_TYPE_SELECT;
#endif /* MHD_USE_SELECT */
    break;
  case MHD_SPS_POLL:
    mhd_assert (! mhd_WM_INT_HAS_EXT_EVENTS (d->wmode_int));
#ifndef MHD_USE_POLL
    mhd_LOG_MSG (d, MHD_SC_POLL_SYSCALL_NOT_AVAILABLE, \
                 "'poll()' is not supported by the platform or " \
                 "this MHD build");
    return MHD_SC_POLL_SYSCALL_NOT_AVAILABLE;
#else  /* MHD_USE_POLL */
    chosen_type = mhd_POLL_TYPE_POLL;
#endif /* MHD_USE_POLL */
    break;
  case MHD_SPS_EPOLL:
    mhd_assert (! mhd_WM_INT_HAS_EXT_EVENTS (d->wmode_int));
#ifndef MHD_USE_EPOLL
    mhd_LOG_MSG (d, MHD_SC_EPOLL_SYSCALL_NOT_AVAILABLE, \
                 "'epoll' is not supported by the platform or " \
                 "this MHD build");
    return MHD_SC_EPOLL_SYSCALL_NOT_AVAILABLE;
#else  /* MHD_USE_EPOLL */
    chosen_type = mhd_POLL_TYPE_EPOLL;
#endif /* MHD_USE_EPOLL */
    break;
  default:
    mhd_LOG_MSG (d, MHD_SC_CONFIGURATION_UNEXPECTED_SPS,
                 "Wrong socket polling syscall specified");
    return MHD_SC_CONFIGURATION_UNEXPECTED_SPS;
  }

  mhd_assert (mhd_POLL_TYPE_EXT != chosen_type);

  if (mhd_POLL_TYPE_NOT_SET_YET == chosen_type)
  {
    if (mhd_WM_INT_HAS_EXT_EVENTS (d->wmode_int))
      chosen_type = mhd_POLL_TYPE_EXT;
#ifdef MHD_USE_EPOLL
    else if (mhd_WM_INT_INTERNAL_EVENTS_THREAD_PER_CONNECTION != d->wmode_int)
      chosen_type = mhd_POLL_TYPE_EPOLL; /* with possible fallback */
#endif
    else
    {
#if defined(MHD_USE_POLL)
      chosen_type = mhd_POLL_TYPE_POLL;
#elif defined(MHD_USE_SELECT)
      chosen_type = mhd_POLL_TYPE_SELECT;
#else
      (void) 0; /* Do nothing. Mute compiler warning */
#endif
    }
  }

  /* Try 'epoll' if possible */
#ifdef MHD_USE_EPOLL
  if (mhd_POLL_TYPE_EPOLL == chosen_type)
  {
    enum MHD_StatusCode epoll_res;

    mhd_assert (mhd_WM_INT_INTERNAL_EVENTS_THREAD_PER_CONNECTION != \
                d->wmode_int);
    epoll_res = init_epoll (d);

    if (MHD_SC_OK != epoll_res)
    {
      if ((MHD_SPS_EPOLL == s->poll_syscall) ||
          (MHD_WM_EXTERNAL_SINGLE_FD_WATCH == s->work_mode.mode))
        return epoll_res; /* Cannot init epoll, but epoll is required */
      chosen_type = mhd_POLL_TYPE_NOT_SET_YET; /* Choose again */
    }
  }
  mhd_assert ((mhd_POLL_TYPE_EPOLL != d->events.poll_type) || \
              (0 < d->events.data.epoll.e_fd));
#endif /* MHD_USE_EPOLL */

  if (mhd_POLL_TYPE_NOT_SET_YET == chosen_type)
  {
#if defined(MHD_USE_POLL)
    chosen_type = mhd_POLL_TYPE_POLL;
#elif defined(MHD_USE_SELECT)
    chosen_type = mhd_POLL_TYPE_SELECT;
#else
    mhd_LOG_MSG (d, MHD_SC_FEATURE_DISABLED, \
                 "All suitable internal sockets polling technologies are " \
                 "disabled in this MHD build");
    return MHD_SC_FEATURE_DISABLED;
#endif
  }

  switch (chosen_type)
  {
  case mhd_POLL_TYPE_EXT:
    mhd_assert ((MHD_WM_EXTERNAL_EVENT_LOOP_CB_LEVEL == s->work_mode.mode) || \
                (MHD_WM_EXTERNAL_EVENT_LOOP_CB_EDGE != s->work_mode.mode));
    mhd_assert (mhd_WM_INT_HAS_EXT_EVENTS (d->wmode_int));
    mhd_assert (MHD_WM_EXTERNAL_SINGLE_FD_WATCH != s->work_mode.mode);
    d->events.poll_type = mhd_POLL_TYPE_EXT;
    d->events.data.ext.cb =
      s->work_mode.params.v_external_event_loop_cb.reg_cb;
    d->events.data.ext.cls =
      s->work_mode.params.v_external_event_loop_cb.reg_cb_cls;
    break;
#ifdef MHD_USE_SELECT
  case mhd_POLL_TYPE_SELECT:
    mhd_assert (! mhd_WM_INT_HAS_EXT_EVENTS (d->wmode_int));
    mhd_assert (MHD_WM_EXTERNAL_SINGLE_FD_WATCH != s->work_mode.mode);
    d->events.poll_type = mhd_POLL_TYPE_SELECT;
    d->events.data.select.rfds = NULL; /* Memory allocated during event and threads init */
    d->events.data.select.wfds = NULL; /* Memory allocated during event and threads init */
    d->events.data.select.efds = NULL; /* Memory allocated during event and threads init */
    break;
#endif /* MHD_USE_SELECT */
#ifdef MHD_USE_POLL
  case mhd_POLL_TYPE_POLL:
    mhd_assert (! mhd_WM_INT_HAS_EXT_EVENTS (d->wmode_int));
    mhd_assert (MHD_WM_EXTERNAL_SINGLE_FD_WATCH != s->work_mode.mode);
    d->events.poll_type = mhd_POLL_TYPE_POLL;
    d->events.data.poll.fds = NULL; /* Memory allocated during event and threads init */
    d->events.data.poll.rel = NULL; /* Memory allocated during event and threads init */
    break;
#endif /* MHD_USE_POLL */
#ifdef MHD_USE_EPOLL
  case mhd_POLL_TYPE_EPOLL:
    mhd_assert (! mhd_WM_INT_HAS_EXT_EVENTS (d->wmode_int));
    /* Pre-initialised by init_epoll() */
    mhd_assert (mhd_POLL_TYPE_EPOLL == d->events.poll_type);
    mhd_assert (0 <= d->events.data.epoll.e_fd);
    mhd_assert (NULL == d->events.data.epoll.events);
    break;
#endif /* MHD_USE_EPOLL */
#ifndef MHD_USE_SELECT
  case mhd_POLL_TYPE_SELECT:
#endif /* ! MHD_USE_SELECT */
#ifndef MHD_USE_POLL
  case mhd_POLL_TYPE_POLL:
#endif /* ! MHD_USE_POLL */
#ifndef MHD_USE_EPOLL
  case mhd_POLL_TYPE_EPOLL:
#endif /* ! MHD_USE_EPOLL */
  case mhd_POLL_TYPE_NOT_SET_YET:
  default:
    mhd_assert (0 && "Impossible value");
    MHD_UNREACHABLE_;
    return MHD_SC_INTERNAL_ERROR;
    break;
  }
  return MHD_SC_OK;
}


/**
 * Initialise network/sockets for the daemon.
 * Also choose events mode / sockets polling syscall.
 * @param d the daemon object
 * @param s the user settings
 * @return #MHD_SC_OK on success,
 *         the error code otherwise
 */
static MHD_FN_PAR_NONNULL_ (1) MHD_FN_PAR_NONNULL_ (2) \
  MHD_FN_MUST_CHECK_RESULT_ enum MHD_StatusCode
daemon_init_net (struct MHD_Daemon *restrict d,
                 struct DaemonOptions *restrict s)
{
  enum MHD_StatusCode ret;

  mhd_assert (! d->dbg.net_inited);
  mhd_assert (! d->dbg.net_deinited);
#ifdef MHD_POSIX_SOCKETS
  d->net.cfg.max_fd_num = s->fd_number_limit;
#endif /* MHD_POSIX_SOCKETS */

  ret = daemon_choose_and_preinit_events (d, s);
  if (MHD_SC_OK != ret)
    return ret;

  mhd_assert (mhd_POLL_TYPE_NOT_SET_YET != d->events.poll_type);

  /* No direct return of error codes is allowed beyond this point.
     Deinit/cleanup must be performed before return of any error. */

#if defined(MHD_POSIX_SOCKETS) && defined(MHD_USE_SELECT)
  if (mhd_POLL_TYPE_SELECT == d->events.poll_type)
  {
    if ((MHD_INVALID_SOCKET == d->net.cfg.max_fd_num) ||
        (FD_SETSIZE < d->net.cfg.max_fd_num))
      d->net.cfg.max_fd_num = FD_SETSIZE;
  }
#endif /* MHD_POSIX_SOCKETS && MHD_USE_SELECT */

  if (MHD_SC_OK == ret)
  {
    ret = create_bind_listen_stream_socket (d, s, false, false);

    if (MHD_SC_OK == ret)
    {
      if ((MHD_INVALID_SOCKET != d->net.listen.fd)
          && ! d->net.listen.non_block
          && ((mhd_WM_INT_EXTERNAL_EVENTS_EDGE == d->wmode_int) ||
              (mhd_WM_INT_INTERNAL_EVENTS_THREAD_POOL == d->wmode_int)))
      {
        mhd_LOG_MSG (d, MHD_SC_LISTEN_SOCKET_NONBLOCKING_FAILURE, \
                     "The selected daemon work mode requires listening socket "
                     "in non-blocking mode");
        ret = MHD_SC_LISTEN_SOCKET_NONBLOCKING_FAILURE;
      }

      if (MHD_SC_OK == ret)
      {
        if ((MHD_INVALID_SOCKET != d->net.listen.fd) &&
            ((0 == d->net.listen.port) ||
             (mhd_SOCKET_TYPE_UNKNOWN == d->net.listen.type)))
          detect_listen_type_and_port (d);

#ifndef NDEBUG
        d->dbg.net_inited = true;
#endif
        return MHD_SC_OK; /* Success exit point */
      }

      /* Below is a cleanup path */
      if (MHD_INVALID_SOCKET != d->net.listen.fd)
        mhd_socket_close (d->net.listen.fd);
    }
  }

#ifdef MHD_USE_EPOLL
  if ((mhd_POLL_TYPE_EPOLL == d->events.poll_type))
    close (d->events.data.epoll.e_fd);
#endif /* MHD_USE_EPOLL */

  mhd_assert (MHD_SC_OK != ret);

  return ret;
}


/**
 * Deinitialise daemon's network data
 * @param d the daemon object
 */
MHD_FN_PAR_NONNULL_ (1) static void
daemon_deinit_net (struct MHD_Daemon *restrict d)
{
  mhd_assert (d->dbg.net_inited);
  mhd_assert (! d->dbg.net_deinited);
  mhd_assert (mhd_POLL_TYPE_NOT_SET_YET != d->events.poll_type);
#ifdef MHD_USE_EPOLL
  if (mhd_POLL_TYPE_EPOLL == d->events.poll_type)
    deinit_epoll (d);
#endif /* MHD_USE_EPOLL */
  if (MHD_INVALID_SOCKET != d->net.listen.fd)
    mhd_socket_close (d->net.listen.fd);

#ifndef NDEBUG
  d->dbg.net_deinited = true;
#endif
}


#if 0
void
dauth_init (struct MHD_Daemon *restrict d,
            struct DaemonOptions *restrict s)
{
  mhd_assert ((NULL == s->random_entropy.v_buf) || \
              (0 != s->random_entropy.v_buf_size));
  mhd_assert ((0 == s->random_entropy.v_buf_size) || \
              (NULL != s->random_entropy.v_buf));
}


#endif

/**
 * Initialise large buffer tracking.
 * @param d the daemon object
 * @param s the user settings
 * @return #MHD_SC_OK on success,
 *         the error code otherwise
 */
static MHD_FN_PAR_NONNULL_ (1) MHD_FN_PAR_NONNULL_ (2) \
  MHD_FN_MUST_CHECK_RESULT_ enum MHD_StatusCode
daemon_init_large_buf (struct MHD_Daemon *restrict d,
                       struct DaemonOptions *restrict s)
{
  mhd_assert (! mhd_D_HAS_MASTER (d));
  d->req_cfg.large_buf.space_left = s->large_pool_size;
  if (0 == d->req_cfg.large_buf.space_left)             // TODO: USE SETTINGS!
    d->req_cfg.large_buf.space_left = 1024 * 1024U;     // TODO: USE SETTINGS!
  if (! mhd_mutex_init_short (&(d->req_cfg.large_buf.lock)))
  {
    mhd_LOG_MSG (d, MHD_SC_MUTEX_INIT_FAILURE, \
                 "Failed to initialise mutex for the global large buffer.");
    return MHD_SC_MUTEX_INIT_FAILURE;
  }
  return MHD_SC_OK;
}


/**
 * Initialise large buffer tracking.
 * @param d the daemon object
 * @param s the user settings
 * @return #MHD_SC_OK on success,
 *         the error code otherwise
 */
static MHD_FN_PAR_NONNULL_ (1) void
daemon_deinit_large_buf (struct MHD_Daemon *restrict d)
{
  mhd_mutex_destroy_chk (&(d->req_cfg.large_buf.lock));
}


/**
 * Finish initialisation of events processing
 * @param d the daemon object
 * @return #MHD_SC_OK on success,
 *         the error code otherwise
 */
static MHD_FN_PAR_NONNULL_ (1)
MHD_FN_MUST_CHECK_RESULT_ enum MHD_StatusCode
allocate_events (struct MHD_Daemon *restrict d)
{
#if defined(MHD_USE_POLL) || defined(MHD_USE_EPOLL)
  /**
   * The number of elements to be monitored by sockets polling function
   */
  unsigned int num_elements;
  num_elements = 0;
#ifdef MHD_USE_THREADS
  ++num_elements;  /* For the ITC */
#endif
  if (MHD_INVALID_SOCKET != d->net.listen.fd)
    ++num_elements;  /* For the listening socket */
  if (! mhd_D_HAS_THR_PER_CONN (d))
    num_elements += d->conns.cfg.count_limit;
#endif /* MHD_USE_POLL || MHD_USE_EPOLL */

  mhd_assert (0 != d->conns.cfg.count_limit);
  mhd_assert (mhd_D_TYPE_HAS_EVENTS_PROCESSING (d->threading.d_type));

  mhd_DLINKEDL_INIT_LIST (&(d->events),proc_ready);

  switch (d->events.poll_type)
  {
  case mhd_POLL_TYPE_EXT:
    mhd_assert (NULL != d->events.data.ext.cb);
#ifndef NDEBUG
    d->dbg.events_allocated = true;
#endif
    return MHD_SC_OK; /* Success exit point */
    break;
#ifdef MHD_USE_SELECT
  case mhd_POLL_TYPE_SELECT:
    /* The pointers have been set to NULL during pre-initialisations of the events */
    mhd_assert (NULL == d->events.data.select.rfds);
    mhd_assert (NULL == d->events.data.select.wfds);
    mhd_assert (NULL == d->events.data.select.efds);
    d->events.data.select.rfds = (fd_set *) malloc (sizeof(fd_set));
    if (NULL != d->events.data.select.rfds)
    {
      d->events.data.select.wfds = (fd_set *) malloc (sizeof(fd_set));
      if (NULL != d->events.data.select.wfds)
      {
        d->events.data.select.efds = (fd_set *) malloc (sizeof(fd_set));
        if (NULL != d->events.data.select.efds)
        {
#ifndef NDEBUG
          d->dbg.num_events_elements = FD_SETSIZE;
          d->dbg.events_allocated = true;
#endif
          return MHD_SC_OK; /* Success exit point */
        }

        free (d->events.data.select.wfds);
      }
      free (d->events.data.select.rfds);
    }
    mhd_LOG_MSG (d, MHD_SC_FD_SET_MEMORY_ALLOCATE_FAILURE, \
                 "Failed to allocate memory for fd_sets for the daemon");
    return MHD_SC_FD_SET_MEMORY_ALLOCATE_FAILURE;
    break;
#endif /* MHD_USE_SELECT */
#ifdef MHD_USE_POLL
  case mhd_POLL_TYPE_POLL:
    /* The pointers have been set to NULL during pre-initialisations of the events */
    mhd_assert (NULL == d->events.data.poll.fds);
    mhd_assert (NULL == d->events.data.poll.rel);
    if ((num_elements > d->conns.cfg.count_limit) /* Check for value overflow */
        || (mhd_D_HAS_THR_PER_CONN (d)))
    {
      d->events.data.poll.fds =
        (struct pollfd *) malloc (sizeof(struct pollfd) * num_elements);
      if (NULL != d->events.data.poll.fds)
      {
        d->events.data.poll.rel =
          (union mhd_SocketRelation *) malloc (sizeof(union mhd_SocketRelation)
                                               * num_elements);
        if (NULL != d->events.data.poll.rel)
        {
#ifndef NDEBUG
          d->dbg.num_events_elements = num_elements;
          d->dbg.events_allocated = true;
#endif
          return MHD_SC_OK; /* Success exit point */
        }
        free (d->events.data.poll.fds);
      }
    }
    mhd_LOG_MSG (d, MHD_SC_POLL_FDS_MEMORY_ALLOCATE_FAILURE, \
                 "Failed to allocate memory for poll fds for the daemon");
    return MHD_SC_POLL_FDS_MEMORY_ALLOCATE_FAILURE;
    break;
#endif /* MHD_USE_POLL */
#ifdef MHD_USE_EPOLL
  case mhd_POLL_TYPE_EPOLL:
    mhd_assert (! mhd_D_HAS_THR_PER_CONN (d));
    /* The event FD has been created during pre-initialisations of the events */
    mhd_assert (MHD_INVALID_SOCKET != d->events.data.epoll.e_fd);
    /* The pointer has been set to NULL during pre-initialisations of the events */
    mhd_assert (NULL == d->events.data.epoll.events);
    mhd_assert (0 == d->events.data.epoll.num_elements);
    if ((num_elements > d->conns.cfg.count_limit) /* Check for value overflow */
        || (mhd_D_HAS_THR_PER_CONN (d)))
    {
      const unsigned int upper_limit = (sizeof(void*) >= 8) ? 4096 : 1024;

      /* Trade neglectable performance penalty for memory saving */
      /* Very large amount of new events processed in batches */
      if (num_elements > upper_limit)
        num_elements = upper_limit;

      d->events.data.epoll.events =
        (struct epoll_event *) malloc (sizeof(struct epoll_event)
                                       * num_elements);
      if (NULL != d->events.data.epoll.events)
      {
        d->events.data.epoll.num_elements = num_elements;
#ifndef NDEBUG
        d->dbg.num_events_elements = num_elements;
        d->dbg.events_allocated = true;
#endif
        return MHD_SC_OK; /* Success exit point */
      }
    }
    mhd_LOG_MSG (d, MHD_SC_EPOLL_EVENTS_MEMORY_ALLOCATE_FAILURE, \
                 "Failed to allocate memory for epoll events for the daemon");
    return MHD_SC_EPOLL_EVENTS_MEMORY_ALLOCATE_FAILURE;
    break;
#endif /* MHD_USE_EPOLL */
#ifndef MHD_USE_SELECT
  case mhd_POLL_TYPE_SELECT:
#endif /* ! MHD_USE_SELECT */
#ifndef MHD_USE_POLL
  case mhd_POLL_TYPE_POLL:
#endif /* ! MHD_USE_POLL */
#ifndef MHD_USE_EPOLL
  case mhd_POLL_TYPE_EPOLL:
#endif /* ! MHD_USE_EPOLL */
  case mhd_POLL_TYPE_NOT_SET_YET:
  default:
    mhd_assert (0 && "Impossible value");
  }
  MHD_UNREACHABLE_;
  return MHD_SC_INTERNAL_ERROR;
}


/**
 * Deallocate events data
 * @param d the daemon object
 * @return #MHD_SC_OK on success,
 *         the error code otherwise
 */
static MHD_FN_PAR_NONNULL_ (1) void
deallocate_events (struct MHD_Daemon *restrict d)
{
  mhd_assert (0 != d->conns.cfg.count_limit);
  mhd_assert (mhd_D_TYPE_HAS_EVENTS_PROCESSING (d->threading.d_type));
  if (mhd_POLL_TYPE_NOT_SET_YET == d->events.poll_type)
  {
    mhd_assert (0 && "Wrong workflow");
    MHD_UNREACHABLE_;
    return;
  }
#ifdef MHD_USE_SELECT
  else if (mhd_POLL_TYPE_SELECT == d->events.poll_type)
  {
    mhd_assert (NULL != d->events.data.select.efds);
    mhd_assert (NULL != d->events.data.select.wfds);
    mhd_assert (NULL != d->events.data.select.rfds);
    free (d->events.data.select.efds);
    free (d->events.data.select.wfds);
    free (d->events.data.select.rfds);
  }
#endif /* MHD_USE_SELECT */
#ifdef MHD_USE_POLL
  else if (mhd_POLL_TYPE_POLL == d->events.poll_type)
  {
    mhd_assert (NULL != d->events.data.poll.rel);
    mhd_assert (NULL != d->events.data.poll.fds);
    free (d->events.data.poll.rel);
    free (d->events.data.poll.fds);
  }
#endif /* MHD_USE_POLL */
#ifdef MHD_USE_EPOLL
  else if (mhd_POLL_TYPE_EPOLL == d->events.poll_type)
  {
    mhd_assert (0 != d->events.data.epoll.num_elements);
    mhd_assert (NULL != d->events.data.epoll.events);
    free (d->events.data.epoll.events);
  }
#endif /* MHD_USE_EPOLL */
#ifndef NDEBUG
  d->dbg.events_allocated = false;
#endif
  return;
}


/**
 * Initialise daemon's ITC
 * @param d the daemon object
 * @return #MHD_SC_OK on success,
 *         the error code otherwise
 */
static MHD_FN_PAR_NONNULL_ (1)
MHD_FN_MUST_CHECK_RESULT_ enum MHD_StatusCode
init_itc (struct MHD_Daemon *restrict d)
{
  mhd_assert (mhd_D_TYPE_IS_VALID (d->threading.d_type));
  mhd_assert (mhd_D_TYPE_HAS_EVENTS_PROCESSING (d->threading.d_type));
#ifdef MHD_USE_THREADS
  // TODO: add and process "thread unsafe" daemon's option
  if (! mhd_itc_init (&(d->threading.itc)))
  {
#if defined(MHD_ITC_EVENTFD_)
    mhd_LOG_MSG ( \
      d, MHD_SC_ITC_INITIALIZATION_FAILED, \
      "Failed to initialise eventFD for inter-thread communication");
#elif defined(MHD_ITC_PIPE_)
    mhd_LOG_MSG ( \
      d, MHD_SC_ITC_INITIALIZATION_FAILED, \
      "Failed to create a pipe for inter-thread communication");
#elif defined(MHD_ITC_SOCKETPAIR_)
    mhd_LOG_MSG ( \
      d, MHD_SC_ITC_INITIALIZATION_FAILED, \
      "Failed to create a socketpair for inter-thread communication");
#else
#warning Missing expicit handling of the ITC type
    mhd_LOG_MSG ( \
      d, MHD_SC_ITC_INITIALIZATION_FAILED, \
      "Failed to initialise inter-thread communication");
#endif
    return MHD_SC_ITC_INITIALIZATION_FAILED;
  }
  if (! mhd_FD_FITS_DAEMON (d,mhd_itc_r_fd (d->threading.itc)))
  {
    mhd_LOG_MSG (d, MHD_SC_ITC_FD_OUTSIDE_OF_SET_RANGE, \
                 "The inter-thread communication FD value is " \
                 "higher than allowed");
    (void) mhd_itc_destroy (d->threading.itc);
    mhd_itc_set_invalid (&(d->threading.itc));
    return MHD_SC_ITC_FD_OUTSIDE_OF_SET_RANGE;
  }
#endif /* MHD_USE_THREADS */
  return MHD_SC_OK;
}


/**
 * Deallocate events data
 * @param d the daemon object
 * @return #MHD_SC_OK on success,
 *         the error code otherwise
 */
static MHD_FN_PAR_NONNULL_ (1) void
deinit_itc (struct MHD_Daemon *restrict d)
{
  mhd_assert (mhd_D_TYPE_IS_VALID (d->threading.d_type));
  mhd_assert (mhd_D_TYPE_HAS_EVENTS_PROCESSING (d->threading.d_type));
#ifdef MHD_USE_THREADS
  // TODO: add and process "thread unsafe" daemon's option
  mhd_assert (! mhd_ITC_IS_INVALID (d->threading.itc));
  (void) mhd_itc_destroy (d->threading.itc);
#endif /* MHD_USE_THREADS */
}


/**
 * The final part of events initialisation: pre-add ITC and listening FD to
 * the monitored items (if supported by monitoring syscall).
 * @param d the daemon object
 * @return #MHD_SC_OK on success,
 *         the error code otherwise
 */
static MHD_FN_PAR_NONNULL_ (1)
MHD_FN_MUST_CHECK_RESULT_ enum MHD_StatusCode
add_itc_and_listen_to_monitoring (struct MHD_Daemon *restrict d)
{
  mhd_assert (d->dbg.net_inited);
  mhd_assert (! d->dbg.net_deinited);
  mhd_assert (d->dbg.events_allocated);
  mhd_assert (! d->dbg.events_fully_inited);
  mhd_assert (mhd_D_TYPE_HAS_EVENTS_PROCESSING (d->threading.d_type));
#ifdef MHD_USE_THREADS
  mhd_assert (mhd_ITC_IS_VALID (d->threading.itc));
#endif

  switch (d->events.poll_type)
  {
  case mhd_POLL_TYPE_EXT:
    mhd_assert (NULL != d->events.data.ext.cb);
    /* Nothing to do with the external events */
    // FIXME: Register the ITC and the listening NOW?
    return MHD_SC_OK;
    break;
#ifdef MHD_USE_SELECT
  case mhd_POLL_TYPE_SELECT:
    mhd_assert (NULL != d->events.data.select.rfds);
    mhd_assert (NULL != d->events.data.select.wfds);
    mhd_assert (NULL != d->events.data.select.efds);
    /* Nothing to do when using 'select()' */
    return MHD_SC_OK;
    break;
#endif /* MHD_USE_SELECT */
#ifdef MHD_USE_POLL
  case mhd_POLL_TYPE_POLL:
    mhd_assert (NULL != d->events.data.poll.fds);
    mhd_assert (NULL != d->events.data.poll.rel);
    if (1)
    {
      unsigned int i;
      i = 0;
#ifdef MHD_USE_THREADS
      d->events.data.poll.fds[i].fd = mhd_itc_r_fd (d->threading.itc);
      d->events.data.poll.fds[i].events = POLLIN;
      d->events.data.poll.rel[i].fd_id = mhd_SOCKET_REL_MARKER_ITC;
      ++i;
#endif
      if (MHD_INVALID_SOCKET != d->net.listen.fd)
      {
        d->events.data.poll.fds[i].fd = d->net.listen.fd;
        d->events.data.poll.fds[i].events = POLLIN;
        d->events.data.poll.rel[i].fd_id = mhd_SOCKET_REL_MARKER_LISTEN;
      }
    }
    return MHD_SC_OK;
    break;
#endif /* MHD_USE_POLL */
#ifdef MHD_USE_EPOLL
  case mhd_POLL_TYPE_EPOLL:
    mhd_assert (MHD_INVALID_SOCKET != d->events.data.epoll.e_fd);
    mhd_assert (NULL != d->events.data.epoll.events);
    mhd_assert (0 < d->events.data.epoll.num_elements);
    if (1)
    {
      struct epoll_event reg_event;
#ifdef MHD_USE_THREADS
      reg_event.events = EPOLLIN;
      reg_event.data.u64 = (uint64_t) mhd_SOCKET_REL_MARKER_ITC; /* uint64_t is used in the epoll header */
      if (0 != epoll_ctl (d->events.data.epoll.e_fd, EPOLL_CTL_ADD,
                          mhd_itc_r_fd (d->threading.itc), &reg_event))
      {
        mhd_LOG_MSG (d, MHD_SC_EPOLL_ADD_DAEMON_FDS_FAILURE, \
                     "Failed to add ITC fd to the epoll monitoring.");
        return MHD_SC_EPOLL_ADD_DAEMON_FDS_FAILURE;
      }
#endif
      if (MHD_INVALID_SOCKET != d->net.listen.fd)
      {
        reg_event.events = EPOLLIN;
        reg_event.data.u64 = (uint64_t) mhd_SOCKET_REL_MARKER_LISTEN; /* uint64_t is used in the epoll header */
        if (0 != epoll_ctl (d->events.data.epoll.e_fd, EPOLL_CTL_ADD,
                            d->net.listen.fd, &reg_event))
        {
          mhd_LOG_MSG (d, MHD_SC_EPOLL_ADD_DAEMON_FDS_FAILURE, \
                       "Failed to add listening fd to the epoll monitoring.");
          return MHD_SC_EPOLL_ADD_DAEMON_FDS_FAILURE;
        }
      }
    }
    return MHD_SC_OK;
    break;
#endif /* MHD_USE_EPOLL */
#ifndef MHD_USE_SELECT
  case mhd_POLL_TYPE_SELECT:
#endif /* ! MHD_USE_SELECT */
#ifndef MHD_USE_POLL
  case mhd_POLL_TYPE_POLL:
#endif /* ! MHD_USE_POLL */
#ifndef MHD_USE_EPOLL
  case mhd_POLL_TYPE_EPOLL:
#endif /* ! MHD_USE_EPOLL */
  case mhd_POLL_TYPE_NOT_SET_YET:
  default:
    mhd_assert (0 && "Impossible value");
  }
  MHD_UNREACHABLE_;
  return MHD_SC_INTERNAL_ERROR;
}


/**
 * Initialise daemon connections' data.
 * @param d the daemon object
 * @param s the user settings
 * @return #MHD_SC_OK on success,
 *         the error code otherwise
 */
static MHD_FN_PAR_NONNULL_ (1) MHD_FN_PAR_NONNULL_ (2)
MHD_FN_MUST_CHECK_RESULT_ enum MHD_StatusCode
init_individual_conns (struct MHD_Daemon *restrict d,
                       struct DaemonOptions *restrict s)
{
  mhd_assert (! mhd_D_TYPE_HAS_WORKERS (d->threading.d_type));
  mhd_assert (0 != d->conns.cfg.count_limit);

  mhd_DLINKEDL_INIT_LIST (&(d->conns),all_conn);
  mhd_DLINKEDL_INIT_LIST (&(d->conns),def_timeout);
  mhd_DLINKEDL_INIT_LIST (&(d->conns),to_clean);
  d->conns.count = 0;
  d->conns.block_new = false;

  d->conns.cfg.mem_pool_size = s->conn_memory_limit;
  if (0 == d->conns.cfg.mem_pool_size)
    d->conns.cfg.mem_pool_size = 32 * 1024;
  else if (256 > d->conns.cfg.mem_pool_size)
    d->conns.cfg.mem_pool_size = 256;

#ifndef NDEBUG
  d->dbg.connections_inited = true;
#endif
  return MHD_SC_OK;
}


/**
 * Prepare daemon-local (worker daemon for thread pool mode) threading data
 * and finish events initialising.
 * To be used only with non-master daemons.
 * Do not start the thread even if configured for the internal threads.
 * @param d the daemon object
 * @return #MHD_SC_OK on success,
 *         the error code otherwise
 */
static MHD_FN_PAR_NONNULL_ (1) MHD_FN_PAR_NONNULL_ (2)
MHD_FN_MUST_CHECK_RESULT_ enum MHD_StatusCode
init_individual_thread_data_events_conns (struct MHD_Daemon *restrict d,
                                          struct DaemonOptions *restrict s)
{
  enum MHD_StatusCode res;
  mhd_assert (mhd_D_TYPE_IS_VALID (d->threading.d_type));
  mhd_assert (mhd_D_TYPE_HAS_EVENTS_PROCESSING (d->threading.d_type));
  mhd_assert (! mhd_D_TYPE_HAS_WORKERS (d->threading.d_type));
  mhd_assert (! d->dbg.connections_inited);

  res = allocate_events (d);
  if (MHD_SC_OK != res)
    return res;

  res = init_itc (d);
  if (MHD_SC_OK == res)
  {
    res = add_itc_and_listen_to_monitoring (d);

    if (MHD_SC_OK == res)
    {
#ifndef NDEBUG
      d->dbg.events_fully_inited = true;
#endif
#ifdef MHD_USE_THREADS
      mhd_thread_handle_ID_set_invalid (&(d->threading.tid));
      d->threading.stop_requested = false;
#endif /* MHD_USE_THREADS */
#ifndef NDEBUG
      d->dbg.threading_inited = true;
#endif

      res = init_individual_conns (d, s);
      if (MHD_SC_OK == res)
        return MHD_SC_OK;
    }
    deinit_itc (d);
  }
  deallocate_events (d);
  mhd_assert (MHD_SC_OK != res);
  return res;
}


/**
 * Deinit daemon-local (worker daemon for thread pool mode) threading data
 * and deallocate events.
 * To be used only with non-master daemons.
 * Do not start the thread even if configured for the internal threads.
 * @param d the daemon object
 * @return #MHD_SC_OK on success,
 *         the error code otherwise
 */
static MHD_FN_PAR_NONNULL_ (1) void
deinit_individual_thread_data_events_conns (struct MHD_Daemon *restrict d)
{
  deinit_itc (d);
  deallocate_events (d);
  mhd_assert (NULL == mhd_DLINKEDL_GET_FIRST (&(d->conns),all_conn));
  mhd_assert (NULL == mhd_DLINKEDL_GET_FIRST (&(d->events),proc_ready));
#ifndef NDEBUG
  d->dbg.events_fully_inited = false;
#endif
}


/**
 * Set the maximum number of handled connections for the daemon.
 * Works only for global limit, does not work for the worker daemon.
 * @param d the daemon object
 * @param s the user settings
 * @return #MHD_SC_OK on success,
 *         the error code otherwise
 */
static MHD_FN_PAR_NONNULL_ (1) MHD_FN_PAR_NONNULL_ (2)
MHD_FN_MUST_CHECK_RESULT_ enum MHD_StatusCode
set_connections_total_limits (struct MHD_Daemon *restrict d,
                              struct DaemonOptions *restrict s)
{
  unsigned int limit_by_conf;
  unsigned int limit_by_num;
  unsigned int limit_by_select;
  unsigned int resulting_limit;
  bool error_by_fd_setsize;
  unsigned int num_worker_daemons;

  mhd_assert (! mhd_D_HAS_MASTER (d));
  mhd_assert (mhd_D_TYPE_IS_VALID (d->threading.d_type));

  if (mhd_WM_INT_INTERNAL_EVENTS_THREAD_POOL == d->wmode_int)
  {
    mhd_assert (MHD_WM_WORKER_THREADS == s->work_mode.mode);
    if ((0 != s->global_connection_limit) &&
        (0 != s->work_mode.params.num_worker_threads) &&
        (s->global_connection_limit < s->work_mode.params.num_worker_threads))
    {
      mhd_LOG_MSG ( \
        d, MHD_SC_CONFIGURATION_CONN_LIMIT_TOO_SMALL, \
        "The limit specified by MHD_D_O_GLOBAL_CONNECTION_LIMIT is smaller " \
        "then the number of worker threads.");
      return MHD_SC_CONFIGURATION_CONN_LIMIT_TOO_SMALL;
    }
  }
  num_worker_daemons = 1;
#ifdef MHD_USE_THREADS
  if (mhd_D_TYPE_HAS_WORKERS (d->threading.d_type))
    num_worker_daemons = s->work_mode.params.num_worker_threads;
#endif /* MHD_USE_THREADS */

  limit_by_conf = s->global_connection_limit;
  limit_by_num = UINT_MAX;
  limit_by_select = UINT_MAX;

  error_by_fd_setsize = false;
#ifdef MHD_POSIX_SOCKETS
  if (1)
  {
    limit_by_num = (unsigned int) d->net.cfg.max_fd_num;
    if (0 != limit_by_num)
    {
      /* Find the upper limit.
         The real limit is lower, as any other process FDs will use the slots
         in the allowed numbers range */
      limit_by_num -= 3; /* The numbers zero, one and two are used typically */
#ifdef MHD_USE_THREADS
      limit_by_num -= mhd_ITC_NUM_FDS * num_worker_daemons;
#endif /* MHD_USE_THREADS */
      if (MHD_INVALID_SOCKET != d->net.listen.fd)
        --limit_by_num; /* One FD is used for the listening socket */
      if ((num_worker_daemons > limit_by_num) ||
          (limit_by_num > (unsigned int) d->net.cfg.max_fd_num) /* Underflow */)
      {
        if (d->net.cfg.max_fd_num == s->fd_number_limit)
        {
          mhd_LOG_MSG ( \
            d, MHD_SC_MAX_FD_NUMBER_LIMIT_TOO_STRICT, \
            "The limit specified by MHD_D_O_FD_NUMBER_LIMIT is too strict " \
            "for this daemon settings.");
          return MHD_SC_MAX_FD_NUMBER_LIMIT_TOO_STRICT;
        }
        else
        {
          mhd_assert (mhd_POLL_TYPE_SELECT == d->events.poll_type);
          error_by_fd_setsize = true;
        }
      }
    }
    else
      limit_by_num = (unsigned int) INT_MAX;
  }
#elif defined(MHD_WINSOCK_SOCKETS)
  if (1)
  {
#ifdef MHD_USE_SELECT
    if ((mhd_DAEMON_TYPE_SINGLE == d->threading.d_type) &&
        (mhd_POLL_TYPE_SELECT == d->events.poll_type))
    {
      /* W32 limits the total number (count) of sockets used for select() */
      unsigned int limit_per_worker;

      limit_per_worker = FD_SETSIZE;
      if (MHD_INVALID_SOCKET != d->net.listen.fd)
        --limit_per_worker;  /* The slot for the listening socket */
#ifdef MHD_USE_THREADS
      --limit_per_worker;  /* The slot for the ITC */
#endif /* MHD_USE_THREADS */
      if ((0 == limit_per_worker) || (limit_per_worker > FD_SETSIZE))
        error_by_fd_setsize = true;
      else
      {
        limit_by_select = limit_per_worker * num_worker_daemons;
        if (limit_by_select / limit_per_worker != num_worker_daemons)
          limit_by_select = UINT_MAX;
      }
    }
#endif /* MHD_USE_SELECT */
    (void) 0; /* Mute compiler warning */
  }
#endif /* MHD_POSIX_SOCKETS */
  if (error_by_fd_setsize)
  {
    mhd_LOG_MSG ( \
      d, MHD_SC_SYS_FD_SETSIZE_TOO_STRICT, \
      "The FD_SETSIZE is too strict to run daemon with the polling " \
      "by select() and with the specified number of workers.");
    return MHD_SC_SYS_FD_SETSIZE_TOO_STRICT;
  }

  if (0 != limit_by_conf)
  {
    /* The number has bet set explicitly */
    resulting_limit = limit_by_conf;
  }
  else
  {
    /* No user configuration provided */
    unsigned int suggested_limit;
#ifndef MHD_WINSOCK_SOCKETS
#define TYPICAL_NOFILES_LIMIT (1024)  /* The usual limit for the number of open FDs */
    suggested_limit = TYPICAL_NOFILES_LIMIT;
    suggested_limit -= 3; /* The numbers zero, one and two are used typically */
#ifdef MHD_USE_THREADS
    suggested_limit -= mhd_ITC_NUM_FDS * num_worker_daemons;
#endif /* MHD_USE_THREADS */
    if (MHD_INVALID_SOCKET != d->net.listen.fd)
      --suggested_limit; /* One FD is used for the listening socket */
    if (suggested_limit > TYPICAL_NOFILES_LIMIT)
      suggested_limit = 0; /* Overflow */
#else  /* MHD_WINSOCK_SOCKETS */
#ifdef _WIN64
    suggested_limit = 2048;
#else
    suggested_limit = 1024;
#endif
#endif /* MHD_WINSOCK_SOCKETS */
    if (suggested_limit < num_worker_daemons)
    {
      /* Use at least one connection for every worker daemon and
         let the system to restrict the new connections if they are above
         the system limits. */
      suggested_limit = num_worker_daemons;
    }
    resulting_limit = suggested_limit;
  }
  if (resulting_limit > limit_by_num)
    resulting_limit = limit_by_num;

  if (resulting_limit > limit_by_select)
    resulting_limit = limit_by_select;

  mhd_assert (resulting_limit >= num_worker_daemons);
  d->conns.cfg.count_limit = resulting_limit;

  return MHD_SC_OK;
}


/**
 * Set correct daemon threading type.
 * Set the number of workers for thread pool type.
 * @param d the daemon object
 * @param s the user settings
 * @return #MHD_SC_OK on success,
 *         the error code otherwise
 */
MHD_FN_PAR_NONNULL_ (1) \
  MHD_FN_MUST_CHECK_RESULT_ static inline enum MHD_StatusCode
set_d_threading_type (struct MHD_Daemon *restrict d)
{
  switch (d->wmode_int)
  {
  case mhd_WM_INT_EXTERNAL_EVENTS_EDGE:
  case mhd_WM_INT_EXTERNAL_EVENTS_LEVEL:
    mhd_assert (! mhd_WM_INT_HAS_THREADS (d->wmode_int));
    mhd_assert (mhd_POLL_TYPE_EXT == d->events.poll_type);
    mhd_assert (NULL != d->events.data.ext.cb);
#ifdef MHD_USE_THREADS
    d->threading.d_type = mhd_DAEMON_TYPE_SINGLE;
#endif /* MHD_USE_THREADS */
    return MHD_SC_OK;
  case mhd_WM_INT_INTERNAL_EVENTS_NO_THREADS:
    mhd_assert (! mhd_WM_INT_HAS_THREADS (d->wmode_int));
    mhd_assert (mhd_POLL_TYPE_EXT != d->events.poll_type);
#ifdef MHD_USE_THREADS
    d->threading.d_type = mhd_DAEMON_TYPE_SINGLE;
#endif /* MHD_USE_THREADS */
    return MHD_SC_OK;
#ifdef MHD_USE_THREADS
  case mhd_WM_INT_INTERNAL_EVENTS_ONE_THREAD:
    mhd_assert (mhd_WM_INT_HAS_THREADS (d->wmode_int));
    mhd_assert (mhd_POLL_TYPE_EXT != d->events.poll_type);
    d->threading.d_type = mhd_DAEMON_TYPE_SINGLE;
    return MHD_SC_OK;
  case mhd_WM_INT_INTERNAL_EVENTS_THREAD_PER_CONNECTION:
    mhd_assert (mhd_WM_INT_HAS_THREADS (d->wmode_int));
    mhd_assert (mhd_POLL_TYPE_EXT != d->events.poll_type);
    mhd_assert (mhd_POLL_TYPE_EPOLL != d->events.poll_type);
    d->threading.d_type = mhd_DAEMON_TYPE_LISTEN_ONLY;
    return MHD_SC_OK;
  case mhd_WM_INT_INTERNAL_EVENTS_THREAD_POOL:
    mhd_assert (mhd_WM_INT_HAS_THREADS (d->wmode_int));
    mhd_assert (mhd_POLL_TYPE_EXT != d->events.poll_type);
    d->threading.d_type = mhd_DAEMON_TYPE_MASTER_CONTROL_ONLY;
    return MHD_SC_OK;
#else  /* ! MHD_USE_THREADS */
  case mhd_WM_INT_INTERNAL_EVENTS_ONE_THREAD:
  case mhd_WM_INT_INTERNAL_EVENTS_THREAD_PER_CONNECTION:
  case mhd_WM_INT_INTERNAL_EVENTS_THREAD_POOL:
#endif /* ! MHD_USE_THREADS */
  default:
    mhd_assert (0 && "Impossible value");
  }
  MHD_UNREACHABLE_;
  return MHD_SC_INTERNAL_ERROR;
}


#ifdef MHD_USE_THREADS

/**
 * De-initialise workers pool, including workers daemons.
 * The threads must be not running.
 * @param d the daemon object
 * @param num_workers the number of workers to deinit
 * @return #MHD_SC_OK on success,
 *         the error code otherwise
 */
static MHD_FN_PAR_NONNULL_ (1) void
deinit_workers_pool (struct MHD_Daemon *restrict d,
                     unsigned int num_workers)
{
  unsigned int i;
  mhd_assert (mhd_D_TYPE_HAS_WORKERS (d->threading.d_type));
  mhd_assert (NULL != d->threading.hier.pool.workers);
  mhd_assert ((2 <= d->threading.hier.pool.num) || \
              (mhd_DAEMON_STATE_STARTING == d->state));
  mhd_assert ((num_workers == d->threading.hier.pool.num) || \
              (mhd_DAEMON_STATE_STARTING == d->state));
  mhd_assert ((mhd_DAEMON_STATE_STOPPING == d->state) || \
              (mhd_DAEMON_STATE_STARTING == d->state));

  /* Deinitialise in reverse order */
  for (i = num_workers - 1; num_workers > i; --i)
  { /* Note: loop exits after underflow of 'i' */
    struct MHD_Daemon *const worker = d->threading.hier.pool.workers + i;
    deinit_individual_thread_data_events_conns (worker);
#ifdef MHD_USE_EPOLL
    if (mhd_POLL_TYPE_EPOLL == worker->events.poll_type)
      deinit_epoll (worker);
#endif /* MHD_USE_EPOLL */
  }
  free (d->threading.hier.pool.workers);
#ifndef NDEBUG
  d->dbg.thread_pool_inited = false;
#endif
}


/**
 * Nullify worker daemon member that should be set only in master daemon
 * @param d
 */
static MHD_FN_PAR_NONNULL_ (1) void
reset_master_only_areas (struct MHD_Daemon *restrict d)
{
  /* Not needed. It is initialised later */
  /* memset (&(d->req_cfg.large_buf), 0, sizeof(d->req_cfg.large_buf)); */
  (void) d;
}


/**
 * Initialise workers pool, including workers daemons.
 * Do not start the threads.
 * @param d the daemon object
 * @param s the user settings
 * @return #MHD_SC_OK on success,
 *         the error code otherwise
 */
static MHD_FN_PAR_NONNULL_ (1) MHD_FN_PAR_NONNULL_ (2)
MHD_FN_MUST_CHECK_RESULT_ enum MHD_StatusCode
init_workers_pool (struct MHD_Daemon *restrict d,
                   struct DaemonOptions *restrict s)
{
  enum MHD_StatusCode res;
  size_t workers_pool_size;
  unsigned int conn_per_daemon;
  unsigned int num_workers;
  unsigned int conn_remainder;
  unsigned int i;

  mhd_assert (d->dbg.net_inited);
  mhd_assert (! d->dbg.net_deinited);
  mhd_assert (mhd_WM_INT_INTERNAL_EVENTS_THREAD_POOL == d->wmode_int);
  mhd_assert (mhd_D_TYPE_HAS_WORKERS (d->threading.d_type));
  mhd_assert (mhd_POLL_TYPE_NOT_SET_YET < d->events.poll_type);
  mhd_assert (1 < s->work_mode.params.num_worker_threads);
  mhd_assert (0 != d->conns.cfg.count_limit);
  mhd_assert (s->work_mode.params.num_worker_threads <= \
              d->conns.cfg.count_limit);
  mhd_assert (! d->dbg.thread_pool_inited);

  num_workers = s->work_mode.params.num_worker_threads;
  workers_pool_size =
    (sizeof(struct MHD_Daemon) * num_workers);
  if (workers_pool_size / num_workers != sizeof(struct MHD_Daemon))
  { /* Overflow */
    mhd_LOG_MSG ( \
      d, MHD_SC_THREAD_POOL_MALLOC_FAILURE, \
      "The size of the thread pool is too large.");
    return MHD_SC_THREAD_POOL_MALLOC_FAILURE;
  }

#ifndef NDEBUG
  mhd_itc_set_invalid (&(d->threading.itc));
  mhd_thread_handle_ID_set_invalid (&(d->threading.tid));
#endif

  d->threading.hier.pool.workers = malloc (workers_pool_size);
  if (NULL == d->threading.hier.pool.workers)
  {
    mhd_LOG_MSG ( \
      d, MHD_SC_THREAD_POOL_MALLOC_FAILURE, \
      "Failed to allocate memory for the thread pool.");
    return MHD_SC_THREAD_POOL_MALLOC_FAILURE;
  }

  conn_per_daemon = d->conns.cfg.count_limit / num_workers;
  conn_remainder = d->conns.cfg.count_limit % num_workers;
  res = MHD_SC_OK;
  for (i = 0; num_workers > i; ++i)
  {
    struct MHD_Daemon *restrict const worker =
      d->threading.hier.pool.workers + i;
    memcpy (worker, d, sizeof(struct MHD_Daemon));
    reset_master_only_areas (worker);

    worker->threading.d_type = mhd_DAEMON_TYPE_WORKER;
    worker->threading.hier.master = d;
    worker->conns.cfg.count_limit = conn_per_daemon;
    if (conn_remainder > i)
      worker->conns.cfg.count_limit++; /* Distribute the reminder */
#ifdef MHD_USE_EPOLL
    if (mhd_POLL_TYPE_EPOLL == worker->events.poll_type)
    {
      if (0 == i)
      {
        mhd_assert (0 <= d->events.data.epoll.e_fd);
        /* Move epoll control FD from the master daemon to the first worker */
        /* The FD has been copied by memcpy(). Clean-up the master daemon. */
        d->events.data.epoll.e_fd = MHD_INVALID_SOCKET;
      }
      else
        res = init_epoll (worker);
    }
#endif /* MHD_USE_EPOLL */
    if (MHD_SC_OK == res)
    {
      res = init_individual_thread_data_events_conns (worker, s);
      if (MHD_SC_OK == res)
        continue; /* Process the next worker */

#ifdef MHD_USE_EPOLL
      if (mhd_POLL_TYPE_EPOLL == worker->events.poll_type)
        deinit_epoll (worker);
#endif /* MHD_USE_EPOLL */

      /* Below is the clean-up of the current slot */
    }
    free (worker);
    break;
  }
  if (num_workers == i)
  {
    mhd_assert (MHD_SC_OK == res);
#ifndef NDEBUG
    d->dbg.thread_pool_inited = true;
    d->dbg.threading_inited = true;
#endif
    d->threading.hier.pool.num = num_workers;
    return MHD_SC_OK;
  }

  /* Below is a clean-up */

  mhd_assert (MHD_SC_OK != res);
  deinit_workers_pool (d, i);
  return res;
}


#endif /* MHD_USE_THREADS */

/**
 * Initialise threading and inter-thread communications.
 * Also finish initialisation of events processing and initialise daemon's
 * connection data.
 * Do not start the thread even if configured for the internal threads.
 * @param d the daemon object
 * @param s the user settings
 * @return #MHD_SC_OK on success,
 *         the error code otherwise
 */
static MHD_FN_PAR_NONNULL_ (1) MHD_FN_PAR_NONNULL_ (2)
MHD_FN_MUST_CHECK_RESULT_ enum MHD_StatusCode
daemon_init_threading_and_conn (struct MHD_Daemon *restrict d,
                                struct DaemonOptions *restrict s)
{
  enum MHD_StatusCode res;

  mhd_assert (d->dbg.net_inited);
  mhd_assert (! d->dbg.net_deinited);
  mhd_assert (mhd_POLL_TYPE_NOT_SET_YET != d->events.poll_type);

  res = set_d_threading_type (d);
  if (MHD_SC_OK != res)
    return res;

  res = set_connections_total_limits (d, s);
  if (MHD_SC_OK != res)
    return res;

  d->threading.cfg.stack_size = s->stack_size;

  if (! mhd_D_TYPE_HAS_WORKERS (d->threading.d_type))
    res = init_individual_thread_data_events_conns (d, s);
  else
  {
#ifdef MHD_USE_THREADS
    res = init_workers_pool (d, s);
#else  /* ! MHD_USE_THREADS */
    mhd_assert (0 && "Impossible value");
    MHD_UNREACHABLE_;
    return MHD_SC_INTERNAL_ERROR;
#endif /* ! MHD_USE_THREADS */
  }
  if (MHD_SC_OK == res)
  {
    mhd_assert (d->dbg.events_allocated || \
                mhd_D_TYPE_HAS_WORKERS (d->threading.d_type));
    mhd_assert (! mhd_D_TYPE_HAS_WORKERS (d->threading.d_type) || \
                ! d->dbg.events_allocated);
    mhd_assert (! d->dbg.thread_pool_inited || \
                mhd_D_TYPE_HAS_WORKERS (d->threading.d_type));
    mhd_assert (! mhd_D_TYPE_HAS_WORKERS (d->threading.d_type) || \
                d->dbg.thread_pool_inited);
    mhd_assert (! mhd_D_TYPE_IS_INTERNAL_ONLY (d->threading.d_type));
    mhd_assert (! d->dbg.events_allocated || d->dbg.connections_inited);
    mhd_assert (! d->dbg.connections_inited || d->dbg.events_allocated);
  }
  return res;
}


/**
 * De-initialise threading and inter-thread communications.
 * Also deallocate events and de-initialise daemon's connection data.
 * No daemon-manged threads should be running.
 * @param d the daemon object
 * @param s the user settings
 * @return #MHD_SC_OK on success,
 *         the error code otherwise
 */
static MHD_FN_PAR_NONNULL_ (1) void
daemon_deinit_threading_and_conn (struct MHD_Daemon *restrict d)
{
  mhd_assert (d->dbg.net_inited);
  mhd_assert (! d->dbg.net_deinited);
  mhd_assert (d->dbg.threading_inited);
  mhd_assert (! mhd_D_TYPE_IS_INTERNAL_ONLY (d->threading.d_type));
  if (! mhd_D_TYPE_HAS_WORKERS (d->threading.d_type))
  {
    mhd_assert (mhd_WM_INT_INTERNAL_EVENTS_THREAD_POOL != d->wmode_int);
    mhd_assert (d->dbg.connections_inited);
    mhd_assert (d->dbg.events_allocated);
    mhd_assert (! d->dbg.thread_pool_inited);
    deinit_individual_thread_data_events_conns (d);
  }
  else
  {
#ifdef MHD_USE_THREADS
    mhd_assert (mhd_WM_INT_INTERNAL_EVENTS_THREAD_POOL == d->wmode_int);
    mhd_assert (! d->dbg.connections_inited);
    mhd_assert (! d->dbg.events_allocated);
    mhd_assert (d->dbg.thread_pool_inited);
    deinit_workers_pool (d, d->threading.hier.pool.num);
#else  /* ! MHD_USE_THREADS */
    mhd_assert (0 && "Impossible value");
    MHD_UNREACHABLE_;
    (void) 0;
#endif /* ! MHD_USE_THREADS */
  }
}


#ifdef MHD_USE_THREADS

/**
 * Start the daemon individual single thread.
 * Works both for single thread daemons and for worker daemon for thread
 * pool mode.
 * Must be called only for daemons with internal threads.
 * @param d the daemon object, must be completely initialised
 * @return #MHD_SC_OK on success,
 *         the error code otherwise
 */
static MHD_FN_PAR_NONNULL_ (1)
MHD_FN_MUST_CHECK_RESULT_ enum MHD_StatusCode
start_individual_daemon_thread (struct MHD_Daemon *restrict d)
{
  mhd_assert (d->dbg.threading_inited);
  mhd_assert (mhd_WM_INT_HAS_THREADS (d->wmode_int));
  mhd_assert (mhd_D_TYPE_IS_VALID (d->threading.d_type));
  mhd_assert (! mhd_D_TYPE_HAS_WORKERS (d->threading.d_type));
  mhd_assert (! mhd_thread_handle_ID_is_valid_handle (d->threading.tid));

  if (mhd_DAEMON_TYPE_SINGLE == d->threading.d_type)
  {
    if (! mhd_create_named_thread ( \
          &(d->threading.tid), "MHD-single", \
          d->threading.cfg.stack_size, \
          &mhd_worker_all_events, \
          (void*) d))
    {
      mhd_LOG_MSG (d, MHD_SC_THREAD_MAIN_LAUNCH_FAILURE, \
                   "Failed to start daemon main thread.");
      return MHD_SC_THREAD_MAIN_LAUNCH_FAILURE;
    }
  }
  else if (mhd_DAEMON_TYPE_WORKER == d->threading.d_type)
  {
    if (! mhd_create_named_thread ( \
          &(d->threading.tid), "MHD-worker", \
          d->threading.cfg.stack_size, \
          &mhd_worker_all_events, \
          (void*) d))
    {
      mhd_LOG_MSG (d, MHD_SC_THREAD_WORKER_LAUNCH_FAILURE, \
                   "Failed to start daemon worker thread.");
      return MHD_SC_THREAD_WORKER_LAUNCH_FAILURE;
    }
  }
  else if (mhd_DAEMON_TYPE_LISTEN_ONLY == d->threading.d_type)
  {
    if (! mhd_create_named_thread ( \
          &(d->threading.tid), "MHD-listen", \
          d->threading.cfg.stack_size, \
          &mhd_worker_listening_only, \
          (void*) d))
    {
      mhd_LOG_MSG (d, MHD_SC_THREAD_LISTENING_LAUNCH_FAILURE, \
                   "Failed to start daemon listening thread.");
      return MHD_SC_THREAD_LISTENING_LAUNCH_FAILURE;
    }
  }
  else
  {
    mhd_assert (0 && "Impossible value");
    MHD_UNREACHABLE_;
    return MHD_SC_INTERNAL_ERROR;
  }
  mhd_assert (mhd_thread_handle_ID_is_valid_handle (d->threading.tid));
  return MHD_SC_OK;
}


/**
 * Stop the daemon individual single thread.
 * Works both for single thread daemons and for worker daemon for thread
 * pool mode.
 * Must be called only for daemons with internal threads.
 * @param d the daemon object, must be completely initialised
 * @return #MHD_SC_OK on success,
 *         the error code otherwise
 */
MHD_FN_PAR_NONNULL_ (1) static void
stop_individual_daemon_thread (struct MHD_Daemon *restrict d)
{
  mhd_assert (d->dbg.threading_inited);
  mhd_assert (mhd_WM_INT_HAS_THREADS (d->wmode_int));
  mhd_assert (mhd_D_TYPE_IS_VALID (d->threading.d_type));
  mhd_assert (! mhd_D_TYPE_HAS_WORKERS (d->threading.d_type));
  mhd_assert ((mhd_DAEMON_STATE_STOPPING == d->state) || \
              (mhd_DAEMON_STATE_STARTING == d->state));
  mhd_assert (mhd_thread_handle_ID_is_valid_handle (d->threading.tid));

  d->threading.stop_requested = true;

  mhd_daemon_trigger_itc (d);
  if (! mhd_thread_handle_ID_join_thread (d->threading.tid))
  {
    mhd_LOG_MSG (d, MHD_SC_DAEMON_THREAD_STOP_ERROR, \
                 "Failed to stop daemon main thread.");
  }
}


/**
 * Stop all worker threads in the thread pool.
 * Must be called only for master daemons with thread pool.
 * @param d the daemon object, the workers threads must be running
 * @param num_workers the number of threads to stop
 */
static MHD_FN_PAR_NONNULL_ (1) void
stop_worker_pool_threads (struct MHD_Daemon *restrict d,
                          unsigned int num_workers)
{
  unsigned int i;
  mhd_assert (mhd_D_TYPE_HAS_WORKERS (d->threading.d_type));
  mhd_assert (NULL != d->threading.hier.pool.workers);
  mhd_assert (0 != d->threading.hier.pool.num);
  mhd_assert (d->dbg.thread_pool_inited);
  mhd_assert (2 <= d->threading.hier.pool.num);
  mhd_assert ((num_workers == d->threading.hier.pool.num) || \
              (mhd_DAEMON_STATE_STARTING == d->state));
  mhd_assert ((mhd_DAEMON_STATE_STOPPING == d->state) || \
              (mhd_DAEMON_STATE_STARTING == d->state));

  /* Process all the threads in the reverse order */

  /* Trigger all threads */
  for (i = num_workers - 1; num_workers > i; --i)
  { /* Note: loop exits after underflow of 'i' */
    d->threading.hier.pool.workers[i].threading.stop_requested = true;
    mhd_assert (mhd_ITC_IS_VALID ( \
                  d->threading.hier.pool.workers[i].threading.itc));
    mhd_daemon_trigger_itc (d->threading.hier.pool.workers + i);
  }

  /* Collect all threads */
  for (i = num_workers - 1; num_workers > i; --i)
  { /* Note: loop exits after underflow of 'i' */
    struct MHD_Daemon *const restrict worker =
      d->threading.hier.pool.workers + i;
    mhd_assert (mhd_thread_handle_ID_is_valid_handle (worker->threading.tid));
    if (! mhd_thread_handle_ID_join_thread (worker->threading.tid))
    {
      mhd_LOG_MSG (d, MHD_SC_DAEMON_THREAD_STOP_ERROR, \
                   "Failed to stop a worker thread.");
    }
  }
}


/**
 * Start the workers pool threads.
 * Must be called only for master daemons with thread pool.
 * @param d the daemon object, must be completely initialised
 * @return #MHD_SC_OK on success,
 *         the error code otherwise
 */
static MHD_FN_PAR_NONNULL_ (1)
MHD_FN_MUST_CHECK_RESULT_ enum MHD_StatusCode
start_worker_pool_threads (struct MHD_Daemon *restrict d)
{
  enum MHD_StatusCode res;
  unsigned int i;

  mhd_assert (d->dbg.threading_inited);
  mhd_assert (mhd_WM_INT_HAS_THREADS (d->wmode_int));
  mhd_assert (mhd_D_TYPE_IS_VALID (d->threading.d_type));
  mhd_assert (mhd_D_TYPE_HAS_WORKERS (d->threading.d_type));
  mhd_assert (d->dbg.thread_pool_inited);
  mhd_assert (2 <= d->threading.hier.pool.num);

  res = MHD_SC_OK;

  for (i = 0; d->threading.hier.pool.num > i; ++i)
  {
    res = start_individual_daemon_thread (d->threading.hier.pool.workers + i);
    if (MHD_SC_OK != res)
      break;
  }
  if (d->threading.hier.pool.num == i)
  {
    mhd_assert (MHD_SC_OK == res);
    return MHD_SC_OK;
  }

  stop_worker_pool_threads (d, i);
  mhd_assert (MHD_SC_OK != res);
  return res;
}


#endif /* MHD_USE_THREADS */

/**
 * Start the daemon internal threads, if the daemon configured to use them.
 * @param d the daemon object, must be completely initialised
 * @return #MHD_SC_OK on success,
 *         the error code otherwise
 */
static MHD_FN_PAR_NONNULL_ (1)
MHD_FN_MUST_CHECK_RESULT_ enum MHD_StatusCode
daemon_start_threads (struct MHD_Daemon *restrict d)
{
  mhd_assert (d->dbg.net_inited);
  mhd_assert (! d->dbg.net_deinited);
  mhd_assert (d->dbg.threading_inited);
  mhd_assert (! mhd_D_TYPE_IS_INTERNAL_ONLY (d->threading.d_type));
  if (mhd_WM_INT_HAS_THREADS (d->wmode_int))
  {
#ifdef MHD_USE_THREADS
    if (mhd_WM_INT_INTERNAL_EVENTS_THREAD_POOL != d->wmode_int)
    {
      mhd_assert (d->dbg.threading_inited);
      mhd_assert (mhd_DAEMON_TYPE_MASTER_CONTROL_ONLY != d->threading.d_type);
      return start_individual_daemon_thread (d);
    }
    else
    {
      mhd_assert (d->dbg.thread_pool_inited);
      mhd_assert (mhd_DAEMON_TYPE_MASTER_CONTROL_ONLY == d->threading.d_type);
      return start_worker_pool_threads (d);
    }
#else  /* ! MHD_USE_THREADS */
    mhd_assert (0 && "Impossible value");
    MHD_UNREACHABLE_;
    return MHD_SC_INTERNAL_ERROR;
#endif /* ! MHD_USE_THREADS */
  }
  return MHD_SC_OK;
}


/**
 * Stop the daemon internal threads, if the daemon configured to use them.
 * @param d the daemon object, the threads (if any) must be started
 * @return #MHD_SC_OK on success,
 *         the error code otherwise
 */
static MHD_FN_PAR_NONNULL_ (1) void
daemon_stop_threads (struct MHD_Daemon *restrict d)
{
  mhd_assert (d->dbg.net_inited);
  mhd_assert (! d->dbg.net_deinited);
  mhd_assert (d->dbg.threading_inited);
  if (mhd_WM_INT_HAS_THREADS (d->wmode_int))
  {
#ifdef MHD_USE_THREADS
    if (mhd_WM_INT_INTERNAL_EVENTS_THREAD_POOL != d->wmode_int)
    {
      mhd_assert (d->dbg.threading_inited);
      mhd_assert (! mhd_D_TYPE_HAS_WORKERS (d->threading.d_type));
      stop_individual_daemon_thread (d);
      return;
    }
    else
    {
      mhd_assert (d->dbg.thread_pool_inited);
      mhd_assert (mhd_D_TYPE_HAS_WORKERS (d->threading.d_type));
      stop_worker_pool_threads (d, d->threading.hier.pool.num);
      return;
    }
#else  /* ! MHD_USE_THREADS */
    mhd_assert (0 && "Impossible value");
    MHD_UNREACHABLE_;
    return MHD_SC_INTERNAL_ERROR;
#endif /* ! MHD_USE_THREADS */
  }
}


/**
 * Internal daemon initialisation function.
 * This function calls all required initialisation stages one-by-one.
 * @param d the daemon object
 * @param s the user settings
 * @return #MHD_SC_OK on success,
 *         the error code otherwise
 */
static MHD_FN_PAR_NONNULL_ (1) MHD_FN_PAR_NONNULL_ (2)
MHD_FN_MUST_CHECK_RESULT_ enum MHD_StatusCode
daemon_start_internal (struct MHD_Daemon *restrict d,
                       struct DaemonOptions *restrict s)
{
  enum MHD_StatusCode res;

  res = daemon_set_work_mode (d, s);
  if (MHD_SC_OK != res)
    return res;

  res = daemon_init_net (d, s);
  if (MHD_SC_OK != res)
    return res;


  // TODO: Other init

  res = daemon_init_threading_and_conn (d, s);
  if (MHD_SC_OK == res)
  {
    mhd_assert (d->dbg.net_inited);
    mhd_assert (d->dbg.threading_inited);
    mhd_assert (! mhd_D_TYPE_IS_INTERNAL_ONLY (d->threading.d_type));

    res = daemon_init_large_buf (d, s);
    if (MHD_SC_OK == res)
    {
      res = daemon_start_threads (d);
      if (MHD_SC_OK == res)
      {
        return MHD_SC_OK;
      }

      /* Below is a clean-up path */
      daemon_deinit_large_buf (d);
    }
    daemon_deinit_threading_and_conn (d);
  }


  daemon_deinit_net (d);
  mhd_assert (MHD_SC_OK != res);
  return res;
}


MHD_EXTERN_
MHD_FN_PAR_NONNULL_ (1) MHD_FN_MUST_CHECK_RESULT_ enum MHD_StatusCode
MHD_daemon_start (struct MHD_Daemon *daemon)
{
  struct MHD_Daemon *const d = daemon; /* a short alias */
  struct DaemonOptions *const s = daemon->settings; /* a short alias */
  enum MHD_StatusCode res;

  if (mhd_DAEMON_STATE_NOT_STARTED != daemon->state)
    return MHD_SC_TOO_LATE;

  mhd_assert (NULL != s);

  d->state = mhd_DAEMON_STATE_STARTING;
  res = daemon_start_internal (d, s);

  d->settings = NULL;
  dsettings_release (s);

  d->state =
    (MHD_SC_OK == res) ? mhd_DAEMON_STATE_STARTED : mhd_DAEMON_STATE_FAILED;

  return res;
}


MHD_EXTERN_ MHD_FN_PAR_NONNULL_ALL_ void
MHD_daemon_destroy (struct MHD_Daemon *daemon)
{
  bool not_yet_started = (mhd_DAEMON_STATE_NOT_STARTED == daemon->state);
  bool has_failed = (mhd_DAEMON_STATE_FAILED == daemon->state);
  mhd_assert (mhd_DAEMON_STATE_STOPPING > daemon->state);
  mhd_assert (mhd_DAEMON_STATE_STARTING != daemon->state);

  daemon->state = mhd_DAEMON_STATE_STOPPING;
  if (not_yet_started)
  {
    mhd_assert (NULL != daemon->settings);
    dsettings_release (daemon->settings);
    return;
  }
  else if (! has_failed)
  {
    mhd_assert (NULL == daemon->settings);
    mhd_assert (daemon->dbg.threading_inited);

    daemon_stop_threads (daemon);

    daemon_deinit_threading_and_conn (daemon);

    daemon_deinit_large_buf (daemon);

    daemon_deinit_net (daemon);
  }
  daemon->state = mhd_DAEMON_STATE_STOPPED; /* Useful only for debugging */

  free (daemon);
}
