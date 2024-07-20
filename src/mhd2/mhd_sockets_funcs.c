/*
  This file is part of GNU libmicrohttpd
  Copyright (C) 2014-2024 Karlson2k (Evgeny Grin)

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
 * @file src/mhd2/mhd_sockets_funcs.c
 * @brief  Implementations of sockets manipulating functions
 * @author Karlson2k (Evgeny Grin)
 */
#include "mhd_sys_options.h"
#include "sys_sockets_types.h"
#include "mhd_sockets_funcs.h"
#include "sys_sockets_headers.h"
#include "sys_ip_headers.h"
#ifdef MHD_POSIX_SOCKETS
#  ifdef HAVE_SYS_TYPES_H
#    include <sys/types.h>
#  endif
#  ifdef HAVE_UNISTD_H
#    include <unistd.h>
#  else
#    include <stdlib.h>
#  endif
#  include <fcntl.h>
#elif defined(MHD_WINSOCK_SOCKETS)
#  include <windows.h>
#endif
#ifndef INADDR_LOOPBACK
#  include <string.h> /* For memcpy() */
#endif

#include "mhd_sockets_macros.h"


MHD_INTERNAL bool
mhd_socket_nonblocking (MHD_Socket sckt)
{
#if defined(MHD_POSIX_SOCKETS)
  // TODO: detect constants in configure
#if defined(F_GETFL) && defined(O_NONBLOCK) && defined(F_SETFL)
  int get_flags;
  int set_flags;

  get_flags = fcntl (sckt, F_GETFL);
  if (0 > get_flags)
    return false;

  set_flags = (get_flags | O_NONBLOCK);
  if (get_flags == set_flags)
    return true;

  if (-1 != fcntl (sckt, F_SETFL, set_flags))
    return true;
#endif /* F_GETFL && O_NONBLOCK && F_SETFL */
#elif defined(MHD_WINSOCK_SOCKETS)
  unsigned long set_flag = 1;

  if (0 == ioctlsocket (sckt, (long) FIONBIO, &set_flag))
    return true;
#endif /* MHD_WINSOCK_SOCKETS */

  return false;
}


MHD_INTERNAL bool
mhd_socket_noninheritable (MHD_Socket sckt)
{
#if defined(MHD_POSIX_SOCKETS)
  // TODO: detect constants in configure
#if defined(F_GETFD) && defined(FD_CLOEXEC) && defined(F_SETFD)
  int get_flags;
  int set_flags;

  get_flags = fcntl (sckt, F_GETFD);
  if (0 > get_flags)
    return false;

  set_flags = (get_flags | FD_CLOEXEC);
  if (get_flags == set_flags)
    return true;

  if (-1 != fcntl (sckt, F_SETFD, set_flags))
    return true;
#endif /* F_GETFD && FD_CLOEXEC && F_SETFD */
#elif defined(MHD_WINSOCK_SOCKETS)
  if (SetHandleInformation ((HANDLE) sckt, HANDLE_FLAG_INHERIT, 0))
    return true;
#endif /* MHD_WINSOCK_SOCKETS */
  return false;
}


MHD_INTERNAL bool
mhd_socket_set_nodelay (MHD_Socket sckt,
                        bool on)
{
  // TODO: detect constants in configure
#ifdef TCP_NODELAY
  mhd_SCKT_OPT_BOOL value;

  value = on ? 1 : 0;

  return 0 == setsockopt (sckt, IPPROTO_TCP, TCP_NODELAY,
                          (const void *) &value, sizeof (value));
#else  /* ! TCP_NODELAY */
  (void) sock; (void) on;
  return false;
#endif /* ! TCP_NODELAY */
}


MHD_INTERNAL bool
mhd_socket_set_hard_close (MHD_Socket sckt)
{
  // TODO: detect constants in configure
#if defined(SOL_SOCKET) && defined(SO_LINGER)
  struct linger par;

  par.l_onoff = 1;
  par.l_linger = 0;

  return 0 == setsockopt (sckt, SOL_SOCKET, SO_LINGER,
                          (const void *) &par, sizeof (par));
#else  /* ! TCP_NODELAY */
  (void) sock;
  return false;
#endif /* ! TCP_NODELAY */
}


MHD_INTERNAL bool
mhd_socket_shut_wr (MHD_Socket sckt)
{
#if defined(SHUT_WR) // TODO: detect constants in configure
  return 0 == shutdown (sckt, SHUT_WR);
#elif defined(SD_SEND) // TODO: detect constants in configure
  return 0 == shutdown (sckt, SD_SEND);
#else
  return false;
#endif
}


#ifndef HAVE_SOCKETPAIR

static bool
mhd_socket_blocking (MHD_Socket sckt)
{
#if defined(MHD_POSIX_SOCKETS)
  // TODO: detect constants in configure
#if defined(F_GETFL) && defined(O_NONBLOCK) && defined(F_SETFL)
  int get_flags;
  int set_flags;

  get_flags = fcntl (sckt, F_GETFL);
  if (0 > get_flags)
    return false;

  set_flags = (flags & ~O_NONBLOCK);
  if (get_flags == set_flags)
    return true;

  if (-1 != fcntl (sckt, F_SETFL, set_flags))
    return true;
#endif /* F_GETFL && O_NONBLOCK && F_SETFL */
#elif defined(MHD_WINSOCK_SOCKETS)
  unsigned long set_flag = 0;

  if (0 == ioctlsocket (sckt, (long) FIONBIO, &set_flag))
    return true;
#endif /* MHD_WINSOCK_SOCKETS */

  return false;
}


MHD_INTERNAL bool
mhd_socket_pair_func (MHD_Socket sckt[2], bool non_blk)
{
  int i;

#define PAIR_MAX_TRIES 511
  for (i = 0; i < PAIR_MAX_TRIES; i++)
  {
    struct sockaddr_in listen_addr;
    MHD_Socket listen_s;
    static const socklen_t c_addinlen = sizeof(struct sockaddr_in);   /* Try to help compiler to optimise */
    socklen_t addr_len = c_addinlen;

    listen_s = socket (AF_INET,
                       SOCK_STREAM,
                       IPPROTO_TCP);
    if (INVALID_SOCKET == listen_s)
      break;   /* can't create even single socket */

    listen_addr.sin_family = AF_INET;
    listen_addr.sin_port = 0;   /* same as htons(0) */
#ifdef INADDR_LOOPBACK
    listen_addr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
#else
    memcpy (&(listen_addr.sin_addr.s_addr), "\x7F\x00\x00\x01", 4);
#endif
    if ( ((0 == bind (listen_s,
                      (struct sockaddr *) &listen_addr,
                      c_addinlen)) &&
          (0 == listen (listen_s,
                        1) ) &&
          (0 == getsockname (listen_s,
                             (struct sockaddr *) &listen_addr,
                             &addr_len))) )
    {
      MHD_Socket client_s = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
      struct sockaddr_in accepted_from_addr;
      struct sockaddr_in client_addr;

      if (INVALID_SOCKET != client_s)
      {
        if (mhd_socket_nonblocking (client_s) &&
            ( (0 == connect (client_s,
                             (struct sockaddr *) &listen_addr,
                             c_addinlen)) ||
              mhd_SCKT_LERR_IS_EAGAIN () ))
        {
          MHD_Socket server_s;

          addr_len = c_addinlen;
          server_s = accept (listen_s,
                             (struct sockaddr *) &accepted_from_addr,
                             &addr_len);
          if (MHD_INVALID_SOCKET != server_s)
          {
            addr_len = c_addinlen;
            if ( (0 == getsockname (client_s,
                                    (struct sockaddr *) &client_addr,
                                    &addr_len)) &&
                 (accepted_from_addr.sin_port == client_addr.sin_port) &&
                 (accepted_from_addr.sin_addr.s_addr ==
                  client_addr.sin_addr.s_addr) )
            {
              (void) mhd_socket_set_nodelay (server_s, true);
              (void) mhd_socket_set_nodelay (client_s, true);
              if (non_blk ?
                  mhd_socket_nonblocking (server_s) :
                  mhd_socket_blocking (client_s))
              {
                mhd_socket_close (listen_s);
                sckt[0] = server_s;
                sckt[1] = client_s;
                return true;
              }
            }
            mhd_socket_close (server_s);
          }
        }
        mhd_socket_close (client_s);
      }
    }
    mhd_socket_close (listen_s);
  }

  sckt[0] = INVALID_SOCKET;
  sckt[1] = INVALID_SOCKET;

  return false;
}


#endif /* ! HAVE_SOCKETPAIR */
