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
 * @file src/mhd2/mhd_conn_socket.h
 * @brief  The definition of the connection-specific socket data
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_CONN_SOCKET_H
#define MHD_CONN_SOCKET_H 1

#include "mhd_sys_options.h"

#include "sys_bool_type.h"

#include "mhd_socket_type.h"
#include "mhd_tristate.h"
#include "mhd_socket_error.h"


struct sockaddr_storage; /* Forward declaration */

/**
 * The network states for connected sockets
 * An internal version of #MHD_FdState. Keep in sync!
 */
enum MHD_FIXED_FLAGS_ENUM_ mhd_SocketNetState
{
  /**
   * No active states of the socket
   */
  mhd_SOCKET_NET_STATE_NOTHING = 0
  ,
  /**
   * The socket is ready for receiving
   */
  mhd_SOCKET_NET_STATE_RECV_READY = 1 << 0
  ,
  /**
   * The socket is ready for sending
   */
  mhd_SOCKET_NET_STATE_SEND_READY = 1 << 1
  ,
  /**
   * The socket has some unrecoverable error
   */
  mhd_SOCKET_NET_STATE_ERROR_READY = 1 << 2
};

/**
 * Connection-specific socket state data
 */
struct mhd_ConnSocketState
{
  /**
   * The current state of TCP_NODELAY socket setting
   */
  enum mhd_Tristate nodelay;

// #ifndef MHD_SOCKETS_KIND_WINSOCK // TODO: conditionally use in the code
  /**
   * The current state of TCP_CORK / TCP_NOPUSH socket setting
   */
  enum mhd_Tristate corked;
// #endif

  /**
   * Set to 'true' when the remote side shut down write/send and
   * __the last byte from the remote has been read__.
   */
  bool rmt_shut_wr;

  /**
   * The type of the error when the socket disconnected early
   */
  enum mhd_SocketError discnt_err;
};

/**
 * Connection-specific socket properties
 */
struct mhd_ConnSocketProperties
{
  /**
   * The type of the socket: TCP/IP or non TCP/IP (a UNIX domain socket, a pipe)
   */
  enum mhd_Tristate is_nonip;

  /**
   * true if the socket is non-blocking, false otherwise.
   */
  bool is_nonblck;

  /**
   * true if the socket has set SIGPIPE suppression
   */
  bool has_spipe_supp;
};


/**
 * The connection socket remote address information
 */
struct mhd_ConnSocketAddr
{
  /**
   * The remote address.
   * Allocated by malloc() (not in the connection memory pool!).
   * Could be NULL if the address is not known.
   */
  struct sockaddr_storage *data;

  /**
   * The size of the address pointed by @a data.
   * Zero is @a data is NULL.
   */
  size_t size;
};

/**
 * Connection-specific socket data
 */
struct mhd_ConnSocket
{
  /**
   * The network socket.
   */
  MHD_Socket fd;

  /**
   * Connection-specific socket state data
   */
  struct mhd_ConnSocketState state;

  /**
   * The receive / send / error readiness the socket
   */
  enum mhd_SocketNetState ready;

  /**
   * Connection-specific socket properties
   */
  struct mhd_ConnSocketProperties props;

  /**
   * The connection socket remote address information
   */
  struct mhd_ConnSocketAddr addr;
};

#endif /* ! MHD_CONN_SOCKET_H */
