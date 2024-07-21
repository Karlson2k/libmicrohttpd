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
 * @file src/mhd2/mhd_socket_error.h
 * @brief  The definition of the mhd_SocketError enum and related macros and
 *         declarations of related functions
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_SOCKET_ERROR_H
#define MHD_SOCKET_ERROR_H 1

#include "mhd_sys_options.h"
#include "mhd_socket_type.h"

// TODO: better classification, when clearer local closing / network aborts
/**
 * Recognised socket errors for recv() and send()
 */
enum MHD_FIXED_ENUM_ mhd_SocketError
{
  /**
   * No error.
   */
  mhd_SOCKET_ERR_NO_ERROR = 0
  ,
  /**
   * No more data to get / no more space to put the data.
   */
  mhd_SOCKET_ERR_AGAIN
  ,
  /**
   * The process has been interrupted by external factors.
   */
  mhd_SOCKET_ERR_INTR
  ,
  /**
   * "Not enough memory" / "not enough system resources"
   */
  mhd_SOCKET_ERR_NOMEM
  ,
  /**
   * The connection has been gracefully closed by remote peer
   */
  mhd_SOCKET_ERR_REMT_DISCONN
  ,
  /**
   * The connection has been hard-closed by remote peer.
   */
  mhd_SOCKET_ERR_CONNRESET
  ,
  /**
   * Meta-error for any other errors indicating a broken connection.
   * It can be keep-alive ping failure or timeout to get ACK for the
   * transmitted data.
   */
  mhd_SOCKET_ERR_CONN_BROKEN
  ,
  /**
   * Connection is not connected anymore due to network error or
   * any other reason.
   */
  mhd_SOCKET_ERR_NOTCONN
  ,
  /**
   * General TLS encryption or decryption error
   */
  mhd_SOCKET_ERR_TLS
  ,
  /**
   * The socket has been shut down for writing or no longer connected
   * Only for 'send()'.
   */
  mhd_SOCKET_ERR_PIPE
  ,
  /**
   * The error status reported, but concrete code error has not been
   * checked by MHD
   */
  mhd_SOCKET_ERR_NOT_CHECKED
  ,
  /**
   * The socket FD is invalid
   */
  mhd_SOCKET_ERR_BADF
  ,
  /**
   * Socket function parameters are invalid
   */
  mhd_SOCKET_ERR_INVAL
  ,
  /**
   * Socket function parameters are not supported
   */
  mhd_SOCKET_ERR_OPNOTSUPP
  ,
  /**
   * Used FD is not a socket
   */
  mhd_SOCKET_ERR_NOTSOCK
  ,
  /**
   * Other socket error
   */
  mhd_SOCKET_ERR_OTHER
  ,
  /**
   * Internal (MHD) error
   * Not actually reported by the OS
   */
  mhd_SOCKET_ERR_INTERNAL

};

/**
 * Check whether the socket error is unrecoverable
 */
#define mhd_SOCKET_ERR_IS_HARD(err) (mhd_SOCKET_ERR_REMT_DISCONN <= (err))

/**
 * Check whether the socket error is unexpected
 */
#define mhd_SOCKET_ERR_IS_BAD(err) (mhd_SOCKET_ERR_BADF <= (err))

/**
 * Map recv() / send() system socket error to the enum value
 * @param socket_err the system socket error
 * @return the enum value for the @a socket_err
 */
MHD_INTERNAL enum mhd_SocketError
mhd_socket_error_get_from_sys_err (int socket_err);

/**
 * Get the last socket error recoded for the given socket
 * @param fd the socket to check for the error
 * @return the recorded error @a fd,
 *         #mhd_SOCKET_ERR_NOT_CHECKED if not possible to check @a fd for
 *         the error
 */
MHD_INTERNAL enum mhd_SocketError
mhd_socket_error_get_from_socket (MHD_Socket fd);

#endif /* ! MHD_SOCKET_ERROR_H */
