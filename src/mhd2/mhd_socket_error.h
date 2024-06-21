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
 * @brief  The definition of the mhd_SocketError enum
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_SOCKET_ERROR_H
#define MHD_SOCKET_ERROR_H 1

#include "mhd_sys_options.h"

/**
 * Recognised socket errors
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
   * The remote side shut down reading, the socket has been shut down
   * for writing or no longer connected
   * Only for 'send()'.
   */
  mhd_SOCKET_ERR_PIPE
  ,
  /**
   * General TLS encryption or decryption error
   */
  mhd_SOCKET_ERR_TLS
  ,
  /**
   * Other socket error
   */
  mhd_SOCKET_ERR_OTHER

};

/**
 * Check whether the socket error is unrecoverable
 */
#define mhd_SOCKET_ERR_IS_HARD(err) (mhd_SOCKET_ERR_CONNRESET <= (err))

#endif /* ! MHD_SOCKET_ERROR_H */
