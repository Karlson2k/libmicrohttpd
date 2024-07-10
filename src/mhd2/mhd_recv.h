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
 * @file src/mhd2/mhd_recv.h
 * @brief  The definition of the mhd_recv() function
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_RECV_H
#define MHD_RECV_H 1

#include "mhd_sys_options.h"

#include "sys_base_types.h"
#include "mhd_socket_error.h"

struct MHD_Connection; /* forward declaration */

/**
 * Receive the data from the network socket.
 * Clear #mhd_SOCKET_NET_STATE_RECV_READY in sk_ready if necessary.
 *
 * @param c the connection to use
 * @param buf_size the size of the @a buf buffer
 * @param[out] buf the buffer to fill with the received data
 * @param[out] received the pointer to variable to get the size of the data
 *                      actually put to the @a buffer
 * @return mhd_SOCKET_ERR_NO_ERROR if receive succeed (the @a received gets
 *         the received size) or socket error
 */
MHD_INTERNAL enum mhd_SocketError
mhd_recv (struct MHD_Connection *restrict c,
          size_t buf_size,
          char buffer[MHD_FN_PAR_DYN_ARR_SIZE_(buf_size)],
          size_t *restrict received)
MHD_FN_PAR_NONNULL_ALL_ MHD_FN_PAR_OUT_SIZE_(3,2) MHD_FN_PAR_OUT_ (4);


#endif /* ! MHD_RECV_H */
