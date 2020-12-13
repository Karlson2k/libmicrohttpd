/*
  This file is part of libmicrohttpd
  Copyright (C) 2019 ng0
  Copyright (C) 2017 Karlson2k (Evgeny Grin)

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

*/

/**
 * @file mhd_send.h
 * @brief Declarations of send() wrappers.
 * @author ng0
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_SEND_H
#define MHD_SEND_H

#include "platform.h"
#include "internal.h"
#if defined(HAVE_STDBOOL_H)
#include <stdbool.h>
#endif /* HAVE_STDBOOL_H */
#include <errno.h>
#include "mhd_sockets.h"
#include "connection.h"
#ifdef HTTPS_SUPPORT
#include "connection_https.h"
#endif

#ifdef HAVE_FREEBSD_SENDFILE
/**
 * Initialises static variables
 */
void
MHD_send_init_static_vars_ (void);

#endif /* HAVE_FREEBSD_SENDFILE */

/**
 * The enumeration of send socket options.
 */
enum MHD_SendSocketOptions
{
  /**
   * Need to flush buffers after send to push data to the network.
   * Used to avoid delay before the last part of data (which is usually
   * incomplete IP packet / MSS) is pushed by kernel to the network.
   */
  MHD_SSO_PUSH_DATA = 0,
  /**
   * Buffer data if possible.
   * If more response data is to be sent than try to buffer data in
   * the local buffers so kernel able to send complete packets with
   * lower overhead.
   */
  MHD_SSO_PREFER_BUFF = 1,
  /**
   * consider tcpi_snd_mss and consider not corking for the header
   * part if the size of the header is close to the MSS.
   * Only used if we are NOT doing 100 Continue and are still
   * sending the header (provided in full as the buffer to
   * MHD_send_on_connection_ or as the header to
   * MHD_send_on_connection2_).
   */
  MHD_SSO_HDR_CORK = 2
};


ssize_t
MHD_send_on_connection_ (struct MHD_Connection *connection,
                         const char *buffer,
                         size_t buffer_size,
                         enum MHD_SendSocketOptions options);


/**
 * Send reply header with optional reply body.
 *
 * @param connection the MHD_Connection structure
 * @param header content of header to send
 * @param header_size the size of the header (in bytes)
 * @param body content of the body to send (optional, may be NULL)
 * @param body_size the size of the body (in bytes)
 * @return sum of the number of bytes sent from both buffers or
 *         error code (negative)
 */
ssize_t
MHD_send_hdr_and_body_ (struct MHD_Connection *connection,
                        const char *header,
                        size_t header_size,
                        const char *body,
                        size_t body_size);

#if defined(_MHD_HAVE_SENDFILE)
ssize_t
MHD_send_sendfile_ (struct MHD_Connection *connection);

#endif

#endif /* MHD_SEND_H */
