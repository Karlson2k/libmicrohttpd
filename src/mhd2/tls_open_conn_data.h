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
 * @file src/mhd2/tls_open_conn_data.h
 * @brief  The definition of OpenSSL daemon-specific data structures
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_TLS_OPEN_CONN_DATA_H
#define MHD_TLS_OPEN_CONN_DATA_H 1

#include "mhd_sys_options.h"

#ifndef MHD_USE_OPENSSL
#error This header can be used only if GnuTLS is enabled
#endif

#include "tls_open_tls_lib.h"

#include "sys_bool_type.h"

#ifndef NDEBUG
struct mhd_TlsOpenConnDebug
{
  unsigned int is_inited;
  unsigned int is_tls_handshake_completed;
  unsigned int is_failed;
};
#endif /* ! NDEBUG */

/**
 * The structure with connection-specific GnuTLS data
 */
struct mhd_TlsOpenConnData
{
  /**
   * OpenSSL session data
   */
  SSL *sess;

  /**
   * 'true' if sent TLS shutdown "alert"
   */
  bool shut_tls_wr_sent;

  /**
   * 'true' if received EOF (the remote side initiated shutting down)
   */
  bool shut_tls_wr_received;
#ifndef NDEBUG
  /**
   * Debugging data
   */
  struct mhd_TlsOpenConnDebug dbg;
#endif /* ! NDEBUG */
};

#endif /* ! MHD_TLS_OPEN_CONN_DATA_H */
