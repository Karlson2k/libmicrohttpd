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
 * @file src/mhd2/tls_gnu_conn_data.h
 * @brief  The definition of GnuTLS daemon-specific data structures
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_TLS_GNU_CONN_DATA_H
#define MHD_TLS_GNU_CONN_DATA_H 1

#include "mhd_sys_options.h"

#ifndef MHD_USE_GNUTLS
#error This header can be used only if GnuTLS is enabled
#endif

#include "tls_gnu_tls_lib.h"

/**
 * The structure with connection-specific GnuTLS data
 */
struct mhd_TlsGnuConnData
{
  /**
   * GnuTLS session data
   */
  gnutls_session_t sess;
};

#endif /* ! MHD_TLS_GNU_CONN_DATA_H */
