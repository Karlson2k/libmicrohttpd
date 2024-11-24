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
 * @file src/mhd2/conn_tls_check.h
 * @brief  The declarations of connection TLS handling functions
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_CONN_TLS_CHECK_H
#define MHD_CONN_TLS_CHECK_H 1

#include "mhd_sys_options.h"

#include "sys_bool_type.h"

struct MHD_Connection; /* forward declaration */

/**
 * The results of connection TLS checking
 */
enum mhd_ConnTlsCheckResult
{
  /**
   * The TLS layer is connected, the communication over TLS can be performed
   */
  mhd_CONN_TLS_CHECK_OK = 0
  ,
  /**
   * The TLS layer connection is in progress.
   * Communication over TLS is not possible yet.
   */
  mhd_CONN_TLS_CHECK_HANDSHAKING
  ,
  /**
   * The connection is broken and must be closed
   */
  mhd_CONN_TLS_CHECK_BROKEN
};


/**
 * Check connection TLS status, perform TLS (re-)handshake if necessary,
 * update connection's recv()/send() event loop state and connection active
 * state if network operation has been performed.
 * @param c the connection to process
 * @return #mhd_CONN_TLS_CHECK_OK if the connection can be used,
 *         other enum mhd_ConnTlsCheckResult values otherwise
 */
MHD_INTERNAL enum mhd_ConnTlsCheckResult
mhd_conn_tls_check (struct MHD_Connection *restrict c)
MHD_FN_PAR_NONNULL_ALL_;

#endif /* ! MHD_CONN_TLS_CHECK_H */
