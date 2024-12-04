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
 * @file src/mhd2/mhd_tls_funcs.h
 * @brief  The TLS backend functions generic declaration, mapped to specific TLS
 *         backend at compile-time
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_TLS_FUNCS_H
#define MHD_TLS_FUNCS_H 1

#include "mhd_sys_options.h"

#include "sys_bool_type.h"

#include "mhd_tls_choice.h"
#ifndef MHD_ENABLE_HTTPS
#error This header should be used only if HTTPS is enabled
#endif

#if defined(MHD_USE_MULTITLS)
#  include "tls_multi_funcs.h"
#elif defined(MHD_USE_GNUTLS)
#  include "tls_gnu_funcs.h"
#elif defined(MHD_USE_OPENSSL)
#  include "tls_open_funcs.h"
#endif

/* ** Global initialisation / de-initialisation ** */

/**
 * Perform one-time global initialisation of TLS backend
 */
#define mhd_tls_global_init_once()        mhd_TLS_FUNC (_global_init_once)()

/**
 * Perform de-initialisation of TLS backend
 */
#define mhd_tls_global_deinit()           mhd_TLS_FUNC (_global_deinit)()

/**
 * Perform re-initialisation of TLS backend
 */
#define mhd_tls_global_re_init()          mhd_TLS_FUNC (_global_re_init)()

/* ** Daemon initialisation / de-initialisation ** */

/**
 * Check whether OpenSSL backend supports edge-triggered sockets polling
 * @param s the daemon settings
 * @return 'true' if the backend supports edge-triggered sockets polling,
 *         'false' if edge-triggered sockets polling cannot be used
 */
#define mhd_tls_is_edge_trigg_supported(s) \
        mhd_TLS_FUNC (_is_edge_trigg_supported)((s))

/**
 * Allocate and initialise daemon TLS parameters
 * @param d the daemon handle
 * @param et if 'true' then sockets polling uses edge-triggering
 * @param s the daemon settings
 * @param p_d_tls the pointer to variable to set the pointer to
 *                the daemon's TLS settings (allocated by this function)
 * @return #MHD_SC_OK on success (p_d_tls set to the allocated settings),
 *         error code otherwise
 */
#define mhd_tls_daemon_init(d,et,s,p_d_tls)        \
        mhd_TLS_FUNC (_daemon_init)((d),(et),(s),(p_d_tls))

/**
 * De-initialise daemon TLS parameters (and free memory allocated for TLS
 * settings)
 * @param d_tls the pointer to  the daemon's TLS settings
 */
#define mhd_tls_daemon_deinit(d_tls)    \
        mhd_TLS_FUNC (_daemon_deinit)((d_tls))


/* ** Connection initialisation / de-initialisation ** */

/**
 * Get size size of the connection's TLS settings
 * @param d_tls the pointer to  the daemon's TLS settings
 */
#define mhd_tls_conn_get_tls_size(d_tls)     \
        mhd_TLS_FUNC (_conn_get_tls_size)(d_tls)

/**
 * Initialise connection TLS settings
 * @param d_tls the daemon TLS settings
 * @param sk data about the socket for the connection
 * @param[out] c_tls the pointer to the allocated space for
 *                   the connection TLS settings
 * @return 'true' on success,
 *         'false' otherwise
 */
#define mhd_tls_conn_init(d_tls,sk,c_tls)       \
        mhd_TLS_FUNC (_conn_init)((d_tls),(sk),(c_tls))

/**
 * De-initialise connection TLS settings.
 * The provided pointer is not freed/deallocated.
 * @param c_tls the initialised connection TLS settings
 */
#define mhd_tls_conn_deinit(c_tls)       \
        mhd_TLS_FUNC (_conn_deinit)((c_tls))


/* ** TLS connection establishing ** */

/**
 * Perform TLS handshake
 * @param c_tls the connection TLS handle
 * @return #mhd_TLS_PROCED_SUCCESS if completed successfully
 *         or other enum mhd_TlsProcedureResult values
 */
#define mhd_tls_conn_handshake(c_tls)       \
        mhd_TLS_FUNC (_conn_handshake)((c_tls))

/**
 * Perform shutdown of TLS layer
 * @param c_tls the connection TLS handle
 * @return #mhd_TLS_PROCED_SUCCESS if completed successfully
 *         or other enum mhd_TlsProcedureResult values
 */
#define mhd_tls_conn_shutdown(c_tls)       \
        mhd_TLS_FUNC (_conn_shutdown)((c_tls))

/* ** Data sending and receiving over TLS connection ** */

/**
 * Receive the data from the remote side over TLS connection
 *
 * @param c_tls the connection TLS handle
 * @param buf_size the size of the @a buf buffer
 * @param[out] buf the buffer to fill with the received data
 * @param[out] received the pointer to variable to get the size of the data
 *                      actually put to the @a buffer
 * @return mhd_SOCKET_ERR_NO_ERROR if receive succeed (the @a received gets
 *         the received size) or socket error
 */
#define mhd_tls_conn_recv(c_tls,buf_size,buf,received)  \
        mhd_TLS_FUNC (_conn_recv)((c_tls),(buf_size),(buf),(received))

/**
 * Check whether any incoming data is pending in the TLS buffers
 *
 * @param c_tls the connection TLS handle
 * @return 'true' if any incoming remote data is already pending (the TLS recv()
 *          call can be performed),
 *         'false' otherwise
 */
#define mhd_tls_conn_has_data_in(c_tls)       \
        mhd_TLS_FUNC (_conn_has_data_in)((c_tls))

/**
 * Send data to the remote side over TLS connection
 *
 * @param c_tls the connection TLS handle
 * @param buffer_size the size of the @a buffer (in bytes)
 * @param buffer content of the buffer to send
 * @param[out] sent the pointer to get amount of actually sent bytes
 * @return mhd_SOCKET_ERR_NO_ERROR if send succeed (the @a sent gets
 *         the sent size) or socket error
 */
#define mhd_tls_conn_send(c_tls,buf_size,buf,sent)      \
        mhd_TLS_FUNC (_conn_send)((c_tls),(buf_size),(buf),(sent))


/* ** General information function ** */

/**
 * Result of TLS backend availability check
 */
enum mhd_TlsBackendAvailable
{
  /**
   * The TLS backend is available and can be used
   */
  mhd_TLS_BACKEND_AVAIL_OK = 0
  ,
  /**
   * The TLS backend support is not enabled in this MHD build
   */
  mhd_TLS_BACKEND_AVAIL_NOT_SUPPORTED
  ,
  /**
   * The TLS backend supported, but not available
   */
  mhd_TLS_BACKEND_AVAIL_NOT_AVAILABLE
};

/**
 * Check whether the requested TLS backend is available
 * @param s the daemon settings
 * @return 'mhd_TLS_BACKEND_AVAIL_OK' if requested backend is available,
 *         error code otherwise
 */
MHD_INTERNAL enum mhd_TlsBackendAvailable
mhd_tls_is_backend_available (struct DaemonOptions *s)
MHD_FN_PAR_NONNULL_ALL_ MHD_FN_MUST_CHECK_RESULT_;

#endif /* ! MHD_TLS_FUNCS_H */
