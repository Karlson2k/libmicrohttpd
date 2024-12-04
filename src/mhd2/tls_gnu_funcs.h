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
 * @file src/mhd2/tls_gnu_funcs.h
 * @brief  The declarations of GnuTLS wrapper functions
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_TLS_GNU_FUNCS_H
#define MHD_TLS_GNU_FUNCS_H 1

#include "mhd_sys_options.h"

#ifndef MHD_USE_GNUTLS
#error This header can be used only if GnuTLS is enabled
#endif

#include "sys_bool_type.h"
#include "sys_base_types.h"

#include "mhd_status_code_int.h"

#include "mhd_tls_enums.h"
#include "mhd_socket_error.h"

/**
 * The structure with daemon-specific GnuTLS data
 */
struct mhd_TlsGnuDaemonData;    /* Forward declaration */

/**
 * The structure with connection-specific GnuTLS data
 */
struct mhd_TlsGnuConnData;      /* Forward declaration */


/* ** Global initialisation / de-initialisation ** */

/**
 * Globally initialise GnuTLS backend
 */
MHD_INTERNAL void
mhd_tls_gnu_global_init (void);

/* An alias for mhd_tls_gnu_global_init() */
#define mhd_tls_gnu_global_init_once()    mhd_tls_gnu_global_init ()

/* An alias for mhd_tls_gnu_global_init() */
#define mhd_tls_gnu_global_re_init()      mhd_tls_gnu_global_init ()

/**
 * Globally de-initialise GnuTLS backend
 */
MHD_INTERNAL void
mhd_tls_gnu_global_deinit (void);

/**
 * Check whether GnuTLS backend was successfully initialised globally
 * @return 'true' if backend has been successfully initialised,
 *         'false' if backend cannot be used
 */
MHD_INTERNAL bool
mhd_tls_gnu_is_inited_fine (void)
MHD_FN_PURE_;


/* ** Daemon initialisation / de-initialisation ** */

struct MHD_Daemon;      /* Forward declaration */
struct DaemonOptions;   /* Forward declaration */

/**
 * Check whether GnuTLS backend supports edge-triggered sockets polling
 * @param s the daemon settings
 * @return 'true' if the backend supports edge-triggered sockets polling,
 *         'false' if edge-triggered sockets polling cannot be used
 */
#define mhd_tls_gnu_is_edge_trigg_supported(s) (! 0)


/**
 * Allocate and initialise daemon TLS parameters
 * @param d the daemon handle
 * @param s the daemon settings
 * @param p_d_tls the pointer to variable to set the pointer to
 *                the daemon's TLS settings (allocated by this function)
 * @return #MHD_SC_OK on success (p_d_tls set to the allocated settings),
 *         error code otherwise
 */
MHD_INTERNAL mhd_StatusCodeInt
mhd_tls_gnu_daemon_init3 (struct MHD_Daemon *restrict d,
                          struct DaemonOptions *restrict s,
                          struct mhd_TlsGnuDaemonData **restrict p_d_tls)
MHD_FN_MUST_CHECK_RESULT_ MHD_FN_PAR_NONNULL_ALL_ MHD_FN_PAR_OUT_ (3);


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
#define mhd_tls_gnu_daemon_init(d,et,s,p_d_tls)        \
        mhd_tls_gnu_daemon_init3 ((d),(s),(p_d_tls))

/**
 * De-initialise daemon TLS parameters (and free memory allocated for TLS
 * settings)
 * @param d_tls the pointer to  the daemon's TLS settings
 */
MHD_INTERNAL void
mhd_tls_gnu_daemon_deinit (struct mhd_TlsGnuDaemonData *restrict d_tls)
MHD_FN_PAR_NONNULL_ALL_ MHD_FN_PAR_INOUT_ (1);


/* ** Connection initialisation / de-initialisation ** */

struct mhd_ConnSocket; /* Forward declaration */

/**
 * Get size size of the connection's TLS settings
 */
MHD_INTERNAL size_t
mhd_tls_gnu_conn_get_tls_size_v (void);

/**
 * Get size size of the connection's TLS settings
 * @param d_tls the pointer to  the daemon's TLS settings
 */
#define mhd_tls_gnu_conn_get_tls_size(d_tls) \
        mhd_tls_gnu_conn_get_tls_size_v ()

/**
 * Initialise connection TLS settings
 * @param d_tls the daemon TLS settings
 * @param sk data about the socket for the connection
 * @param[out] c_tls the pointer to the allocated space for
 *                   the connection TLS settings
 * @return 'true' on success,
 *         'false' otherwise
 */
MHD_INTERNAL bool
mhd_tls_gnu_conn_init (const struct mhd_TlsGnuDaemonData *restrict d_tls,
                       const struct mhd_ConnSocket *sk,
                       struct mhd_TlsGnuConnData *restrict c_tls)
MHD_FN_MUST_CHECK_RESULT_ MHD_FN_PAR_NONNULL_ALL_ MHD_FN_PAR_OUT_ (3);

/**
 * De-initialise connection TLS settings.
 * The provided pointer is not freed/deallocated.
 * @param c_tls the initialised connection TLS settings
 */
MHD_INTERNAL void
mhd_tls_gnu_conn_deinit (struct mhd_TlsGnuConnData *restrict c_tls)
MHD_FN_PAR_NONNULL_ALL_;


/* ** TLS connection establishing ** */

/**
 * Perform TLS handshake
 * @param c_tls the connection TLS handle
 * @return #mhd_TLS_PROCED_SUCCESS if completed successfully
 *         or other enum mhd_TlsProcedureResult values
 */
MHD_INTERNAL enum mhd_TlsProcedureResult
mhd_tls_gnu_conn_handshake (struct mhd_TlsGnuConnData *restrict c_tls)
MHD_FN_MUST_CHECK_RESULT_ MHD_FN_PAR_NONNULL_ALL_;

/**
 * Perform shutdown of TLS layer
 * @param c_tls the connection TLS handle
 * @return #mhd_TLS_PROCED_SUCCESS if completed successfully
 *         or other enum mhd_TlsProcedureResult values
 */
MHD_INTERNAL enum mhd_TlsProcedureResult
mhd_tls_gnu_conn_shutdown (struct mhd_TlsGnuConnData *restrict c_tls)
MHD_FN_MUST_CHECK_RESULT_ MHD_FN_PAR_NONNULL_ALL_;


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
MHD_INTERNAL enum mhd_SocketError
mhd_tls_gnu_conn_recv (struct mhd_TlsGnuConnData *restrict c_tls,
                       size_t buf_size,
                       char buf[MHD_FN_PAR_DYN_ARR_SIZE_ (buf_size)],
                       size_t *restrict received)
MHD_FN_PAR_NONNULL_ALL_ MHD_FN_PAR_OUT_SIZE_ (3,2) MHD_FN_PAR_OUT_ (4);

/**
 * Check whether any incoming data is pending in the TLS buffers
 *
 * @param c_tls the connection TLS handle
 * @return 'true' if any incoming remote data is already pending (the TLS recv()
 *          call can be performed),
 *         'false' otherwise
 */
MHD_INTERNAL bool
mhd_tls_gnu_conn_has_data_in (struct mhd_TlsGnuConnData *restrict c_tls)
MHD_FN_PAR_NONNULL_ALL_;

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
MHD_INTERNAL enum mhd_SocketError
mhd_tls_gnu_conn_send (struct mhd_TlsGnuConnData *restrict c_tls,
                       size_t buf_size,
                       const char buf[MHD_FN_PAR_DYN_ARR_SIZE_ (buf_size)],
                       size_t *restrict sent)
MHD_FN_PAR_NONNULL_ALL_ MHD_FN_PAR_IN_SIZE_ (3,2) MHD_FN_PAR_OUT_ (4);

#endif /* ! MHD_TLS_GNU_FUNCS_H */
