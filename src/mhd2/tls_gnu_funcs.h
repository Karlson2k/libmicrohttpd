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
 */
MHD_INTERNAL bool
mhd_tls_gnu_is_inited_fine (void);


/* ** Daemon initialisation / de-initialisation ** */

struct MHD_Daemon;      /* Forward declaration */
struct DaemonOptions;   /* Forward declaration */

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
mhd_tls_gnu_daemon_init (struct MHD_Daemon *restrict d,
                         struct DaemonOptions *restrict s,
                         struct mhd_TlsGnuDaemonData **restrict p_d_tls)
MHD_FN_MUST_CHECK_RESULT_ MHD_FN_PAR_NONNULL_ALL_ MHD_FN_PAR_OUT_ (3);

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
mhd_tls_gnu_conn_get_tls_size (void);

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

#endif /* ! MHD_TLS_GNU_FUNCS_H */
