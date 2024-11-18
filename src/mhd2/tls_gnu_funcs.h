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

#include "mhd_status_code_int.h"

/**
 * The structure with daemon-specific GnuTLS data
 */
struct mhd_DaemonTlsGnuData;    /* Forward declaration */

/**
 * The structure with connection-specific GnuTLS data
 */
struct mhd_ConnTlsGnuData;      /* Forward declaration */


/* ** Global initialisation ** */

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


/* ** Daemon initialisation ** */

struct MHD_Daemon;      /* Forward declaration */
struct DaemonOptions;   /* Forward declaration */

/**
 * Set daemon TLS parameters
 * @param d the daemon handle
 * @param p_d_tls the pointer to variable to set the pointer to
 *                the daemon's TLS settings (allocated by this function)
 * @param s the daemon settings
 * @return #MHD_SC_OK on success (p_d_tls set to the allocated settings),
 *         error code otherwise
 */
MHD_INTERNAL mhd_StatusCodeInt
mhd_tls_gnu_daemon_init (struct MHD_Daemon *restrict d,
                         struct mhd_DaemonTlsGnuData **restrict p_d_tls,
                         struct DaemonOptions *restrict s)
MHD_FN_PAR_NONNULL_ALL_ MHD_FN_PAR_OUT_ (2);

/**
 * De-initialise daemon TLS parameters (and free memory allocated for TLS
 * settings)
 * @param d_tls the pointer to  the daemon's TLS settings
 */
MHD_INTERNAL void
mhd_tls_gnu_daemon_deinit (struct mhd_DaemonTlsGnuData *restrict d_tls)
MHD_FN_PAR_NONNULL_ALL_ MHD_FN_PAR_INOUT_ (1);

#endif /* ! MHD_TLS_GNU_FUNCS_H */
