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
 * @file src/mhd2/tls_gnu_funcs.c
 * @brief  The implementation of GnuTLS wrapper functions
 * @author Karlson2k (Evgeny Grin)
 */

#include "mhd_sys_options.h"

#include "sys_bool_type.h"
#include "sys_base_types.h"

#include <gnutls/gnutls.h>

#include "tls_gnu_funcs.h"

struct mhd_DaemonTlsGnuData;    /* Forward declaration */

struct mhd_ConnTlsGnuData;      /* Forward declaration */


/* ** Global initialisation ** */

static bool gnutls_lib_inited = false;

MHD_INTERNAL void
mhd_tls_gnu_global_init (void)
{
#ifdef GNUTLS_VERSION
  /* Make sure that used shared GnuTLS library has least the same version as
     MHD was configured for. Fail if the version is earlier. */
  gnutls_lib_inited = (NULL != gnutls_check_version (GNUTLS_VERSION));
#endif
  gnutls_lib_inited =
    gnutls_lib_inited && (GNUTLS_E_SUCCESS == gnutls_global_init ());
}


MHD_INTERNAL void
mhd_tls_gnu_global_deinit (void)
{
  if (gnutls_lib_inited)
    gnutls_global_deinit ();
  gnutls_lib_inited = false;
}
