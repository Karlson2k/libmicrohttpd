/*
 * Copyright (C) 2002, 2003, 2004, 2005, 2007 Free Software Foundation
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GNUTLS.
 *
 * The GNUTLS library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA
 *
 */

/* This file contains common stuff in Ephemeral Diffie Hellman (DHE) and
 * Anonymous DH key exchange(DHA). These are used in the handshake procedure
 * of the certificate and anoymous authentication.
 */

#include "gnutls_int.h"
#include "gnutls_auth_int.h"
#include "gnutls_errors.h"
#include "gnutls_dh.h"
#include "gnutls_num.h"
#include "gnutls_sig.h"
#include <gnutls_datum.h>
#include <gnutls_x509.h>
#include <gnutls_state.h>
#include <auth_dh_common.h>
#include <gnutls_algorithms.h>

/* Frees the MHD_gtls_dh_info_st structure.
 */
void
MHD_gtls_free_dh_info (MHD_gtls_dh_info_st * dh)
{
  dh->secret_bits = 0;
  MHD__gnutls_free_datum (&dh->prime);
  MHD__gnutls_free_datum (&dh->generator);
  MHD__gnutls_free_datum (&dh->public_key);
}

