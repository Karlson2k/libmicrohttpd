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

#ifndef AUTH_CERT_H
# define AUTH_CERT_H

# include "gnutls_cert.h"
# include "gnutls_auth.h"
# include "auth_dh_common.h"
# include "x509.h"
# include "openpgp.h"

/* This structure may be complex, but it's the only way to
 * support a server that has multiple certificates
 */
typedef struct gnutls_certificate_credentials_st
{
  gnutls_dh_params_t dh_params;
  gnutls_rsa_params_t rsa_params;
  /* this callback is used to retrieve the DH or RSA
   * parameters.
   */
  gnutls_params_function *params_func;

  gnutls_cert **cert_list;
  /* contains a list of a list of certificates.
   * eg (X509): [0] certificate1, certificate11, certificate111 
   * (if more than one, one certificate certifies the one before)
   *       [1] certificate2, certificate22, ...
   */
  unsigned *cert_list_length;
  /* contains the number of the certificates in a
   * row (should be 1 for OpenPGP keys).
   */
  unsigned ncerts;		/* contains the number of columns in cert_list.
				 * This is the same with the number of pkeys.
				 */

  gnutls_privkey *pkey;
  /* private keys. It contains ncerts private
   * keys. pkey[i] corresponds to certificate in
   * cert_list[i][0].
   */

  /* OpenPGP specific stuff */

#ifndef KEYRING_HACK
  gnutls_openpgp_keyring_t keyring;
#else
  gnutls_datum_t keyring;
  int keyring_format;
#endif

  /* X509 specific stuff */

  gnutls_x509_crt_t *x509_ca_list;
  unsigned x509_ncas;		/* number of CAs in the ca_list 
				 */

  gnutls_x509_crl_t *x509_crl_list;
  unsigned x509_ncrls;		/* number of CRLs in the crl_list 
				 */

  unsigned int verify_flags;	/* flags to be used at 
				 * certificate verification.
				 */
  unsigned int verify_depth;
  unsigned int verify_bits;

  /* holds a sequence of the
   * RDNs of the CAs above.
   * This is better than
   * generating on every handshake.
   */
  gnutls_datum_t x509_rdn_sequence;

  gnutls_certificate_client_retrieve_function *client_get_cert_callback;
  gnutls_certificate_server_retrieve_function *server_get_cert_callback;
} certificate_credentials_st;

typedef struct rsa_info_st
{
  gnutls_datum_t modulus;
  gnutls_datum_t exponent;
} rsa_info_st;

typedef struct cert_auth_info_st
{
  int certificate_requested;	/* if the peer requested certificate
				 * this is non zero;
				 */

  /* These (dh/rsa) are just copies from the credentials_t structure.
   * They must be freed.
   */
  dh_info_st dh;
  rsa_info_st rsa_export;

  gnutls_datum_t *raw_certificate_list;	/* holds the raw certificate of the
					 * peer.
					 */
  unsigned int ncerts;		/* holds the size of the list above */
} *cert_auth_info_t;

typedef struct cert_auth_info_st cert_auth_info_st;

void _gnutls_free_rsa_info (rsa_info_st * rsa);

/* AUTH X509 functions */
int _gnutls_gen_cert_server_certificate (gnutls_session_t, opaque **);
int _gnutls_gen_cert_client_certificate (gnutls_session_t, opaque **);
int _gnutls_gen_cert_client_cert_vrfy (gnutls_session_t, opaque **);
int _gnutls_gen_cert_server_cert_req (gnutls_session_t, opaque **);
int _gnutls_proc_cert_cert_req (gnutls_session_t, opaque *, size_t);
int _gnutls_proc_cert_client_cert_vrfy (gnutls_session_t, opaque *, size_t);
int _gnutls_proc_cert_server_certificate (gnutls_session_t, opaque *, size_t);
int _gnutls_get_selected_cert (gnutls_session_t session,
			       gnutls_cert ** apr_cert_list,
			       int *apr_cert_list_length,
			       gnutls_privkey ** apr_pkey);

int _gnutls_server_select_cert (struct gnutls_session_int *,
				gnutls_pk_algorithm_t);
void _gnutls_selected_certs_deinit (gnutls_session_t session);
void _gnutls_selected_certs_set (gnutls_session_t session,
				 gnutls_cert * certs, int ncerts,
				 gnutls_privkey * key, int need_free);

#define _gnutls_proc_cert_client_certificate _gnutls_proc_cert_server_certificate

gnutls_rsa_params_t _gnutls_certificate_get_rsa_params (gnutls_rsa_params_t
							rsa_params,
							gnutls_params_function
							* func,
							gnutls_session_t);

#endif
