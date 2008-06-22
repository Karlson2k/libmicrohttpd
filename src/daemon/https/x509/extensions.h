/*
 * Copyright (C) 2003, 2004, 2005, 2006, 2007 Free Software Foundation
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

int _gnutls_x509_crt_get_extension (gnutls_x509_crt_t cert,
				    const char *extension_id, int indx,
				    gnutls_datum_t * ret,
				    unsigned int *critical);

int _gnutls_x509_crt_get_extension_oid (gnutls_x509_crt_t cert,
					int indx, void *ret,
					size_t * ret_size);
int _gnutls_x509_ext_extract_keyUsage (uint16_t * keyUsage,
				       opaque * extnValue, int extnValueLen);
int _gnutls_x509_ext_extract_basicConstraints (int *CA,
					       int *pathLenConstraint,
					       opaque * extnValue,
					       int extnValueLen);
int _gnutls_x509_crt_set_extension (gnutls_x509_crt_t cert,
				    const char *extension_id,
				    const gnutls_datum_t * ext_data,
				    unsigned int critical);
int _gnutls_x509_ext_gen_basicConstraints (int CA, int pathLenConstraint,
					   gnutls_datum_t * der_ext);
int _gnutls_x509_ext_gen_keyUsage (uint16_t usage, gnutls_datum_t * der_ext);
int _gnutls_x509_ext_gen_subject_alt_name (gnutls_x509_subject_alt_name_t
					   type, const char *data_string,
					   gnutls_datum_t * der_ext);
int _gnutls_x509_ext_gen_crl_dist_points (gnutls_x509_subject_alt_name_t
					  type, const void *data_string,
					  unsigned int reason_flags,
					  gnutls_datum_t * der_ext);
int _gnutls_x509_ext_gen_key_id (const void *id, size_t id_size,
				 gnutls_datum_t * der_data);
int _gnutls_x509_ext_gen_auth_key_id (const void *id, size_t id_size,
				      gnutls_datum_t * der_data);

int _gnutls_x509_ext_extract_proxyCertInfo (int *pathLenConstraint,
					    char **policyLanguage,
					    char **policy,
					    size_t *sizeof_policy,
					    opaque * extnValue,
					    int extnValueLen);
int _gnutls_x509_ext_gen_proxyCertInfo (int pathLenConstraint,
					const char *policyLanguage,
					const char *policy,
					size_t sizeof_policy,
					gnutls_datum_t * der_ext);
