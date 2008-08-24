/*
 * Copyright (C) 2000, 2001, 2002, 2003, 2004, 2005, 2007 Free Software Foundation
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

#ifndef ALGORITHMS_H
#define ALGORITHMS_H

#include "gnutls_auth.h"

/* Functions for version handling. */
enum MHD_GNUTLS_Protocol mhd_gtls_version_lowest (mhd_gtls_session_t session);
enum MHD_GNUTLS_Protocol mhd_gtls_version_max (mhd_gtls_session_t session);
int mhd_gtls_version_priority (mhd_gtls_session_t session,
			      enum MHD_GNUTLS_Protocol version);
int mhd_gtls_version_is_supported (mhd_gtls_session_t session,
				  const enum MHD_GNUTLS_Protocol version);
int mhd_gtls_version_get_major (enum MHD_GNUTLS_Protocol ver);
int mhd_gtls_version_get_minor (enum MHD_GNUTLS_Protocol ver);
enum MHD_GNUTLS_Protocol mhd_gtls_version_get (int major, int minor);

/* Functions for MACs. */
int mhd_gnutls_mac_is_ok (enum MHD_GNUTLS_HashAlgorithm algorithm);
enum MHD_GNUTLS_HashAlgorithm mhd_gtls_x509_oid2mac_algorithm (const char *oid);
const char * mhd_gtls_x509_mac_to_oid (enum MHD_GNUTLS_HashAlgorithm mac);

/* Functions for cipher suites. */
int mhd_gtls_supported_ciphersuites (mhd_gtls_session_t session,
				    cipher_suite_st ** ciphers);
int mhd_gtls_supported_ciphersuites_sorted (mhd_gtls_session_t session,
					   cipher_suite_st ** ciphers);
int mhd_gtls_supported_compression_methods (mhd_gtls_session_t session,
					   uint8_t ** comp);
const char * mhd_gtls_cipher_suite_get_name (cipher_suite_st * algorithm);
enum MHD_GNUTLS_CipherAlgorithm mhd_gtls_cipher_suite_get_cipher_algo (const
								cipher_suite_st
								* algorithm);
enum MHD_GNUTLS_KeyExchangeAlgorithm mhd_gtls_cipher_suite_get_kx_algo (const cipher_suite_st
							* algorithm);
enum MHD_GNUTLS_HashAlgorithm mhd_gtls_cipher_suite_get_mac_algo (const
							  cipher_suite_st *
							  algorithm);
enum MHD_GNUTLS_Protocol mhd_gtls_cipher_suite_get_version (const cipher_suite_st *
						    algorithm);
cipher_suite_st mhd_gtls_cipher_suite_get_suite_name (cipher_suite_st *
						     algorithm);

/* Functions for ciphers. */
int mhd_gtls_cipher_get_block_size (enum MHD_GNUTLS_CipherAlgorithm algorithm);
int mhd_gtls_cipher_is_block (enum MHD_GNUTLS_CipherAlgorithm algorithm);
int mhd_gtls_cipher_is_ok (enum MHD_GNUTLS_CipherAlgorithm algorithm);
int mhd_gtls_cipher_get_iv_size (enum MHD_GNUTLS_CipherAlgorithm algorithm);
int mhd_gtls_cipher_get_export_flag (enum MHD_GNUTLS_CipherAlgorithm algorithm);

/* Functions for key exchange. */
int mhd_gtls_kx_needs_dh_params (enum MHD_GNUTLS_KeyExchangeAlgorithm algorithm);
int mhd_gtls_kx_needs_rsa_params (enum MHD_GNUTLS_KeyExchangeAlgorithm algorithm);
mhd_gtls_mod_auth_st * mhd_gtls_kx_auth_struct (enum MHD_GNUTLS_KeyExchangeAlgorithm algorithm);
int mhd_gtls_kx_is_ok (enum MHD_GNUTLS_KeyExchangeAlgorithm algorithm);

/* Functions for compression. */
int mhd_gtls_compression_is_ok (enum MHD_GNUTLS_CompressionMethod algorithm);
int mhd_gtls_compression_get_num (enum MHD_GNUTLS_CompressionMethod algorithm);
enum MHD_GNUTLS_CompressionMethod mhd_gtls_compression_get_id (int num);
int mhd_gtls_compression_get_mem_level (enum MHD_GNUTLS_CompressionMethod algorithm);
int mhd_gtls_compression_get_comp_level (enum MHD_GNUTLS_CompressionMethod
					algorithm);
int mhd_gtls_compression_get_wbits (enum MHD_GNUTLS_CompressionMethod algorithm);

/* Type to KX mappings. */
enum MHD_GNUTLS_KeyExchangeAlgorithm mhd_gtls_map_kx_get_kx (enum MHD_GNUTLS_CredentialsType type,
					     int server);
enum MHD_GNUTLS_CredentialsType mhd_gtls_map_kx_get_cred (enum MHD_GNUTLS_KeyExchangeAlgorithm
						   algorithm, int server);

/* KX to PK mapping. */
enum MHD_GNUTLS_PublicKeyAlgorithm mhd_gtls_map_pk_get_pk (enum MHD_GNUTLS_KeyExchangeAlgorithm
					     kx_algorithm);
enum MHD_GNUTLS_PublicKeyAlgorithm mhd_gtls_x509_oid2pk_algorithm (const char *oid);
const char * mhd_gtls_x509_pk_to_oid (enum MHD_GNUTLS_PublicKeyAlgorithm pk);

enum encipher_type
{ CIPHER_ENCRYPT = 0, CIPHER_SIGN = 1, CIPHER_IGN };

enum encipher_type mhd_gtls_kx_encipher_type (enum MHD_GNUTLS_KeyExchangeAlgorithm algorithm);

struct mhd_gtls_compression_entry
{
  const char *name;
  enum MHD_GNUTLS_CompressionMethod id;
  int num;			/* the number reserved in TLS for the specific compression method */

  /* used in zlib compressor */
  int window_bits;
  int mem_level;
  int comp_level;
};
typedef struct mhd_gtls_compression_entry gnutls_compression_entry;

/* Functions for sign algorithms. */
gnutls_sign_algorithm_t mhd_gtls_x509_oid2sign_algorithm (const char *oid);
gnutls_sign_algorithm_t mhd_gtls_x509_pk_to_sign (enum MHD_GNUTLS_PublicKeyAlgorithm pk,
						 enum MHD_GNUTLS_HashAlgorithm mac);
const char * mhd_gtls_x509_sign_to_oid (enum MHD_GNUTLS_PublicKeyAlgorithm,
				      enum MHD_GNUTLS_HashAlgorithm mac);

int mhd_gtls_mac_priority (mhd_gtls_session_t session,
			  enum MHD_GNUTLS_HashAlgorithm algorithm);
int mhd_gtls_cipher_priority (mhd_gtls_session_t session,
			     enum MHD_GNUTLS_CipherAlgorithm algorithm);
int mhd_gtls_kx_priority (mhd_gtls_session_t session,
			 enum MHD_GNUTLS_KeyExchangeAlgorithm algorithm);
int mhd_gtls_compression_priority (mhd_gtls_session_t session,
				  enum MHD_GNUTLS_CompressionMethod algorithm);

enum MHD_GNUTLS_HashAlgorithm MHD_gtls_mac_get_id (const char* name);
enum MHD_GNUTLS_CipherAlgorithm MHD_gtls_cipher_get_id (const char* name);
enum MHD_GNUTLS_KeyExchangeAlgorithm MHD_gtls_kx_get_id (const char* name);
enum MHD_GNUTLS_Protocol MHD_gtls_protocol_get_id (const char* name);
enum MHD_GNUTLS_CertificateType MHD_gtls_certificate_type_get_id (const char* name);

#endif
