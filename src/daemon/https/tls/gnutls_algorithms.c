/*
 * Copyright (C) 2000, 2002, 2003, 2004, 2005, 2006, 2007 Free Software Foundation
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

#include "gnutls_int.h"
#include "gnutls_algorithms.h"
#include "gnutls_errors.h"
#include "gnutls_cert.h"
/* x509 */
#include "common.h"

/* Cred type mappings to KX algorithms
 * FIXME: The mappings are not 1-1. Some KX such as SRP_RSA require
 * more than one credentials type.
 */
typedef struct
{
  gnutls_kx_algorithm_t algorithm;
  gnutls_credentials_type_t client_type;
  gnutls_credentials_type_t server_type;        /* The type of credentials a server
                                                 * needs to set */
} gnutls_cred_map;

static const gnutls_cred_map cred_mappings[] = {
  {MHD_GNUTLS_KX_ANON_DH,
   MHD_GNUTLS_CRD_ANON,
   MHD_GNUTLS_CRD_ANON},
  {MHD_GNUTLS_KX_RSA,
   MHD_GNUTLS_CRD_CERTIFICATE,
   MHD_GNUTLS_CRD_CERTIFICATE},
  {MHD_GNUTLS_KX_RSA_EXPORT,
   MHD_GNUTLS_CRD_CERTIFICATE,
   MHD_GNUTLS_CRD_CERTIFICATE},
  {MHD_GNUTLS_KX_DHE_DSS,
   MHD_GNUTLS_CRD_CERTIFICATE,
   MHD_GNUTLS_CRD_CERTIFICATE},
  {MHD_GNUTLS_KX_DHE_RSA,
   MHD_GNUTLS_CRD_CERTIFICATE,
   MHD_GNUTLS_CRD_CERTIFICATE},
  {MHD_GNUTLS_KX_SRP,
   MHD_GNUTLS_CRD_SRP,
   MHD_GNUTLS_CRD_SRP},
  {MHD_GNUTLS_KX_SRP_RSA,
   MHD_GNUTLS_CRD_SRP,
   MHD_GNUTLS_CRD_CERTIFICATE},
  {MHD_GNUTLS_KX_SRP_DSS,
   MHD_GNUTLS_CRD_SRP,
   MHD_GNUTLS_CRD_CERTIFICATE},
  {0,
   0,
   0}
};

#define GNUTLS_KX_MAP_LOOP(b) \
        const gnutls_cred_map *p; \
                for(p = cred_mappings; p->algorithm != 0; p++) { b ; }

#define GNUTLS_KX_MAP_ALG_LOOP_SERVER(a) \
                        GNUTLS_KX_MAP_LOOP( if(p->server_type == type) { a; break; })

#define GNUTLS_KX_MAP_ALG_LOOP_CLIENT(a) \
                        GNUTLS_KX_MAP_LOOP( if(p->client_type == type) { a; break; })

/* KX mappings to PK algorithms */
typedef struct
{
  gnutls_kx_algorithm_t kx_algorithm;
  gnutls_pk_algorithm_t pk_algorithm;
  enum encipher_type encipher_type;     /* CIPHER_ENCRYPT if this algorithm is to be used
                                         * for encryption, CIPHER_SIGN if signature only,
                                         * CIPHER_IGN if this does not apply at all.
                                         *
                                         * This is useful to certificate cipher suites, which check
                                         * against the certificate key usage bits.
                                         */
} gnutls_pk_map;

/* This table maps the Key exchange algorithms to
 * the certificate algorithms. Eg. if we have
 * RSA algorithm in the certificate then we can
 * use GNUTLS_KX_RSA or GNUTLS_KX_DHE_RSA.
 */
static const gnutls_pk_map pk_mappings[] = {
  {MHD_GNUTLS_KX_RSA,
   MHD_GNUTLS_PK_RSA,
   CIPHER_ENCRYPT},
  {MHD_GNUTLS_KX_RSA_EXPORT,
   MHD_GNUTLS_PK_RSA,
   CIPHER_SIGN},
  {MHD_GNUTLS_KX_DHE_RSA,
   MHD_GNUTLS_PK_RSA,
   CIPHER_SIGN},
  {MHD_GNUTLS_KX_SRP_RSA,
   MHD_GNUTLS_PK_RSA,
   CIPHER_SIGN},
  {0,
   0,
   0}
};

#define GNUTLS_PK_MAP_LOOP(b) \
        const gnutls_pk_map *p; \
                for(p = pk_mappings; p->kx_algorithm != 0; p++) { b }

#define GNUTLS_PK_MAP_ALG_LOOP(a) \
                        GNUTLS_PK_MAP_LOOP( if(p->kx_algorithm == kx_algorithm) { a; break; })

/* TLS Versions */

typedef struct
{
  const char *name;
  gnutls_protocol_t id;         /* gnutls internal version number */
  int major;                    /* defined by the protocol */
  int minor;                    /* defined by the protocol */
  int supported;                /* 0 not supported, > 0 is supported */
} gnutls_version_entry;

static const gnutls_version_entry sup_versions[] = {
  {"SSL3.0",
   MHD_GNUTLS_SSL3,
   3,
   0,
   1},
  {"TLS1.0",
   MHD_GNUTLS_TLS1_0,
   3,
   1,
   1},
  {"TLS1.1",
   MHD_GNUTLS_TLS1_1,
   3,
   2,
   1},
  {"TLS1.2",
   MHD_GNUTLS_TLS1_2,
   3,
   3,
   1},
  {0,
   0,
   0,
   0,
   0}
};

/* Keep the contents of this struct the same as the previous one. */
static const gnutls_protocol_t supported_protocols[] = { MHD_GNUTLS_SSL3,
  MHD_GNUTLS_TLS1_0,
  MHD_GNUTLS_TLS1_1,
  MHD_GNUTLS_TLS1_2,
  0
};

#define GNUTLS_VERSION_LOOP(b) \
        const gnutls_version_entry *p; \
                for(p = sup_versions; p->name != NULL; p++) { b ; }

#define GNUTLS_VERSION_ALG_LOOP(a) \
                        GNUTLS_VERSION_LOOP( if(p->id == version) { a; break; })

struct gnutls_cipher_entry
{
  const char *name;
  gnutls_cipher_algorithm_t id;
  uint16_t blocksize;
  uint16_t keysize;
  cipher_type_t block;
  uint16_t iv;
  int export_flag;              /* 0 non export */
};
typedef struct gnutls_cipher_entry gnutls_cipher_entry;

/* Note that all algorithms are in CBC or STREAM modes.
 * Do not add any algorithms in other modes (avoid modified algorithms).
 * View first: "The order of encryption and authentication for
 * protecting communications" by Hugo Krawczyk - CRYPTO 2001
 */
static const gnutls_cipher_entry algorithms[] = {
  {"AES-256-CBC",
   MHD_GNUTLS_CIPHER_AES_256_CBC,
   16,
   32,
   CIPHER_BLOCK,
   16,
   0},
  {"AES-128-CBC",
   MHD_GNUTLS_CIPHER_AES_128_CBC,
   16,
   16,
   CIPHER_BLOCK,
   16,
   0},
  {"3DES-CBC",
   MHD_GNUTLS_CIPHER_3DES_CBC,
   8,
   24,
   CIPHER_BLOCK,
   8,
   0},
  {"DES-CBC",
   MHD_GNUTLS_CIPHER_DES_CBC,
   8,
   8,
   CIPHER_BLOCK,
   8,
   0},
  {"ARCFOUR-128",
   MHD_GNUTLS_CIPHER_ARCFOUR_128,
   1,
   16,
   CIPHER_STREAM,
   0,
   0},
  {"ARCFOUR-40",
   MHD_GNUTLS_CIPHER_ARCFOUR_40,
   1,
   5,
   CIPHER_STREAM,
   0,
   1},
  {"RC2-40",
   MHD_GNUTLS_CIPHER_RC2_40_CBC,
   8,
   5,
   CIPHER_BLOCK,
   8,
   1},
#ifdef	ENABLE_CAMELLIA
  {"CAMELLIA-256-CBC", MHD_GNUTLS_CIPHER_CAMELLIA_256_CBC, 16, 32,
   CIPHER_BLOCK,
   16, 0},
  {"CAMELLIA-128-CBC", MHD_GNUTLS_CIPHER_CAMELLIA_128_CBC, 16, 16,
   CIPHER_BLOCK,
   16, 0},
#endif
  {"NULL",
   MHD_GNUTLS_CIPHER_NULL,
   1,
   0,
   CIPHER_STREAM,
   0,
   0},
  {0,
   0,
   0,
   0,
   0,
   0,
   0}
};

/* Keep the contents of this struct the same as the previous one. */
static const gnutls_cipher_algorithm_t supported_ciphers[] =
  { MHD_GNUTLS_CIPHER_AES_256_CBC,
  MHD_GNUTLS_CIPHER_AES_128_CBC,
  MHD_GNUTLS_CIPHER_3DES_CBC,
  MHD_GNUTLS_CIPHER_DES_CBC,
  MHD_GNUTLS_CIPHER_ARCFOUR_128,
  MHD_GNUTLS_CIPHER_ARCFOUR_40,
  MHD_GNUTLS_CIPHER_RC2_40_CBC,
#ifdef	ENABLE_CAMELLIA
  MHD_GNUTLS_CIPHER_CAMELLIA_256_CBC,
  MHD_GNUTLS_CIPHER_CAMELLIA_128_CBC,
#endif
  MHD_GNUTLS_CIPHER_NULL,
  0
};

#define GNUTLS_LOOP(b) \
        const gnutls_cipher_entry *p; \
                for(p = algorithms; p->name != NULL; p++) { b ; }

#define GNUTLS_ALG_LOOP(a) \
                        GNUTLS_LOOP( if(p->id == algorithm) { a; break; } )

struct gnutls_hash_entry
{
  const char *name;
  const char *oid;
  gnutls_mac_algorithm_t id;
  size_t key_size;              /* in case of mac */
};
typedef struct gnutls_hash_entry gnutls_hash_entry;

static const gnutls_hash_entry hash_algorithms[] = {
  {"SHA1",
   HASH_OID_SHA1,
   MHD_GNUTLS_MAC_SHA1,
   20},
  {"MD5",
   HASH_OID_MD5,
   MHD_GNUTLS_MAC_MD5,
   16},
  {"SHA256",
   HASH_OID_SHA256,
   MHD_GNUTLS_MAC_SHA256,
   32},
  {"NULL",
   NULL,
   MHD_GNUTLS_MAC_NULL,
   0},
  {0,
   0,
   0,
   0}
};

/* Keep the contents of this struct the same as the previous one. */
static const gnutls_mac_algorithm_t supported_macs[] = { MHD_GNUTLS_MAC_SHA1,
  MHD_GNUTLS_MAC_MD5,
  MHD_GNUTLS_MAC_SHA256,
  MHD_GNUTLS_MAC_NULL,
  0
};

#define GNUTLS_HASH_LOOP(b) \
        const gnutls_hash_entry *p; \
                for(p = hash_algorithms; p->name != NULL; p++) { b ; }

#define GNUTLS_HASH_ALG_LOOP(a) \
                        GNUTLS_HASH_LOOP( if(p->id == algorithm) { a; break; } )

/* Compression Section */
#define GNUTLS_COMPRESSION_ENTRY(name, id, wb, ml, cl) \
	{ #name, name, id, wb, ml, cl}

#define MAX_COMP_METHODS 5
const int _gnutls_comp_algorithms_size = MAX_COMP_METHODS;

/* the compression entry is defined in gnutls_algorithms.h */

gnutls_compression_entry _gnutls_compression_algorithms[MAX_COMP_METHODS] =
  { GNUTLS_COMPRESSION_ENTRY (MHD_GNUTLS_COMP_NULL, 0x00, 0, 0, 0),
#ifdef HAVE_LIBZ
  /* draft-ietf-tls-compression-02 */
  GNUTLS_COMPRESSION_ENTRY (MHD_GNUTLS_COMP_DEFLATE, 0x01, 15, 8, 3),
#endif
  {0,
   0,
   0,
   0,
   0,
   0}
};

static const gnutls_compression_method_t supported_compressions[] = {
#ifdef HAVE_LIBZ
  MHD_GNUTLS_COMP_DEFLATE,
#endif
  MHD_GNUTLS_COMP_NULL,
  0
};

#define GNUTLS_COMPRESSION_LOOP(b) \
        const gnutls_compression_entry *p; \
                for(p = _gnutls_compression_algorithms; p->name != NULL; p++) { b ; }
#define GNUTLS_COMPRESSION_ALG_LOOP(a) \
                        GNUTLS_COMPRESSION_LOOP( if(p->id == algorithm) { a; break; } )
#define GNUTLS_COMPRESSION_ALG_LOOP_NUM(a) \
                        GNUTLS_COMPRESSION_LOOP( if(p->num == num) { a; break; } )

/* Key Exchange Section */
extern mod_auth_st rsa_auth_struct;
extern mod_auth_st rsa_export_auth_struct;
extern mod_auth_st dhe_rsa_auth_struct;
extern mod_auth_st dhe_dss_auth_struct;
extern mod_auth_st anon_auth_struct;
extern mod_auth_st srp_auth_struct;
extern mod_auth_st psk_auth_struct;
extern mod_auth_st dhe_psk_auth_struct;
extern mod_auth_st srp_rsa_auth_struct;
extern mod_auth_st srp_dss_auth_struct;

struct gnutls_kx_algo_entry
{
  const char *name;
  gnutls_kx_algorithm_t algorithm;
  mod_auth_st *auth_struct;
  int needs_dh_params;
  int needs_rsa_params;
};
typedef struct gnutls_kx_algo_entry gnutls_kx_algo_entry;

static const gnutls_kx_algo_entry _gnutls_kx_algorithms[] = {
#ifdef ENABLE_ANON
  {"ANON-DH", MHD_GNUTLS_KX_ANON_DH, &anon_auth_struct, 1, 0},
#endif
  {"RSA",
   MHD_GNUTLS_KX_RSA,
   &rsa_auth_struct,
   0,
   0},
  {"RSA-EXPORT",
   MHD_GNUTLS_KX_RSA_EXPORT,
   &rsa_export_auth_struct,
   0,
   1 /* needs RSA params */ },
  {"DHE-RSA",
   MHD_GNUTLS_KX_DHE_RSA,
   &dhe_rsa_auth_struct,
   1,
   0},
  {"DHE-DSS",
   MHD_GNUTLS_KX_DHE_DSS,
   &dhe_dss_auth_struct,
   1,
   0},

#ifdef ENABLE_SRP
  {"SRP-DSS", MHD_GNUTLS_KX_SRP_DSS, &srp_dss_auth_struct, 0, 0},
  {"SRP-RSA", MHD_GNUTLS_KX_SRP_RSA, &srp_rsa_auth_struct, 0, 0},
  {"SRP", MHD_GNUTLS_KX_SRP, &srp_auth_struct, 0, 0},
#endif
#ifdef ENABLE_PSK
  {"PSK", GNUTLS_KX_PSK, &psk_auth_struct, 0, 0},
  {"DHE-PSK", GNUTLS_KX_DHE_PSK, &dhe_psk_auth_struct,
   1 /* needs DHE params */ , 0},
#endif
  {0,
   0,
   0,
   0,
   0}
};

/* Keep the contents of this struct the same as the previous one. */
static const gnutls_kx_algorithm_t supported_kxs[] = {
#ifdef ENABLE_ANON
  MHD_GNUTLS_KX_ANON_DH,
#endif
  MHD_GNUTLS_KX_RSA,
  MHD_GNUTLS_KX_RSA_EXPORT,
  MHD_GNUTLS_KX_DHE_RSA,
  MHD_GNUTLS_KX_DHE_DSS,
#ifdef ENABLE_SRP
  MHD_GNUTLS_KX_SRP_DSS,
  MHD_GNUTLS_KX_SRP_RSA,
  MHD_GNUTLS_KX_SRP,
#endif
#ifdef ENABLE_PSK
  GNUTLS_KX_PSK,
  GNUTLS_KX_DHE_PSK,
#endif
  0
};

#define GNUTLS_KX_LOOP(b) \
        const gnutls_kx_algo_entry *p; \
                for(p = _gnutls_kx_algorithms; p->name != NULL; p++) { b ; }

#define GNUTLS_KX_ALG_LOOP(a) \
                        GNUTLS_KX_LOOP( if(p->algorithm == algorithm) { a; break; } )

/* Cipher SUITES */
#define GNUTLS_CIPHER_SUITE_ENTRY( name, block_algorithm, kx_algorithm, mac_algorithm, version ) \
	{ #name, {name}, block_algorithm, kx_algorithm, mac_algorithm, version }

typedef struct
{
  const char *name;
  cipher_suite_st id;
  gnutls_cipher_algorithm_t block_algorithm;
  gnutls_kx_algorithm_t kx_algorithm;
  gnutls_mac_algorithm_t mac_algorithm;
  gnutls_protocol_t version;    /* this cipher suite is supported
                                 * from 'version' and above;
                                 */
} gnutls_cipher_suite_entry;

/* RSA with NULL cipher and MD5 MAC
 * for test purposes.
 */
#define GNUTLS_RSA_NULL_MD5 { 0x00, 0x01 }

/* ANONymous cipher suites.
 */

#define GNUTLS_ANON_DH_3DES_EDE_CBC_SHA1 { 0x00, 0x1B }
#define GNUTLS_ANON_DH_ARCFOUR_MD5 { 0x00, 0x18 }

/* rfc3268: */
#define GNUTLS_ANON_DH_AES_128_CBC_SHA1 { 0x00, 0x34 }
#define GNUTLS_ANON_DH_AES_256_CBC_SHA1 { 0x00, 0x3A }

/* rfc4132 */
#define GNUTLS_ANON_DH_CAMELLIA_128_CBC_SHA1 { 0x00,0x46 }
#define GNUTLS_ANON_DH_CAMELLIA_256_CBC_SHA1 { 0x00,0x89 }

/* PSK (not in TLS 1.0)
 * draft-ietf-tls-psk:
 */
#define GNUTLS_PSK_SHA_ARCFOUR_SHA1 { 0x00, 0x8A }
#define GNUTLS_PSK_SHA_3DES_EDE_CBC_SHA1 { 0x00, 0x8B }
#define GNUTLS_PSK_SHA_AES_128_CBC_SHA1 { 0x00, 0x8C }
#define GNUTLS_PSK_SHA_AES_256_CBC_SHA1 { 0x00, 0x8D }

#define GNUTLS_DHE_PSK_SHA_ARCFOUR_SHA1 { 0x00, 0x8E }
#define GNUTLS_DHE_PSK_SHA_3DES_EDE_CBC_SHA1 { 0x00, 0x8F }
#define GNUTLS_DHE_PSK_SHA_AES_128_CBC_SHA1 { 0x00, 0x90 }
#define GNUTLS_DHE_PSK_SHA_AES_256_CBC_SHA1 { 0x00, 0x91 }

/* SRP (rfc5054)
 */
#define GNUTLS_SRP_SHA_3DES_EDE_CBC_SHA1 { 0xC0, 0x1A }
#define GNUTLS_SRP_SHA_RSA_3DES_EDE_CBC_SHA1 { 0xC0, 0x1B }
#define GNUTLS_SRP_SHA_DSS_3DES_EDE_CBC_SHA1 { 0xC0, 0x1C }

#define GNUTLS_SRP_SHA_AES_128_CBC_SHA1 { 0xC0, 0x1D }
#define GNUTLS_SRP_SHA_RSA_AES_128_CBC_SHA1 { 0xC0, 0x1E }
#define GNUTLS_SRP_SHA_DSS_AES_128_CBC_SHA1 { 0xC0, 0x1F }

#define GNUTLS_SRP_SHA_AES_256_CBC_SHA1 { 0xC0, 0x20 }
#define GNUTLS_SRP_SHA_RSA_AES_256_CBC_SHA1 { 0xC0, 0x21 }
#define GNUTLS_SRP_SHA_DSS_AES_256_CBC_SHA1 { 0xC0, 0x22 }

/* RSA
 */
#define GNUTLS_RSA_ARCFOUR_SHA1 { 0x00, 0x05 }
#define GNUTLS_RSA_ARCFOUR_MD5 { 0x00, 0x04 }
#define GNUTLS_RSA_3DES_EDE_CBC_SHA1 { 0x00, 0x0A }

#define GNUTLS_RSA_EXPORT_ARCFOUR_40_MD5 { 0x00, 0x03 }

/* rfc3268:
 */
#define GNUTLS_RSA_AES_128_CBC_SHA1 { 0x00, 0x2F }
#define GNUTLS_RSA_AES_256_CBC_SHA1 { 0x00, 0x35 }

/* rfc4132 */
#define GNUTLS_RSA_CAMELLIA_128_CBC_SHA1 { 0x00,0x41 }
#define GNUTLS_RSA_CAMELLIA_256_CBC_SHA1 { 0x00,0x84 }

/* DHE DSS
 */

#define GNUTLS_DHE_DSS_3DES_EDE_CBC_SHA1 { 0x00, 0x13 }

/* draft-ietf-tls-56-bit-ciphersuites-01:
 */
#define GNUTLS_DHE_DSS_ARCFOUR_SHA1 { 0x00, 0x66 }

/* rfc3268:
 */
#define GNUTLS_DHE_DSS_AES_256_CBC_SHA1 { 0x00, 0x38 }
#define GNUTLS_DHE_DSS_AES_128_CBC_SHA1 { 0x00, 0x32 }

/* rfc4132 */
#define GNUTLS_DHE_DSS_CAMELLIA_128_CBC_SHA1 { 0x00,0x44 }
#define GNUTLS_DHE_DSS_CAMELLIA_256_CBC_SHA1 { 0x00,0x87 }

/* DHE RSA
 */
#define GNUTLS_DHE_RSA_3DES_EDE_CBC_SHA1 { 0x00, 0x16 }

/* rfc3268:
 */
#define GNUTLS_DHE_RSA_AES_128_CBC_SHA1 { 0x00, 0x33 }
#define GNUTLS_DHE_RSA_AES_256_CBC_SHA1 { 0x00, 0x39 }

/* rfc4132 */
#define GNUTLS_DHE_RSA_CAMELLIA_128_CBC_SHA1 { 0x00,0x45 }
#define GNUTLS_DHE_RSA_CAMELLIA_256_CBC_SHA1 { 0x00,0x88 }

#define CIPHER_SUITES_COUNT sizeof(cs_algorithms)/sizeof(gnutls_cipher_suite_entry)-1

static const gnutls_cipher_suite_entry cs_algorithms[] = {
  /* ANON_DH */
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_ANON_DH_ARCFOUR_MD5,
                             MHD_GNUTLS_CIPHER_ARCFOUR_128,
                             MHD_GNUTLS_KX_ANON_DH, MHD_GNUTLS_MAC_MD5,
                             MHD_GNUTLS_SSL3),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_ANON_DH_3DES_EDE_CBC_SHA1,
                             MHD_GNUTLS_CIPHER_3DES_CBC,
                             MHD_GNUTLS_KX_ANON_DH,
                             MHD_GNUTLS_MAC_SHA1, MHD_GNUTLS_SSL3),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_ANON_DH_AES_128_CBC_SHA1,
                             MHD_GNUTLS_CIPHER_AES_128_CBC,
                             MHD_GNUTLS_KX_ANON_DH,
                             MHD_GNUTLS_MAC_SHA1, MHD_GNUTLS_SSL3),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_ANON_DH_AES_256_CBC_SHA1,
                             MHD_GNUTLS_CIPHER_AES_256_CBC,
                             MHD_GNUTLS_KX_ANON_DH,
                             MHD_GNUTLS_MAC_SHA1, MHD_GNUTLS_SSL3),
#ifdef	ENABLE_CAMELLIA
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_ANON_DH_CAMELLIA_128_CBC_SHA1,
                             MHD_GNUTLS_CIPHER_CAMELLIA_128_CBC,
                             MHD_GNUTLS_KX_ANON_DH,
                             MHD_GNUTLS_MAC_SHA1, MHD_GNUTLS_TLS1_0),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_ANON_DH_CAMELLIA_256_CBC_SHA1,
                             MHD_GNUTLS_CIPHER_CAMELLIA_256_CBC,
                             MHD_GNUTLS_KX_ANON_DH,
                             MHD_GNUTLS_MAC_SHA1, MHD_GNUTLS_TLS1_0),
#endif

  /* SRP */
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_SRP_SHA_3DES_EDE_CBC_SHA1,
                             MHD_GNUTLS_CIPHER_3DES_CBC, MHD_GNUTLS_KX_SRP,
                             MHD_GNUTLS_MAC_SHA1, MHD_GNUTLS_TLS1_0),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_SRP_SHA_AES_128_CBC_SHA1,
                             MHD_GNUTLS_CIPHER_AES_128_CBC, MHD_GNUTLS_KX_SRP,
                             MHD_GNUTLS_MAC_SHA1, MHD_GNUTLS_TLS1_0),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_SRP_SHA_AES_256_CBC_SHA1,
                             MHD_GNUTLS_CIPHER_AES_256_CBC, MHD_GNUTLS_KX_SRP,
                             MHD_GNUTLS_MAC_SHA1, MHD_GNUTLS_TLS1_0),

  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_SRP_SHA_DSS_3DES_EDE_CBC_SHA1,
                             MHD_GNUTLS_CIPHER_3DES_CBC,
                             MHD_GNUTLS_KX_SRP_DSS,
                             MHD_GNUTLS_MAC_SHA1, MHD_GNUTLS_TLS1_0),

  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_SRP_SHA_RSA_3DES_EDE_CBC_SHA1,
                             MHD_GNUTLS_CIPHER_3DES_CBC,
                             MHD_GNUTLS_KX_SRP_RSA,
                             MHD_GNUTLS_MAC_SHA1, MHD_GNUTLS_TLS1_0),

  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_SRP_SHA_DSS_AES_128_CBC_SHA1,
                             MHD_GNUTLS_CIPHER_AES_128_CBC,
                             MHD_GNUTLS_KX_SRP_DSS,
                             MHD_GNUTLS_MAC_SHA1, MHD_GNUTLS_TLS1_0),

  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_SRP_SHA_RSA_AES_128_CBC_SHA1,
                             MHD_GNUTLS_CIPHER_AES_128_CBC,
                             MHD_GNUTLS_KX_SRP_RSA,
                             MHD_GNUTLS_MAC_SHA1, MHD_GNUTLS_TLS1_0),

  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_SRP_SHA_DSS_AES_256_CBC_SHA1,
                             MHD_GNUTLS_CIPHER_AES_256_CBC,
                             MHD_GNUTLS_KX_SRP_DSS,
                             MHD_GNUTLS_MAC_SHA1, MHD_GNUTLS_TLS1_0),

  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_SRP_SHA_RSA_AES_256_CBC_SHA1,
                             MHD_GNUTLS_CIPHER_AES_256_CBC,
                             MHD_GNUTLS_KX_SRP_RSA,
                             MHD_GNUTLS_MAC_SHA1, MHD_GNUTLS_TLS1_0),

  /* DHE_DSS */
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_DHE_DSS_ARCFOUR_SHA1,
                             MHD_GNUTLS_CIPHER_ARCFOUR_128,
                             MHD_GNUTLS_KX_DHE_DSS,
                             MHD_GNUTLS_MAC_SHA1, MHD_GNUTLS_TLS1_0),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_DHE_DSS_3DES_EDE_CBC_SHA1,
                             MHD_GNUTLS_CIPHER_3DES_CBC,
                             MHD_GNUTLS_KX_DHE_DSS,
                             MHD_GNUTLS_MAC_SHA1, MHD_GNUTLS_SSL3),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_DHE_DSS_AES_128_CBC_SHA1,
                             MHD_GNUTLS_CIPHER_AES_128_CBC,
                             MHD_GNUTLS_KX_DHE_DSS,
                             MHD_GNUTLS_MAC_SHA1, MHD_GNUTLS_SSL3),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_DHE_DSS_AES_256_CBC_SHA1,
                             MHD_GNUTLS_CIPHER_AES_256_CBC,
                             MHD_GNUTLS_KX_DHE_DSS,
                             MHD_GNUTLS_MAC_SHA1, MHD_GNUTLS_SSL3),
#ifdef	ENABLE_CAMELLIA
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_DHE_DSS_CAMELLIA_128_CBC_SHA1,
                             MHD_GNUTLS_CIPHER_CAMELLIA_128_CBC,
                             MHD_GNUTLS_KX_DHE_DSS,
                             MHD_GNUTLS_MAC_SHA1, MHD_GNUTLS_TLS1_0),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_DHE_DSS_CAMELLIA_256_CBC_SHA1,
                             MHD_GNUTLS_CIPHER_CAMELLIA_256_CBC,
                             MHD_GNUTLS_KX_DHE_DSS,
                             MHD_GNUTLS_MAC_SHA1, MHD_GNUTLS_TLS1_0),
#endif
  /* DHE_RSA */
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_DHE_RSA_3DES_EDE_CBC_SHA1,
                             MHD_GNUTLS_CIPHER_3DES_CBC,
                             MHD_GNUTLS_KX_DHE_RSA,
                             MHD_GNUTLS_MAC_SHA1, MHD_GNUTLS_SSL3),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_DHE_RSA_AES_128_CBC_SHA1,
                             MHD_GNUTLS_CIPHER_AES_128_CBC,
                             MHD_GNUTLS_KX_DHE_RSA,
                             MHD_GNUTLS_MAC_SHA1, MHD_GNUTLS_SSL3),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_DHE_RSA_AES_256_CBC_SHA1,
                             MHD_GNUTLS_CIPHER_AES_256_CBC,
                             MHD_GNUTLS_KX_DHE_RSA,
                             MHD_GNUTLS_MAC_SHA1, MHD_GNUTLS_SSL3),
#ifdef	ENABLE_CAMELLIA
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_DHE_RSA_CAMELLIA_128_CBC_SHA1,
                             MHD_GNUTLS_CIPHER_CAMELLIA_128_CBC,
                             MHD_GNUTLS_KX_DHE_RSA,
                             MHD_GNUTLS_MAC_SHA1, MHD_GNUTLS_TLS1_0),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_DHE_RSA_CAMELLIA_256_CBC_SHA1,
                             MHD_GNUTLS_CIPHER_CAMELLIA_256_CBC,
                             MHD_GNUTLS_KX_DHE_RSA,
                             MHD_GNUTLS_MAC_SHA1, MHD_GNUTLS_TLS1_0),
#endif
  /* RSA */
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_RSA_NULL_MD5,
                             MHD_GNUTLS_CIPHER_NULL,
                             MHD_GNUTLS_KX_RSA, MHD_GNUTLS_MAC_MD5,
                             MHD_GNUTLS_SSL3),

  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_RSA_EXPORT_ARCFOUR_40_MD5,
                             MHD_GNUTLS_CIPHER_ARCFOUR_40,
                             MHD_GNUTLS_KX_RSA_EXPORT, MHD_GNUTLS_MAC_MD5,
                             MHD_GNUTLS_SSL3),

  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_RSA_ARCFOUR_SHA1,
                             MHD_GNUTLS_CIPHER_ARCFOUR_128,
                             MHD_GNUTLS_KX_RSA, MHD_GNUTLS_MAC_SHA1,
                             MHD_GNUTLS_SSL3),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_RSA_ARCFOUR_MD5,
                             MHD_GNUTLS_CIPHER_ARCFOUR_128,
                             MHD_GNUTLS_KX_RSA, MHD_GNUTLS_MAC_MD5,
                             MHD_GNUTLS_SSL3),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_RSA_3DES_EDE_CBC_SHA1,
                             MHD_GNUTLS_CIPHER_3DES_CBC,
                             MHD_GNUTLS_KX_RSA, MHD_GNUTLS_MAC_SHA1,
                             MHD_GNUTLS_SSL3),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_RSA_AES_128_CBC_SHA1,
                             MHD_GNUTLS_CIPHER_AES_128_CBC, MHD_GNUTLS_KX_RSA,
                             MHD_GNUTLS_MAC_SHA1, MHD_GNUTLS_SSL3),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_RSA_AES_256_CBC_SHA1,
                             MHD_GNUTLS_CIPHER_AES_256_CBC, MHD_GNUTLS_KX_RSA,
                             MHD_GNUTLS_MAC_SHA1, MHD_GNUTLS_SSL3),
#ifdef	ENABLE_CAMELLIA
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_RSA_CAMELLIA_128_CBC_SHA1,
                             MHD_GNUTLS_CIPHER_CAMELLIA_128_CBC,
                             MHD_GNUTLS_KX_RSA,
                             MHD_GNUTLS_MAC_SHA1, MHD_GNUTLS_TLS1_0),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_RSA_CAMELLIA_256_CBC_SHA1,
                             MHD_GNUTLS_CIPHER_CAMELLIA_256_CBC,
                             MHD_GNUTLS_KX_RSA,
                             MHD_GNUTLS_MAC_SHA1, MHD_GNUTLS_TLS1_0),
#endif
  {0,
   {
    {0,
     0}},
   0,
   0,
   0,
   0}
};

#define GNUTLS_CIPHER_SUITE_LOOP(b) \
        const gnutls_cipher_suite_entry *p; \
                for(p = cs_algorithms; p->name != NULL; p++) { b ; }

#define GNUTLS_CIPHER_SUITE_ALG_LOOP(a) \
                        GNUTLS_CIPHER_SUITE_LOOP( if( (p->id.suite[0] == suite->suite[0]) && (p->id.suite[1] == suite->suite[1])) { a; break; } )

/* Generic Functions */

int
_gnutls_mac_priority (gnutls_session_t session,
                      gnutls_mac_algorithm_t algorithm)
{                               /* actually returns the priority */
  unsigned int i;
  for (i = 0; i < session->internals.priorities.mac.algorithms; i++)
    {
      if (session->internals.priorities.mac.priority[i] == algorithm)
        return i;
    }
  return -1;
}

/**
 * gnutls_mac_get_name - Returns a string with the name of the specified mac algorithm
 * @algorithm: is a MAC algorithm
 *
 * Returns: a string that contains the name of the specified MAC
 * algorithm, or %NULL.
 **/
const char *
gnutls_mac_get_name (gnutls_mac_algorithm_t algorithm)
{
  const char *ret = NULL;

  /* avoid prefix */
  GNUTLS_HASH_ALG_LOOP (ret = p->name);

  return ret;
}

/**
 * gnutls_mac_get_id - Returns the gnutls id of the specified in string algorithm
 * @algorithm: is a MAC algorithm name
 *
 * Returns: an %gnutls_mac_algorithm_tid of the specified in a string
 * MAC algorithm, or %GNUTLS_MAC_UNKNOWN on failures.  The names are
 * compared in a case insensitive way.
 **/
gnutls_mac_algorithm_t
gnutls_mac_get_id (const char *name)
{
  gnutls_mac_algorithm_t ret = MHD_GNUTLS_MAC_UNKNOWN;

  GNUTLS_HASH_LOOP (if (strcasecmp (p->name, name) == 0) ret = p->id)
    ;

  return ret;
}

/**
 * gnutls_mac_get_key_size - Returns the length of the MAC's key size
 * @algorithm: is an encryption algorithm
 *
 * Returns: length (in bytes) of the given MAC key size, or 0 if the
 * given MAC algorithm is invalid.
 *
 **/
size_t
gnutls_mac_get_key_size (gnutls_mac_algorithm_t algorithm)
{
  size_t ret = 0;

  /* avoid prefix */
  GNUTLS_HASH_ALG_LOOP (ret = p->key_size);

  return ret;
}

/**
 * gnutls_mac_list:
 *
 * Get a list of hash algorithms for use as MACs.  Note that not
 * necessarily all MACs are supported in TLS cipher suites.  For
 * example, MD2 is not supported as a cipher suite, but is supported
 * for other purposes (e.g., X.509 signature verification or similar).
 *
 * Returns: Return a zero-terminated list of %gnutls_mac_algorithm_t
 * integers indicating the available MACs.
 **/
const gnutls_mac_algorithm_t *
gnutls_mac_list (void)
{
  return supported_macs;
}

const char *
_gnutls_x509_mac_to_oid (gnutls_mac_algorithm_t algorithm)
{
  const char *ret = NULL;

  /* avoid prefix */
  GNUTLS_HASH_ALG_LOOP (ret = p->oid);

  return ret;
}

gnutls_mac_algorithm_t
_gnutls_x509_oid2mac_algorithm (const char *oid)
{
  gnutls_mac_algorithm_t ret = 0;

  GNUTLS_HASH_LOOP (if (p->oid && strcmp (oid, p->oid) == 0)
                    {
                    ret = p->id; break;}
  )
    ;

  if (ret == 0)
    return MHD_GNUTLS_MAC_UNKNOWN;
  return ret;
}

int
_gnutls_mac_is_ok (gnutls_mac_algorithm_t algorithm)
{
  ssize_t ret = -1;
  GNUTLS_HASH_ALG_LOOP (ret = p->id);
  if (ret >= 0)
    ret = 0;
  else
    ret = 1;
  return ret;
}

/* Compression Functions */
int
_gnutls_compression_priority (gnutls_session_t session,
                              gnutls_compression_method_t algorithm)
{                               /* actually returns the priority */
  unsigned int i;
  for (i = 0; i < session->internals.priorities.compression.algorithms; i++)
    {
      if (session->internals.priorities.compression.priority[i] == algorithm)
        return i;
    }
  return -1;
}

/**
 * gnutls_compression_get_name - Returns a string with the name of the specified compression algorithm
 * @algorithm: is a Compression algorithm
 *
 * Returns: a pointer to a string that contains the name of the
 * specified compression algorithm, or %NULL.
 **/
const char *
gnutls_compression_get_name (gnutls_compression_method_t algorithm)
{
  const char *ret = NULL;

  /* avoid prefix */
  GNUTLS_COMPRESSION_ALG_LOOP (ret = p->name + sizeof ("GNUTLS_COMP_") - 1);

  return ret;
}

/**
 * gnutls_compression_get_id - Returns the gnutls id of the specified in string algorithm
 * @algorithm: is a compression method name
 *
 * The names are compared in a case insensitive way.
 *
 * Returns: an id of the specified in a string compression method, or
 * %GNUTLS_COMP_UNKNOWN on error.
 *
 **/
gnutls_compression_method_t
gnutls_compression_get_id (const char *name)
{
  gnutls_compression_method_t ret = MHD_GNUTLS_COMP_UNKNOWN;

  GNUTLS_COMPRESSION_LOOP (if
                           (strcasecmp
                            (p->name + sizeof ("GNUTLS_COMP_") - 1,
                             name) == 0) ret = p->id)
    ;

  return ret;
}

/**
 * gnutls_compression_list:
 *
 * Get a list of compression methods.  Note that to be able to use LZO
 * compression, you must link to libgnutls-extra and call
 * gnutls_global_init_extra().
 *
 * Returns: a zero-terminated list of %gnutls_compression_method_t
 * integers indicating the available compression methods.
 **/
const gnutls_compression_method_t *
gnutls_compression_list (void)
{
  return supported_compressions;
}

/* return the tls number of the specified algorithm */
int
_gnutls_compression_get_num (gnutls_compression_method_t algorithm)
{
  int ret = -1;

  /* avoid prefix */
  GNUTLS_COMPRESSION_ALG_LOOP (ret = p->num);

  return ret;
}

int
_gnutls_compression_get_wbits (gnutls_compression_method_t algorithm)
{
  int ret = -1;
  /* avoid prefix */
  GNUTLS_COMPRESSION_ALG_LOOP (ret = p->window_bits);
  return ret;
}

int
_gnutls_compression_get_mem_level (gnutls_compression_method_t algorithm)
{
  int ret = -1;
  /* avoid prefix */
  GNUTLS_COMPRESSION_ALG_LOOP (ret = p->mem_level);
  return ret;
}

int
_gnutls_compression_get_comp_level (gnutls_compression_method_t algorithm)
{
  int ret = -1;
  /* avoid prefix */
  GNUTLS_COMPRESSION_ALG_LOOP (ret = p->comp_level);
  return ret;
}

/* returns the gnutls internal ID of the TLS compression
 * method num
 */
gnutls_compression_method_t
_gnutls_compression_get_id (int num)
{
  gnutls_compression_method_t ret = -1;

  /* avoid prefix */
  GNUTLS_COMPRESSION_ALG_LOOP_NUM (ret = p->id);

  return ret;
}

int
_gnutls_compression_is_ok (gnutls_compression_method_t algorithm)
{
  ssize_t ret = -1;
  GNUTLS_COMPRESSION_ALG_LOOP (ret = p->id);
  if (ret >= 0)
    ret = 0;
  else
    ret = 1;
  return ret;
}

/* CIPHER functions */
int
_gnutls_cipher_get_block_size (gnutls_cipher_algorithm_t algorithm)
{
  size_t ret = 0;
  GNUTLS_ALG_LOOP (ret = p->blocksize);
  return ret;

}

/* returns the priority */
int
_gnutls_cipher_priority (gnutls_session_t session,
                         gnutls_cipher_algorithm_t algorithm)
{
  unsigned int i;
  for (i = 0; i < session->internals.priorities.cipher.algorithms; i++)
    {
      if (session->internals.priorities.cipher.priority[i] == algorithm)
        return i;
    }
  return -1;
}

int
_gnutls_cipher_is_block (gnutls_cipher_algorithm_t algorithm)
{
  size_t ret = 0;

  GNUTLS_ALG_LOOP (ret = p->block);
  return ret;

}

/**
 * gnutls_cipher_get_key_size - Returns the length of the cipher's key size
 * @algorithm: is an encryption algorithm
 *
 * Returns: length (in bytes) of the given cipher's key size, o 0 if
 *   the given cipher is invalid.
 **/
size_t
gnutls_cipher_get_key_size (gnutls_cipher_algorithm_t algorithm)
{                               /* In bytes */
  size_t ret = 0;
  GNUTLS_ALG_LOOP (ret = p->keysize);
  return ret;

}

int
_gnutls_cipher_get_iv_size (gnutls_cipher_algorithm_t algorithm)
{                               /* In bytes */
  size_t ret = 0;
  GNUTLS_ALG_LOOP (ret = p->iv);
  return ret;

}

int
_gnutls_cipher_get_export_flag (gnutls_cipher_algorithm_t algorithm)
{                               /* In bytes */
  size_t ret = 0;
  GNUTLS_ALG_LOOP (ret = p->export_flag);
  return ret;

}

/**
 * gnutls_cipher_get_name - Returns a string with the name of the specified cipher algorithm
 * @algorithm: is an encryption algorithm
 *
 * Returns: a pointer to a string that contains the name of the
 *   specified cipher, or %NULL.
 **/
const char *
gnutls_cipher_get_name (gnutls_cipher_algorithm_t algorithm)
{
  const char *ret = NULL;

  /* avoid prefix */
  GNUTLS_ALG_LOOP (ret = p->name);

  return ret;
}

/**
 * gnutls_cipher_get_id - Returns the gnutls id of the specified in string algorithm
 * @algorithm: is a MAC algorithm name
 *
 * The names are compared in a case insensitive way.
 *
 * Returns: an id of the specified cipher, or %GNUTLS_CIPHER_UNKNOWN
 * on error.
 *
 **/
gnutls_cipher_algorithm_t
gnutls_cipher_get_id (const char *name)
{
  gnutls_cipher_algorithm_t ret = MHD_GNUTLS_CIPHER_UNKNOWN;

  GNUTLS_LOOP (if (strcasecmp (p->name, name) == 0) ret = p->id)
    ;

  return ret;
}

/**
 * gnutls_cipher_list:
 *
 * Get a list of supported cipher algorithms.  Note that not
 * necessarily all ciphers are supported as TLS cipher suites.  For
 * example, DES is not supported as a cipher suite, but is supported
 * for other purposes (e.g., PKCS#8 or similar).
 *
 * Returns: a zero-terminated list of %gnutls_cipher_algorithm_t
 * integers indicating the available ciphers.
 *
 **/
const gnutls_cipher_algorithm_t *
gnutls_cipher_list (void)
{
  return supported_ciphers;
}

int
_gnutls_cipher_is_ok (gnutls_cipher_algorithm_t algorithm)
{
  ssize_t ret = -1;
  GNUTLS_ALG_LOOP (ret = p->id);
  if (ret >= 0)
    ret = 0;
  else
    ret = 1;
  return ret;
}

/* Key EXCHANGE functions */
mod_auth_st *
_gnutls_kx_auth_struct (gnutls_kx_algorithm_t algorithm)
{
  mod_auth_st *ret = NULL;
  GNUTLS_KX_ALG_LOOP (ret = p->auth_struct);
  return ret;

}

int
_gnutls_kx_priority (gnutls_session_t session,
                     gnutls_kx_algorithm_t algorithm)
{
  unsigned int i;
  for (i = 0; i < session->internals.priorities.kx.algorithms; i++)
    {
      if (session->internals.priorities.kx.priority[i] == algorithm)
        return i;
    }
  return -1;
}

/**
 * gnutls_kx_get_name - Returns a string with the name of the specified key exchange algorithm
 * @algorithm: is a key exchange algorithm
 *
 * Returns: a pointer to a string that contains the name of the
 * specified key exchange algorithm, or %NULL.
 **/
const char *
gnutls_kx_get_name (gnutls_kx_algorithm_t algorithm)
{
  const char *ret = NULL;

  /* avoid prefix */
  GNUTLS_KX_ALG_LOOP (ret = p->name);

  return ret;
}

/**
 * gnutls_kx_get_id - Returns the gnutls id of the specified in string algorithm
 * @algorithm: is a KX name
 *
 * The names are compared in a case insensitive way.
 *
 * Returns: an id of the specified KX algorithm, or
 * %GNUTLS_KX_UNKNOWN on error.
 **/
gnutls_kx_algorithm_t
gnutls_kx_get_id (const char *name)
{
  gnutls_cipher_algorithm_t ret = MHD_GNUTLS_KX_UNKNOWN;

  GNUTLS_KX_LOOP (if (strcasecmp (p->name, name) == 0) ret = p->algorithm)
    ;

  return ret;
}

/**
 * gnutls_kx_list:
 *
 * Get a list of supported key exchange algorithms.
 *
 * Returns: a zero-terminated list of %gnutls_kx_algorithm_t integers
 * indicating the available key exchange algorithms.
 **/
const gnutls_kx_algorithm_t *
gnutls_kx_list (void)
{
  return supported_kxs;
}

int
_gnutls_kx_is_ok (gnutls_kx_algorithm_t algorithm)
{
  ssize_t ret = -1;
  GNUTLS_KX_ALG_LOOP (ret = p->algorithm);
  if (ret >= 0)
    ret = 0;
  else
    ret = 1;
  return ret;
}

int
_gnutls_kx_needs_rsa_params (gnutls_kx_algorithm_t algorithm)
{
  ssize_t ret = 0;
  GNUTLS_KX_ALG_LOOP (ret = p->needs_rsa_params);
  return ret;
}

int
_gnutls_kx_needs_dh_params (gnutls_kx_algorithm_t algorithm)
{
  ssize_t ret = 0;
  GNUTLS_KX_ALG_LOOP (ret = p->needs_dh_params);
  return ret;
}

/* Version */
int
_gnutls_version_priority (gnutls_session_t session, gnutls_protocol_t version)
{                               /* actually returns the priority */
  unsigned int i;

  if (session->internals.priorities.protocol.priority == NULL)
    {
      gnutls_assert ();
      return -1;
    }

  for (i = 0; i < session->internals.priorities.protocol.algorithms; i++)
    {
      if (session->internals.priorities.protocol.priority[i] == version)
        return i;
    }
  return -1;
}

gnutls_protocol_t
_gnutls_version_lowest (gnutls_session_t session)
{                               /* returns the lowest version supported */
  unsigned int i, min = 0xff;

  if (session->internals.priorities.protocol.priority == NULL)
    {
      return MHD_GNUTLS_VERSION_UNKNOWN;
    }
  else
    for (i = 0; i < session->internals.priorities.protocol.algorithms; i++)
      {
        if (session->internals.priorities.protocol.priority[i] < min)
          min = session->internals.priorities.protocol.priority[i];
      }

  if (min == 0xff)
    return MHD_GNUTLS_VERSION_UNKNOWN;  /* unknown version */

  return min;
}

gnutls_protocol_t
_gnutls_version_max (gnutls_session_t session)
{                               /* returns the maximum version supported */
  unsigned int i, max = 0x00;

  if (session->internals.priorities.protocol.priority == NULL)
    {
      return MHD_GNUTLS_VERSION_UNKNOWN;
    }
  else
    for (i = 0; i < session->internals.priorities.protocol.algorithms; i++)
      {
        if (session->internals.priorities.protocol.priority[i] > max)
          max = session->internals.priorities.protocol.priority[i];
      }

  if (max == 0x00)
    return MHD_GNUTLS_VERSION_UNKNOWN;  /* unknown version */

  return max;
}

/**
 * gnutls_protocol_get_name - Returns a string with the name of the specified SSL/TLS version
 * @version: is a (gnutls) version number
 *
 * Returns: a string that contains the name of the specified TLS
 * version (e.g., "TLS 1.0"), or %NULL.
 **/
const char *
gnutls_protocol_get_name (gnutls_protocol_t version)
{
  const char *ret = NULL;

  /* avoid prefix */
  GNUTLS_VERSION_ALG_LOOP (ret = p->name);
  return ret;
}

/**
 * gnutls_protocol_get_id - Returns the gnutls id of the specified in string protocol
 * @algorithm: is a protocol name
 *
 * The names are compared in a case insensitive way.
 *
 * Returns: an id of the specified protocol, or
 * %GNUTLS_VERSION_UNKNOWN on error.
 **/
gnutls_protocol_t
gnutls_protocol_get_id (const char *name)
{
  gnutls_protocol_t ret = MHD_GNUTLS_VERSION_UNKNOWN;

  GNUTLS_VERSION_LOOP (if (strcasecmp (p->name, name) == 0) ret = p->id)
    ;

  return ret;
}

/**
 * gnutls_protocol_list:
 *
 * Get a list of supported protocols, e.g. SSL 3.0, TLS 1.0 etc.
 *
 * Returns: a zero-terminated list of %gnutls_protocol_t integers
 * indicating the available protocols.
 *
 **/
const gnutls_protocol_t *
gnutls_protocol_list (void)
{
  return supported_protocols;
}

int
_gnutls_version_get_minor (gnutls_protocol_t version)
{
  int ret = -1;

  GNUTLS_VERSION_ALG_LOOP (ret = p->minor);
  return ret;
}

gnutls_protocol_t
_gnutls_version_get (int major, int minor)
{
  int ret = -1;

  GNUTLS_VERSION_LOOP (if ((p->major == major) && (p->minor == minor))
                       ret = p->id)
    ;
  return ret;
}

int
_gnutls_version_get_major (gnutls_protocol_t version)
{
  int ret = -1;

  GNUTLS_VERSION_ALG_LOOP (ret = p->major);
  return ret;
}

/* Version Functions */

int
_gnutls_version_is_supported (gnutls_session_t session,
                              const gnutls_protocol_t version)
{
  int ret = 0;

  GNUTLS_VERSION_ALG_LOOP (ret = p->supported);
  if (ret == 0)
    return 0;

  if (_gnutls_version_priority (session, version) < 0)
    return 0;                   /* disabled by the user */
  else
    return 1;
}

/* Type to KX mappings */
gnutls_kx_algorithm_t
_gnutls_map_kx_get_kx (gnutls_credentials_type_t type, int server)
{
  gnutls_kx_algorithm_t ret = -1;

  if (server)
    {
      GNUTLS_KX_MAP_ALG_LOOP_SERVER (ret = p->algorithm);
    }
  else
    {
      GNUTLS_KX_MAP_ALG_LOOP_SERVER (ret = p->algorithm);
    }
  return ret;
}

gnutls_credentials_type_t
_gnutls_map_kx_get_cred (gnutls_kx_algorithm_t algorithm, int server)
{
  gnutls_credentials_type_t ret = -1;
  if (server)
    {
      GNUTLS_KX_MAP_LOOP (if (p->algorithm == algorithm) ret = p->server_type)
        ;
    }
  else
    {
      GNUTLS_KX_MAP_LOOP (if (p->algorithm == algorithm) ret = p->client_type)
        ;
    }

  return ret;
}

/* Cipher Suite's functions */
gnutls_cipher_algorithm_t
_gnutls_cipher_suite_get_cipher_algo (const cipher_suite_st * suite)
{
  int ret = 0;
  GNUTLS_CIPHER_SUITE_ALG_LOOP (ret = p->block_algorithm);
  return ret;
}

gnutls_protocol_t
_gnutls_cipher_suite_get_version (const cipher_suite_st * suite)
{
  int ret = 0;
  GNUTLS_CIPHER_SUITE_ALG_LOOP (ret = p->version);
  return ret;
}

gnutls_kx_algorithm_t
_gnutls_cipher_suite_get_kx_algo (const cipher_suite_st * suite)
{
  int ret = 0;

  GNUTLS_CIPHER_SUITE_ALG_LOOP (ret = p->kx_algorithm);
  return ret;

}

gnutls_mac_algorithm_t
_gnutls_cipher_suite_get_mac_algo (const cipher_suite_st * suite)
{                               /* In bytes */
  int ret = 0;
  GNUTLS_CIPHER_SUITE_ALG_LOOP (ret = p->mac_algorithm);
  return ret;

}

const char *
_gnutls_cipher_suite_get_name (cipher_suite_st * suite)
{
  const char *ret = NULL;

  /* avoid prefix */
  GNUTLS_CIPHER_SUITE_ALG_LOOP (ret = p->name + sizeof ("GNUTLS_") - 1);

  return ret;
}

/**
 * gnutls_cipher_suite_get_name - Returns a string with the name of the specified cipher suite
 * @kx_algorithm: is a Key exchange algorithm
 * @cipher_algorithm: is a cipher algorithm
 * @mac_algorithm: is a MAC algorithm
 *
 * Note that the full cipher suite name must be prepended by TLS or
 * SSL depending of the protocol in use.
 *
 * Returns: a string that contains the name of a TLS cipher suite,
 * specified by the given algorithms, or %NULL.
 **/
const char *
gnutls_cipher_suite_get_name (gnutls_kx_algorithm_t kx_algorithm,
                              gnutls_cipher_algorithm_t cipher_algorithm,
                              gnutls_mac_algorithm_t mac_algorithm)
{
  const char *ret = NULL;

  /* avoid prefix */
  GNUTLS_CIPHER_SUITE_LOOP (if (kx_algorithm == p->kx_algorithm &&
                                cipher_algorithm == p->block_algorithm &&
                                mac_algorithm == p->mac_algorithm)
                            ret = p->name + sizeof ("GNUTLS_") - 1)
    ;

  return ret;
}

/**
 * gnutls_cipher_suite_info:
 * @idx: index of cipher suite to get information about, starts on 0.
 * @cs_id: output buffer with room for 2 bytes, indicating cipher suite value
 * @kx: output variable indicating key exchange algorithm, or %NULL.
 * @cipher: output variable indicating cipher, or %NULL.
 * @mac: output variable indicating MAC algorithm, or %NULL.
 * @version: output variable indicating TLS protocol version, or %NULL.
 *
 * Get information about supported cipher suites.  Use the function
 * iteratively to get information about all supported cipher suites.
 * Call with idx=0 to get information about first cipher suite, then
 * idx=1 and so on until the function returns NULL.
 *
 * Returns: the name of @idx cipher suite, and set the information
 * about the cipher suite in the output variables.  If @idx is out of
 * bounds, %NULL is returned.
 **/
const char *
gnutls_cipher_suite_info (size_t idx,
                          char *cs_id,
                          gnutls_kx_algorithm_t * kx,
                          gnutls_cipher_algorithm_t * cipher,
                          gnutls_mac_algorithm_t * mac,
                          gnutls_protocol_t * version)
{
  if (idx >= CIPHER_SUITES_COUNT)
    return NULL;

  if (cs_id)
    memcpy (cs_id, cs_algorithms[idx].id.suite, 2);
  if (kx)
    *kx = cs_algorithms[idx].kx_algorithm;
  if (cipher)
    *cipher = cs_algorithms[idx].block_algorithm;
  if (mac)
    *mac = cs_algorithms[idx].mac_algorithm;
  if (version)
    *version = cs_algorithms[idx].version;

  return cs_algorithms[idx].name + sizeof ("GNU") - 1;
}

static inline int
_gnutls_cipher_suite_is_ok (cipher_suite_st * suite)
{
  size_t ret;
  const char *name = NULL;

  GNUTLS_CIPHER_SUITE_ALG_LOOP (name = p->name);
  if (name != NULL)
    ret = 0;
  else
    ret = 1;
  return ret;

}

#define SWAP(x, y) memcpy(tmp,x,size); \
		   memcpy(x,y,size); \
		   memcpy(y,tmp,size);

#define MAX_ELEM_SIZE 4
static inline int
_gnutls_partition (gnutls_session_t session,
                   void *_base,
                   size_t nmemb,
                   size_t size,
                   int (*compar) (gnutls_session_t,
                                  const void *, const void *))
{
  uint8_t *base = _base;
  uint8_t tmp[MAX_ELEM_SIZE];
  uint8_t ptmp[MAX_ELEM_SIZE];
  unsigned int pivot;
  unsigned int i, j;
  unsigned int full;

  i = pivot = 0;
  j = full = (nmemb - 1) * size;

  memcpy (ptmp, &base[0], size);        /* set pivot item */

  while (i < j)
    {
      while ((compar (session, &base[i], ptmp) <= 0) && (i < full))
        {
          i += size;
        }
      while ((compar (session, &base[j], ptmp) >= 0) && (j > 0))
        j -= size;

      if (i < j)
        {
          SWAP (&base[j], &base[i]);
        }
    }

  if (j > pivot)
    {
      SWAP (&base[pivot], &base[j]);
      pivot = j;
    }
  else if (i < pivot)
    {
      SWAP (&base[pivot], &base[i]);
      pivot = i;
    }
  return pivot / size;
}

static void
_gnutls_qsort (gnutls_session_t session,
               void *_base,
               size_t nmemb,
               size_t size,
               int (*compar) (gnutls_session_t, const void *, const void *))
{
  unsigned int pivot;
  char *base = _base;
  size_t snmemb = nmemb;

#ifdef DEBUG
  if (size > MAX_ELEM_SIZE)
    {
      gnutls_assert ();
      _gnutls_debug_log ("QSORT BUG\n");
      exit (1);
    }
#endif

  if (snmemb <= 1)
    return;
  pivot = _gnutls_partition (session, _base, nmemb, size, compar);

  _gnutls_qsort (session, base, pivot < nmemb ? pivot + 1
                 : pivot, size, compar);
  _gnutls_qsort (session, &base[(pivot + 1) * size], nmemb - pivot - 1, size,
                 compar);
}

/* a compare function for KX algorithms (using priorities).
 * For use with qsort
 */
static int
_gnutls_compare_algo (gnutls_session_t session,
                      const void *i_A1, const void *i_A2)
{
  gnutls_kx_algorithm_t kA1 =
    _gnutls_cipher_suite_get_kx_algo ((const cipher_suite_st *) i_A1);
  gnutls_kx_algorithm_t kA2 =
    _gnutls_cipher_suite_get_kx_algo ((const cipher_suite_st *) i_A2);
  gnutls_cipher_algorithm_t cA1 =
    _gnutls_cipher_suite_get_cipher_algo ((const cipher_suite_st *) i_A1);
  gnutls_cipher_algorithm_t cA2 =
    _gnutls_cipher_suite_get_cipher_algo ((const cipher_suite_st *) i_A2);
  gnutls_mac_algorithm_t mA1 =
    _gnutls_cipher_suite_get_mac_algo ((const cipher_suite_st *) i_A1);
  gnutls_mac_algorithm_t mA2 =
    _gnutls_cipher_suite_get_mac_algo ((const cipher_suite_st *) i_A2);

  int p1 = (_gnutls_kx_priority (session, kA1) + 1) * 64;
  int p2 = (_gnutls_kx_priority (session, kA2) + 1) * 64;
  p1 += (_gnutls_cipher_priority (session, cA1) + 1) * 8;
  p2 += (_gnutls_cipher_priority (session, cA2) + 1) * 8;
  p1 += _gnutls_mac_priority (session, mA1);
  p2 += _gnutls_mac_priority (session, mA2);

  if (p1 > p2)
    {
      return 1;
    }
  else
    {
      if (p1 == p2)
        {
          return 0;
        }
      return -1;
    }
}

#ifdef SORT_DEBUG
static void
_gnutls_bsort (gnutls_session_t session, void *_base, size_t nmemb,
               size_t size, int (*compar) (gnutls_session_t, const void *,
                                           const void *))
{
  unsigned int i, j;
  int full = nmemb * size;
  char *base = _base;
  char tmp[MAX_ELEM_SIZE];

  for (i = 0; i < full; i += size)
    {
      for (j = 0; j < full; j += size)
        {
          if (compar (session, &base[i], &base[j]) < 0)
            {
              SWAP (&base[j], &base[i]);
            }
        }
    }

}
#endif

int
_gnutls_supported_ciphersuites_sorted (gnutls_session_t session,
                                       cipher_suite_st ** ciphers)
{

#ifdef SORT_DEBUG
  unsigned int i;
#endif
  int count;

  count = _gnutls_supported_ciphersuites (session, ciphers);
  if (count <= 0)
    {
      gnutls_assert ();
      return count;
    }
#ifdef SORT_DEBUG
  _gnutls_debug_log ("Unsorted: \n");
  for (i = 0; i < count; i++)
    _gnutls_debug_log ("\t%d: %s\n", i,
                       _gnutls_cipher_suite_get_name ((*ciphers)[i]));
#endif

  _gnutls_qsort (session, *ciphers, count, sizeof (cipher_suite_st),
                 _gnutls_compare_algo);

#ifdef SORT_DEBUG
  _gnutls_debug_log ("Sorted: \n");
  for (i = 0; i < count; i++)
    _gnutls_debug_log ("\t%d: %s\n", i,
                       _gnutls_cipher_suite_get_name ((*ciphers)[i]));
#endif

  return count;
}

int
_gnutls_supported_ciphersuites (gnutls_session_t session,
                                cipher_suite_st ** _ciphers)
{

  unsigned int i, ret_count, j;
  unsigned int count = CIPHER_SUITES_COUNT;
  cipher_suite_st *tmp_ciphers;
  cipher_suite_st *ciphers;
  gnutls_protocol_t version;

  if (count == 0)
    {
      return 0;
    }

  tmp_ciphers = gnutls_alloca (count * sizeof (cipher_suite_st));
  if (tmp_ciphers == NULL)
    return GNUTLS_E_MEMORY_ERROR;

  ciphers = gnutls_malloc (count * sizeof (cipher_suite_st));
  if (ciphers == NULL)
    {
      gnutls_afree (tmp_ciphers);
      return GNUTLS_E_MEMORY_ERROR;
    }

  version = gnutls_protocol_get_version (session);

  for (i = 0; i < count; i++)
    {
      memcpy (&tmp_ciphers[i], &cs_algorithms[i].id,
              sizeof (cipher_suite_st));
    }

  for (i = j = 0; i < count; i++)
    {
      /* remove private cipher suites, if requested.
       */
      if (tmp_ciphers[i].suite[0] == 0xFF && session->internals.enable_private
          == 0)
        continue;

      /* remove cipher suites which do not support the
       * protocol version used.
       */
      if (_gnutls_cipher_suite_get_version (&tmp_ciphers[i]) > version)
        continue;

      if (_gnutls_kx_priority (session,
                               _gnutls_cipher_suite_get_kx_algo (&tmp_ciphers
                                                                 [i])) < 0)
        continue;
      if (_gnutls_mac_priority (session,
                                _gnutls_cipher_suite_get_mac_algo
                                (&tmp_ciphers[i])) < 0)
        continue;
      if (_gnutls_cipher_priority (session,
                                   _gnutls_cipher_suite_get_cipher_algo
                                   (&tmp_ciphers[i])) < 0)
        continue;

      memcpy (&ciphers[j], &tmp_ciphers[i], sizeof (cipher_suite_st));
      j++;
    }

  ret_count = j;

#if 0                           /* expensive */
  if (ret_count > 0 && ret_count != count)
    {
      ciphers =
        gnutls_realloc_fast (ciphers, ret_count * sizeof (cipher_suite_st));
    }
  else
    {
      if (ret_count != count)
        {
          gnutls_free (ciphers);
          ciphers = NULL;
        }
    }
#endif

  gnutls_afree (tmp_ciphers);

  /* This function can no longer return 0 cipher suites.
   * It returns an error code instead.
   */
  if (ret_count == 0)
    {
      gnutls_assert ();
      gnutls_free (ciphers);
      return GNUTLS_E_NO_CIPHER_SUITES;
    }
  *_ciphers = ciphers;
  return ret_count;
}

/* For compression  */

#define MIN_PRIVATE_COMP_ALGO 0xEF

/* returns the TLS numbers of the compression methods we support
 */
#define SUPPORTED_COMPRESSION_METHODS session->internals.priorities.compression.algorithms
int
_gnutls_supported_compression_methods (gnutls_session_t session,
                                       uint8_t ** comp)
{
  unsigned int i, j;

  *comp = gnutls_malloc (sizeof (uint8_t) * SUPPORTED_COMPRESSION_METHODS);
  if (*comp == NULL)
    return GNUTLS_E_MEMORY_ERROR;

  for (i = j = 0; i < SUPPORTED_COMPRESSION_METHODS; i++)
    {
      int tmp = _gnutls_compression_get_num (session->internals.priorities.
                                             compression.priority[i]);

      /* remove private compression algorithms, if requested.
       */
      if (tmp == -1 || (tmp >= MIN_PRIVATE_COMP_ALGO
                        && session->internals.enable_private == 0))
        {
          gnutls_assert ();
          continue;
        }

      (*comp)[j] = (uint8_t) tmp;
      j++;
    }

  if (j == 0)
    {
      gnutls_assert ();
      gnutls_free (*comp);
      *comp = NULL;
      return GNUTLS_E_NO_COMPRESSION_ALGORITHMS;
    }
  return j;
}

/**
 * gnutls_certificate_type_get_name - Returns a string with the name of the specified certificate type
 * @type: is a certificate type
 *
 * Returns: a string (or %NULL) that contains the name of the
 * specified certificate type.
 **/
const char *
gnutls_certificate_type_get_name (gnutls_certificate_type_t type)
{
  const char *ret = NULL;

  if (type == MHD_GNUTLS_CRT_X509)
    ret = "X.509";
  if (type == MHD_GNUTLS_CRT_OPENPGP)
    ret = "OPENPGP";

  return ret;
}

/**
 * gnutls_certificate_type_get_id - Returns the gnutls id of the specified in string type
 * @name: is a certificate type name
 *
 * The names are compared in a case insensitive way.
 *
 * Returns: an id of the specified in a string certificate type, or
 * %GNUTLS_CRT_UNKNOWN on error.
 **/
gnutls_certificate_type_t
gnutls_certificate_type_get_id (const char *name)
{
  gnutls_certificate_type_t ret = MHD_GNUTLS_CRT_UNKNOWN;

  if (strcasecmp (name, "X.509") == 0 || strcasecmp (name, "X509") == 0)
    return MHD_GNUTLS_CRT_X509;
  if (strcasecmp (name, "OPENPGP") == 0)
    return MHD_GNUTLS_CRT_OPENPGP;

  return ret;
}

static const gnutls_certificate_type_t supported_certificate_types[] =
  { MHD_GNUTLS_CRT_X509,
  MHD_GNUTLS_CRT_OPENPGP,
  0
};

/**
 * gnutls_certificate_type_list:
 *
 * Get a list of certificate types.  Note that to be able to use
 * OpenPGP certificates, you must link to libgnutls-extra and call
 * gnutls_global_init_extra().
 *
 * Returns: a zero-terminated list of %gnutls_certificate_type_t
 * integers indicating the available certificate types.
 *
 **/
const gnutls_certificate_type_t *
gnutls_certificate_type_list (void)
{
  return supported_certificate_types;
}

/* returns the gnutls_pk_algorithm_t which is compatible with
 * the given gnutls_kx_algorithm_t.
 */
gnutls_pk_algorithm_t
_gnutls_map_pk_get_pk (gnutls_kx_algorithm_t kx_algorithm)
{
  gnutls_pk_algorithm_t ret = -1;

  GNUTLS_PK_MAP_ALG_LOOP (ret = p->pk_algorithm) return ret;
}

/* Returns the encipher type for the given key exchange algorithm.
 * That one of CIPHER_ENCRYPT, CIPHER_SIGN, CIPHER_IGN.
 *
 * ex. GNUTLS_KX_RSA requires a certificate able to encrypt... so returns CIPHER_ENCRYPT.
 */
enum encipher_type
_gnutls_kx_encipher_type (gnutls_kx_algorithm_t kx_algorithm)
{
  int ret = CIPHER_IGN;
  GNUTLS_PK_MAP_ALG_LOOP (ret = p->encipher_type) return ret;

}

/* signature algorithms;
 */
struct gnutls_sign_entry
{
  const char *name;
  const char *oid;
  gnutls_sign_algorithm_t id;
  gnutls_pk_algorithm_t pk;
  gnutls_mac_algorithm_t mac;
};
typedef struct gnutls_sign_entry gnutls_sign_entry;

static const gnutls_sign_entry sign_algorithms[] = {
  {"RSA-SHA",
   SIG_RSA_SHA1_OID,
   GNUTLS_SIGN_RSA_SHA1,
   MHD_GNUTLS_PK_RSA,
   MHD_GNUTLS_MAC_SHA1},
  {"RSA-SHA256",
   SIG_RSA_SHA256_OID,
   GNUTLS_SIGN_RSA_SHA256,
   MHD_GNUTLS_PK_RSA,
   MHD_GNUTLS_MAC_SHA256},
  {"RSA-MD5",
   SIG_RSA_MD5_OID,
   GNUTLS_SIGN_RSA_MD5,
   MHD_GNUTLS_PK_RSA,
   MHD_GNUTLS_MAC_MD5},
  {"GOST R 34.10-2001",
   SIG_GOST_R3410_2001_OID,
   0,
   0,
   0},
  {"GOST R 34.10-94",
   SIG_GOST_R3410_94_OID,
   0,
   0,
   0},
  {0,
   0,
   0,
   0,
   0}
};

#define GNUTLS_SIGN_LOOP(b) \
  do {								       \
    const gnutls_sign_entry *p;					       \
    for(p = sign_algorithms; p->name != NULL; p++) { b ; }	       \
  } while (0)

#define GNUTLS_SIGN_ALG_LOOP(a) \
  GNUTLS_SIGN_LOOP( if(p->id && p->id == sign) { a; break; } )

/**
 * gnutls_sign_algorithm_get_name - Returns a string with the name of the specified sign algorithm
 * @algorithm: is a sign algorithm
 *
 * Returns: a string that contains the name of the specified sign
 * algorithm, or %NULL.
 **/
const char *
gnutls_sign_algorithm_get_name (gnutls_sign_algorithm_t sign)
{
  const char *ret = NULL;

  /* avoid prefix */
  GNUTLS_SIGN_ALG_LOOP (ret = p->name);

  return ret;
}

gnutls_sign_algorithm_t
_gnutls_x509_oid2sign_algorithm (const char *oid)
{
  gnutls_sign_algorithm_t ret = 0;

  GNUTLS_SIGN_LOOP (if (strcmp (oid, p->oid) == 0)
                    {
                    ret = p->id; break;}
  );

  if (ret == 0)
    {
      _gnutls_x509_log ("Unknown SIGN OID: '%s'\n", oid);
      return GNUTLS_SIGN_UNKNOWN;
    }
  return ret;
}

gnutls_sign_algorithm_t
_gnutls_x509_pk_to_sign (gnutls_pk_algorithm_t pk, gnutls_mac_algorithm_t mac)
{
  gnutls_sign_algorithm_t ret = 0;

  GNUTLS_SIGN_LOOP (if (pk == p->pk && mac == p->mac)
                    {
                    ret = p->id; break;}
  );

  if (ret == 0)
    return GNUTLS_SIGN_UNKNOWN;
  return ret;
}

const char *
_gnutls_x509_sign_to_oid (gnutls_pk_algorithm_t pk,
                          gnutls_mac_algorithm_t mac)
{
  gnutls_sign_algorithm_t sign;
  const char *ret = NULL;

  sign = _gnutls_x509_pk_to_sign (pk, mac);
  if (sign == GNUTLS_SIGN_UNKNOWN)
    return NULL;

  GNUTLS_SIGN_ALG_LOOP (ret = p->oid);
  return ret;
}

/* pk algorithms;
 */
struct gnutls_pk_entry
{
  const char *name;
  const char *oid;
  gnutls_pk_algorithm_t id;
};
typedef struct gnutls_pk_entry gnutls_pk_entry;

static const gnutls_pk_entry pk_algorithms[] = {
  {"RSA",
   PK_PKIX1_RSA_OID,
   MHD_GNUTLS_PK_RSA},
  {"GOST R 34.10-2001",
   PK_GOST_R3410_2001_OID,
   0},
  {"GOST R 34.10-94",
   PK_GOST_R3410_94_OID,
   0},
  {0,
   0,
   0}
};

/**
 * gnutls_pk_algorithm_get_name - Returns a string with the name of the specified public key algorithm
 * @algorithm: is a pk algorithm
 *
 * Returns: a string that contains the name of the specified public
 * key algorithm, or %NULL.
 **/
const char *
gnutls_pk_algorithm_get_name (gnutls_pk_algorithm_t algorithm)
{
  const char *ret = NULL;
  const gnutls_pk_entry *p;

  for (p = pk_algorithms; p->name != NULL; p++)
    if (p->id && p->id == algorithm)
      {
        ret = p->name;
        break;
      }

  return ret;
}

gnutls_pk_algorithm_t
_gnutls_x509_oid2pk_algorithm (const char *oid)
{
  gnutls_pk_algorithm_t ret = MHD_GNUTLS_PK_UNKNOWN;
  const gnutls_pk_entry *p;

  for (p = pk_algorithms; p->name != NULL; p++)
    if (strcmp (p->oid, oid) == 0)
      {
        ret = p->id;
        break;
      }

  return ret;
}

const char *
_gnutls_x509_pk_to_oid (gnutls_pk_algorithm_t algorithm)
{
  const char *ret = NULL;
  const gnutls_pk_entry *p;

  for (p = pk_algorithms; p->name != NULL; p++)
    if (p->id == algorithm)
      {
        ret = p->oid;
        break;
      }

  return ret;
}
