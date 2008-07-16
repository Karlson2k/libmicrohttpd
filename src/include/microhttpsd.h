/*
     This file is part of libmicrohttpd
     (C) 2006, 2007, 2008 Christian Grothoff (and other contributing authors)

     This library is free software; you can redistribute it and/or
     modify it under the terms of the GNU Lesser General Public
     License as published by the Free Software Foundation; either
     version 2.1 of the License, or (at your option) any later version.

     This library is distributed in the hope that it will be useful,
     but WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Lesser General Public License for more details.

     You should have received a copy of the GNU Lesser General Public
     License along with this library; if not, write to the Free Software
     Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

/**
 * @file microhttpsd.h
 * @brief public interface to libmicrohttpd
 * @author Sagie Amir
 *
 */

#ifndef MHD_MICROHTTPSD_H
#define MHD_MICROHTTPSD_H

#include "microhttpd.h"

typedef enum gnutls_cipher_algorithm
{
  GNUTLS_CIPHER_UNKNOWN = 0,
  GNUTLS_CIPHER_NULL = 1,
  GNUTLS_CIPHER_ARCFOUR_128,
  GNUTLS_CIPHER_3DES_CBC,
  GNUTLS_CIPHER_AES_128_CBC,
  GNUTLS_CIPHER_AES_256_CBC,
  GNUTLS_CIPHER_ARCFOUR_40,
  GNUTLS_CIPHER_CAMELLIA_128_CBC,
  GNUTLS_CIPHER_CAMELLIA_256_CBC,
  GNUTLS_CIPHER_RC2_40_CBC = 90,
  GNUTLS_CIPHER_DES_CBC
} gnutls_cipher_algorithm_t;

typedef enum
{
  GNUTLS_KX_UNKNOWN = 0,
  GNUTLS_KX_RSA = 1,
  GNUTLS_KX_DHE_DSS,
  GNUTLS_KX_DHE_RSA,
  GNUTLS_KX_ANON_DH,
  GNUTLS_KX_SRP,
  GNUTLS_KX_RSA_EXPORT,
  GNUTLS_KX_SRP_RSA,
  GNUTLS_KX_SRP_DSS,
} gnutls_kx_algorithm_t;

typedef enum
{
  GNUTLS_CRD_CERTIFICATE = 1,
  GNUTLS_CRD_ANON,
  GNUTLS_CRD_SRP,
  GNUTLS_CRD_PSK,
  GNUTLS_CRD_IA
} gnutls_credentials_type_t;

typedef enum
{
  GNUTLS_MAC_UNKNOWN = 0,
  GNUTLS_MAC_NULL = 1,
  GNUTLS_MAC_MD5,
  GNUTLS_MAC_SHA1,
  GNUTLS_MAC_SHA256,
  //GNUTLS_MAC_SHA384,
  //GNUTLS_MAC_SHA512
} gnutls_mac_algorithm_t;

  /* The enumerations here should have the same value with
     gnutls_mac_algorithm_t.
   */
typedef enum
{
  GNUTLS_DIG_NULL = GNUTLS_MAC_NULL,
  GNUTLS_DIG_MD5 = GNUTLS_MAC_MD5,
  GNUTLS_DIG_SHA1 = GNUTLS_MAC_SHA1,
  GNUTLS_DIG_SHA256 = GNUTLS_MAC_SHA256,
} gnutls_digest_algorithm_t;


typedef enum
{
  GNUTLS_COMP_UNKNOWN = 0,
  GNUTLS_COMP_NULL = 1,
  GNUTLS_COMP_DEFLATE,
  GNUTLS_COMP_LZO               /* only available if gnutls-extra has
                                   been initialized
                                 */
} gnutls_compression_method_t;

#define GNUTLS_TLS1 GNUTLS_TLS1_0
typedef enum
{
  GNUTLS_SSL3 = 1,
  GNUTLS_TLS1_0,
  GNUTLS_TLS1_1,
  GNUTLS_TLS1_2,
  GNUTLS_VERSION_UNKNOWN = 0xff
} gnutls_protocol_t;

typedef enum
{
  GNUTLS_CRT_UNKNOWN = 0,
  GNUTLS_CRT_X509 = 1,
  GNUTLS_CRT_OPENPGP
} gnutls_certificate_type_t;

typedef enum
{
  GNUTLS_PK_UNKNOWN = 0,
  GNUTLS_PK_RSA = 1,
  //GNUTLS_PK_DSA
} gnutls_pk_algorithm_t;

union MHD_SessionInfo
{
  gnutls_cipher_algorithm_t cipher_algorithm;
  gnutls_kx_algorithm_t kx_algorithm;
  gnutls_credentials_type_t credentials_type;
  gnutls_mac_algorithm_t mac_algorithm;
  gnutls_compression_method_t compression_method;
  gnutls_protocol_t protocol;
  gnutls_certificate_type_t certificate_type;
  gnutls_pk_algorithm_t pk_algorithm;
};

enum MHD_InfoType
{
  MHS_INFO_CIPHER_ALGO,
  MHD_INFO_KX_ALGO,
  MHD_INFO_CREDENTIALS_TYPE,
  MHD_INFO_MAC_ALGO,
  MHD_INFO_COMPRESSION_METHOD,
  MHD_INFO_PROTOCOL,
  MHD_INFO_CERT_TYPE,
};

union MHD_SessionInfo MHD_get_session_info (struct MHD_Connection *con,
                                            enum MHD_InfoType infoType);

//TODO impl
size_t MHDS_get_key_size (struct MHD_Daemon *daemon,
                          gnutls_cipher_algorithm_t algorithm);
size_t MHDS_get_mac_key_size (struct MHD_Daemon *daemon,
                              gnutls_mac_algorithm_t algorithm);

#endif
