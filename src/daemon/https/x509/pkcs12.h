/*
 * Copyright (C) 2003, 2004, 2005 Free Software Foundation
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

/* TODO clean */
#ifndef GNUTLS_PKCS12_H
#define GNUTLS_PKCS12_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <x509.h>

#define MAX_BAG_ELEMENTS 32

/* PKCS12 structures handling
 */
  struct MHD_gnutls_pkcs12_int;

  struct MHD_gnutls_pkcs12_bag_int;
  typedef struct MHD_gnutls_pkcs12_int
  {
    ASN1_TYPE pkcs12;
  } MHD_gnutls_pkcs12_int;

  typedef enum MHD_gnutls_pkcs12_bag_type_t
  {
    GNUTLS_BAG_EMPTY = 0,

    GNUTLS_BAG_PKCS8_ENCRYPTED_KEY = 1,
    GNUTLS_BAG_PKCS8_KEY,
    GNUTLS_BAG_CERTIFICATE,
    GNUTLS_BAG_CRL,
    GNUTLS_BAG_ENCRYPTED = 10,
    GNUTLS_BAG_UNKNOWN = 20
  } MHD_gnutls_pkcs12_bag_type_t;

  struct bag_element
  {
    MHD_gnutls_datum_t data;
    MHD_gnutls_pkcs12_bag_type_t type;
    MHD_gnutls_datum_t local_key_id;
    char *friendly_name;
  };

  typedef struct MHD_gnutls_pkcs12_bag_int
  {
    struct bag_element element[MAX_BAG_ELEMENTS];
    int bag_elements;
  } MHD_gnutls_pkcs12_bag_int;

/* Bag attributes */
#define FRIENDLY_NAME_OID "1.2.840.113549.1.9.20"
#define KEY_ID_OID "1.2.840.113549.1.9.21"

  typedef struct MHD_gnutls_pkcs12_int *MHD_gnutls_pkcs12_t;
  typedef struct MHD_gnutls_pkcs12_bag_int *MHD_gnutls_pkcs12_bag_t;

  int MHD_gnutls_pkcs12_init (MHD_gnutls_pkcs12_t * pkcs12);
  void MHD_gnutls_pkcs12_deinit (MHD_gnutls_pkcs12_t pkcs12);
  int MHD_gnutls_pkcs12_import (MHD_gnutls_pkcs12_t pkcs12,
                                const MHD_gnutls_datum_t * data,
                                MHD_gnutls_x509_crt_fmt_t format,
                                unsigned int flags);
  int MHD_gnutls_pkcs12_export (MHD_gnutls_pkcs12_t pkcs12,
                                MHD_gnutls_x509_crt_fmt_t format,
                                void *output_data, size_t * output_data_size);

  int MHD_gnutls_pkcs12_bag_decrypt (MHD_gnutls_pkcs12_bag_t bag,
                                     const char *pass);
  int MHD_gnutls_pkcs12_bag_encrypt (MHD_gnutls_pkcs12_bag_t bag,
                                     const char *pass, unsigned int flags);

  int MHD_gnutls_pkcs12_bag_get_data (MHD_gnutls_pkcs12_bag_t bag,
                                      int indx, MHD_gnutls_datum_t * data);
  int MHD_gnutls_pkcs12_bag_set_data (MHD_gnutls_pkcs12_bag_t bag,
                                      MHD_gnutls_pkcs12_bag_type_t type,
                                      const MHD_gnutls_datum_t * data);
  int MHD_gnutls_pkcs12_bag_set_crl (MHD_gnutls_pkcs12_bag_t bag,
                                     MHD_gnutls_x509_crl_t crl);
  int MHD_gnutls_pkcs12_bag_set_crt (MHD_gnutls_pkcs12_bag_t bag,
                                     MHD_gnutls_x509_crt_t crt);

  int MHD_gnutls_pkcs12_bag_get_count (MHD_gnutls_pkcs12_bag_t bag);

  int MHD_gnutls_pkcs12_bag_get_key_id (MHD_gnutls_pkcs12_bag_t bag,
                                        int indx, MHD_gnutls_datum_t * id);
  int MHD_gnutls_pkcs12_bag_set_key_id (MHD_gnutls_pkcs12_bag_t bag,
                                        int indx,
                                        const MHD_gnutls_datum_t * id);

  int MHD_gnutls_pkcs12_bag_get_friendly_name (MHD_gnutls_pkcs12_bag_t bag,
                                               int indx, char **name);
  int MHD_gnutls_pkcs12_bag_set_friendly_name (MHD_gnutls_pkcs12_bag_t bag,
                                               int indx, const char *name);

#ifdef __cplusplus
}
#endif

#define BAG_PKCS8_KEY "1.2.840.113549.1.12.10.1.1"
#define BAG_PKCS8_ENCRYPTED_KEY "1.2.840.113549.1.12.10.1.2"
#define BAG_CERTIFICATE "1.2.840.113549.1.12.10.1.3"
#define BAG_CRL "1.2.840.113549.1.12.10.1.4"

/* PKCS #7
 */
#define DATA_OID "1.2.840.113549.1.7.1"
#define ENC_DATA_OID "1.2.840.113549.1.7.6"

typedef enum schema_id
{
  PBES2,                        /* the stuff in PKCS #5 */
  PKCS12_3DES_SHA1,             /* the stuff in PKCS #12 */
  PKCS12_ARCFOUR_SHA1,
  PKCS12_RC2_40_SHA1
} schema_id;

int MHD_pkcs12_string_to_key (unsigned int id,
                              const opaque * salt,
                              unsigned int salt_size,
                              unsigned int iter,
                              const char *pw,
                              unsigned int req_keylen, opaque * keybuf);

#endif /* GNUTLS_PKCS12_H */
