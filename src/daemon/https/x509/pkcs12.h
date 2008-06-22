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

// TODO clean

#ifndef GNUTLS_PKCS12_H
# define GNUTLS_PKCS12_H

#ifdef __cplusplus
extern "C"
  {
#endif

#include <x509.h>

#define MAX_BAG_ELEMENTS 32

/* PKCS12 structures handling 
 */
struct gnutls_pkcs12_int;

struct gnutls_pkcs12_bag_int;
typedef struct gnutls_pkcs12_int
  {
    ASN1_TYPE pkcs12;
  } gnutls_pkcs12_int;

typedef enum gnutls_pkcs12_bag_type_t
  {
    GNUTLS_BAG_EMPTY = 0,

    GNUTLS_BAG_PKCS8_ENCRYPTED_KEY = 1,
    GNUTLS_BAG_PKCS8_KEY,
    GNUTLS_BAG_CERTIFICATE,
    GNUTLS_BAG_CRL,
    GNUTLS_BAG_ENCRYPTED = 10,
    GNUTLS_BAG_UNKNOWN = 20
  } gnutls_pkcs12_bag_type_t;

struct bag_element
  {
    gnutls_datum_t data;
    gnutls_pkcs12_bag_type_t type;
    gnutls_datum_t local_key_id;
    char *friendly_name;
  };

typedef struct gnutls_pkcs12_bag_int
  {
    struct bag_element element[MAX_BAG_ELEMENTS];
    int bag_elements;
  } gnutls_pkcs12_bag_int;

/* Bag attributes */
#define FRIENDLY_NAME_OID "1.2.840.113549.1.9.20"
#define KEY_ID_OID "1.2.840.113549.1.9.21"

typedef struct gnutls_pkcs12_int *gnutls_pkcs12_t;
typedef struct gnutls_pkcs12_bag_int *gnutls_pkcs12_bag_t;

int gnutls_pkcs12_init(gnutls_pkcs12_t * pkcs12);
void gnutls_pkcs12_deinit(gnutls_pkcs12_t pkcs12);
int gnutls_pkcs12_import(gnutls_pkcs12_t pkcs12,
                         const gnutls_datum_t * data,
                         gnutls_x509_crt_fmt_t format,
                         unsigned int flags);
int gnutls_pkcs12_export(gnutls_pkcs12_t pkcs12,
                         gnutls_x509_crt_fmt_t format,
                         void *output_data,
                         size_t * output_data_size);

int gnutls_pkcs12_get_bag(gnutls_pkcs12_t pkcs12,
                          int indx,
                          gnutls_pkcs12_bag_t bag);
int gnutls_pkcs12_set_bag(gnutls_pkcs12_t pkcs12,
                          gnutls_pkcs12_bag_t bag);

int gnutls_pkcs12_generate_mac(gnutls_pkcs12_t pkcs12,
                               const char *pass);
int gnutls_pkcs12_verify_mac(gnutls_pkcs12_t pkcs12,
                             const char *pass);

int gnutls_pkcs12_bag_decrypt(gnutls_pkcs12_bag_t bag,
                              const char *pass);
int gnutls_pkcs12_bag_encrypt(gnutls_pkcs12_bag_t bag,
                              const char *pass,
                              unsigned int flags);

gnutls_pkcs12_bag_type_t gnutls_pkcs12_bag_get_type(gnutls_pkcs12_bag_t
                                                    bag,
                                                    int indx);
int gnutls_pkcs12_bag_get_data(gnutls_pkcs12_bag_t bag,
                               int indx,
                               gnutls_datum_t * data);
int gnutls_pkcs12_bag_set_data(gnutls_pkcs12_bag_t bag,
                               gnutls_pkcs12_bag_type_t type,
                               const gnutls_datum_t * data);
int gnutls_pkcs12_bag_set_crl(gnutls_pkcs12_bag_t bag,
                              gnutls_x509_crl_t crl);
int gnutls_pkcs12_bag_set_crt(gnutls_pkcs12_bag_t bag,
                              gnutls_x509_crt_t crt);

int gnutls_pkcs12_bag_init(gnutls_pkcs12_bag_t * bag);
void gnutls_pkcs12_bag_deinit(gnutls_pkcs12_bag_t bag);
int gnutls_pkcs12_bag_get_count(gnutls_pkcs12_bag_t bag);

int gnutls_pkcs12_bag_get_key_id(gnutls_pkcs12_bag_t bag,
                                 int indx,
                                 gnutls_datum_t * id);
int gnutls_pkcs12_bag_set_key_id(gnutls_pkcs12_bag_t bag,
                                 int indx,
                                 const gnutls_datum_t * id);

int gnutls_pkcs12_bag_get_friendly_name(gnutls_pkcs12_bag_t bag,
                                        int indx,
                                        char **name);
int gnutls_pkcs12_bag_set_friendly_name(gnutls_pkcs12_bag_t bag,
                                        int indx,
                                        const char *name);

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

int gnutls_pkcs12_init(gnutls_pkcs12_t * pkcs12);
void gnutls_pkcs12_deinit(gnutls_pkcs12_t pkcs12);
int gnutls_pkcs12_import(gnutls_pkcs12_t pkcs12,
                         const gnutls_datum_t * data,
                         gnutls_x509_crt_fmt_t format,
                         unsigned int flags);

int gnutls_pkcs12_get_bag(gnutls_pkcs12_t pkcs12,
                          int indx,
                          gnutls_pkcs12_bag_t bag);

int gnutls_pkcs12_bag_init(gnutls_pkcs12_bag_t * bag);
void gnutls_pkcs12_bag_deinit(gnutls_pkcs12_bag_t bag);

int _pkcs12_string_to_key(unsigned int id,
                          const opaque * salt,
                          unsigned int salt_size,
                          unsigned int iter,
                          const char *pw,
                          unsigned int req_keylen,
                          opaque * keybuf);

int _gnutls_pkcs7_decrypt_data(const gnutls_datum_t * data,
                               const char *password,
                               gnutls_datum_t * dec);

typedef enum schema_id
  {
    PBES2, /* the stuff in PKCS #5 */
    PKCS12_3DES_SHA1, /* the fucking stuff in PKCS #12 */
    PKCS12_ARCFOUR_SHA1,
    PKCS12_RC2_40_SHA1
  } schema_id;

int _gnutls_pkcs7_encrypt_data(schema_id schema,
                               const gnutls_datum_t * data,
                               const char *password,
                               gnutls_datum_t * enc);
int _pkcs12_decode_safe_contents(const gnutls_datum_t * content,
                                 gnutls_pkcs12_bag_t bag);

int _pkcs12_encode_safe_contents(gnutls_pkcs12_bag_t bag,
                                 ASN1_TYPE * content,
                                 int *enc);

int _pkcs12_decode_crt_bag(gnutls_pkcs12_bag_type_t type,
                           const gnutls_datum_t * in,
                           gnutls_datum_t * out);
int _pkcs12_encode_crt_bag(gnutls_pkcs12_bag_type_t type,
                           const gnutls_datum_t * raw,
                           gnutls_datum_t * out);

#endif        /* GNUTLS_PKCS12_H */
