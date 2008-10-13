/*
 * Copyright (C) 2003, 2004, 2005, 2007 Free Software Foundation
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

#ifndef X509_H
#define X509_H

#define MIN(X,Y) ((X) > (Y) ? (Y) : (X));

#ifdef __cplusplus
extern "C"
{
#endif

#include <gnutls.h>
#include "gnutls_mpi.h"

/* Some OIDs usually found in Distinguished names, or
 * in Subject Directory Attribute extensions.
 */
#define GNUTLS_OID_X520_COUNTRY_NAME    "2.5.4.6"
#define GNUTLS_OID_X520_ORGANIZATION_NAME "2.5.4.10"
#define GNUTLS_OID_X520_ORGANIZATIONAL_UNIT_NAME "2.5.4.11"
#define GNUTLS_OID_X520_COMMON_NAME   "2.5.4.3"
#define GNUTLS_OID_X520_LOCALITY_NAME   "2.5.4.7"
#define GNUTLS_OID_X520_STATE_OR_PROVINCE_NAME  "2.5.4.8"

#define GNUTLS_OID_X520_INITIALS    "2.5.4.43"
#define GNUTLS_OID_X520_GENERATION_QUALIFIER  "2.5.4.44"
#define GNUTLS_OID_X520_SURNAME     "2.5.4.4"
#define GNUTLS_OID_X520_GIVEN_NAME    "2.5.4.42"
#define GNUTLS_OID_X520_TITLE     "2.5.4.12"
#define GNUTLS_OID_X520_DN_QUALIFIER    "2.5.4.46"
#define GNUTLS_OID_X520_PSEUDONYM   "2.5.4.65"

#define GNUTLS_OID_LDAP_DC      "0.9.2342.19200300.100.1.25"
#define GNUTLS_OID_LDAP_UID     "0.9.2342.19200300.100.1.1"

/* The following should not be included in DN.
 */
#define GNUTLS_OID_PKCS9_EMAIL      "1.2.840.113549.1.9.1"

#define GNUTLS_OID_PKIX_DATE_OF_BIRTH   "1.3.6.1.5.5.7.9.1"
#define GNUTLS_OID_PKIX_PLACE_OF_BIRTH    "1.3.6.1.5.5.7.9.2"
#define GNUTLS_OID_PKIX_GENDER      "1.3.6.1.5.5.7.9.3"
#define GNUTLS_OID_PKIX_COUNTRY_OF_CITIZENSHIP  "1.3.6.1.5.5.7.9.4"
#define GNUTLS_OID_PKIX_COUNTRY_OF_RESIDENCE  "1.3.6.1.5.5.7.9.5"

/* Key purpose Object Identifiers.
 */
#define GNUTLS_KP_TLS_WWW_SERVER    "1.3.6.1.5.5.7.3.1"
#define GNUTLS_KP_TLS_WWW_CLIENT                "1.3.6.1.5.5.7.3.2"
#define GNUTLS_KP_CODE_SIGNING      "1.3.6.1.5.5.7.3.3"
#define GNUTLS_KP_EMAIL_PROTECTION    "1.3.6.1.5.5.7.3.4"
#define GNUTLS_KP_TIME_STAMPING     "1.3.6.1.5.5.7.3.8"
#define GNUTLS_KP_OCSP_SIGNING      "1.3.6.1.5.5.7.3.9"
#define GNUTLS_KP_ANY       "2.5.29.37.0"

/* Certificate handling functions.
 */
  typedef enum MHD_gnutls_certificate_import_flags
  {
    /* Fail if the certificates in the buffer are more than the space
     * allocated for certificates. The error code will be
     * GNUTLS_E_SHORT_MEMORY_BUFFER.
     */
    GNUTLS_X509_CRT_LIST_IMPORT_FAIL_IF_EXCEED = 1
  } MHD_gnutls_certificate_import_flags;

  int MHD_gnutls_x509_crt_init (MHD_gnutls_x509_crt_t * cert);
  void MHD_gnutls_x509_crt_deinit (MHD_gnutls_x509_crt_t cert);
  int MHD_gnutls_x509_crt_import (MHD_gnutls_x509_crt_t cert,
                                  const MHD_gnutls_datum_t * data,
                                  MHD_gnutls_x509_crt_fmt_t format);
  int MHD_gnutls_x509_crt_export (MHD_gnutls_x509_crt_t cert,
                                  MHD_gnutls_x509_crt_fmt_t format,
                                  void *output_data,
                                  size_t * output_data_size);
  int MHD_gnutls_x509_crt_check_hostname (MHD_gnutls_x509_crt_t cert,
                                          const char *hostname);

  int MHD_gnutls_x509_crt_get_signature_algorithm (MHD_gnutls_x509_crt_t
                                                   cert);
  int MHD_gnutls_x509_crt_get_signature (MHD_gnutls_x509_crt_t cert,
                                         char *sig, size_t * sizeof_sig);
  int MHD_gnutls_x509_crt_get_version (MHD_gnutls_x509_crt_t cert);

#define GNUTLS_CRL_REASON_UNUSED 128
#define GNUTLS_CRL_REASON_KEY_COMPROMISE 64
#define GNUTLS_CRL_REASON_CA_COMPROMISE 32
#define GNUTLS_CRL_REASON_AFFILIATION_CHANGED 16
#define GNUTLS_CRL_REASON_SUPERSEEDED 8
#define GNUTLS_CRL_REASON_CESSATION_OF_OPERATION 4
#define GNUTLS_CRL_REASON_CERTIFICATE_HOLD 2
#define GNUTLS_CRL_REASON_PRIVILEGE_WITHDRAWN 1
#define GNUTLS_CRL_REASON_AA_COMPROMISE 32768

  time_t MHD_gnutls_x509_crt_get_activation_time (MHD_gnutls_x509_crt_t cert);
  time_t MHD_gnutls_x509_crt_get_expiration_time (MHD_gnutls_x509_crt_t cert);
  int MHD_gnutls_x509_crt_get_serial (MHD_gnutls_x509_crt_t cert,
                                      void *result, size_t * result_size);

  int MHD_gnutls_x509_crt_get_pk_algorithm (MHD_gnutls_x509_crt_t cert,
                                            unsigned int *bits);
  int MHD_gnutls_x509_crt_get_subject_alt_name (MHD_gnutls_x509_crt_t cert,
                                                unsigned int seq,
                                                void *ret,
                                                size_t * ret_size,
                                                unsigned int *critical);
  int MHD_gnutls_x509_crt_get_ca_status (MHD_gnutls_x509_crt_t cert,
                                         unsigned int *critical);
/* The key_usage flags are defined in gnutls.h. They are the
 * GNUTLS_KEY_* definitions.
 */
  int MHD_gnutls_x509_crt_get_key_usage (MHD_gnutls_x509_crt_t cert,
                                         unsigned int *key_usage,
                                         unsigned int *critical);
  int MHD_gnutls_x509_crt_set_key_usage (MHD_gnutls_x509_crt_t crt,
                                         unsigned int usage);

  int MHD_gnutls_x509_dn_oid_known (const char *oid);

/* Read extensions by sequence number. */
  int MHD_gnutls_x509_crt_set_extension_by_oid (MHD_gnutls_x509_crt_t crt,
                                                const char *oid,
                                                const void *buf,
                                                size_t sizeof_buf,
                                                unsigned int critical);

/* X.509 Certificate writing.
 */
  int MHD_gnutls_x509_crt_set_dn_by_oid (MHD_gnutls_x509_crt_t crt,
                                         const char *oid,
                                         unsigned int raw_flag,
                                         const void *name,
                                         unsigned int sizeof_name);
  int MHD_gnutls_x509_crt_set_issuer_dn_by_oid (MHD_gnutls_x509_crt_t crt,
                                                const char *oid,
                                                unsigned int raw_flag,
                                                const void *name,
                                                unsigned int sizeof_name);
  int MHD_gnutls_x509_crt_set_version (MHD_gnutls_x509_crt_t crt,
                                       unsigned int version);
  int MHD_gnutls_x509_crt_set_key (MHD_gnutls_x509_crt_t crt,
                                   MHD_gnutls_x509_privkey_t key);
  int MHD_gnutls_x509_crt_set_ca_status (MHD_gnutls_x509_crt_t crt,
                                         unsigned int ca);
  int MHD_gnutls_x509_crt_set_basic_constraints (MHD_gnutls_x509_crt_t crt,
                                                 unsigned int ca,
                                                 int pathLenConstraint);
  int MHD_gnutls_x509_crt_set_subject_alternative_name (MHD_gnutls_x509_crt_t
                                                        crt,
                                                        MHD_gnutls_x509_subject_alt_name_t
                                                        type,
                                                        const char
                                                        *data_string);
  int MHD_gnutls_x509_crt_sign (MHD_gnutls_x509_crt_t crt,
                                MHD_gnutls_x509_crt_t issuer,
                                MHD_gnutls_x509_privkey_t issuer_key);
  int MHD_gnutls_x509_crt_sign2 (MHD_gnutls_x509_crt_t crt,
                                 MHD_gnutls_x509_crt_t issuer,
                                 MHD_gnutls_x509_privkey_t issuer_key,
                                 enum MHD_GNUTLS_HashAlgorithm,
                                 unsigned int flags);
  int MHD_gnutls_x509_crt_set_activation_time (MHD_gnutls_x509_crt_t cert,
                                               time_t act_time);
  int MHD_gnutls_x509_crt_set_expiration_time (MHD_gnutls_x509_crt_t cert,
                                               time_t exp_time);
  int MHD_gnutls_x509_crt_set_serial (MHD_gnutls_x509_crt_t cert,
                                      const void *serial, size_t serial_size);

  int MHD_gnutls_x509_crt_set_subject_key_id (MHD_gnutls_x509_crt_t cert,
                                              const void *id, size_t id_size);

  int MHD_gnutls_x509_crt_set_proxy_dn (MHD_gnutls_x509_crt_t crt,
                                        MHD_gnutls_x509_crt_t eecrt,
                                        unsigned int raw_flag,
                                        const void *name,
                                        unsigned int sizeof_name);
  int MHD_gnutls_x509_crt_set_proxy (MHD_gnutls_x509_crt_t crt,
                                     int pathLenConstraint,
                                     const char *policyLanguage,
                                     const char *policy,
                                     size_t sizeof_policy);

  typedef enum MHD_gnutls_certificate_print_formats
  {
    GNUTLS_X509_CRT_FULL,
    GNUTLS_X509_CRT_ONELINE,
    GNUTLS_X509_CRT_UNSIGNED_FULL
  } MHD_gnutls_certificate_print_formats_t;

  int MHD_gnutls_x509_crt_print (MHD_gnutls_x509_crt_t cert,
                                 MHD_gnutls_certificate_print_formats_t
                                 format, MHD_gnutls_datum_t * out);
  int MHD_gnutls_x509_crl_print (MHD_gnutls_x509_crl_t crl,
                                 MHD_gnutls_certificate_print_formats_t
                                 format, MHD_gnutls_datum_t * out);

/* Access to internal Certificate fields.
 */
  int MHD_gnutls_x509_crt_get_raw_issuer_dn (MHD_gnutls_x509_crt_t cert,
                                             MHD_gnutls_datum_t * start);
  int MHD_gnutls_x509_crt_get_raw_dn (MHD_gnutls_x509_crt_t cert,
                                      MHD_gnutls_datum_t * start);

/* RDN handling.
 */
  int MHD_gnutls_x509_rdn_get (const MHD_gnutls_datum_t * idn,
                               char *buf, size_t * sizeof_buf);
  int MHD_gnutls_x509_rdn_get_oid (const MHD_gnutls_datum_t * idn,
                                   int indx, void *buf, size_t * sizeof_buf);

  int MHD_gnutls_x509_rdn_get_by_oid (const MHD_gnutls_datum_t * idn,
                                      const char *oid,
                                      int indx,
                                      unsigned int raw_flag,
                                      void *buf, size_t * sizeof_buf);

  typedef void *MHD_gnutls_x509_dn_t;

  typedef struct MHD_gnutls_x509_ava_st
  {
    MHD_gnutls_datum_t oid;
    MHD_gnutls_datum_t value;
    unsigned long value_tag;
  } MHD_gnutls_x509_ava_st;

  int MHD_gnutls_x509_crt_get_subject (MHD_gnutls_x509_crt_t cert,
                                       MHD_gnutls_x509_dn_t * dn);
/* CRL handling functions.
 */
  int MHD_gnutls_x509_crl_init (MHD_gnutls_x509_crl_t * crl);
  void MHD_gnutls_x509_crl_deinit (MHD_gnutls_x509_crl_t crl);

  int MHD_gnutls_x509_crl_import (MHD_gnutls_x509_crl_t crl,
                                  const MHD_gnutls_datum_t * data,
                                  MHD_gnutls_x509_crt_fmt_t format);
  int MHD_gnutls_x509_crl_export (MHD_gnutls_x509_crl_t crl,
                                  MHD_gnutls_x509_crt_fmt_t format,
                                  void *output_data,
                                  size_t * output_data_size);

  int MHD_gnutls_x509_crl_get_issuer_dn_by_oid (MHD_gnutls_x509_crl_t crl,
                                                const char *oid,
                                                int indx,
                                                unsigned int raw_flag,
                                                void *buf,
                                                size_t * sizeof_buf);
  int MHD_gnutls_x509_crl_get_dn_oid (MHD_gnutls_x509_crl_t crl, int indx,
                                      void *oid, size_t * sizeof_oid);

  int MHD_gnutls_x509_crl_get_signature_algorithm (MHD_gnutls_x509_crl_t crl);
  int MHD_gnutls_x509_crl_get_signature (MHD_gnutls_x509_crl_t crl,
                                         char *sig, size_t * sizeof_sig);
  int MHD_gnutls_x509_crl_get_version (MHD_gnutls_x509_crl_t crl);

  time_t MHD_gnutls_x509_crl_get_this_update (MHD_gnutls_x509_crl_t crl);
  time_t MHD_gnutls_x509_crl_get_next_update (MHD_gnutls_x509_crl_t crl);

  int MHD_gnutls_x509_crl_get_crt_count (MHD_gnutls_x509_crl_t crl);
  int MHD_gnutls_x509_crl_get_crt_serial (MHD_gnutls_x509_crl_t crl,
                                          int indx,
                                          unsigned char *serial,
                                          size_t * serial_size, time_t * t);
#define MHD_gnutls_x509_crl_get_certificate_count MHD_gnutls_x509_crl_get_crt_count
#define MHD_gnutls_x509_crl_get_certificate MHD_gnutls_x509_crl_get_crt_serial

  int MHD_gnutls_x509_crl_check_issuer (MHD_gnutls_x509_crl_t crl,
                                        MHD_gnutls_x509_crt_t issuer);

/* CRL writing.
 */
  int MHD_gnutls_x509_crl_set_version (MHD_gnutls_x509_crl_t crl,
                                       unsigned int version);
  int MHD_gnutls_x509_crl_sign (MHD_gnutls_x509_crl_t crl,
                                MHD_gnutls_x509_crt_t issuer,
                                MHD_gnutls_x509_privkey_t issuer_key);
  int MHD_gnutls_x509_crl_sign2 (MHD_gnutls_x509_crl_t crl,
                                 MHD_gnutls_x509_crt_t issuer,
                                 MHD_gnutls_x509_privkey_t issuer_key,
                                 enum MHD_GNUTLS_HashAlgorithm,
                                 unsigned int flags);
  int MHD_gnutls_x509_crl_set_this_update (MHD_gnutls_x509_crl_t crl,
                                           time_t act_time);
  int MHD_gnutls_x509_crl_set_next_update (MHD_gnutls_x509_crl_t crl,
                                           time_t exp_time);
  int MHD_gnutls_x509_crl_set_crt_serial (MHD_gnutls_x509_crl_t crl,
                                          const void *serial,
                                          size_t serial_size,
                                          time_t revocation_time);
  int MHD_gnutls_x509_crl_set_crt (MHD_gnutls_x509_crl_t crl,
                                   MHD_gnutls_x509_crt_t crt,
                                   time_t revocation_time);

/* PKCS7 structures handling
 */
  struct MHD_gnutls_pkcs7_int;
  typedef struct MHD_gnutls_pkcs7_int *MHD_gnutls_pkcs7_t;

  int MHD_gnutls_pkcs7_init (MHD_gnutls_pkcs7_t * pkcs7);
  void MHD_gnutls_pkcs7_deinit (MHD_gnutls_pkcs7_t pkcs7);
  int MHD_gnutls_pkcs7_import (MHD_gnutls_pkcs7_t pkcs7,
                               const MHD_gnutls_datum_t * data,
                               MHD_gnutls_x509_crt_fmt_t format);
  int MHD_gnutls_pkcs7_export (MHD_gnutls_pkcs7_t pkcs7,
                               MHD_gnutls_x509_crt_fmt_t format,
                               void *output_data, size_t * output_data_size);

  int MHD_gnutls_pkcs7_get_crt_count (MHD_gnutls_pkcs7_t pkcs7);
  int MHD_gnutls_pkcs7_get_crt_raw (MHD_gnutls_pkcs7_t pkcs7,
                                    int indx,
                                    void *certificate,
                                    size_t * certificate_size);

  int MHD_gnutls_pkcs7_set_crt_raw (MHD_gnutls_pkcs7_t pkcs7,
                                    const MHD_gnutls_datum_t * crt);
  int MHD_gnutls_pkcs7_set_crt (MHD_gnutls_pkcs7_t pkcs7,
                                MHD_gnutls_x509_crt_t crt);
  int MHD_gnutls_pkcs7_delete_crt (MHD_gnutls_pkcs7_t pkcs7, int indx);

  int MHD_gnutls_pkcs7_get_crl_raw (MHD_gnutls_pkcs7_t pkcs7,
                                    int indx, void *crl, size_t * crl_size);
  int MHD_gnutls_pkcs7_get_crl_count (MHD_gnutls_pkcs7_t pkcs7);

  int MHD_gnutls_pkcs7_set_crl_raw (MHD_gnutls_pkcs7_t pkcs7,
                                    const MHD_gnutls_datum_t * crt);
  int MHD_gnutls_pkcs7_set_crl (MHD_gnutls_pkcs7_t pkcs7,
                                MHD_gnutls_x509_crl_t crl);
  int MHD_gnutls_pkcs7_delete_crl (MHD_gnutls_pkcs7_t pkcs7, int indx);

/* X.509 Certificate verification functions.
 */
  typedef enum MHD_gnutls_certificate_verify_flags
  {
    /* If set a signer does not have to be a certificate authority. This
     * flag should normaly be disabled, unless you know what this means.
     */
    GNUTLS_VERIFY_DISABLE_CA_SIGN = 1,

    /* Allow only trusted CA certificates that have version 1.  This is
     * safer than GNUTLS_VERIFY_ALLOW_ANY_X509_V1_CA_CRT, and should be
     * used instead. That way only signers in your trusted list will be
     * allowed to have certificates of version 1.
     */
    GNUTLS_VERIFY_ALLOW_X509_V1_CA_CRT = 2,

    /* If a certificate is not signed by anyone trusted but exists in
     * the trusted CA list do not treat it as trusted.
     */
    GNUTLS_VERIFY_DO_NOT_ALLOW_SAME = 4,

    /* Allow CA certificates that have version 1 (both root and
     * intermediate). This might be dangerous since those haven't the
     * basicConstraints extension. Must be used in combination with
     * GNUTLS_VERIFY_ALLOW_X509_V1_CA_CRT.
     */
    GNUTLS_VERIFY_ALLOW_ANY_X509_V1_CA_CRT = 8,

    /* Allow certificates to be signed using the broken MD2 algorithm.
     */
    GNUTLS_VERIFY_ALLOW_SIGN_RSA_MD2 = 16,

    /* Allow certificates to be signed using the broken MD5 algorithm.
     */
    GNUTLS_VERIFY_ALLOW_SIGN_RSA_MD5 = 32
  } MHD_gnutls_certificate_verify_flags;

  int MHD_gnutls_x509_crt_check_issuer (MHD_gnutls_x509_crt_t cert,
                                        MHD_gnutls_x509_crt_t issuer);

  int MHD_gnutls_x509_crt_list_verify (const MHD_gnutls_x509_crt_t *
                                       cert_list, int cert_list_length,
                                       const MHD_gnutls_x509_crt_t * CA_list,
                                       int CA_list_length,
                                       const MHD_gnutls_x509_crl_t * CRL_list,
                                       int CRL_list_length,
                                       unsigned int flags,
                                       unsigned int *verify);

  int MHD_gnutls_x509_crt_verify (MHD_gnutls_x509_crt_t cert,
                                  const MHD_gnutls_x509_crt_t * CA_list,
                                  int CA_list_length,
                                  unsigned int flags, unsigned int *verify);
  int MHD_gnutls_x509_crl_verify (MHD_gnutls_x509_crl_t crl,
                                  const MHD_gnutls_x509_crt_t * CA_list,
                                  int CA_list_length,
                                  unsigned int flags, unsigned int *verify);

  int MHD_gnutls_x509_crt_check_revocation (MHD_gnutls_x509_crt_t cert,
                                            const MHD_gnutls_x509_crl_t *
                                            crl_list, int crl_list_length);


/* Flags for the MHD_gnutls_x509_privkey_export_pkcs8() function.
 */
  typedef enum MHD_gnutls_pkcs_encrypt_flags_t
  {
    GNUTLS_PKCS_PLAIN = 1,      /* if set the private key will not
                                 * be encrypted.
                                 */
    GNUTLS_PKCS_USE_PKCS12_3DES = 2,
    GNUTLS_PKCS_USE_PKCS12_ARCFOUR = 4,
    GNUTLS_PKCS_USE_PKCS12_RC2_40 = 8,
    GNUTLS_PKCS_USE_PBES2_3DES = 16
  } MHD_gnutls_pkcs_encrypt_flags_t;

#define GNUTLS_PKCS8_PLAIN GNUTLS_PKCS_PLAIN
#define GNUTLS_PKCS8_USE_PKCS12_3DES GNUTLS_PKCS_USE_PKCS12_3DES
#define GNUTLS_PKCS8_USE_PKCS12_ARCFOUR GNUTLS_PKCS_USE_PKCS12_ARCFOUR
#define GNUTLS_PKCS8_USE_PKCS12_RC2_40 GNUTLS_PKCS_USE_PKCS12_RC2_40

  int MHD_gnutls_x509_privkey_init (MHD_gnutls_x509_privkey_t * key);
  void MHD_gnutls_x509_privkey_deinit (MHD_gnutls_x509_privkey_t key);
  int MHD_gnutls_x509_privkey_cpy (MHD_gnutls_x509_privkey_t dst,
                                   MHD_gnutls_x509_privkey_t src);
  int MHD_gnutls_x509_privkey_import (MHD_gnutls_x509_privkey_t key,
                                      const MHD_gnutls_datum_t * data,
                                      MHD_gnutls_x509_crt_fmt_t format);
  int MHD_gnutls_x509_privkey_import_pkcs8 (MHD_gnutls_x509_privkey_t key,
                                            const MHD_gnutls_datum_t * data,
                                            MHD_gnutls_x509_crt_fmt_t format,
                                            const char *pass,
                                            unsigned int flags);
  int MHD_gnutls_x509_privkey_import_rsa_raw (MHD_gnutls_x509_privkey_t key,
                                              const MHD_gnutls_datum_t * m,
                                              const MHD_gnutls_datum_t * e,
                                              const MHD_gnutls_datum_t * d,
                                              const MHD_gnutls_datum_t * p,
                                              const MHD_gnutls_datum_t * q,
                                              const MHD_gnutls_datum_t * u);
  int MHD_gnutls_x509_privkey_export_dsa_raw (MHD_gnutls_x509_privkey_t key,
                                              MHD_gnutls_datum_t * p,
                                              MHD_gnutls_datum_t * q,
                                              MHD_gnutls_datum_t * g,
                                              MHD_gnutls_datum_t * y,
                                              MHD_gnutls_datum_t * x);
  int MHD_gnutls_x509_privkey_import_dsa_raw (MHD_gnutls_x509_privkey_t key,
                                              const MHD_gnutls_datum_t * p,
                                              const MHD_gnutls_datum_t * q,
                                              const MHD_gnutls_datum_t * g,
                                              const MHD_gnutls_datum_t * y,
                                              const MHD_gnutls_datum_t * x);

  int MHD_gnutls_x509_privkey_get_pk_algorithm (MHD_gnutls_x509_privkey_t
                                                key);
  int MHD_gnutls_x509_privkey_get_key_id (MHD_gnutls_x509_privkey_t key,
                                          unsigned int flags,
                                          unsigned char *output_data,
                                          size_t * output_data_size);

  int MHD_gnutls_x509_privkey_export (MHD_gnutls_x509_privkey_t key,
                                      MHD_gnutls_x509_crt_fmt_t format,
                                      void *output_data,
                                      size_t * output_data_size);
  int MHD_gnutls_x509_privkey_export_pkcs8 (MHD_gnutls_x509_privkey_t key,
                                            MHD_gnutls_x509_crt_fmt_t format,
                                            const char *password,
                                            unsigned int flags,
                                            void *output_data,
                                            size_t * output_data_size);
  int MHD_gnutls_x509_privkey_export_rsa_raw (MHD_gnutls_x509_privkey_t key,
                                              MHD_gnutls_datum_t * m,
                                              MHD_gnutls_datum_t * e,
                                              MHD_gnutls_datum_t * d,
                                              MHD_gnutls_datum_t * p,
                                              MHD_gnutls_datum_t * q,
                                              MHD_gnutls_datum_t * u);

  int MHD_gnutls_x509_privkey_verify_data (MHD_gnutls_x509_privkey_t key,
                                           unsigned int flags,
                                           const MHD_gnutls_datum_t * data,
                                           const MHD_gnutls_datum_t *
                                           signature);

/* Certificate request stuff.
 */
  struct MHD_gnutls_x509_crq_int;
  typedef struct MHD_gnutls_x509_crq_int *MHD_gnutls_x509_crq_t;

  int MHD_gnutls_x509_crq_init (MHD_gnutls_x509_crq_t * crq);
  void MHD_gnutls_x509_crq_deinit (MHD_gnutls_x509_crq_t crq);
  int MHD_gnutls_x509_crq_import (MHD_gnutls_x509_crq_t crq,
                                  const MHD_gnutls_datum_t * data,
                                  MHD_gnutls_x509_crt_fmt_t format);
  int MHD_gnutls_x509_crq_get_pk_algorithm (MHD_gnutls_x509_crq_t crq,
                                            unsigned int *bits);
  int MHD_gnutls_x509_crq_get_dn (MHD_gnutls_x509_crq_t crq,
                                  char *buf, size_t * sizeof_buf);
  int MHD_gnutls_x509_crq_get_dn_oid (MHD_gnutls_x509_crq_t crq,
                                      int indx, void *oid,
                                      size_t * sizeof_oid);
  int MHD_gnutls_x509_crq_get_dn_by_oid (MHD_gnutls_x509_crq_t crq,
                                         const char *oid, int indx,
                                         unsigned int raw_flag, void *buf,
                                         size_t * sizeof_buf);
  int MHD_gnutls_x509_crq_set_dn_by_oid (MHD_gnutls_x509_crq_t crq,
                                         const char *oid,
                                         unsigned int raw_flag,
                                         const void *name,
                                         unsigned int sizeof_name);
  int MHD_gnutls_x509_crq_set_version (MHD_gnutls_x509_crq_t crq,
                                       unsigned int version);
  int MHD_gnutls_x509_crq_set_key (MHD_gnutls_x509_crq_t crq,
                                   MHD_gnutls_x509_privkey_t key);
  int MHD_gnutls_x509_crq_sign2 (MHD_gnutls_x509_crq_t crq,
                                 MHD_gnutls_x509_privkey_t key,
                                 enum MHD_GNUTLS_HashAlgorithm,
                                 unsigned int flags);
  int MHD_gnutls_x509_crq_sign (MHD_gnutls_x509_crq_t crq,
                                MHD_gnutls_x509_privkey_t key);

  int MHD_gnutls_x509_crq_set_challenge_password (MHD_gnutls_x509_crq_t crq,
                                                  const char *pass);
  int MHD_gnutls_x509_crq_get_challenge_password (MHD_gnutls_x509_crq_t crq,
                                                  char *pass,
                                                  size_t * sizeof_pass);

  int MHD_gnutls_x509_crq_set_attribute_by_oid (MHD_gnutls_x509_crq_t crq,
                                                const char *oid,
                                                void *buf, size_t sizeof_buf);
  int MHD_gnutls_x509_crq_get_attribute_by_oid (MHD_gnutls_x509_crq_t crq,
                                                const char *oid,
                                                int indx,
                                                void *buf,
                                                size_t * sizeof_buf);

  int MHD_gnutls_x509_crq_export (MHD_gnutls_x509_crq_t crq,
                                  MHD_gnutls_x509_crt_fmt_t format,
                                  void *output_data,
                                  size_t * output_data_size);

  int MHD_gnutls_x509_crt_set_crq (MHD_gnutls_x509_crt_t crt,
                                   MHD_gnutls_x509_crq_t crq);

#ifdef __cplusplus
}
#endif

#define HASH_OID_SHA1 "1.3.14.3.2.26"
#define HASH_OID_MD5 "1.2.840.113549.2.5"
#define HASH_OID_MD2 "1.2.840.113549.2.2"
#define HASH_OID_RMD160 "1.3.36.3.2.1"
#define HASH_OID_SHA256 "2.16.840.1.101.3.4.2.1"
#define HASH_OID_SHA384 "2.16.840.1.101.3.4.2.2"
#define HASH_OID_SHA512 "2.16.840.1.101.3.4.2.3"

typedef struct MHD_gnutls_x509_crl_int
{
  ASN1_TYPE crl;
} MHD_gnutls_x509_crl_int;

typedef struct MHD_gnutls_x509_crt_int
{
  ASN1_TYPE cert;
  int use_extensions;
} MHD_gnutls_x509_crt_int;

#define MAX_PRIV_PARAMS_SIZE 6  /* ok for RSA and DSA */

/* parameters should not be larger than this limit */
#define DSA_PRIVATE_PARAMS 5
#define DSA_PUBLIC_PARAMS 4
#define RSA_PRIVATE_PARAMS 6
#define RSA_PUBLIC_PARAMS 2

#if MAX_PRIV_PARAMS_SIZE - RSA_PRIVATE_PARAMS < 0
# error INCREASE MAX_PRIV_PARAMS
#endif

#if MAX_PRIV_PARAMS_SIZE - DSA_PRIVATE_PARAMS < 0
# error INCREASE MAX_PRIV_PARAMS
#endif

typedef struct MHD_gtls_x509_privkey_int
{
  mpi_t params[MAX_PRIV_PARAMS_SIZE];   /* the size of params depends on the public
                                         * key algorithm
                                         */
  /*
   * RSA: [0] is modulus
   *      [1] is public exponent
   *      [2] is private exponent
   *      [3] is prime1 (p)
   *      [4] is prime2 (q)
   *      [5] is coefficient (u == inverse of p mod q)
   *          note that other packages used inverse of q mod p,
   *          so we need to perform conversions.
   * DSA: [0] is p
   *      [1] is q
   *      [2] is g
   *      [3] is y (public key)
   *      [4] is x (private key)
   */
  int params_size;              /* holds the number of params */

  enum MHD_GNUTLS_PublicKeyAlgorithm pk_algorithm;

  int crippled;                 /* The crippled keys will not use the ASN1_TYPE key.
                                 * The encoding will only be performed at the export
                                 * phase, to optimize copying etc. Cannot be used with
                                 * the exported API (used internally only).
                                 */
  ASN1_TYPE key;
} MHD_gnutls_x509_privkey_int;

int MHD_gnutls_x509_crt_get_issuer_dn_by_oid (MHD_gnutls_x509_crt_t cert,
                                              const char *oid,
                                              int indx,
                                              unsigned int raw_flag,
                                              void *buf, size_t * sizeof_buf);
int MHD_gnutls_x509_crt_get_subject_alt_name (MHD_gnutls_x509_crt_t cert,
                                              unsigned int seq,
                                              void *ret,
                                              size_t * ret_size,
                                              unsigned int *critical);
int MHD_gnutls_x509_crt_get_dn_by_oid (MHD_gnutls_x509_crt_t cert,
                                       const char *oid,
                                       int indx,
                                       unsigned int raw_flag,
                                       void *buf, size_t * sizeof_buf);
int MHD_gnutls_x509_crt_get_ca_status (MHD_gnutls_x509_crt_t cert,
                                       unsigned int *critical);
int MHD_gnutls_x509_crt_get_pk_algorithm (MHD_gnutls_x509_crt_t cert,
                                          unsigned int *bits);

int MHD_gnutls_x509_crt_get_serial (MHD_gnutls_x509_crt_t cert,
                                    void *result, size_t * result_size);

int MHD__gnutls_x509_compare_raw_dn (const MHD_gnutls_datum_t * dn1,
                                     const MHD_gnutls_datum_t * dn2);

int MHD_gnutls_x509_crt_check_revocation (MHD_gnutls_x509_crt_t cert,
                                          const MHD_gnutls_x509_crl_t *
                                          crl_list, int crl_list_length);

int MHD__gnutls_x509_crl_cpy (MHD_gnutls_x509_crl_t dest,
                              MHD_gnutls_x509_crl_t src);
int MHD__gnutls_x509_crl_get_raw_issuer_dn (MHD_gnutls_x509_crl_t crl,
                                            MHD_gnutls_datum_t * dn);
int MHD_gnutls_x509_crl_get_crt_count (MHD_gnutls_x509_crl_t crl);
int MHD_gnutls_x509_crl_get_crt_serial (MHD_gnutls_x509_crl_t crl,
                                        int indx,
                                        unsigned char *serial,
                                        size_t * serial_size, time_t * t);

void MHD_gnutls_x509_crl_deinit (MHD_gnutls_x509_crl_t crl);
int MHD_gnutls_x509_crl_init (MHD_gnutls_x509_crl_t * crl);
int MHD_gnutls_x509_crl_import (MHD_gnutls_x509_crl_t crl,
                                const MHD_gnutls_datum_t * data,
                                MHD_gnutls_x509_crt_fmt_t format);
int MHD_gnutls_x509_crl_export (MHD_gnutls_x509_crl_t crl,
                                MHD_gnutls_x509_crt_fmt_t format,
                                void *output_data, size_t * output_data_size);

int MHD_gnutls_x509_crt_init (MHD_gnutls_x509_crt_t * cert);
void MHD_gnutls_x509_crt_deinit (MHD_gnutls_x509_crt_t cert);
int MHD_gnutls_x509_crt_import (MHD_gnutls_x509_crt_t cert,
                                const MHD_gnutls_datum_t * data,
                                MHD_gnutls_x509_crt_fmt_t format);
int MHD_gnutls_x509_crt_export (MHD_gnutls_x509_crt_t cert,
                                MHD_gnutls_x509_crt_fmt_t format,
                                void *output_data, size_t * output_data_size);

int MHD_gnutls_x509_crt_get_key_usage (MHD_gnutls_x509_crt_t cert,
                                       unsigned int *key_usage,
                                       unsigned int *critical);
int MHD_gnutls_x509_crt_get_signature_algorithm (MHD_gnutls_x509_crt_t cert);
int MHD_gnutls_x509_crt_get_version (MHD_gnutls_x509_crt_t cert);

int MHD_gnutls_x509_privkey_init (MHD_gnutls_x509_privkey_t * key);
void MHD_gnutls_x509_privkey_deinit (MHD_gnutls_x509_privkey_t key);

int MHD_gnutls_x509_privkey_generate (MHD_gnutls_x509_privkey_t key,
                                      enum MHD_GNUTLS_PublicKeyAlgorithm algo,
                                      unsigned int bits, unsigned int flags);

int MHD_gnutls_x509_privkey_import (MHD_gnutls_x509_privkey_t key,
                                    const MHD_gnutls_datum_t * data,
                                    MHD_gnutls_x509_crt_fmt_t format);
int MHD_gnutls_x509_privkey_get_pk_algorithm (MHD_gnutls_x509_privkey_t key);
int MHD_gnutls_x509_privkey_import_rsa_raw (MHD_gnutls_x509_privkey_t key,
                                            const MHD_gnutls_datum_t * m,
                                            const MHD_gnutls_datum_t * e,
                                            const MHD_gnutls_datum_t * d,
                                            const MHD_gnutls_datum_t * p,
                                            const MHD_gnutls_datum_t * q,
                                            const MHD_gnutls_datum_t * u);
int MHD_gnutls_x509_privkey_export_rsa_raw (MHD_gnutls_x509_privkey_t key,
                                            MHD_gnutls_datum_t * m,
                                            MHD_gnutls_datum_t * e,
                                            MHD_gnutls_datum_t * d,
                                            MHD_gnutls_datum_t * p,
                                            MHD_gnutls_datum_t * q,
                                            MHD_gnutls_datum_t * u);
int MHD_gnutls_x509_privkey_export (MHD_gnutls_x509_privkey_t key,
                                    MHD_gnutls_x509_crt_fmt_t format,
                                    void *output_data,
                                    size_t * output_data_size);

#define GNUTLS_CRL_REASON_UNUSED 128
#define GNUTLS_CRL_REASON_KEY_COMPROMISE 64
#define GNUTLS_CRL_REASON_CA_COMPROMISE 32
#define GNUTLS_CRL_REASON_AFFILIATION_CHANGED 16
#define GNUTLS_CRL_REASON_SUPERSEEDED 8
#define GNUTLS_CRL_REASON_CESSATION_OF_OPERATION 4
#define GNUTLS_CRL_REASON_CERTIFICATE_HOLD 2
#define GNUTLS_CRL_REASON_PRIVILEGE_WITHDRAWN 1
#define GNUTLS_CRL_REASON_AA_COMPROMISE 32768

#endif
