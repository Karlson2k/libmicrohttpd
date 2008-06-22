#ifndef OPENPGP_H
#define OPENPGP_H

#include "config.h"

#ifdef ENABLE_OPENPGP

#ifdef __cplusplus
extern "C"
  {
#endif

#include <gnutls.h>
#include <gnutls_cert.h>
#include "opencdk.h"

/* Internal context to store the OpenPGP key. */
typedef struct gnutls_openpgp_crt_int
  {
    cdk_kbnode_t knode;
  } gnutls_openpgp_crt_int;

/* Internal context to store the private OpenPGP key. */
typedef struct gnutls_openpgp_privkey_int
  {
    gnutls_privkey pkey;
  } gnutls_openpgp_privkey_int;

typedef struct gnutls_openpgp_keyring_int
  {
    cdk_keydb_hd_t db;
    cdk_stream_t db_stream;
  } gnutls_openpgp_keyring_int;

typedef struct gnutls_openpgp_keyring_int * gnutls_openpgp_keyring_t;
/* gnutls_openpgp_cert_t should be defined in gnutls.h */

/* initializes the memory for gnutls_openpgp_crt_t struct */
int gnutls_openpgp_crt_init(gnutls_openpgp_crt_t * key);
/* frees all memory */
void gnutls_openpgp_crt_deinit(gnutls_openpgp_crt_t key);

int gnutls_openpgp_crt_import(gnutls_openpgp_crt_t key,
                              const gnutls_datum_t * data,
                              gnutls_openpgp_crt_fmt_t format);
int gnutls_openpgp_crt_export(gnutls_openpgp_crt_t key,
                              gnutls_openpgp_crt_fmt_t format,
                              void *output_data,
                              size_t * output_data_size);

/* The key_usage flags are defined in gnutls.h. They are
 * the GNUTLS_KEY_* definitions.
 */
int gnutls_openpgp_crt_get_key_usage(gnutls_openpgp_crt_t cert,
                                     unsigned int *key_usage);
int gnutls_openpgp_crt_get_fingerprint(gnutls_openpgp_crt_t key,
                                       void *fpr,
                                       size_t * fprlen);

int gnutls_openpgp_crt_get_name(gnutls_openpgp_crt_t key,
                                int idx,
                                char *buf,
                                size_t * sizeof_buf);

gnutls_pk_algorithm_t
    gnutls_openpgp_crt_get_pk_algorithm(gnutls_openpgp_crt_t key,
                                        unsigned int *bits);

int gnutls_openpgp_crt_get_version(gnutls_openpgp_crt_t key);

time_t gnutls_openpgp_crt_get_creation_time(gnutls_openpgp_crt_t key);
time_t gnutls_openpgp_crt_get_expiration_time(gnutls_openpgp_crt_t key);

int gnutls_openpgp_crt_get_id(gnutls_openpgp_crt_t key,
                              unsigned char keyid[8]);

int gnutls_openpgp_crt_check_hostname(gnutls_openpgp_crt_t key,
                                      const char *hostname);

/* privkey stuff.  */
int gnutls_openpgp_privkey_init(gnutls_openpgp_privkey_t * key);
void gnutls_openpgp_privkey_deinit(gnutls_openpgp_privkey_t key);
gnutls_pk_algorithm_t
    gnutls_openpgp_privkey_get_pk_algorithm(gnutls_openpgp_privkey_t key,
                                            unsigned int *bits);
int gnutls_openpgp_privkey_import(gnutls_openpgp_privkey_t key,
                                  const gnutls_datum_t * data,
                                  gnutls_openpgp_crt_fmt_t format,
                                  const char *pass,
                                  unsigned int flags);
int gnutls_openpgp_privkey_sign_hash(gnutls_openpgp_privkey_t key,
                                     const gnutls_datum_t * hash,
                                     gnutls_datum_t * signature);

/* Keyring stuff. */

int gnutls_openpgp_keyring_init(gnutls_openpgp_keyring_t * keyring);
void gnutls_openpgp_keyring_deinit(gnutls_openpgp_keyring_t keyring);

int gnutls_openpgp_keyring_import(gnutls_openpgp_keyring_t keyring,
                                  const gnutls_datum_t * data,
                                  gnutls_openpgp_crt_fmt_t format);

int gnutls_openpgp_keyring_check_id(gnutls_openpgp_keyring_t ring,
                                    const unsigned char keyid[8],
                                    unsigned int flags);

int gnutls_openpgp_crt_verify_ring(gnutls_openpgp_crt_t key,
                                   gnutls_openpgp_keyring_t keyring,
                                   unsigned int flags,
                                   unsigned int *verify
/* the output of the verification */);

int gnutls_openpgp_crt_verify_self(gnutls_openpgp_crt_t key,
                                   unsigned int flags,
                                   unsigned int *verify);

/* certificate authentication stuff.
 */
int gnutls_certificate_set_openpgp_key(gnutls_certificate_credentials_t
                                       res,
                                       gnutls_openpgp_crt_t key,
                                       gnutls_openpgp_privkey_t pkey);

#ifdef __cplusplus
}
#endif    

int _gnutls_map_cdk_rc(int rc);
int gnutls_openpgp_crt_get_name(gnutls_openpgp_crt_t key,
                                int idx,
                                char *buf,
                                size_t * sizeof_buf);
int gnutls_openpgp_crt_get_fingerprint(gnutls_openpgp_crt_t key,
                                       void *fpr,
                                       size_t * fprlen);
gnutls_pk_algorithm_t
    gnutls_openpgp_crt_get_pk_algorithm(gnutls_openpgp_crt_t key,
                                        unsigned int *bits);
int gnutls_openpgp_crt_get_version(gnutls_openpgp_crt_t key);
time_t gnutls_openpgp_crt_get_creation_time(gnutls_openpgp_crt_t key);
time_t gnutls_openpgp_crt_get_expiration_time(gnutls_openpgp_crt_t key);
int gnutls_openpgp_crt_get_id(gnutls_openpgp_crt_t key,
                              unsigned char keyid[8]);

int gnutls_openpgp_crt_init(gnutls_openpgp_crt_t * key);
void gnutls_openpgp_crt_deinit(gnutls_openpgp_crt_t key);
int gnutls_openpgp_crt_import(gnutls_openpgp_crt_t key,
                              const gnutls_datum_t * data,
                              gnutls_openpgp_crt_fmt_t format);
int gnutls_openpgp_crt_export(gnutls_openpgp_crt_t key,
                              gnutls_openpgp_crt_fmt_t format,
                              void *output_data,
                              size_t * output_data_size);

void gnutls_openpgp_keyring_deinit(gnutls_openpgp_keyring_t keyring);
int gnutls_openpgp_keyring_init(gnutls_openpgp_keyring_t * keyring);
int gnutls_openpgp_keyring_import(gnutls_openpgp_keyring_t keyring,
                                  const gnutls_datum_t * data,
                                  gnutls_openpgp_crt_fmt_t format);
int gnutls_openpgp_keyring_check_id(gnutls_openpgp_keyring_t ring,
                                    const unsigned char keyid[8],
                                    unsigned int flags);

int gnutls_openpgp_crt_verify_ring(gnutls_openpgp_crt_t key,
                                   gnutls_openpgp_keyring_t keyring,
                                   unsigned int flags,
                                   unsigned int *verify);

int gnutls_openpgp_crt_verify_self(gnutls_openpgp_crt_t key,
                                   unsigned int flags,
                                   unsigned int *verify);

int _gnutls_openpgp_crt_to_gcert(gnutls_cert * gcert,
                                 gnutls_openpgp_crt_t cert);
int _gnutls_openpgp_privkey_to_gkey(gnutls_privkey * dest,
                                    gnutls_openpgp_privkey_t src);

void gnutls_openpgp_privkey_deinit(gnutls_openpgp_privkey_t key);

#endif /* ENABLE_OPENPGP */
#endif /* OPENPGP_H */
