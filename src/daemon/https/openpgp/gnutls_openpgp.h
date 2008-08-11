#include <config.h>

#if ENABLE_OPENPGP

#ifndef GNUTLS_OPENPGP_H
#define GNUTLS_OPENPGP_H

#include <auth_cert.h>
#include <opencdk.h>

typedef struct
  {
    int type;
    size_t size;
    uint8_t *data;
  }keybox_blob;

typedef enum
  {
    KBX_BLOB_FILE = 0x00,
    KBX_BLOB_DATA = 0x01
  }keyring_blob_types;

/* OpenCDK compatible */
typedef enum
  {
    KEY_ATTR_NONE = 0,
    KEY_ATTR_SHORT_KEYID = 3,
    KEY_ATTR_KEYID = 4,
    KEY_ATTR_FPR = 5
  }key_attr_t;

int
gnutls_certificate_set_openpgp_key_file (mhd_gtls_cert_credentials_t
    res, const char *CERTFILE,
    const char *KEYFILE, gnutls_openpgp_crt_fmt_t);

int gnutls_openpgp_count_key_names (const gnutls_datum_t * cert);

int gnutls_certificate_set_openpgp_keyring_file
(mhd_gtls_cert_credentials_t c, const char *file, gnutls_openpgp_crt_fmt_t);

int
gnutls_certificate_set_openpgp_keyring_mem (mhd_gtls_cert_credentials_t
    c, const opaque * data,
    size_t dlen, gnutls_openpgp_crt_fmt_t);

int gnutls_openpgp_get_key (gnutls_datum_t * key,
    gnutls_openpgp_keyring_t keyring,
    key_attr_t by, opaque * pattern);

int gnutls_openpgp_recv_key (const char *host,
    short port, uint32_t keyid,
    gnutls_datum_t * key);

/* internal */
int _gnutls_openpgp_raw_key_to_gcert (gnutls_cert * cert,
    const gnutls_datum_t * raw);

extern int
_gnutls_openpgp_raw_privkey_to_gkey (gnutls_privkey * pkey,
    const gnutls_datum_t * raw_key,
    gnutls_openpgp_crt_fmt_t format);

int
_gnutls_openpgp_request_key (mhd_gtls_session_t,
    gnutls_datum_t * ret,
    const mhd_gtls_cert_credentials_t cred,
    opaque * key_fpr, int key_fpr_size);

int _gnutls_openpgp_verify_key (const mhd_gtls_cert_credentials_t,
    const gnutls_datum_t * cert_list,
    int cert_list_length, unsigned int *status);
int _gnutls_openpgp_fingerprint (const gnutls_datum_t * cert,
    unsigned char *fpr, size_t * fprlen);
time_t _gnutls_openpgp_get_raw_key_creation_time (const gnutls_datum_t *
    cert);
time_t _gnutls_openpgp_get_raw_key_expiration_time (const gnutls_datum_t *
    cert);

int
gnutls_openpgp_privkey_init (gnutls_openpgp_privkey_t * key);

int
gnutls_openpgp_privkey_init (gnutls_openpgp_privkey_t * key);

void
gnutls_openpgp_privkey_deinit (gnutls_openpgp_privkey_t key);

int
gnutls_openpgp_privkey_import (gnutls_openpgp_privkey_t key,
    const gnutls_datum_t * data,
    gnutls_openpgp_crt_fmt_t format,
    const char *pass, unsigned int flags);

#endif /*GNUTLS_OPENPGP_H */

#endif /*ENABLE_OPENPGP */
