/*
 * Copyright (C) 2002, 2003, 2004, 2005, 2007 Free Software Foundation
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GNUTLS-EXTRA.
 *
 * GNUTLS-EXTRA is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 3 of the
 * License, or (at your option) any later version.
 *
 * GNUTLS-EXTRA is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNUTLS-EXTRA; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 */

/* Note the libgnutls-extra is not a standalone library. It requires
 * to link also against libgnutls.
 */

#ifndef GNUTLS_EXTRA_H
# define GNUTLS_EXTRA_H

#include <gnutls.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define LIBGNUTLS_EXTRA_VERSION LIBGNUTLS_VERSION

/* Openpgp certificate stuff 
 */

  typedef enum gnutls_openpgp_crt_fmt
  { GNUTLS_OPENPGP_FMT_RAW,
    GNUTLS_OPENPGP_FMT_BASE64
  } gnutls_openpgp_crt_fmt_t;

/**
 * gnutls_openpgp_recv_key_func - Callback prototype to get OpenPGP keys
 * @session: a TLS session
 * @keyfpr: key fingerprint
 * @keyfpr_length: length of key fingerprint
 * @key: output key.
 *
 * A callback of this type is used to retrieve OpenPGP keys.  Only
 * useful on the server, and will only be used if the peer send a key
 * fingerprint instead of a full key.  See also
 * gnutls_openpgp_set_recv_key_function().
 *
 */
  typedef int (*gnutls_openpgp_recv_key_func) (gnutls_session_t session,
					       const unsigned char *keyfpr,
					       unsigned int keyfpr_length,
					       gnutls_datum_t * key);

  void gnutls_openpgp_set_recv_key_function (gnutls_session_t session,
					     gnutls_openpgp_recv_key_func
					     func);

  int
    gnutls_certificate_set_openpgp_key_file (gnutls_certificate_credentials_t
					     res, const char *CERTFILE,
					     const char *KEYFILE, gnutls_openpgp_crt_fmt_t);
  int gnutls_certificate_set_openpgp_key_mem (gnutls_certificate_credentials_t
					      res,
					      const gnutls_datum_t * CERT,
					      const gnutls_datum_t * KEY, gnutls_openpgp_crt_fmt_t);

  int
    gnutls_certificate_set_openpgp_keyring_mem
    (gnutls_certificate_credentials_t c, const unsigned char *data,
     size_t dlen, gnutls_openpgp_crt_fmt_t);

  int
    gnutls_certificate_set_openpgp_keyring_file
    (gnutls_certificate_credentials_t c, const char *file, gnutls_openpgp_crt_fmt_t);

  /* TLS/IA stuff
   */

  typedef enum
  {
    GNUTLS_IA_APPLICATION_PAYLOAD = 0,
    GNUTLS_IA_INTERMEDIATE_PHASE_FINISHED = 1,
    GNUTLS_IA_FINAL_PHASE_FINISHED = 2
  } gnutls_ia_apptype_t;

  /* TLS/IA credential
   */

  typedef int (*gnutls_ia_avp_func) (gnutls_session_t session, void *ptr,
				     const char *last, size_t lastlen,
				     char **next, size_t * nextlen);

  typedef struct gnutls_ia_server_credentials_st
    *gnutls_ia_server_credentials_t;
  typedef struct gnutls_ia_client_credentials_st
    *gnutls_ia_client_credentials_t;

  /* Allocate and free TLS/IA credentials. */
  extern void
    gnutls_ia_free_client_credentials (gnutls_ia_client_credentials_t sc);
  extern int
    gnutls_ia_allocate_client_credentials (gnutls_ia_client_credentials_t *
					   sc);

  extern void
    gnutls_ia_free_server_credentials (gnutls_ia_server_credentials_t sc);
  extern int
    gnutls_ia_allocate_server_credentials (gnutls_ia_server_credentials_t *
					   sc);

  /* Client TLS/IA credential functions. */
  extern void
    gnutls_ia_set_client_avp_function (gnutls_ia_client_credentials_t cred,
				       gnutls_ia_avp_func avp_func);
  extern void
    gnutls_ia_set_client_avp_ptr (gnutls_ia_client_credentials_t cred,
				  void *ptr);
  extern void *gnutls_ia_get_client_avp_ptr (gnutls_ia_client_credentials_t
					     cred);

  /* Server TLS/IA credential functions. */
  extern void
    gnutls_ia_set_server_avp_function (gnutls_ia_server_credentials_t cred,
				       gnutls_ia_avp_func avp_func);
  extern void
    gnutls_ia_set_server_avp_ptr (gnutls_ia_server_credentials_t cred,
				  void *ptr);
  extern void *gnutls_ia_get_server_avp_ptr (gnutls_ia_server_credentials_t
					     cred);

  /* TLS/IA handshake. */
  extern int gnutls_ia_handshake_p (gnutls_session_t session);

  extern int gnutls_ia_handshake (gnutls_session_t session);

  /* TLS/IA low level interface. */
  extern int
    gnutls_ia_permute_inner_secret (gnutls_session_t session,
				    size_t session_keys_size,
				    const char *session_keys);
  extern int gnutls_ia_endphase_send (gnutls_session_t session,
				      int final_p);

  extern int gnutls_ia_verify_endphase (gnutls_session_t session,
					const char *checksum);

  extern ssize_t gnutls_ia_send (gnutls_session_t session,
				 const char *data, size_t sizeofdata);
  extern ssize_t gnutls_ia_recv (gnutls_session_t session,
				 char *data, size_t sizeofdata);

  /* Utility stuff. */
  extern int gnutls_ia_generate_challenge (gnutls_session_t session,
					   size_t buffer_size,
					   char *buffer);
  extern void gnutls_ia_extract_inner_secret (gnutls_session_t session,
					      char *buffer);

  /* Define whether inner phases are wanted. */
  extern void gnutls_ia_enable (gnutls_session_t session,
				int allow_skip_on_resume);

  int gnutls_global_init_extra (void);

/* returns libgnutls-extra version (call it with a NULL argument) 
 */
  const char *gnutls_extra_check_version (const char *req_version);

#ifdef __cplusplus
}
#endif
#endif
