/*
  This file is part of GNU libmicrohttpd
  Copyright (C) 2024 Evgeny Grin (Karlson2k)

  GNU libmicrohttpd is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  GNU libmicrohttpd is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

*/

/**
 * @file src/mhd2/tls_open_funcs.c
 * @brief  The implementation of GnuTLS wrapper functions
 * @author Karlson2k (Evgeny Grin)
 */

#include "mhd_sys_options.h"

#include "sys_bool_type.h"
#include "sys_base_types.h"

#include "mhd_assert.h"
#include "mhd_unreachable.h"

#include <string.h>

#include "compat_calloc.h"
#include "sys_malloc.h"

#include "mhd_conn_socket.h"

#include "tls_open_tls_lib.h"

#include "tls_open_daemon_data.h"
#include "tls_open_conn_data.h"
#include "tls_open_funcs.h"

#include "daemon_options.h"

#include "daemon_logger.h"

#include "mhd_public_api.h"

#ifdef mhd_USE_TLS_DEBUG_MESSAGES
#  include <stdio.h> /* For TLS debug printing */
#endif

#ifdef mhd_USE_TLS_DEBUG_MESSAGES

static MHD_FN_PAR_NONNULL_ (1) int
mhd_tls_open_dbg_print_errs (const char *msg,
                             size_t msg_len,
                             void *cls)
{
  int ret;
  int print_size = (int) msg_len;

  (void) cls; /* Not used */

  if ((print_size < 0) ||
      (msg_len != (unsigned int) print_size))
    print_size = (int) ((~((unsigned int) 0u)) >> 1);

  ret = fprintf (stderr,
                 "## OpenSSL error: %.*s\n",
                 print_size, msg);
  (void) fflush (stderr);
  return ret;
}


#  define mhd_DBG_PRINT_TLS_ERRS() \
        ERR_print_errors_cb (&mhd_tls_open_dbg_print_errs, NULL)
#else
#  define mhd_DBG_PRINT_TLS_ERRS()      ERR_clear_error ()
#endif

/* ** Global initialisation / de-initialisation ** */

static bool openssl_lib_inited = false;

MHD_INTERNAL void
mhd_tls_open_global_init_once (void)
{
  const unsigned long ver_num = OpenSSL_version_num ();
  /* Make sure that used shared OpenSSL library has least the same version as
     MHD was configured for. Fail if the version is earlier. */
  openssl_lib_inited = ((0x900000UL < ver_num) /* Versions before 3.0 */
                        && (OPENSSL_VERSION_NUMBER <= ver_num));

  /* The call of OPENSSL_init_ssl() typically not needed, but it won't hurt
     if library was initialised automatically.
     In some exotic situations automatic initialisation could fail, and
     this call would make sure that the library is initialised before used. */
  openssl_lib_inited = openssl_lib_inited
                       && (0 < OPENSSL_init_ssl (0, NULL));
}


MHD_INTERNAL MHD_FN_PURE_ bool
mhd_tls_open_is_inited_fine (void)
{
  return openssl_lib_inited;
}


/* ** Daemon initialisation / de-initialisation ** */

/**
 * Check application-provided daemon TLS settings
 * @param d the daemon handle
 * @param s the application-provided settings
 * @return #MHD_SC_OK on success,
 *         error code otherwise
 */
static MHD_FN_PAR_NONNULL_ALL_ MHD_FN_MUST_CHECK_RESULT_ enum MHD_StatusCode
check_app_tls_sessings (struct MHD_Daemon *restrict d,
                        struct DaemonOptions *restrict s)
{
  mhd_assert (MHD_TLS_BACKEND_NONE != s->tls);
  mhd_assert ((MHD_TLS_BACKEND_GNUTLS == s->tls) || \
              (MHD_TLS_BACKEND_ANY == s->tls));
  if (NULL == s->tls_cert_key.v_mem_cert)
  {
    mhd_LOG_MSG (d, MHD_SC_TLS_CONF_BAD_CERT, \
                 "No valid TLS certificate is provided");
    return MHD_SC_TLS_CONF_BAD_CERT;
  }
  mhd_assert (NULL != s->tls_cert_key.v_mem_key);

  return MHD_SC_OK;
}


/* Helper to prevent password prompts in terminal */
static int
null_passwd_cb (char *buf,
                int size,
                int rwflag,
                void *cls)
{
  (void) buf; (void) size; (void) rwflag; (void) cls; /* Unused */
#ifdef mhd_USE_TLS_DEBUG_MESSAGES
  fprintf (stderr, "## OpenSSL: the NULL passphrase callback is called\n");
  fflush (stderr);
#endif
  return 0;
}


/**
 * Initialise OpenSSL library context
 * @param d the daemon handle
 * @param d_tls the daemon TLS settings
 * @param s the application-provided settings
 * @return #MHD_SC_OK on success,
 *         error code otherwise
 */
static MHD_FN_PAR_NONNULL_ALL_ MHD_FN_MUST_CHECK_RESULT_ enum MHD_StatusCode
daemon_init_lib_ctx (struct MHD_Daemon *restrict d,
                     struct mhd_TlsOpenDaemonData *restrict d_tls,
                     struct DaemonOptions *restrict s)
{
  bool fallback_config;
  bool prevent_fallbacks;
  char *conf_filename;
  d_tls->libctx = OSSL_LIB_CTX_new ();

  (void) s; // TODO: support app-defined name for TLS backend profile

  if (NULL == d_tls->libctx)
  {
    mhd_DBG_PRINT_TLS_ERRS ();
    mhd_LOG_MSG (d, MHD_SC_TLS_DAEMON_INIT_FAILED, \
                 "Failed to create TLS library context");
    return MHD_SC_TLS_DAEMON_INIT_FAILED;
  }

  prevent_fallbacks = false;
#ifdef mhd_TLS_OPEN_HAS_CONF_DIAG
  prevent_fallbacks = prevent_fallbacks ||
                      (0 != OSSL_LIB_CTX_get_conf_diagnostics (d_tls->libctx));
#endif

  fallback_config = false;
  ERR_clear_error ();

  conf_filename = CONF_get1_default_config_file ();
  if (NULL == conf_filename)
    mhd_DBG_PRINT_TLS_ERRS ();
  else
  {
    bool libctx_inited;
    CONF *conf;

    libctx_inited = false;
    conf = NCONF_new_ex (d_tls->libctx,
                         NULL);
    if (NULL == conf)
      mhd_DBG_PRINT_TLS_ERRS ();
    else
    {
      if (0 >= NCONF_load (conf,
                           conf_filename,
                           NULL))
      {
        unsigned long err;

        err = ERR_peek_last_error ();
        mhd_DBG_PRINT_TLS_ERRS ();
        libctx_inited = true; /* Nothing to initialise */

        if ((ERR_LIB_CONF != ERR_GET_LIB (err)) ||
            (CONF_R_NO_SUCH_FILE != ERR_GET_REASON (err)))
        {
          fallback_config = true;
          mhd_LOG_PRINT (d, MHD_SC_TLS_LIB_CONF_WARNING, \
                         mhd_LOG_FMT ("Error in TLS library configuration "
                                      "file '%s'"), \
                         conf_filename);
        }
      }
      else /* NCONF_load() succeed */
      {
        (void) s; // TODO: support app-defined name for TLS backend profile

        if (! libctx_inited)
        {
          if (NULL != NCONF_get_section (conf,
                                         "libmicrohttpd"))
          {
            if (0 <
                CONF_modules_load (conf,
                                   "libmicrohttpd",
                                   0))
              libctx_inited = true;
            else
            {
              mhd_DBG_PRINT_TLS_ERRS ();
              fallback_config = true;
              mhd_LOG_PRINT (d, MHD_SC_TLS_LIB_CONF_WARNING, \
                             mhd_LOG_FMT ("Failed to load configuration file " \
                                          "section [%s]"), \
                             "libmicrohttpd");

              libctx_inited =
                (0 < CONF_modules_load (conf,
                                        "libmicrohttpd",
                                        CONF_MFLAGS_IGNORE_ERRORS));
              if (! libctx_inited)
                mhd_DBG_PRINT_TLS_ERRS ();
            }
          }
        }
        if (! libctx_inited)
        {
          if (0 <
              CONF_modules_load (conf,
                                 NULL,
                                 0))
            libctx_inited = true;
          else
          {
            mhd_DBG_PRINT_TLS_ERRS ();
            fallback_config = true;
            mhd_LOG_PRINT (d, MHD_SC_TLS_LIB_CONF_WARNING, \
                           mhd_LOG_FMT ("Failed to load configuration file " \
                                        "default section"));

            libctx_inited =
              (0 < CONF_modules_load (conf,
                                      NULL,
                                      CONF_MFLAGS_IGNORE_ERRORS));
            if (! libctx_inited)
              mhd_DBG_PRINT_TLS_ERRS ();
          }
        }
#ifdef mhd_TLS_OPEN_HAS_CONF_DIAG
        if (fallback_config && libctx_inited && ! prevent_fallbacks)
          prevent_fallbacks =
            (0 != OSSL_LIB_CTX_get_conf_diagnostics (d_tls->libctx));
#endif /* mhd_TLS_OPEN_HAS_CONF_DIAG */
      }
      NCONF_free (conf);
    }
    OPENSSL_free (conf_filename);

    if (fallback_config && prevent_fallbacks)
      libctx_inited = true;

    if (libctx_inited)
    {
      return MHD_SC_OK; /* Success exit point */
    }
  }

  OSSL_LIB_CTX_free (d_tls->libctx);
  mhd_LOG_MSG (d, MHD_SC_TLS_DAEMON_INIT_FAILED, \
               "Failed to initialise TLS library context");
  return MHD_SC_TLS_DAEMON_INIT_FAILED;
}


/**
 * De-initialise OpenSSL library context
 * @param d_tls the daemon TLS settings
 */
static MHD_FN_PAR_NONNULL_ALL_ void
daemon_deinit_lib_ctx (struct mhd_TlsOpenDaemonData *restrict d_tls)
{
  mhd_assert (NULL != d_tls->libctx);
  OSSL_LIB_CTX_free (d_tls->libctx);
}


static const unsigned char alpn_codes_list[] = {
#if 0  /* Disabled code */
  2u, 'h', '3'  /* Registered value for HTTP/3 */
  ,
  2u, 'h', '2'  /* Registered value for HTTP/2 over TLS */
  ,
#endif /* Disabled code */
  8u, 'h', 't', 't', 'p', '/', '1', '.', '1' /* Registered value for HTTP/1.1 */
  ,
  8u, 'h', 't', 't', 'p', '/', '1', '.', '0' /* Registered value for HTTP/1.0 */
};

/**
 * Provide the list of supported protocols for NPN extension
 * @param sess the TLS session (ignored)
 * @param[out] out the pointer to get the location of the data
 * @param[out] outlen the size of the data provided
 * @param cls the closure (ignored)
 * @return always SSL_TLSEXT_ERR_OK
 */
static int
get_npn_list (SSL *sess,
              const unsigned char **out,
              unsigned int *outlen,
              void *cls)
{
  (void) sess; (void) cls; /* Unused */
  *out = alpn_codes_list;
  *outlen = sizeof(alpn_codes_list);
  return SSL_TLSEXT_ERR_OK;
}


/**
 * Select protocol from the provided list for ALPN extension
 * @param sess the TLS session (ignored)
 * @param[out] out the pointer to get the location of selected protocol value
 * @param[out] outlen the size of the selected protocol value
 * @param in the list of protocols values provided by the client
 * @param inlen the size of the list of protocols values provided by the client
 * @param cls the closure (ignored)
 * @return SSL_TLSEXT_ERR_OK if matching protocol found and selected,
 *         SSL_TLSEXT_ERR_ALERT_FATAL otherwise
 */
static int
select_alpn_prot (SSL *sess,
                  const unsigned char **out,
                  unsigned char *outlen,
                  const unsigned char *in,
                  unsigned int inlen,
                  void *cls)
{
  (void) sess; (void) cls; /* Unused */
  if (OPENSSL_NPN_NEGOTIATED ==
      SSL_select_next_proto (mhd_DROP_CONST (out),
                             outlen,
                             in,
                             inlen,
                             alpn_codes_list,
                             sizeof(alpn_codes_list)))
    return SSL_TLSEXT_ERR_OK; /* Success */

  return SSL_TLSEXT_ERR_ALERT_FATAL; /* Failure */
}


/**
 * Initialise TLS server context
 * @param d the daemon handle
 * @param d_tls the daemon TLS settings
 * @param s the application-provided settings
 * @return #MHD_SC_OK on success,
 *         error code otherwise
 */
static MHD_FN_PAR_NONNULL_ALL_ MHD_FN_MUST_CHECK_RESULT_ enum MHD_StatusCode
daemon_init_ctx (struct MHD_Daemon *restrict d,
                 struct mhd_TlsOpenDaemonData *restrict d_tls,
                 struct DaemonOptions *restrict s)
{
  uint64_t ctx_opts;

#ifndef HAVE_LOG_FUNCTIONALITY
  (void) d; /* Mute compiler warning */
#endif
  (void) s; // TODO: support configuration options

  mhd_assert (NULL != d_tls->libctx);

  ERR_clear_error ();

  d_tls->ctx = SSL_CTX_new_ex (d_tls->libctx,
                               NULL,
                               TLS_server_method ());
  if (NULL == d_tls->ctx)
  {
    mhd_DBG_PRINT_TLS_ERRS ();
    mhd_LOG_MSG (d, MHD_SC_TLS_DAEMON_INIT_FAILED, \
                 "Failed to initialise TLS server context");
    return MHD_SC_TLS_DAEMON_INIT_FAILED;
  }

  /* Enable some safe and useful workarounds */
  ctx_opts = SSL_OP_SAFARI_ECDHE_ECDSA_BUG | SSL_OP_TLSEXT_PADDING;

  // TODO: add configuration option
  // ctx_opts |= SSL_OP_CIPHER_SERVER_PREFERENCE;

  /* Enable kernel TLS */ // TODO: add configuration option
  ctx_opts |= SSL_OP_ENABLE_KTLS;
#ifdef SSL_OP_ENABLE_KTLS_TX_ZEROCOPY_SENDFILE
  ctx_opts |= SSL_OP_ENABLE_KTLS_TX_ZEROCOPY_SENDFILE;
#endif

  /* HTTP defines strict framing for the client-side data,
     no risk of attack on server on unexpected connection interruption */
  /* ctx_opts |= SSL_OP_IGNORE_UNEXPECTED_EOF; */ // TODO: recheck

  /* There is no reason to use re-negotiation with HTTP */
  ctx_opts |= SSL_OP_NO_RENEGOTIATION;

  /* Do not use session resumption for now */
  ctx_opts |= SSL_OP_NO_TICKET;

  (void) SSL_CTX_set_options (d_tls->ctx,
                              ctx_opts);

  /* Prevent interactive password prompts */
  SSL_CTX_set_default_passwd_cb (d_tls->ctx,
                                 &null_passwd_cb);

  // TODO: regenerate certificates
  // TODO: make the setting configurable
  // FIXME: this is a bad workaround!
  SSL_CTX_set_security_level (d_tls->ctx, 0); /* Required to accept current test CA */

  /* recv()- and send()-related options */
  (void) SSL_CTX_set_mode (d_tls->ctx,
                           SSL_MODE_ENABLE_PARTIAL_WRITE
                           | SSL_MODE_AUTO_RETRY);
  (void) SSL_CTX_clear_mode (d_tls->ctx,
                             SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER
                             | SSL_MODE_ASYNC);

  SSL_CTX_set_read_ahead (d_tls->ctx,
                          ! 0);

  /* ALPN and NPN */
  // TODO: use daemon option to disable them
  SSL_CTX_set_alpn_select_cb (d_tls->ctx,
                              &select_alpn_prot,
                              NULL);
  SSL_CTX_set_next_protos_advertised_cb (d_tls->ctx,
                                         &get_npn_list,
                                         NULL);

  return MHD_SC_OK;
}


/**
 * De-initialise TLS server context
 * @param d_tls the daemon TLS settings
 */
static MHD_FN_PAR_NONNULL_ALL_ void
daemon_deinit_ctx (struct mhd_TlsOpenDaemonData *restrict d_tls)
{
  mhd_assert (NULL != d_tls->ctx);
  SSL_CTX_free (d_tls->ctx);
}


/**
 * Load provided certificates chain
 * @param d the daemon handle
 * @param d_tls the daemon TLS settings
 * @param s the application-provided settings
 * @return #MHD_SC_OK on success,
 *         error code otherwise
 */
static MHD_FN_PAR_NONNULL_ALL_ MHD_FN_MUST_CHECK_RESULT_ enum MHD_StatusCode
daemon_load_certs_chain (struct MHD_Daemon *restrict d,
                         struct mhd_TlsOpenDaemonData *restrict d_tls,
                         struct DaemonOptions *restrict s)
{
  enum MHD_StatusCode ret;
  BIO *m_bio;
  X509 *cert;

  mhd_assert (NULL != d_tls->libctx);
  mhd_assert (NULL != d_tls->ctx);

  ERR_clear_error ();

  m_bio = BIO_new_mem_buf (s->tls_cert_key.v_mem_cert,
                           -1);
  if (NULL == m_bio)
  {
    mhd_DBG_PRINT_TLS_ERRS ();
    return MHD_SC_DAEMON_MALLOC_FAILURE;
  }

  ret = MHD_SC_OK;

  /* The certificate object must be pre-allocated to associate it with
   * the lib context */
  cert = X509_new_ex (d_tls->libctx,
                      NULL);
  if (NULL != cert)
  {
    if (NULL != PEM_read_bio_X509_AUX (m_bio,
                                       &cert,
                                       &null_passwd_cb,
                                       NULL))
    {
      if (0 < SSL_CTX_use_certificate (d_tls->ctx,
                                       cert))
      {
        if (0 != ERR_peek_error ())
          mhd_DBG_PRINT_TLS_ERRS ();

        /* The object successfully "copied" to CTX,
         * the original object is not needed anymore. */
        X509_free (cert);
        cert = NULL;

        do
        {
          X509 *c_cert; /* Certifying certificate */
          c_cert = X509_new_ex (d_tls->libctx,
                                NULL);
          if (NULL == c_cert)
          {
            mhd_DBG_PRINT_TLS_ERRS ();
            mhd_LOG_MSG (d, MHD_SC_TLS_DAEMON_INIT_FAILED, \
                         "Failed to create new chain certificate object");
            ret = MHD_SC_TLS_DAEMON_INIT_FAILED;
          }
          else
          {
            if (NULL == PEM_read_bio_X509 (m_bio,
                                           &cert,
                                           &null_passwd_cb,
                                           NULL))
            {
              unsigned long err;
              err = ERR_peek_last_error ();
              if ((ERR_LIB_PEM == ERR_GET_LIB (err)) &&
                  (PEM_R_NO_START_LINE == ERR_GET_REASON (err)))
              {
                /* End of data */
                ERR_clear_error ();
                X509_free (c_cert); /* Empty, not needed */

                mhd_assert (MHD_SC_OK == ret);
                return MHD_SC_OK; /* Success exit point */
              }
              mhd_DBG_PRINT_TLS_ERRS ();
              mhd_LOG_MSG (d, MHD_SC_TLS_DAEMON_INIT_FAILED, \
                           "Failed to load next object in the certificates " \
                           "chain");
              ret = MHD_SC_TLS_DAEMON_INIT_FAILED;
            }
            else
            {
              if (SSL_CTX_add0_chain_cert (d_tls->ctx,
                                           c_cert))
              {
                /* Success, do not free the certificate as
                 * function '_add0_' was used to add it. */
                /* Read the next certificate in the chain. */
                continue;
              }
              else
              {
                mhd_DBG_PRINT_TLS_ERRS ();
                mhd_LOG_MSG (d, MHD_SC_TLS_DAEMON_INIT_FAILED, \
                             "Failed to add the new certificate object "
                             "to the chain");
                ret = MHD_SC_TLS_DAEMON_INIT_FAILED;
              }
            }
            X509_free (c_cert); /* Failed, the object is not needed */
            mhd_assert (MHD_SC_OK != ret);
          }
        } while (MHD_SC_OK == ret);
      }
      else
      {
        mhd_DBG_PRINT_TLS_ERRS ();
        mhd_LOG_MSG (d, MHD_SC_TLS_DAEMON_INIT_FAILED, \
                     "Failed to set the certificate");
        ret = MHD_SC_TLS_DAEMON_INIT_FAILED;
      }
    }
    else
    {
      mhd_DBG_PRINT_TLS_ERRS ();
      mhd_LOG_MSG (d, MHD_SC_TLS_DAEMON_INIT_FAILED, \
                   "Failed to process the certificate");
      ret = MHD_SC_TLS_DAEMON_INIT_FAILED;
    }
    if (NULL != cert)
      X509_free (cert);
  }
  else
  {
    mhd_DBG_PRINT_TLS_ERRS ();
    mhd_LOG_MSG (d, MHD_SC_TLS_DAEMON_INIT_FAILED, \
                 "Failed to create new certificate object");
    ret = MHD_SC_TLS_DAEMON_INIT_FAILED;
  }
  BIO_free (m_bio);
  mhd_assert (MHD_SC_OK != ret);
  return ret;
}


/**
 * Initialise TLS certificate
 * The function loads the certificate chain and the private key.
 * @param d the daemon handle
 * @param d_tls the daemon TLS settings
 * @param s the application-provided settings
 * @return #MHD_SC_OK on success,
 *         error code otherwise
 */
static MHD_FN_PAR_NONNULL_ALL_ MHD_FN_MUST_CHECK_RESULT_ enum MHD_StatusCode
daemon_init_cert (struct MHD_Daemon *restrict d,
                  struct mhd_TlsOpenDaemonData *restrict d_tls,
                  struct DaemonOptions *restrict s)
{
  enum MHD_StatusCode ret;
  BIO *m_bio;
  EVP_PKEY *pr_key;
  int res;

  mhd_assert (NULL != d_tls->libctx);
  mhd_assert (NULL != d_tls->ctx);

  ERR_clear_error ();

  ret = daemon_load_certs_chain (d,
                                 d_tls,
                                 s);
  if (MHD_SC_OK != ret)
    return ret;

  /* Check and cache the certificates chain.
     This also prevents automatic chain re-building for each session. */
  res =
    SSL_CTX_build_cert_chain (
      d_tls->ctx,
      SSL_BUILD_CHAIN_FLAG_CHECK /* Use only certificates in the chain */
      | SSL_BUILD_CHAIN_FLAG_UNTRUSTED /* Intermediate certs does not need to be trusted */
      | SSL_BUILD_CHAIN_FLAG_NO_ROOT /* The root should not be sent */
      | SSL_BUILD_CHAIN_FLAG_IGNORE_ERROR /* Allow the root CA to be not trusted */
      );
  if (0 >= res)
  {
    mhd_DBG_PRINT_TLS_ERRS ();
    mhd_LOG_MSG (d, MHD_SC_TLS_DAEMON_INIT_FAILED, \
                 "Failed rebuild certificate chain");
    return MHD_SC_TLS_DAEMON_INIT_FAILED;
  }
  if (2 == res)
    mhd_DBG_PRINT_TLS_ERRS ();

  m_bio = BIO_new_mem_buf (s->tls_cert_key.v_mem_key,
                           -1);
  if (NULL == m_bio)
  {
    mhd_DBG_PRINT_TLS_ERRS ();
    return MHD_SC_DAEMON_MALLOC_FAILURE;
  }
  pr_key =
    PEM_read_bio_PrivateKey_ex (m_bio,
                                NULL,
                                NULL == s->tls_cert_key.v_mem_pass ?
                                &null_passwd_cb : NULL,
                                mhd_DROP_CONST (s->tls_cert_key.v_mem_pass),
                                d_tls->libctx,
                                NULL);
  BIO_free (m_bio);
  if (NULL == pr_key)
  {
    mhd_DBG_PRINT_TLS_ERRS ();
    mhd_LOG_MSG (d, MHD_SC_TLS_DAEMON_INIT_FAILED, \
                 "Failed to read the private key");
    return MHD_SC_TLS_DAEMON_INIT_FAILED;
  }

  res = SSL_CTX_use_PrivateKey (d_tls->ctx,
                                pr_key);
  EVP_PKEY_free (pr_key); /* The key has been "copied" or failed */
  if (1 != res)
  {
    mhd_DBG_PRINT_TLS_ERRS ();
    mhd_LOG_MSG (d, MHD_SC_TLS_DAEMON_INIT_FAILED, \
                 "Failed to set the private key");
    return MHD_SC_TLS_DAEMON_INIT_FAILED;
  }
  /* This actually RE-checks the key.
     The key should be already checked automatically when it was set after
     setting the certificate. */
  if (1 != SSL_CTX_check_private_key (d_tls->ctx))
  {
    mhd_DBG_PRINT_TLS_ERRS ();
    mhd_LOG_MSG (d, MHD_SC_TLS_DAEMON_INIT_FAILED, \
                 "The private key does not match the certificate");
    return MHD_SC_TLS_DAEMON_INIT_FAILED;
  }

  return MHD_SC_OK;
}


MHD_INTERNAL MHD_FN_MUST_CHECK_RESULT_ MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_OUT_ (3) mhd_StatusCodeInt
mhd_tls_open_daemon_init (struct MHD_Daemon *restrict d,
                          struct DaemonOptions *restrict s,
                          struct mhd_TlsOpenDaemonData **restrict p_d_tls)
{
  mhd_StatusCodeInt res;
  struct mhd_TlsOpenDaemonData *restrict d_tls;

  res = check_app_tls_sessings (d, s);
  if (MHD_SC_OK != res)
    return res;

  d_tls = (struct mhd_TlsOpenDaemonData *)
          mhd_calloc (1, sizeof (struct mhd_TlsOpenDaemonData));
  *p_d_tls = d_tls;
  if (NULL == d_tls)
    return MHD_SC_DAEMON_MALLOC_FAILURE;

  res = daemon_init_lib_ctx (d,
                             d_tls,
                             s);
  if (MHD_SC_OK == res)
  {
    res = daemon_init_ctx (d,
                           d_tls,
                           s);
    if (MHD_SC_OK == res)
    {
      res = daemon_init_cert (d,
                              d_tls,
                              s);
      if (MHD_SC_OK == res)
        return MHD_SC_OK; /* Success exit point */

      /* Below is a clean-up code path */
      daemon_deinit_ctx (d_tls);
    }
    daemon_deinit_lib_ctx (d_tls);
  }
  free (d_tls);
  *p_d_tls = NULL;
  mhd_assert (MHD_SC_OK != res);
  return res; /* Failure exit point */
}


MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_INOUT_ (1) void
mhd_tls_open_daemon_deinit (struct mhd_TlsOpenDaemonData *restrict d_tls)
{
  mhd_assert (NULL != d_tls);
  daemon_deinit_ctx (d_tls);
  daemon_deinit_lib_ctx (d_tls);
  free (d_tls);
}


/* ** Connection initialisation / de-initialisation ** */

MHD_INTERNAL size_t
mhd_tls_open_conn_get_tls_size_v (void)
{
  return sizeof (struct mhd_TlsOpenConnData);
}


MHD_INTERNAL MHD_FN_MUST_CHECK_RESULT_ MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_OUT_ (3) bool
mhd_tls_open_conn_init (const struct mhd_TlsOpenDaemonData *restrict d_tls,
                        const struct mhd_ConnSocket *sk,
                        struct mhd_TlsOpenConnData *restrict c_tls)
{
  int fd;

  ERR_clear_error ();

  fd = (int) sk->fd;
  if (sk->fd != (MHD_Socket) fd)
    return false; /* OpenSSL docs clam that it should not be possible */

  c_tls->sess = SSL_new (d_tls->ctx);

  if (NULL == c_tls->sess)
  {
    mhd_DBG_PRINT_TLS_ERRS ();
    return false;
  }

  if (0 < SSL_set_fd (c_tls->sess, fd))
  {
    SSL_set_accept_state (c_tls->sess); /* Force server mode */

#ifndef NDEBUG
    c_tls->dbg.is_inited = true;
#endif
    return true; /* Success exit point */
  }

  SSL_free (c_tls->sess);
  c_tls->sess = NULL;
  return false;
}


MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_ void
mhd_tls_open_conn_deinit (struct mhd_TlsOpenConnData *restrict c_tls)
{
  mhd_assert (NULL != c_tls->sess);
  mhd_assert (c_tls->dbg.is_inited);
  SSL_free (c_tls->sess);
}


/* ** TLS connection establishing ** */

MHD_INTERNAL MHD_FN_MUST_CHECK_RESULT_ MHD_FN_PAR_NONNULL_ALL_
enum mhd_TlsProcedureResult
mhd_tls_open_conn_handshake (struct mhd_TlsOpenConnData *restrict c_tls)
{
  int res;

  mhd_assert (c_tls->dbg.is_inited);
  mhd_assert (! c_tls->dbg.is_tls_handshake_completed);
  mhd_assert (! c_tls->shut_tls_wr_sent);
  mhd_assert (! c_tls->shut_tls_wr_received);
  mhd_assert (! c_tls->dbg.is_failed);

  ERR_clear_error ();

  res = SSL_do_handshake (c_tls->sess);

  if (1 == res)
  {
#ifndef NDEBUG
    c_tls->dbg.is_tls_handshake_completed = true;
#endif /* ! NDEBUG */
    return mhd_TLS_PROCED_SUCCESS; /* Success exit point */
  }

  switch (SSL_get_error (c_tls->sess, res))
  {
  case SSL_ERROR_WANT_READ:
    /* OpenSSL does not distinguish between "interrupted" and "try again" codes.
       This is very bad when edge triggered polling is used as is is not clear
       whether the "recv-ready" flag should be cleared.
       If the flag is cleared, but it should not (because the process has been
       "interrupted") then already pending data could be never processed.
       If the flag is not cleared, but it should be cleared (because all
       received data has been processed) then it would create busy-waiting loop.
       Use clear of "ready" flag as safer, but not ideal solution. */
    // TODO: replace "BIO" with custom version and track returned errors.
    return mhd_TLS_PROCED_SEND_MORE_NEEDED;
  case SSL_ERROR_WANT_WRITE:
    /* OpenSSL does not distinguish between "interrupted" and "try again" codes.
       This is very bad when edge triggered polling is used as is is not clear
       whether the "send-ready" flag should be cleared.
       If the flag is cleared, but it should not (because the process has been
       "interrupted") then already pending data could be never sent.
       If the flag is not cleared, but it should be cleared (because the network
       is busy) then it would create busy-waiting loop.
       Use clear of "ready" flag as safer, but not ideal solution. */
    // TODO: replace "BIO" with custom version and track returned errors.
    return mhd_TLS_PROCED_RECV_MORE_NEEDED;
  case SSL_ERROR_NONE:
    mhd_assert (0 && "This should not be possible");
    mhd_UNREACHABLE ();
    break;
  default: /* Handled with all other errors below */
    break;
  }
  mhd_DBG_PRINT_TLS_ERRS ();
#ifndef NDEBUG
  c_tls->dbg.is_failed = true;
#endif /* ! NDEBUG */
  return mhd_TLS_PROCED_FAILED;
}


MHD_INTERNAL MHD_FN_MUST_CHECK_RESULT_ MHD_FN_PAR_NONNULL_ALL_
enum mhd_TlsProcedureResult
mhd_tls_open_conn_shutdown (struct mhd_TlsOpenConnData *restrict c_tls)
{
  int res;

  mhd_assert (c_tls->dbg.is_inited);
  mhd_assert (c_tls->dbg.is_tls_handshake_completed);
  mhd_assert (! c_tls->dbg.is_failed);

  ERR_clear_error ();

  res = SSL_shutdown (c_tls->sess);

  if (1 == res)
  {
    c_tls->shut_tls_wr_sent = true;
    c_tls->shut_tls_wr_received = true;
    return mhd_TLS_PROCED_SUCCESS; /* Success exit point */
  }

  /* The OpenSSL documentation contradicts itself: there are two mutually
     exclusive statements on a single page.
   * https://docs.openssl.org/master/man3/SSL_shutdown/#shutdown-lifecycle
     indicates that for nonblocking socket ZERO could be returned when
     "close_notify" is GOING to be sent, but NOT sent yet.
     It also suggests to CALL SSL_get_error(3) when ZERO is returned.
   * https://docs.openssl.org/master/man3/SSL_shutdown/#return-values
     indicates ZERO is returned ONLY when "close_notify" HAS BEEN sent.
     It also suggests to NOT CALL SSL_get_error(3) when ZERO is returned.
   */
  switch (SSL_get_error (c_tls->sess, res))
  {
  case SSL_ERROR_WANT_READ:
    /* OpenSSL does not distinguish between "interrupted" and "try again" codes.
       This is very bad when edge triggered polling is used as is is not clear
       whether the "recv-ready" flag should be cleared.
       If the flag is cleared, but it should not (because the process has been
       "interrupted") then already pending data could be never processed.
       If the flag is not cleared, but it should be cleared (because all
       received data has been processed) then it would create busy-waiting loop.
       Use clear of "ready" flag as safer, but not ideal solution. */
    // TODO: replace "BIO" with custom version and track returned errors.
    return mhd_TLS_PROCED_SEND_MORE_NEEDED;
  case SSL_ERROR_WANT_WRITE:
    c_tls->shut_tls_wr_sent = true;
    /* OpenSSL does not distinguish between "interrupted" and "try again" codes.
       This is very bad when edge triggered polling is used as is is not clear
       whether the "send-ready" flag should be cleared.
       If the flag is cleared, but it should not (because the process has been
       "interrupted") then already pending data could be never sent.
       If the flag is not cleared, but it should be cleared (because the network
       is busy) then it would create busy-waiting loop.
       Use clear of "ready" flag as safer, but not ideal solution. */
    // TODO: replace "BIO" with custom version and track returned errors.
    return mhd_TLS_PROCED_RECV_MORE_NEEDED;
  case SSL_ERROR_NONE:
    mhd_assert (res != 0 && "Should not be possible");
    c_tls->shut_tls_wr_sent = true;
    return mhd_TLS_PROCED_RECV_INTERRUPTED;
  default: /* Handled with all other errors below */
    break;
  }
  mhd_DBG_PRINT_TLS_ERRS ();
#ifndef NDEBUG
  c_tls->dbg.is_failed = true;
#endif /* ! NDEBUG */
  return mhd_TLS_PROCED_FAILED;
}


/* ** Data receiving and sending ** */

MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_OUT_SIZE_ (3,2)
MHD_FN_PAR_OUT_ (4) enum mhd_SocketError
mhd_tls_open_conn_recv (struct mhd_TlsOpenConnData *restrict c_tls,
                        size_t buf_size,
                        char buf[MHD_FN_PAR_DYN_ARR_SIZE_ (buf_size)],
                        size_t *restrict received)
{
  int res;

  mhd_assert (c_tls->dbg.is_inited);
  mhd_assert (c_tls->dbg.is_tls_handshake_completed);
  mhd_assert (! c_tls->shut_tls_wr_sent);
  mhd_assert (! c_tls->dbg.is_failed);

  ERR_clear_error ();

  res = SSL_read_ex (c_tls->sess,
                     buf,
                     buf_size,
                     received);
  if (1 == res)
  {
    mhd_assert (0 != *received);
    return mhd_SOCKET_ERR_NO_ERROR; /* Success exit point */
  }

  mhd_assert (0 == res);
  *received = 0;
  switch (SSL_get_error (c_tls->sess, res))
  {
  case SSL_ERROR_ZERO_RETURN: /* Not an error */
    c_tls->shut_tls_wr_received = true;
    return mhd_SOCKET_ERR_NO_ERROR;   /* Success exit point */
  case SSL_ERROR_WANT_READ:
    /* OpenSSL does not distinguish between "interrupted" and "try again" codes.
       This is very bad when edge triggered polling is used as is is not clear
       whether the "recv-ready" flag should be cleared.
       If the flag is cleared, but it should not (because the process has been
       "interrupted") then already pending data could be never processed.
       If the flag is not cleared, but it should be cleared (because all
       received data has been processed) then it would create busy-waiting loop.
       Use clear of "ready" flag as safer, but not ideal solution. */
    // TODO: replace "BIO" with custom version and track returned errors.
    return mhd_SOCKET_ERR_AGAIN;
  case SSL_ERROR_NONE:
    mhd_assert (0 && "Should not be possible");
    break;
  case SSL_ERROR_WANT_WRITE:
    mhd_assert (0 && "Should not be possible as re-handshakes are disallowed");
    break;
  case SSL_ERROR_SYSCALL:
    mhd_DBG_PRINT_TLS_ERRS ();
#ifndef NDEBUG
    c_tls->dbg.is_failed = true;
#endif /* ! NDEBUG */
    return mhd_SOCKET_ERR_CONN_BROKEN;
  case SSL_ERROR_SSL:
  default:
    break;
  }
  /* Treat all other kinds of errors as hard errors */
  mhd_DBG_PRINT_TLS_ERRS ();
#ifndef NDEBUG
  c_tls->dbg.is_failed = true;
#endif /* ! NDEBUG */
  return mhd_SOCKET_ERR_TLS;
}


MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_ bool
mhd_tls_open_conn_has_data_in (struct mhd_TlsOpenConnData *restrict c_tls)
{
  return 0 != SSL_pending (c_tls->sess);
}


MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_IN_SIZE_ (3,2)
MHD_FN_PAR_OUT_ (4) enum mhd_SocketError
mhd_tls_open_conn_send (struct mhd_TlsOpenConnData *restrict c_tls,
                        size_t buf_size,
                        const char buf[MHD_FN_PAR_DYN_ARR_SIZE_ (buf_size)],
                        size_t *restrict sent)
{
  int res;

  mhd_assert (c_tls->dbg.is_inited);
  mhd_assert (c_tls->dbg.is_tls_handshake_completed);
  mhd_assert (! c_tls->shut_tls_wr_sent);
  mhd_assert (! c_tls->dbg.is_failed);

  ERR_clear_error ();

  res = SSL_write_ex (c_tls->sess,
                      buf,
                      buf_size,
                      sent);
  if (1 == res)
  {
    mhd_assert (0 != *sent);
    return mhd_SOCKET_ERR_NO_ERROR; /* Success exit point */
  }

  mhd_assert (0 == res);
  *sent = 0;
  switch (SSL_get_error (c_tls->sess, res))
  {
  case SSL_ERROR_WANT_WRITE:
    /* OpenSSL does not distinguish between "interrupted" and "try again" codes.
       This is very bad when edge triggered polling is used as is is not clear
       whether the "send-ready" flag should be cleared.
       If the flag is cleared, but it should not (because the process has been
       "interrupted") then already pending data could be never sent.
       If the flag is not cleared, but it should be cleared (because the network
       is busy) then it would create busy-waiting loop.
       Use clear of "ready" flag as safer, but not ideal solution. */
    // TODO: replace "BIO" with custom version and track returned errors.
    return mhd_SOCKET_ERR_AGAIN;
  case SSL_ERROR_NONE:
    mhd_assert (0 && "Should not be possible");
    break;
  case SSL_ERROR_WANT_READ:
    mhd_assert (0 && "Should not be possible as re-handshakes are disallowed");
    break;
  case SSL_ERROR_ZERO_RETURN:
    mhd_assert (0 && "Should not be possible when sending");
    break;
  case SSL_ERROR_SYSCALL:
    mhd_DBG_PRINT_TLS_ERRS ();
#ifndef NDEBUG
    c_tls->dbg.is_failed = true;
#endif /* ! NDEBUG */
    return mhd_SOCKET_ERR_CONN_BROKEN;
  case SSL_ERROR_SSL:
  default:
    break;
  }
  /* Treat all other kinds of errors as hard errors */
  mhd_DBG_PRINT_TLS_ERRS ();
#ifndef NDEBUG
  c_tls->dbg.is_failed = true;
#endif /* ! NDEBUG */
  return mhd_SOCKET_ERR_TLS;
}
