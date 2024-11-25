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
 * @file src/mhd2/tls_gnu_funcs.c
 * @brief  The implementation of GnuTLS wrapper functions
 * @author Karlson2k (Evgeny Grin)
 */

#include "mhd_sys_options.h"

#include "sys_bool_type.h"
#include "sys_base_types.h"

#include <string.h>

#include "mhd_socket_type.h"
#include "mhd_str_types.h"

#include "mhd_str_macros.h"
#include "mhd_arr_num_elems.h"

#include "compat_calloc.h"
#include "sys_malloc.h"
#include "mhd_assert.h"

#include "mhd_conn_socket.h"

#include "tls_gnu_tls_lib.h"

#include "tls_gnu_daemon_data.h"
#include "tls_gnu_conn_data.h"
#include "tls_gnu_funcs.h"

#include "daemon_options.h"

#include "mhd_public_api.h"
#include "daemon_logger.h"

#ifdef  mhd_TLS_GNU_DH_PARAMS_NEEDS_PKCS3
#  include "tls_dh_params.h"
#endif

#ifdef mhd_USE_TLS_DEBUG_MESSAGES
#  include <stdio.h> /* For TLS debug printing */
#endif

struct mhd_TlsGnuDaemonData;    /* Forward declaration */

struct mhd_TlsGnuConnData;      /* Forward declaration */

#ifdef mhd_USE_TLS_DEBUG_MESSAGES
static void
mhd_tls_gnu_debug_print (int level, const char *msg)
{
  (void) fprintf (stderr, "## GnuTLS %02i: %s",
                  level,
                  msg);
  (void) fflush (stderr);
}


#endif /* mhd_USE_TLS_DEBUG_MESSAGES */

/* ** Global initialisation / de-initialisation ** */

static bool gnutls_lib_inited = false;

MHD_INTERNAL void
mhd_tls_gnu_global_init (void)
{
#ifdef GNUTLS_VERSION
  /* Make sure that used shared GnuTLS library has least the same version as
     MHD was configured for. Fail if the version is earlier. */
  gnutls_lib_inited = (NULL != gnutls_check_version (GNUTLS_VERSION));
#endif
  gnutls_lib_inited =
    gnutls_lib_inited && (GNUTLS_E_SUCCESS == gnutls_global_init ());

#ifdef mhd_USE_TLS_DEBUG_MESSAGES
  gnutls_global_set_log_function (&mhd_tls_gnu_debug_print);
  gnutls_global_set_log_level (2);
#endif
}


MHD_INTERNAL void
mhd_tls_gnu_global_deinit (void)
{
#ifdef mhd_USE_TLS_DEBUG_MESSAGES
  gnutls_global_set_log_level (0);
#endif

  if (gnutls_lib_inited)
    gnutls_global_deinit ();
  gnutls_lib_inited = false;
}


MHD_INTERNAL bool
mhd_tls_gnu_is_inited_fine (void)
{
  return gnutls_lib_inited;
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


/**
 * Initialise daemon TLS Diffie-Hellman parameters.
 *
 * This function initialise Diffie-Hellman parameters for the daemon based
 * on GnuTLS recommended defaults.
 * With modern GnuTLS versions this function is no-op and always succeed.
 *
 * This function does not put any messages to the log.
 * @param d_tls the daemon TLS data
 * @return 'true' if succeed,
 *         'false' if failed
 */
static MHD_FN_PAR_NONNULL_ALL_ MHD_FN_MUST_CHECK_RESULT_ bool
daemon_init_dh_data (struct mhd_TlsGnuDaemonData *restrict d_tls)
{
#if defined(mhd_TLS_GNU_DH_PARAMS_USE_KNOWN)
  /* Rely on reasonable TLS defaults set in the TLS library.
     Modern GnuTLS versions relies completely on RFC 7919 and do not need
     this function therefore do not bother implementing special
     application-defined settings just for limited number of GnuTLS
     versions (>= 3.5.6 && < 3.6.0). */
  return (GNUTLS_E_SUCCESS ==
          gnutls_certificate_set_known_dh_params (d_tls->cred,
                                                  GNUTLS_SEC_PARAM_MEDIUM));
#elif defined(mhd_TLS_GNU_DH_PARAMS_NEEDS_PKCS3)
  gnutls_datum_t dh_data;
  if (GNUTLS_E_SUCCESS  !=
      gnutls_dh_params_init (&(d_tls->dh_params)))
    return false;

  dh_data.data = mhd_DROP_CONST (mhd_tls_dh_params_pkcs3);
  dh_data.size = sizeof (mhd_tls_dh_params_pkcs3);
  if (GNUTLS_E_SUCCESS ==
      gnutls_dh_params_import_pkcs3 (d_tls->dh_params,
                                     &dh_data,
                                     GNUTLS_X509_FMT_PEM))
  {
    gnutls_certificate_set_dh_params (d_tls->cred,
                                      d_tls->dh_params);
    return true; /* success exit point */
  }
  /* Below is a clean-up code path */
  gnutls_dh_params_deinit (d_tls->dh_params);
  return false;
#else
  (void) d_tls; /* Mute compiler warning */
  return true;
#endif
}


/**
 * De-initialise daemon TLS Diffie-Hellman parameters.
 * @param d_tls the daemon TLS data
 */
static MHD_FN_PAR_NONNULL_ALL_ void
daemon_deinit_dh_data (struct mhd_TlsGnuDaemonData *restrict d_tls)
{
#if defined(mhd_TLS_GNU_DH_PARAMS_NEEDS_PKCS3)
  mhd_assert (NULL != d_tls->dh_params);
  gnutls_dh_params_deinit (d_tls->dh_params);
#else
  (void) d_tls; /* Mute compiler warning */
#endif
}


/**
 * Set daemon TLS credentials (and Diffie-Hellman parameters).
 * This function puts error messages to the log if needed.
 * @param d the daemon handle
 * @param d_tls the daemon TLS settings
 * @param s the application-provided settings
 * @return #MHD_SC_OK on success,
 *         error code otherwise
 */
static MHD_FN_PAR_NONNULL_ALL_ MHD_FN_MUST_CHECK_RESULT_ enum MHD_StatusCode
daemon_init_credentials (struct MHD_Daemon *restrict d,
                         struct mhd_TlsGnuDaemonData *restrict d_tls,
                         struct DaemonOptions *restrict s)
{
  enum MHD_StatusCode ret;
  size_t cert_len;
  size_t key_len;

  if (GNUTLS_E_SUCCESS !=
      gnutls_certificate_allocate_credentials (&(d_tls->cred)))
  {
    mhd_LOG_MSG (d, MHD_SC_TLS_DAEMON_INIT_FAILED, \
                 "Failed to initialise TLS credentials for the daemon");
    return MHD_SC_TLS_DAEMON_INIT_FAILED;
  }

  // TODO: Support multiple certificates
  cert_len = strlen (s->tls_cert_key.v_mem_cert); // TODO: Reuse calculated length
  key_len = strlen (s->tls_cert_key.v_mem_key);   // TODO: Reuse calculated length

  mhd_assert (0 != cert_len);
  mhd_assert (0 != key_len);

  if ((cert_len != (unsigned int) cert_len)
      || (key_len != (unsigned int) key_len))
    ret = MHD_SC_TLS_CONF_BAD_CERT; /* Very unlikely, do not waste space on special message */
  else
  {
    gnutls_datum_t cert_data;
    gnutls_datum_t key_data;
    int res;

    cert_data.data = mhd_DROP_CONST (s->tls_cert_key.v_mem_cert);
    cert_data.size = (unsigned int) cert_len;
    key_data.data = mhd_DROP_CONST (s->tls_cert_key.v_mem_key);
    key_data.size = (unsigned int) key_len;
    res = gnutls_certificate_set_x509_key_mem2 (d_tls->cred,
                                                &cert_data,
                                                &key_data,
                                                GNUTLS_X509_FMT_PEM,
                                                s->tls_cert_key.v_mem_pass,
                                                0);
    if (0 > res)
    {
      mhd_LOG_PRINT (d, \
                     MHD_SC_TLS_CONF_BAD_CERT, \
                     mhd_LOG_FMT ("Failed to set the provided " \
                                  "TLS certificate: %s"),
                     gnutls_strerror (res));
      ret = MHD_SC_TLS_CONF_BAD_CERT;
    }
    else
    {
      if (! daemon_init_dh_data (d_tls))
      {
        mhd_LOG_MSG (d, MHD_SC_TLS_DAEMON_INIT_FAILED, \
                     "Failed to initialise Diffie-Hellman parameters " \
                     "for the daemon");
        ret = MHD_SC_TLS_DAEMON_INIT_FAILED;
      }
      else
        return MHD_SC_OK;
    }
  }

  gnutls_certificate_free_credentials (d_tls->cred);
  mhd_assert (MHD_SC_OK != ret);
  return ret; /* Failure exit point */
}


/**
 * Free daemon fully allocated credentials (and Diffie-Hellman parameters).
 * @param d_tls the daemon TLS settings
 */
static MHD_FN_PAR_NONNULL_ALL_ void
daemon_deinit_credentials (struct mhd_TlsGnuDaemonData *restrict d_tls)
{
  mhd_assert (NULL != d_tls->cred);
  /* To avoid dangling pointer to DH data in the credentials,
     free credentials first and then free DH data. */
  gnutls_certificate_free_credentials (d_tls->cred);
  daemon_deinit_dh_data (d_tls);
}


static const struct MHD_StringNullable tlsgnulib_base_priorities[] = {
  {0, NULL} /* Replaced with app-defined name */
  ,
  /* Do not use "multi-keyword": if the first configuration is found, but has
     some error, the next configuration is not tried. */
#if 0 /* ifdef mhd_TLS_GNU_SUPPORTS_MULTI_KEYWORDS_PRIORITY */
  mhd_MSTR_INIT ("@LIBMICROHTTPD,SYSTEM")
#else
  mhd_MSTR_INIT ("@LIBMICROHTTPD")
  ,
  mhd_MSTR_INIT ("@SYSTEM")
#endif
  ,
  {0, NULL}
  ,
  mhd_MSTR_INIT ("NORMAL")
};

/**
 * Initialise GnuTLS priorities cache
 * @param d the daemon handle
 * @param d_tls the daemon TLS settings
 * @param s the application-provided settings
 * @return #MHD_SC_OK on success,
 *         error code otherwise
 */
static MHD_FN_PAR_NONNULL_ALL_ MHD_FN_MUST_CHECK_RESULT_ enum MHD_StatusCode
daemon_init_priorities_cache (struct MHD_Daemon *restrict d,
                              struct mhd_TlsGnuDaemonData *restrict d_tls,
                              struct DaemonOptions *restrict s)
{
  size_t i;

  (void) s; // TODO: support app-defined name for TLS backend profile

  for (i = 0; i < mhd_ARR_NUM_ELEMS (tlsgnulib_base_priorities); ++i)
  {
    int res;

    if (0 == i)
      continue; // TODO: support app-defined name for TLS backend profile
#if ! defined(mhd_TLS_GNU_TREATS_NULL_AS_DEF_PRIORITY)
    if (NULL == tlsgnulib_base_priorities[i].cstr)
    {
      /* GnuTLS default priorities */
#  if defined(mhd_TLS_GNU_NULL_PRIO_CACHE_MEANS_DEF_PRIORITY)
      d_tls->pri_cache = NULL;
      break;
#  else
      continue; /* "default" priorities cannot be used */
#  endif
    }
#endif /* ! mhd_TLS_GNU_TREATS_NULL_AS_DEF_PRIORITY */
    res = gnutls_priority_init (&(d_tls->pri_cache),
                                tlsgnulib_base_priorities[i].cstr,
                                NULL);
    if (GNUTLS_E_SUCCESS == res)
      break;
    if (GNUTLS_E_MEMORY_ERROR == res)
      return MHD_SC_DAEMON_MALLOC_FAILURE;
  }

  if (i < mhd_ARR_NUM_ELEMS (tlsgnulib_base_priorities))
    return MHD_SC_OK; /* Success exit point */

  mhd_LOG_MSG (d, MHD_SC_TLS_DAEMON_INIT_FAILED, \
               "Failed to initialise TLS priorities cache");
  return MHD_SC_TLS_DAEMON_INIT_FAILED;
}


/**
 * De-initialise priorities cache
 * @param d_tls the daemon TLS settings
 */
static MHD_FN_PAR_NONNULL_ALL_ void
daemon_deinit_priorities_cache (struct mhd_TlsGnuDaemonData *restrict d_tls)
{
#if ! defined(mhd_TLS_GNU_NULL_PRIO_CACHE_MEANS_DEF_PRIORITY)
  mhd_assert (NULL != d_tls->pri_cache);
#else
  if (NULL != d_tls->pri_cache)
#endif
  gnutls_priority_deinit (d_tls->pri_cache);
}


MHD_INTERNAL MHD_FN_MUST_CHECK_RESULT_ MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_OUT_ (3) mhd_StatusCodeInt
mhd_tls_gnu_daemon_init (struct MHD_Daemon *restrict d,
                         struct DaemonOptions *restrict s,
                         struct mhd_TlsGnuDaemonData **restrict p_d_tls)
{
  mhd_StatusCodeInt res;
  struct mhd_TlsGnuDaemonData *restrict d_tls;

  res = check_app_tls_sessings (d, s);
  if (MHD_SC_OK != res)
    return res;

  d_tls = (struct mhd_TlsGnuDaemonData *)
          mhd_calloc (1, sizeof (struct mhd_TlsGnuDaemonData));
  *p_d_tls = d_tls;
  if (NULL == d_tls)
    return MHD_SC_DAEMON_MALLOC_FAILURE;

  res = daemon_init_credentials (d,
                                 d_tls,
                                 s);
  if (MHD_SC_OK == res)
  {
    res = daemon_init_priorities_cache (d,
                                        d_tls,
                                        s);
    if (MHD_SC_OK == res)
      return MHD_SC_OK; /* Success exit point */

    /* Below is a clean-up code path */
    daemon_deinit_credentials (d_tls);
  }

  free (d_tls);
  *p_d_tls = NULL;
  mhd_assert (MHD_SC_OK != res);
  return res;
}


MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_INOUT_ (1) void
mhd_tls_gnu_daemon_deinit (struct mhd_TlsGnuDaemonData *restrict d_tls)
{
  mhd_assert (NULL != d_tls);
  daemon_deinit_priorities_cache (d_tls);
  daemon_deinit_credentials (d_tls);
  free (d_tls);
}


/* ** Connection initialisation / de-initialisation ** */

MHD_INTERNAL size_t
mhd_tls_gnu_conn_get_tls_size (void)
{
  return sizeof (struct mhd_TlsGnuConnData);
}


MHD_INTERNAL MHD_FN_MUST_CHECK_RESULT_ MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_OUT_ (3) bool
mhd_tls_gnu_conn_init (const struct mhd_TlsGnuDaemonData *restrict d_tls,
                       const struct mhd_ConnSocket *sk,
                       struct mhd_TlsGnuConnData *restrict c_tls)
{
  unsigned int c_flags;
  int res;

  c_flags = GNUTLS_SERVER;
#if GNUTLS_VERSION_NUMBER >= 0x030000
  /* Note: the proper support for the blocking sockets may require use of
     gnutls_handshake_set_timeout() and
     gnutls_transport_set_pull_timeout_function() (the latter is not actually
     required for the modern GnuTLS versions at least) */
  if (sk->props.is_nonblck)
    c_flags |= GNUTLS_NONBLOCK;
#endif
#ifdef mhd_TLS_GNU_HAS_NO_SIGNAL
  c_flags |= GNUTLS_NO_SIGNAL;
#endif

  if (GNUTLS_E_SUCCESS !=
      gnutls_init (&(c_tls->sess),
                   c_flags))
    return false;

#if GNUTLS_VERSION_NUMBER >= 0x030100
  if (! sk->props.is_nonblck)
    gnutls_handshake_set_timeout (c_tls->sess,
                                  GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
#endif
#if ! defined(mhd_TLS_GNU_NULL_PRIO_CACHE_MEANS_DEF_PRIORITY)
  mhd_assert (NULL != d_tls->pri_cache);
#else
  if (NULL == d_tls->pri_cache)
    res = gnutls_set_default_priority (c_tls->sess);
  else
#endif
  res = gnutls_priority_set (c_tls->sess,
                             d_tls->pri_cache);

  if (GNUTLS_E_SUCCESS == res)
  {
    if (GNUTLS_E_SUCCESS ==
        gnutls_credentials_set (c_tls->sess,
                                GNUTLS_CRD_CERTIFICATE,
                                d_tls->cred))
    {
#ifdef mhd_TLS_GNU_HAS_TRANSP_SET_INT
      if (sizeof(int) == sizeof(MHD_Socket))
        gnutls_transport_set_int (c_tls->sess,
                                  (int) sk->fd);
#endif /* mhd_TLS_GNU_HAS_TRANSP_SET_INT */
      gnutls_transport_set_ptr (c_tls->sess,
                                (void *) sk->fd);

      /* The basic TLS session properties has been set.
         The rest is optional settings. */
#ifdef mhd_TLS_GNU_HAS_ALPN
      if (1)
      {
        static const char alpn_http_1_0[] = "http/1.0"; /* Registered value for HTTP/1.0 */
        static const char alpn_http_1_1[] = "http/1.1"; /* Registered value for HTTP/1.1 */
#  if 0 /* Disabled code */
        static const char alpn_http_2[] = "h2"; /* Registered value for HTTP/2 over TLS */
        static const char alpn_http_3[] = "h3"; /* Registered value for HTTP/3 */
#  endif
        gnutls_datum_t prots[] = {
          { mhd_DROP_CONST (alpn_http_1_1), mhd_SSTR_LEN (alpn_http_1_1) }
          ,
          { mhd_DROP_CONST (alpn_http_1_0), mhd_SSTR_LEN (alpn_http_1_0) }
        };
        unsigned int alpn_flags;
        int alpn_res;

        alpn_flags = 0;
#  if 0
        alpn_flags |= GNUTLS_ALPN_SERVER_PRECEDENCE;
#  endif

        alpn_res =
          gnutls_alpn_set_protocols (c_tls->sess,
                                     prots,
                                     (unsigned int) mhd_ARR_NUM_ELEMS (prots),
                                     alpn_flags);
        (void) alpn_res; /* Ignore any possible ALPN set errors */
      }
#endif /* mhd_TLS_GNU_HAS_ALPN */
#ifndef NDEBUG
      c_tls->dbg.is_inited = true;
#endif /* ! NDEBUG */

      return true; /* Success exit point */
    }
    /* Below is a clean-up code path */
  }

  gnutls_deinit (c_tls->sess);
  return false; /* Failure exit point */
}


/**
 * De-initialise connection TLS settings.
 * The provided pointer is not freed/deallocated.
 * @param c_tls the initialised connection TLS settings
 */
MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_ void
mhd_tls_gnu_conn_deinit (struct mhd_TlsGnuConnData *restrict c_tls)
{
  mhd_assert (NULL != c_tls->sess);
  mhd_assert (c_tls->dbg.is_inited);
  gnutls_deinit (c_tls->sess);
}


/* ** TLS connection establishing ** */

MHD_INTERNAL MHD_FN_MUST_CHECK_RESULT_ MHD_FN_PAR_NONNULL_ALL_
enum mhd_TlsProcedureResult
mhd_tls_gnu_conn_handshake (struct mhd_TlsGnuConnData *restrict c_tls)
{
  int res;

  mhd_assert (c_tls->dbg.is_inited);
  mhd_assert (! c_tls->dbg.is_tls_handshake_completed);
  mhd_assert (! c_tls->dbg.is_failed);

  res = gnutls_handshake (c_tls->sess);
  switch (res)
  {
  case GNUTLS_E_SUCCESS:
#ifndef NDEBUG
    c_tls->dbg.is_tls_handshake_completed = true;
#endif /* ! NDEBUG */
    return mhd_TLS_PROCED_SUCCESS;
  case GNUTLS_E_INTERRUPTED:
  case GNUTLS_E_AGAIN:
  case GNUTLS_E_WARNING_ALERT_RECEIVED: /* Ignore any warning for now */
    if (1)
    {
      int is_sending;

      is_sending = gnutls_record_get_direction (c_tls->sess);
      if (GNUTLS_E_INTERRUPTED == res)
        return is_sending ?
               mhd_TLS_PROCED_SEND_INTERRUPTED :
               mhd_TLS_PROCED_RECV_INTERRUPTED;
      return is_sending ?
             mhd_TLS_PROCED_SEND_MORE_NEEDED :
             mhd_TLS_PROCED_RECV_MORE_NEEDED;
    }
    break;
  default:
    break;
  }
#ifndef NDEBUG
  c_tls->dbg.is_failed = true;
#endif /* ! NDEBUG */
  return mhd_TLS_PROCED_FAILED;
}


MHD_INTERNAL MHD_FN_MUST_CHECK_RESULT_ MHD_FN_PAR_NONNULL_ALL_
enum mhd_TlsProcedureResult
mhd_tls_gnu_conn_shutdown (struct mhd_TlsGnuConnData *restrict c_tls)
{
  int res;

  mhd_assert (c_tls->dbg.is_inited);
  mhd_assert (c_tls->dbg.is_tls_handshake_completed);
  mhd_assert (! c_tls->dbg.is_failed);

  res = gnutls_bye (c_tls->sess,
                    c_tls->rmt_shut_tls_wr ? GNUTLS_SHUT_WR : GNUTLS_SHUT_RDWR);
  switch (res)
  {
  case GNUTLS_E_SUCCESS:
#ifndef NDEBUG
    c_tls->dbg.is_finished = true;
#endif /* ! NDEBUG */
    return mhd_TLS_PROCED_SUCCESS;
  case GNUTLS_E_INTERRUPTED:
  case GNUTLS_E_AGAIN:
  case GNUTLS_E_WARNING_ALERT_RECEIVED: /* Ignore any warning for now */
    if (1)
    {
      int is_sending;

      is_sending = gnutls_record_get_direction (c_tls->sess);
      if (GNUTLS_E_INTERRUPTED == res)
        return is_sending ?
               mhd_TLS_PROCED_SEND_INTERRUPTED :
               mhd_TLS_PROCED_RECV_INTERRUPTED;
      return is_sending ?
             mhd_TLS_PROCED_SEND_MORE_NEEDED :
             mhd_TLS_PROCED_RECV_MORE_NEEDED;
    }
    break;
  default:
    break;
  }
#ifndef NDEBUG
  c_tls->dbg.is_failed = true;
#endif /* ! NDEBUG */
  return mhd_TLS_PROCED_FAILED;
}


/* ** Data receiving and sending ** */

MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_OUT_SIZE_ (3,2)
MHD_FN_PAR_OUT_ (4) enum mhd_SocketError
mhd_tls_gnu_conn_recv (struct mhd_TlsGnuConnData *restrict c_tls,
                       size_t buf_size,
                       char buf[MHD_FN_PAR_DYN_ARR_SIZE_ (buf_size)],
                       size_t *restrict received)
{
  ssize_t res;

  mhd_assert (c_tls->dbg.is_inited);
  mhd_assert (c_tls->dbg.is_tls_handshake_completed);
  mhd_assert (! c_tls->dbg.is_failed);

  /* Check for GnuTLS return value limitation */
  if (0 > (ssize_t) buf_size)
    buf_size = (ssize_t) ((~((size_t) 0u)) >> 1); /* SSIZE_MAX */

  res = gnutls_record_recv (c_tls->sess,
                            buf,
                            buf_size);
  if (0 >= res)
  {
    *received = 0;
    switch (res)
    {
    case 0: /* Not an error */
      c_tls->rmt_shut_tls_wr = true;
      return mhd_SOCKET_ERR_NO_ERROR;
    case GNUTLS_E_AGAIN:
      return mhd_SOCKET_ERR_AGAIN;
    case GNUTLS_E_INTERRUPTED:
      return mhd_SOCKET_ERR_INTR;
    case GNUTLS_E_PREMATURE_TERMINATION:
      return mhd_SOCKET_ERR_CONNRESET;
    default:
      break;
    }
    /* Treat all other kinds of errors as hard errors */
#ifndef NDEBUG
    c_tls->dbg.is_failed = true;
#endif /* ! NDEBUG */
    return mhd_SOCKET_ERR_TLS;
  }

  *received = (size_t) res;
  return mhd_SOCKET_ERR_NO_ERROR;
}


MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_ bool
mhd_tls_gnu_conn_has_data_in (struct mhd_TlsGnuConnData *restrict c_tls)
{
  return 0 != gnutls_record_check_pending (c_tls->sess);
}


MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_IN_SIZE_ (3,2)
MHD_FN_PAR_OUT_ (4) enum mhd_SocketError
mhd_tls_gnu_conn_send (struct mhd_TlsGnuConnData *restrict c_tls,
                       size_t buf_size,
                       const char buf[MHD_FN_PAR_DYN_ARR_SIZE_ (buf_size)],
                       size_t *restrict sent)
{
  ssize_t res;

  mhd_assert (c_tls->dbg.is_inited);
  mhd_assert (c_tls->dbg.is_tls_handshake_completed);
  mhd_assert (! c_tls->dbg.is_failed);

  /* Check for GnuTLS return value limitation */
  if (0 > (ssize_t) buf_size)
    buf_size = (ssize_t) ((~((size_t) 0u)) >> 1); /* SSIZE_MAX */

  res = gnutls_record_send (c_tls->sess,
                            buf,
                            buf_size);

  mhd_assert (0 != res);

  if (0 > res)
  {
    *sent = 0;
    switch (res)
    {
    case GNUTLS_E_AGAIN:
      return mhd_SOCKET_ERR_AGAIN;
    case GNUTLS_E_INTERRUPTED:
      return mhd_SOCKET_ERR_INTR;
    case GNUTLS_E_PREMATURE_TERMINATION:
      return mhd_SOCKET_ERR_CONNRESET;
    default:
      break;
    }
    /* Treat all other kinds of errors as hard errors */
#ifndef NDEBUG
    c_tls->dbg.is_failed = true;
#endif /* ! NDEBUG */
    return mhd_SOCKET_ERR_TLS;
  }

  *sent = (size_t) res;
  return mhd_SOCKET_ERR_NO_ERROR;
}
