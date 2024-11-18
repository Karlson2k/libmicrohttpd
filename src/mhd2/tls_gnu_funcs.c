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

#include "mhd_str_types.h"
#include "mhd_str_macros.h"
#include "mhd_arr_num_elems.h"

#include "compat_calloc.h"
#include "sys_malloc.h"
#include "mhd_assert.h"

#include "tls_gnu_tls_lib.h"

#include "tls_gnu_daemon_data.h"
#include "tls_gnu_funcs.h"

#include "daemon_options.h"

#include "mhd_public_api.h"
#include "daemon_logger.h"

#ifdef  mhd_TLS_GNU_DH_PARAMS_NEEDS_PKCS3
#  include "tls_dh_params.h"
#endif

struct mhd_DaemonTlsGnuData;    /* Forward declaration */

struct mhd_ConnTlsGnuData;      /* Forward declaration */


/* ** Global initialisation ** */

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
}


MHD_INTERNAL void
mhd_tls_gnu_global_deinit (void)
{
  if (gnutls_lib_inited)
    gnutls_global_deinit ();
  gnutls_lib_inited = false;
}


MHD_INTERNAL bool
mhd_tls_gnu_is_inited_fine (void)
{
  return gnutls_lib_inited;
}


/* ** Daemon initialisation ** */

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
  mhd_assert (MHD_TLS_BACKEND_NONE == s->tls);
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
daemon_init_dh_data (struct mhd_DaemonTlsGnuData *restrict d_tls)
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
daemon_deinit_dh_data (struct mhd_DaemonTlsGnuData *restrict d_tls)
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
                         struct mhd_DaemonTlsGnuData *restrict d_tls,
                         struct DaemonOptions *restrict s)
{
  enum MHD_StatusCode res;
  size_t cert_len;
  size_t key_len;

  if (GNUTLS_E_SUCCESS !=
      gnutls_certificate_allocate_credentials (&(d_tls->cred)))
  {
    mhd_LOG_MSG (d, MHD_SC_DAEMON_TLS_INIT_FAILED, \
                 "Failed to initialise TLS credentials for the daemon");
    return MHD_SC_DAEMON_TLS_INIT_FAILED;
  }

  // TODO: Support multiple certificates
  cert_len = strlen (s->tls_cert_key.v_mem_cert) + 1; // TODO: Reuse calculated length
  key_len = strlen (s->tls_cert_key.v_mem_key) + 1;   // TODO: Reuse calculated length

  if (((unsigned int) cert_len != cert_len)
      || ((unsigned int) key_len != key_len))
    res = MHD_SC_TLS_CONF_BAD_CERT; /* Very unlikely, do not waste space on special message */
  else
  {
    gnutls_datum_t cert_data;
    gnutls_datum_t key_data;

    cert_data.data = mhd_DROP_CONST (s->tls_cert_key.v_mem_cert);
    cert_data.size = (unsigned int) cert_len;
    key_data.data = mhd_DROP_CONST (s->tls_cert_key.v_mem_key);
    key_data.size = (unsigned int) key_len;
    if (0 >
        gnutls_certificate_set_x509_key_mem2 (d_tls->cred,
                                              &cert_data,
                                              &key_data,
                                              GNUTLS_X509_FMT_PEM,
                                              s->tls_cert_key.v_mem_pass,
                                              0))
    {
      mhd_LOG_MSG (d, MHD_SC_TLS_CONF_BAD_CERT, \
                   "Failed to set the provided TLS certificate");
      res = MHD_SC_TLS_CONF_BAD_CERT;
    }
    else
    {
      if (! daemon_init_dh_data (d_tls))
      {
        mhd_LOG_MSG (d, MHD_SC_DAEMON_TLS_INIT_FAILED, \
                     "Failed to initialise Diffie-Hellman parameters " \
                     "for the daemon");
        res = MHD_SC_DAEMON_TLS_INIT_FAILED;
      }
      else
        return MHD_SC_OK;
    }
  }

  gnutls_certificate_free_credentials (d_tls->cred);
  mhd_assert (MHD_SC_OK != res);
  return res; /* Failure exit point */
}


/**
 * Free daemon fully allocated credentials (and Diffie-Hellman parameters).
 * @param d_tls the daemon TLS settings
 */
static MHD_FN_PAR_NONNULL_ALL_ void
daemon_deinit_credentials (struct mhd_DaemonTlsGnuData *restrict d_tls)
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
#ifdef mhd_TLS_GNU_SUPPORTS_MULTI_KEYWORDS_PRIORITY
  mhd_MSTR_INIT ("@LIBMICROHTTPD,@SYSTEM")
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
                              struct mhd_DaemonTlsGnuData *restrict d_tls,
                              struct DaemonOptions *restrict s)
{
  size_t i;

  (void) s; // TODO: support app-defined name for TLS backend profile

  for (i = 0; i < mhd_ARR_NUM_ELEMS (tlsgnulib_base_priorities); ++i)
  {
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
    if (GNUTLS_E_SUCCESS ==
        gnutls_priority_init (&(d_tls->pri_cache),
                              tlsgnulib_base_priorities[i].cstr,
                              NULL))
      break;
  }

  if (i < mhd_ARR_NUM_ELEMS (tlsgnulib_base_priorities))
    return MHD_SC_OK; /* Success exit point */

  mhd_LOG_MSG (d, MHD_SC_DAEMON_TLS_INIT_FAILED, \
               "Failed to initialise TLS priorities cache");
  return MHD_SC_DAEMON_TLS_INIT_FAILED;
}


/**
 * De-initialise priorities cache
 * @param d_tls the daemon TLS settings
 */
static MHD_FN_PAR_NONNULL_ALL_ void
daemon_deinit_priorities_cache (struct mhd_DaemonTlsGnuData *restrict d_tls)
{
#if ! defined(mhd_TLS_GNU_NULL_PRIO_CACHE_MEANS_DEF_PRIORITY)
  mhd_assert (NULL != d_tls->pri_cache);
#else
  if (NULL != d_tls->pri_cache)
#endif
  gnutls_priority_deinit (d_tls->pri_cache);
}


MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_OUT_ (2) mhd_StatusCodeInt
mhd_tls_gnu_daemon_init (struct MHD_Daemon *restrict d,
                         struct mhd_DaemonTlsGnuData **restrict p_d_tls,
                         struct DaemonOptions *restrict s)
{
  mhd_StatusCodeInt res;
  struct mhd_DaemonTlsGnuData *restrict d_tls;

  res = check_app_tls_sessings (d, s);
  if (MHD_SC_OK != res)
    return res;

  d_tls = (struct mhd_DaemonTlsGnuData *)
          mhd_calloc (1, sizeof (struct mhd_DaemonTlsGnuData));
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
mhd_tls_gnu_daemon_deinit (struct mhd_DaemonTlsGnuData *restrict d_tls)
{
  mhd_assert (NULL != d_tls);
  daemon_deinit_priorities_cache (d_tls);
  daemon_deinit_credentials (d_tls);
  free (d_tls);
}
