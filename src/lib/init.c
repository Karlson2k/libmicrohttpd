/*
  This file is part of libmicrohttpd
  Copyright (C) 2007-2018 Daniel Pittman and Christian Grothoff

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
 * @file lib/init.c
 * @brief initialization routines
 * @author Christian Grothoff
 */
#include "internal.h"
#include "init.h"


#ifdef MHD_HTTPS_REQUIRE_GRYPT
#if defined(HTTPS_SUPPORT) && GCRYPT_VERSION_NUMBER < 0x010600
#if defined(MHD_USE_POSIX_THREADS)
GCRY_THREAD_OPTION_PTHREAD_IMPL;
#elif defined(MHD_W32_MUTEX_)

static int
gcry_w32_mutex_init (void **ppmtx)
{
  *ppmtx = malloc (sizeof (MHD_mutex_));

  if (NULL == *ppmtx)
    return ENOMEM;
  if (!MHD_mutex_init_ ((MHD_mutex_*)*ppmtx))
    {
      free (*ppmtx);
      *ppmtx = NULL;
      return EPERM;
    }

  return 0;
}


static int
gcry_w32_mutex_destroy (void **ppmtx)
{
  int res = (MHD_mutex_destroy_ ((MHD_mutex_*)*ppmtx)) ? 0 : EINVAL;
  free (*ppmtx);
  return res;
}


static int
gcry_w32_mutex_lock (void **ppmtx)
{
  return MHD_mutex_lock_ ((MHD_mutex_*)*ppmtx) ? 0 : EINVAL;
}


static int
gcry_w32_mutex_unlock (void **ppmtx)
{
  return MHD_mutex_unlock_ ((MHD_mutex_*)*ppmtx) ? 0 : EINVAL;
}


static struct gcry_thread_cbs gcry_threads_w32 = {
  (GCRY_THREAD_OPTION_USER | (GCRY_THREAD_OPTION_VERSION << 8)),
  NULL, gcry_w32_mutex_init, gcry_w32_mutex_destroy,
  gcry_w32_mutex_lock, gcry_w32_mutex_unlock,
  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL };

#endif /* defined(MHD_W32_MUTEX_) */
#endif /* HTTPS_SUPPORT && GCRYPT_VERSION_NUMBER < 0x010600 */
#endif /* MHD_HTTPS_REQUIRE_GRYPT */


#ifndef _AUTOINIT_FUNCS_ARE_SUPPORTED

/**
 * Track global initialisation
 */
volatile int global_init_count = 0;
#ifdef MHD_MUTEX_STATIC_DEFN_INIT_
/**
 * Global initialisation mutex
 */
MHD_MUTEX_STATIC_DEFN_INIT_(global_init_mutex_);
#endif /* MHD_MUTEX_STATIC_DEFN_INIT_ */

#endif


/**
 * Check whether global initialisation was performed
 * and call initialiser if necessary.
 */
void
MHD_check_global_init_ (void)
{
#ifdef MHD_MUTEX_STATIC_DEFN_INIT_
  MHD_mutex_lock_chk_(&global_init_mutex_);
#endif /* MHD_MUTEX_STATIC_DEFN_INIT_ */
  if (0 == global_init_count++)
    MHD_init ();
#ifdef MHD_MUTEX_STATIC_DEFN_INIT_
  MHD_mutex_unlock_chk_(&global_init_mutex_);
#endif /* MHD_MUTEX_STATIC_DEFN_INIT_ */
}


/**
 * Default implementation of the panic function,
 * prints an error message and aborts.
 *
 * @param cls unused
 * @param file name of the file with the problem
 * @param line line number with the problem
 * @param reason error message with details
 */
static void
mhd_panic_std (void *cls,
	       const char *file,
	       unsigned int line,
	       const char *reason)
{
  (void)cls; /* Mute compiler warning. */
#ifdef HAVE_MESSAGES
  fprintf (stderr,
           _("Fatal error in GNU libmicrohttpd %s:%u: %s\n"),
	   file,
           line,
           reason);
#else  /* ! HAVE_MESSAGES */
  (void)file;   /* Mute compiler warning. */
  (void)line;   /* Mute compiler warning. */
  (void)reason; /* Mute compiler warning. */
#endif
  abort ();
}


/**
 * Initialize do setup work.
 */
void
MHD_init(void)
{
#if defined(_WIN32) && ! defined(__CYGWIN__)
  WSADATA wsd;
#endif /* _WIN32 && ! __CYGWIN__ */

  if (NULL == mhd_panic)
    mhd_panic = &mhd_panic_std;

#if defined(_WIN32) && ! defined(__CYGWIN__)
  if (0 != WSAStartup(MAKEWORD(2, 2), &wsd))
    MHD_PANIC (_("Failed to initialize winsock\n"));
  mhd_winsock_inited_ = 1;
  if (2 != LOBYTE(wsd.wVersion) && 2 != HIBYTE(wsd.wVersion))
    MHD_PANIC (_("Winsock version 2.2 is not available\n"));
#endif
#ifdef HTTPS_SUPPORT
#ifdef MHD_HTTPS_REQUIRE_GRYPT
#if GCRYPT_VERSION_NUMBER < 0x010600
#if defined(MHD_USE_POSIX_THREADS)
  if (0 != gcry_control (GCRYCTL_SET_THREAD_CBS,
                         &gcry_threads_pthread))
    MHD_PANIC (_("Failed to initialise multithreading in libgcrypt\n"));
#elif defined(MHD_W32_MUTEX_)
  if (0 != gcry_control (GCRYCTL_SET_THREAD_CBS,
                         &gcry_threads_w32))
    MHD_PANIC (_("Failed to initialise multithreading in libgcrypt\n"));
#endif /* defined(MHD_W32_MUTEX_) */
  gcry_check_version (NULL);
#else
  if (NULL == gcry_check_version ("1.6.0"))
    MHD_PANIC (_("libgcrypt is too old. MHD was compiled for libgcrypt 1.6.0 or newer\n"));
#endif
#endif /* MHD_HTTPS_REQUIRE_GRYPT */
  gnutls_global_init ();
#endif /* HTTPS_SUPPORT */
  MHD_monotonic_sec_counter_init();
#ifdef HAVE_FREEBSD_SENDFILE
  MHD_conn_init_static_ ();
#endif /* HAVE_FREEBSD_SENDFILE */
}


void
MHD_fini(void)
{
#ifdef HTTPS_SUPPORT
  gnutls_global_deinit ();
#endif /* HTTPS_SUPPORT */
#if defined(_WIN32) && ! defined(__CYGWIN__)
  if (mhd_winsock_inited_)
    WSACleanup();
#endif
  MHD_monotonic_sec_counter_finish();
}

#ifdef _AUTOINIT_FUNCS_ARE_SUPPORTED
_SET_INIT_AND_DEINIT_FUNCS(MHD_init, MHD_fini);
#endif /* _AUTOINIT_FUNCS_ARE_SUPPORTED */
