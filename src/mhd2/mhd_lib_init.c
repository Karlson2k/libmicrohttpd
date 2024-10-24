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
 * @file src/mhd2/mhd_lib_init.c
 * @brief  Library global initialisers and de-initialisers
 * @author Karlson2k (Evgeny Grin)
 */
#include "mhd_sys_options.h"

#include "mhd_panic.h"

#include "sys_base_types.h"
#include "sys_bool_type.h"

#include "mhd_locks.h"

#include "mhd_socket_type.h"
#ifdef MHD_SOCKETS_KIND_WINSOCK
#  include <winsock2.h>
#endif

#include "mhd_assert.h"

#ifndef NDEBUG
#  include <stdio.h>  /* For debug error reporting */
#  include <stdlib.h> /* For debug error exit */
#endif

#include "mhd_mono_clock.h"
#include "mhd_send.h"

#include "mhd_lib_init.h"
#include "mhd_lib_init_auto.h"


#if defined(mhd_AUTOINIT_FUNCS_USE)
/**
 * The function is automatically called to perform global lazy initialisation
 */
#  define mhd_INIT_LAZY_BY_FUNC         1
#elif defined(mhd_MUTEX_INITIALISER_STAT)
/**
 * Global lazy initialisation is performed by defined variables with static
 * initialisation values
 */
#  define mhd_INIT_LAZY_BY_STATIC       1
#endif

#if defined(mhd_INIT_LAZY_BY_FUNC) || defined(mhd_INIT_LAZY_BY_STATIC)
/**
 * Global lazy initialisation is automatic
 */
#  define mhd_INIT_LAZY_AUTOMATIC       1
#endif

/**
 * The magic value to determine the library initialisation status
 */
#define mhd_LIB_INIT_MARKER_VALUE 0xB167A105 /* "Big Talos" */


#ifndef mhd_INIT_LAZY_BY_STATIC
#  ifdef mhd_INIT_LAZY_BY_FUNC
/* Markers of performed lazy initialisation */
/* Do not initialise statically to avoid breaking by too early automatic
   initialisation in function, which is then overwritten by library or
   application initialisation. */
/**
 * The indicator of performed global lazy initialisation.
 * Have #mhd_LIB_INIT_MARKER_VALUE value when initialised.
 */
static volatile uint_fast32_t mhd_lib_global_init_marker;
/**
 * The indicator of performed global lazy initialisation.
 * Have (~ #mhd_LIB_INIT_MARKER_VALUE) value when initialised.
 */
static volatile uint_fast32_t mhd_lib_global_init_Nmarker;
#  else  /* ! mhd_INIT_LAZY_BY_FUNC */
/* Markers of performed lazy initialisation */
/**
 * The indicator of performed global lazy initialisation.
 * Have #mhd_LIB_INIT_MARKER_VALUE value when initialised.
 */
static volatile uint_fast32_t mhd_lib_global_init_marker = 0;
/**
 * The indicator of performed global lazy initialisation.
 * Have (~ #mhd_LIB_INIT_MARKER_VALUE) value when initialised.
 */
static volatile uint_fast32_t mhd_lib_global_init_Nmarker = 0;
#  endif

/* Variables used for full initialisation */
/**
 * The number of user of library global resources.
 * In practice the value should correspond to number of running daemons plus
 * number of any possible executed functions with one use of global resources.
 */
static volatile size_t mhd_lib_use_counter;
/**
 * Indicates that library was already fully initialised at least one time.
 * Some resources that do not require re-initialisation, skipped from repeated
 * global initialisation (after deinitialisation).
 */
static volatile bool mhd_lib_fully_inited_once;
#  ifdef MHD_USE_THREADS

/**
 * The mutex to control access to full global initialisers and deinitialisers
 */
static mhd_mutex mhd_init_mutex;
#  endif /* MHD_USE_THREADS */
#else  /* mhd_INIT_LAZY_BY_STATIC */
/* Markers of performed lazy initialisation */
/**
 * The indicator of performed global lazy initialisation.
 * Have #mhd_LIB_INIT_MARKER_VALUE value when initialised.
 */
static volatile uint_fast32_t mhd_lib_global_init_marker =
  (uint_fast32_t) mhd_LIB_INIT_MARKER_VALUE;
/**
 * The indicator of performed global lazy initialisation.
 * Have (~ #mhd_LIB_INIT_MARKER_VALUE) value when initialised.
 */
static volatile uint_fast32_t mhd_lib_global_init_Nmarker =
  (uint_fast32_t) ~((uint_fast32_t) mhd_LIB_INIT_MARKER_VALUE);
/* Variables used for full initialisation */
/**
 * The number of user of library global resources.
 * In practice the value should correspond to number of running daemons plus
 * number of any possible executed functions with one use of global resources.
 */
static volatile size_t mhd_lib_use_counter = 0;
/**
 * Indicates that library was already fully initialised at least one time.
 * Some resources that do not require re-initialisation, skipped from repeated
 * global initialisation (after deinitialisation).
 */
static volatile bool mhd_lib_fully_inited_once = false;
/**
 * The mutex to control access to full global initialisers and deinitialisers
 */
mhd_MUTEX_STATIC_DEFN_INIT (mhd_init_mutex);
#endif /* mhd_INIT_LAZY_BY_STATIC */


/**
 * Check whether the markers of initialisation set to "initialised" values.
 */
#define mhd_LIB_INIT_LAZY_IS_PERFORMED() \
        ((mhd_lib_global_init_marker == \
          ((uint_fast32_t) mhd_LIB_INIT_MARKER_VALUE)) \
         && (mhd_lib_global_init_marker == ~mhd_lib_global_init_Nmarker))

/**
 * Perform global lazy initialisation.
 * If library is initialised statically, this function must never be called
 * unless automatic initialisation has failed.
 * This function does not perform any checking whether the library has been
 * initialised before.
 * @return 'true' if succeed,
 *         'false' if failed
 */
static bool
mhd_lib_global_lazy_init (void)
{
  mhd_panic_init_default (); /* Just set a few variables to NULL */
  if (! mhd_mutex_init (&mhd_init_mutex))
    return false;
  mhd_lib_fully_inited_once = false;
  mhd_lib_use_counter = 0;
  mhd_lib_global_init_marker = (uint_fast32_t) mhd_LIB_INIT_MARKER_VALUE;
  mhd_lib_global_init_Nmarker = (uint_fast32_t) ~mhd_lib_global_init_marker;
  return true;
}


#ifdef mhd_AUTOINIT_FUNCS_USE

/**
 * Perform de-initialisation of the resources previously initialised by
 * #mhd_lib_global_lazy_init().
 * This function does not perform any checking whether the library has been
 * initialised or de-initialised before.
 */
static void
mhd_lib_global_lazy_deinit (void)
{
  mhd_lib_global_init_Nmarker = 0u;
  mhd_lib_global_init_marker = 0u;
  (void) mhd_mutex_destroy (&mhd_init_mutex);
}


#endif /* mhd_AUTOINIT_FUNCS_USE */

/* The automatically called functions */

#ifdef mhd_AUTOINIT_FUNCS_USE

void
mhd_lib_global_init_auto (void)
{
  if (! mhd_lib_global_lazy_init ())
  {
    (void) 0;
    /* Do not abort in non-debug builds, weak workarounds will be used */
#ifndef NDEBUG
    MHD_PANIC ("Failed to initialise the MHD library");
#endif /* ! NDEBUG */
  }
}


void
mhd_lib_global_deinit_auto (void)
{
#ifndef NDEBUG
  if (! mhd_LIB_INIT_LAZY_IS_PERFORMED ())
  {
    fprintf (stderr, "Automatic MHD library initialisation has not been "
             "performed, but the library de-initialisation is called.\n");
    fflush (stderr);
    abort ();
  }
  if (0 != mhd_lib_use_counter)
  {
    fprintf (stderr, "Automatic MHD library de-initialisation started, but "
             "some MHD resources are still in use by the application.\n");
    fflush (stderr);
  }
#endif /* ! NDEBUG */
  mhd_lib_global_lazy_deinit ();
}


#endif /* mhd_AUTOINIT_FUNCS_USE */

#if defined(MHD_SOCKETS_KIND_WINSOCK)
/**
 * Initialise W32 sockets
 * @return 'true' if succeed,
 *         'false' if failed
 */
MHD_static_inline_ bool
mhd_lib_sockets_init_w32 (void)
{
  WSADATA wsd;
  if (0 != WSAStartup (MAKEWORD (2, 2), &wsd))
    return false;
  if (MAKEWORD (2, 2) != wsd.wVersion)
  {
    WSACleanup ();
    return false;
  }
  return true;
}


/**
 * De-initialise W32 sockets
 */
MHD_static_inline_ void
mhd_lib_sockets_deinit_w32 (void)
{
  (void) WSACleanup ();
}


#else  /* ! MHD_SOCKETS_KIND_WINSOCK */
/* No-op implementations */
#  define mhd_lib_sockets_init_w32() (true)
#  define mhd_lib_sockets_deinit_w32() ((void) 0)
#endif /* ! MHD_SOCKETS_KIND_WINSOCK */

/**
 * Perform full initialisation of MHD library global resources.
 * Must be called only with initialisation lock held.
 * @return 'true' if succeed,
 *         'false' if failed
 */
static bool
mhd_lib_global_full_init_once (void)
{
  mhd_assert (mhd_LIB_INIT_LAZY_IS_PERFORMED ());
  mhd_assert (! mhd_lib_fully_inited_once);
  mhd_assert (0 == mhd_lib_use_counter);

  if (! mhd_lib_sockets_init_w32 ())
    return false;
  mhd_mclock_init_once ();
  mhd_send_init_once ();

  mhd_lib_fully_inited_once = true;

  return true;
}


/**
 * Release library global resources allocated
 * by #mhd_lib_global_full_init_once()
 */
static void
mhd_lib_global_full_deinit (void)
{
  mhd_mclock_deinit ();
  mhd_lib_sockets_deinit_w32 ();
}


/**
 * Re-initialise library global resources after
 * de-initialistion by #mhd_lib_global_full_deinit().
 * This function can be called many times.
 * @return 'true' if succeed,
 *         'false' if failed
 */
static bool
mhd_lib_global_full_re_init (void)
{
  mhd_assert (mhd_lib_fully_inited_once);
  if (! mhd_lib_sockets_init_w32 ())
    return false;
  mhd_mclock_re_init ();

  return true;
}


MHD_INTERNAL bool
mhd_lib_init_global_if_needed (void)
{
  bool ret;
  if (! mhd_LIB_INIT_LAZY_IS_PERFORMED ())
  {
#if defined (mhd_INIT_LAZY_AUTOMATIC) && ! defined(NDEBUG)
    /* Problem detected: the library must be already initialised
       automatically, but it is not.  */
    abort (); /* abort if this is a debug build */
#else  /* !mhd_INIT_LAZY_AUTOMATIC || NDEBUG */
    if (! mhd_lib_global_lazy_init ()) /* Not thread safe, but no choice here */
      return false;
#endif /* !mhd_INIT_LAZY_AUTOMATIC || NDEBUG */
  }

  if (! mhd_mutex_lock (&mhd_init_mutex))
    return false;
  if (0 == mhd_lib_use_counter)
  {
    if (! mhd_lib_fully_inited_once)
      ret = mhd_lib_global_full_init_once ();
    else
      ret = mhd_lib_global_full_re_init ();
  }
  else
  {
    mhd_assert (mhd_lib_fully_inited_once);
    ret = true;
  }
  if (ret)
    ++mhd_lib_use_counter;
  mhd_mutex_unlock_chk (&mhd_init_mutex);

  return ret;
}


MHD_INTERNAL void
mhd_lib_deinit_global_if_needed (void)
{
  mhd_assert (0 != mhd_lib_use_counter);

  mhd_mutex_lock_chk (&mhd_init_mutex);
  if (0 == --mhd_lib_use_counter)
    mhd_lib_global_full_deinit ();
  mhd_mutex_unlock_chk (&mhd_init_mutex);
}
