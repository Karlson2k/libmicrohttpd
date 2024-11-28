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
 * @file src/mhd2/mhd_tls_choice.h
 * @brief  The TLS backend compile-time selection header
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_TLS_CHOICE_H
#define MHD_TLS_CHOICE_H 1

#include "mhd_sys_options.h"

#ifndef MHD_ENABLE_HTTPS
#error This header should be used only if HTTPS is enabled
#endif

/* ** Helper macros ** */

/**
 * Concatenate three arguments literally
 */
#define mhd_MACRO_CONCAT3_(a,b,c)        a ## b ## c
/**
 * Concatenate three arguments after expansion
 */
#define mhd_MACRO_CONCAT3(a,b,c)         mhd_MACRO_CONCAT3_ (a,b,c)


/* ** Enumerate TLS backends ** */

/* * GnuTLS * */

#ifdef MHD_USE_GNUTLS
/**
 * Defined to one if GnuTLS is enabled at build time or to zero if not enabled
 */
#  define mhd_TLS_GNU_ENABLED   (1)
#else
/**
 * Defined to one if GnuTLS is enabled at build time or to zero if not enabled
 */
#  define mhd_TLS_GNU_ENABLED   (0)
#endif

/**
 * Return non-zero if GnuTLS is supported
 */
#define mhd_TLS_GNU_IS_SUPPORTED()     (! ! mhd_TLS_GNU_ENABLED)

/* * OpenSSL * */

#ifdef MHD_USE_OPENSSL
/**
 * Defined to one if OpenSSL is enabled at build time or to zero if not enabled
 */
#  define mhd_TLS_OPEN_ENABLED   (1)
#else
/**
 * Defined to one if GnuTLS is enabled at build time or to zero if not enabled
 */
#  define mhd_TLS_OPEN_ENABLED   (0)
#endif

/**
 * Return non-zero if OpenSSL is supported
 */
#define mhd_TLS_OPEN_IS_SUPPORTED()     (! ! mhd_TLS_GNU_ENABLED)

/**
 * Defined to the number of enabled TLS backends
 */
#define mhd_TLS_NUM_BACKENDS \
        (mhd_TLS_GNU_ENABLED + mhd_TLS_OPEN_ENABLED)

#if mhd_TLS_NUM_BACKENDS == 0
#error At least one TLS backend must be enabled if this header is included
#endif

#if mhd_TLS_NUM_BACKENDS > 1
/**
 * Defined to '1' if Multi-TLS should be used
 */
#  define MHD_USE_MULTITLS
#endif

/* Sanity check */
#if defined(MHD_USE_MULTITLS) && ! defined(mhd_HAVE_SEVERAL_TLS_BACKENDS)
#error several TLS backends set by configure, but only one available for code
#endif
#if ! defined(MHD_USE_MULTITLS) && defined(mhd_HAVE_SEVERAL_TLS_BACKENDS)
#error several TLS backends available for code, but ony one set by configure
#endif

#ifdef MHD_USE_MULTITLS
/**
 * Defined to one if Multi-TLS is enabled at build time or
 * to zero if not enabled
 */
#  define mhd_TLS_MULTI_ENABLED         (1)
#else
/**
 * Defined to one if Multi-TLS is enabled at build time or
 * to zero if not enabled
 */
#  define mhd_TLS_MULTI_ENABLED         (0)
#endif
/**
 * Return non-zero if Multi-TLS is supported
 */
#define mhd_TLS_MULTI_IS_SUPPORTED()    (! ! mhd_TLS_MULTI_ENABLED)


#if defined(MHD_USE_MULTITLS)
/**
 * The TLS back-end identifier for function names
 */
#  define mhd_TLS_FUNC_NAME_ID multi
/**
 * The TLS back-end identifier for data names
 */
#  define mhd_TLS_DATA_NAME_ID Multi
/**
 * The TLS back-end identifier for macro names
 */
#  define mhd_TLS_MACRO_NAME_ID MULTI
#elif defined(MHD_USE_GNUTLS)
/**
 * The TLS back-end identifier for function names
 */
#  define mhd_TLS_FUNC_NAME_ID gnu
/**
 * The TLS back-end identifier for data names
 */
#  define mhd_TLS_DATA_NAME_ID Gnu
/**
 * The TLS back-end identifier for macro names
 */
#  define mhd_TLS_MACRO_NAME_ID GNU
#elif defined(MHD_USE_OPENSSL)
/**
 * The TLS back-end identifier for function names
 */
#  define mhd_TLS_FUNC_NAME_ID open
/**
 * The TLS back-end identifier for data names
 */
#  define mhd_TLS_DATA_NAME_ID Open
/**
 * The TLS back-end identifier for macro names
 */
#  define mhd_TLS_MACRO_NAME_ID OPEN
#endif


/* ** Functions names and structures names macros ** */

/**
 * Form function name specific for the selected TLS backend
 */
#define mhd_TLS_DATA(name_suffix)    \
        mhd_MACRO_CONCAT3 (mhd_Tls,mhd_TLS_DATA_NAME_ID,name_suffix)

/**
 * Form name of the data specific for the selected TLS backend
 */
#define mhd_TLS_FUNC(name_suffix)    \
        mhd_MACRO_CONCAT3 (mhd_tls_,mhd_TLS_FUNC_NAME_ID,name_suffix)

/**
 * The name of the structure that holds daemon-specific TLS data
 */
#define mhd_TlsDaemonData       mhd_TLS_DATA (DaemonData)
/**
 * The name of the structure that holds connection-specific TLS data
 */
#define mhd_TlsConnData         mhd_TLS_DATA (ConnData)


/* ** Forward declarations ** */

/**
 * The structure with daemon-specific TLS data
 */
struct mhd_TlsDaemonData;       /* Forward declaration */

/**
 * The structure with connection-specific TLS data
 */
struct mhd_TlsConnData;         /* Forward declaration */


#endif /* ! MHD_TLS_CHOICE_H */
