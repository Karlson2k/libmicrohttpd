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
 * @file src/mhd2/daemon_logger.h
 * @brief  The declaration of the logger function and relevant macros
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_DAEMON_LOGGER_H
#define MHD_DAEMON_LOGGER_H 1

#include "mhd_sys_options.h"

#ifdef HAVE_LOG_FUNCTIONALITY

#include "mhd_public_api.h" /* For enum MHD_StatusCode */

struct MHD_Daemon; /* Forward declaration */

/* Do not use this function directly, use wrapper macros below */
/**
 * The daemon logger function.
 * @param daemon the daemon handle
 * @param sc the status code of the event
 * @param fm the format string ('printf()'-style)
 * @ingroup logging
 */
MHD_INTERNAL void
mhd_logger (struct MHD_Daemon *daemon,
            enum MHD_StatusCode sc,
            const char *fm,
            ...);

/**
 * Log a single message.
 *
 * The @a msg is a 'printf()' string, treated as format specifiers string.
 * Any '%' symbols should be doubled ('%%') to avoid interpretation as a format
 * specifier symbol.
 */
#define mhd_LOG_MSG(daemon,sc,msg) mhd_logger (daemon,sc,msg)

/**
 * Format message and log it
 *
 * Always use with #mhd_LOG_FMT() for the format string.
 */
#define mhd_LOG_PRINT mhd_logger

/**
 * The wrapper macro for the format string to be used for format parameter for
 * the #mhd_LOG_FMT() macro
 */
#define mhd_LOG_FMT(format_string) format_string

#else  /* ! HAVE_LOG_FUNCTIONALITY */


#ifdef HAVE_MACRO_VARIADIC

/**
 * Log a single message.
 *
 * The @a msg is a 'printf()' string, treated as format specifiers string.
 * Any '%' symbols should be doubled ('%%') to avoid interpretation as a format
 * specifier symbol.
 */
#define mhd_LOG_MSG(daemon,sc,msg)  do { (void) daemon; } while (0)

/**
 * Format message and log it
 *
 * Always use with #mhd_LOG_FMT() for the format string.
 */
#define mhd_LOG_PRINT(daemon,sc,fm,...)  do { (void) daemon; } while (0)

#else  /* ! HAVE_MACRO_VARIADIC */

#include "sys_base_types.h" /* For NULL */

/**
 * Format message and log it
 *
 * Always use with #mhd_LOG_FMT() for the format string.
 */
MHD_static_inline_ void
mhd_LOG_PRINT (struct MHD_Daemon *daemon,
               enum MHD_StatusCode sc,
               const char *fm,
               ...)
{
  (void) daemon; (void) sc; (void) fm;
}


/**
 * Log a single message.
 *
 * The @a msg is a 'printf()' string, treated as format specifiers string.
 * Any '%' symbols should be doubled ('%%') to avoid interpretation as a format
 * specifier symbol.
 */
#define mhd_LOG_MSG(daemon,sc,msg) mhd_LOG_PRINT (daemon,sc,NULL)

#endif /* ! HAVE_MACRO_VARIADIC */

/**
 * The wrapper macro for the format string to be used for format parameter for
 * the #mhd_LOG_FMT() macro
 */
#define mhd_LOG_FMT(format_string) NULL

#endif /* ! HAVE_LOG_FUNCTIONALITY */

#endif /* ! MHD_DAEMON_LOGGER_H */
