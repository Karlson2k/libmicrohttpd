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
 * @file src/mhd2/daemon_logger_default.h
 * @brief  The declaration of the default logger function
 * @author Karlson2k (Evgeny Grin)
 */

#include "mhd_sys_options.h"

#ifdef HAVE_LOG_FUNCTIONALITY

#include <stdio.h>

#include "daemon_logger_default.h"
#include "mhd_assert.h" /* For NDEBUG macro */

MHD_INTERNAL void
mhd_logger_default (void *cls,
                    enum MHD_StatusCode sc,
                    const char *fm,
                    va_list ap)
{
  int res;
  (void) cls; /* Not used by default logger */
  (void) sc;  /* Not used by default logger */

  res = vfprintf (stderr, fm, ap);
  (void) res; /* The result of vfprintf() call is ignored */
  res = fprintf (stderr, "\n");
  (void) res; /* The result of vfprintf() call is ignored */
#ifndef NDEBUG
  res = fflush (stderr);
  (void) res; /* The result of fflush() call is ignored */
#endif /* ! NDEBUG */
}


#endif /* ! HAVE_LOG_FUNCTIONALITY */
