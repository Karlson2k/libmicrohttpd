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
 * @file src/mhd2/daemon_logger_default.c
 * @brief  The implementation of the default logger function
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_DAEMON_LOGGER_DEFAULT_H
#define MHD_DAEMON_LOGGER_DEFAULT_H 1

#include "mhd_sys_options.h"

#ifdef HAVE_LOG_FUNCTIONALITY

#include "mhd_public_api.h" /* For enum MHD_StatusCode */

#include <stdarg.h>

/**
 * Default logger function.
 * @param cls the closure
 * @param sc the status code of the event
 * @param fm the format string (`printf()`-style)
 * @param ap the arguments to @a fm
 * @ingroup logging
 */
MHD_INTERNAL void
mhd_logger_default (void *cls,
                    enum MHD_StatusCode sc,
                    const char *fm,
                    va_list ap);

#else /* ! HAVE_LOG_FUNCTIONALITY */

#include "sys_null_macro.h"

#define mhd_logger_default NULL

#endif /* ! MHD_DAEMON_LOGGER_DEFAULT_H */

#endif /* ! MHD_DAEMON_LOGGER_DEFAULT_H */
