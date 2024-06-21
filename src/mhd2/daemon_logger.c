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
 * @file src/mhd2/daemon_logger.c
 * @brief  The implementation of the logger function
 * @author Karlson2k (Evgeny Grin)
 */

#include "mhd_sys_options.h"

#ifdef HAVE_LOG_FUNCTIONALITY
#include <stdarg.h>
#include "sys_null_macro.h"
#include "mhd_daemon.h"
#include "daemon_logger.h"


MHD_INTERNAL void
mhd_logger (struct MHD_Daemon *daemon,
            enum MHD_StatusCode sc,
            const char *fm,
            ...)
{
  if (NULL != daemon->log_params.v_log_cb)
  {
    va_list vargs;
    va_start (vargs, fm);
    daemon->log_params.v_log_cb (daemon->log_params.v_log_cb_cls,
                                 sc, fm, vargs);
    va_end (vargs);
  }
}


#endif /* ! HAVE_LOG_FUNCTIONALITY */
