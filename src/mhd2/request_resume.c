/*
  This file is part of GNU libmicrohttpd
  Copyright (C) 2025 Evgeny Grin (Karlson2k)

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
 * @file src/mhd2/request_resume.c
 * @brief  The implementation of MHD_request_resume() function
 * @author Karlson2k (Evgeny Grin)
 */

#include "mhd_sys_options.h"

#include "mhd_cntnr_ptr.h"

#ifdef mhd_DEBUG_SUSPEND_RESUME
#  include <stdio.h>
#endif /* mhd_DEBUG_SUSPEND_RESUME */

#include "mhd_daemon.h"
#include "mhd_connection.h"

#include "daemon_funcs.h"

#include "mhd_public_api.h"

MHD_EXTERN_ MHD_FN_PAR_NONNULL_ALL_ void
MHD_request_resume (struct MHD_Request *request)
{
  struct MHD_Connection *c = mhd_CNTNR_PTR (request, \
                                            struct MHD_Connection, \
                                            rq);
  struct MHD_Daemon *d = c->daemon;

  if (! c->suspended)
  {
#ifdef mhd_DEBUG_SUSPEND_RESUME
    fprintf (stderr,
             "%%%%%% Requested conn resume, FD: %llu -> "
             "failed as not suspended\n",
             (unsigned long long) c->sk.fd);
#endif /* mhd_DEBUG_SUSPEND_RESUME */
    return;
  }
  c->resuming = true;
#ifdef mhd_DEBUG_SUSPEND_RESUME
  fprintf (stderr,
           "%%%%%% Requested conn resume, FD: %llu\n",
           (unsigned long long) c->sk.fd);
#endif /* mhd_DEBUG_SUSPEND_RESUME */
  d->threading.resume_requested = true;
  mhd_daemon_trigger_itc (d);
}
