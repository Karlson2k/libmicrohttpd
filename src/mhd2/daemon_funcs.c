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
 * @file src/mhd2/daemon_funcs.c
 * @brief  The implementation of internal daemon-related functions
 * @author Karlson2k (Evgeny Grin)
 */

#include "mhd_sys_options.h"

#ifdef MHD_USE_THREADS

#include "daemon_funcs.h"

#include "mhd_itc.h"
#include "mhd_daemon.h"
#include "daemon_logger.h"

MHD_INTERNAL bool
mhd_daemon_trigger_itc (struct MHD_Daemon *restrict d)
{
  mhd_assert (mhd_ITC_IS_VALID (d->threading.itc));
  if (! mhd_itc_activate (d->threading.itc))
  {
    MHD_LOG_MSG (d, MHD_SC_ITC_USE_FAILED, \
                 "Failed to communicate by ITC with the daemon thread.");
    return false;
  }
  return true;
}


#endif /* MHD_USE_THREADS */
