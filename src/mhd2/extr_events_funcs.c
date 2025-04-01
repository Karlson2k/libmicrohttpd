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
 * @file src/mhd2/extr_events_funcs.c
 * @brief  The implementation of the external events internal helper functions
 * @author Karlson2k (Evgeny Grin)
 */

#include "mhd_sys_options.h"
#include "extr_events_funcs.h"

#ifdef MHD_SUPPORT_LOG_FUNCTIONALITY

#include "daemon_logger.h"

MHD_INTERNAL void
mhd_log_extr_event_dereg_failed (struct MHD_Daemon *restrict d)
{
  mhd_LOG_MSG (d, \
               MHD_SC_EXTR_EVENT_DEREG_FAILED, \
               "Application failed to de-register FD: registration callback " \
               "returned non-NULL value");
}


#endif /* MHD_SUPPORT_LOG_FUNCTIONALITY */
