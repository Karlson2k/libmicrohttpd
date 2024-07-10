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
 * @file src/mhd2/daemon_funcs.h
 * @brief  The declarations of internal daemon-related functions
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_DAEMON_FUNCS_H
#define MHD_DAEMON_FUNCS_H 1

#include "mhd_sys_options.h"

#ifdef MHD_USE_THREADS

#include "sys_bool_type.h"

struct MHD_Daemon; /* forward declaration */


/**
 * Trigger daemon ITC.
 * This should cause daemon's thread to stop waiting for the network events
 * and process pending information
 * @param d the daemon object, ITC should be initialised
 * @return true if succeed, false otherwise
 */
MHD_INTERNAL bool
mhd_daemon_trigger_itc (struct MHD_Daemon *restrict d);



/**
 * Check whether any resuming connections are pending and resume them
 * @param d the daemon to use
 */
MHD_INTERNAL void
mhd_daemon_resume_conns (struct MHD_Daemon *restrict d)
MHD_FN_PAR_NONNULL_ALL_ ;

#endif /* MHD_USE_THREADS */

#endif /* ! MHD_DAEMON_FUNCS_H */
