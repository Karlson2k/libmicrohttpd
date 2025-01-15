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
 * @file src/mhd2/events_process.h
 * @brief  The declarations of events processing functions
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_EVENTS_PROCESS_H
#define MHD_EVENTS_PROCESS_H 1

#include "mhd_sys_options.h"

#include "sys_base_types.h"

#include "sys_thread_entry_type.h"

struct MHD_Daemon; /* forward declaration */

/**
 * The entry point for the daemon worker thread
 * @param cls the closure
 */
mhd_THRD_RTRN_TYPE mhd_THRD_CALL_SPEC
mhd_worker_all_events (void *cls);

/**
 * The entry point for the daemon listening thread
 * @param cls the closure
 */
mhd_THRD_RTRN_TYPE mhd_THRD_CALL_SPEC
mhd_worker_listening_only (void *cls);

/**
 * The entry point for the connection thread for thread-per-connection mode
 * @param cls the closure
 */
mhd_THRD_RTRN_TYPE mhd_THRD_CALL_SPEC
mhd_worker_connection (void *cls);

/**
 * Get maximum wait time for the daemon
 * @param d the daemon to check
 * @return the maximum wait time,
 *         #MHD_WAIT_INDEFINITELY if wait time is not limited
 */
MHD_INTERNAL uint_fast64_t
mhd_daemon_get_wait_max (struct MHD_Daemon *restrict d)
MHD_FN_PAR_NONNULL_ALL_;

#endif /* ! MHD_EVENTS_PROCESS_H */
