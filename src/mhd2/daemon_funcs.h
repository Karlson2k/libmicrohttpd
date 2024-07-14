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

#include "sys_bool_type.h"

#include "mhd_buffer.h"

struct MHD_Daemon; /* forward declaration */


/**
 * Get controlling daemon
 * @param d the daemon to get controlling daemon
 * @return the master daemon (possible the same as the @a d)
 */
MHD_INTERNAL struct MHD_Daemon *
mhd_daemon_get_master_daemon (struct MHD_Daemon *restrict d)
MHD_FN_PAR_NONNULL_ALL_ MHD_FN_MUST_CHECK_RESULT_;

#ifdef MHD_USE_THREADS

/**
 * Trigger daemon ITC.
 * This should cause daemon's thread to stop waiting for the network events
 * and process pending information
 * @param d the daemon object, ITC should be initialised
 * @return true if succeed, false otherwise
 */
MHD_INTERNAL bool
mhd_daemon_trigger_itc (struct MHD_Daemon *restrict d);

#endif /* MHD_USE_THREADS */


/**
 * Check whether any resuming connections are pending and resume them
 * @param d the daemon to use
 */
MHD_INTERNAL void
mhd_daemon_resume_conns (struct MHD_Daemon *restrict d)
MHD_FN_PAR_NONNULL_ALL_;


/**
 * Request allocation of the large buffer
 * @param d the daemon to use
 * @param requested_size the requested size of allocation
 * @return true if allocation allowed and counted,
 *         false otherwise
 */
MHD_INTERNAL bool
mhd_daemon_claim_lbuf (struct MHD_Daemon *restrict d,
                       size_t requested_size)
MHD_FN_PAR_NONNULL_ALL_ MHD_FN_MUST_CHECK_RESULT_;


/**
 * Reclaim the large buffer allocation.
 * Must be called when the allocation has been already freed.
 * @param d the daemon to use
 * @param reclaimed_size the deallocated size
 */
MHD_INTERNAL void
mhd_daemon_reclaim_lbuf (struct MHD_Daemon *restrict d,
                         size_t reclaimed_size)
MHD_FN_PAR_NONNULL_ALL_;

/**
 * Allocate the large buffer
 * @param d the daemon to use
 * @param requested_size the requested size of allocation
 * @param[out] buf the buffer to allocate
 * @return true if buffer is allocated,
 *         false otherwise
 */
MHD_INTERNAL bool
mhd_daemon_get_lbuf (struct MHD_Daemon *restrict d,
                     size_t requested_size,
                     struct mhd_Buffer *restrict buf)
MHD_FN_PAR_NONNULL_ALL_ MHD_FN_MUST_CHECK_RESULT_
  MHD_FN_PAR_OUT_ (3);

/**
 * Grow the large buffer, which previously was allocated
 * @param d the daemon to use
 * @param grow_size the requested size of grow
 * @param[in,out] buf the buffer to grow
 * @return true if buffer has been grown,
 *         false otherwise
 */
MHD_INTERNAL bool
mhd_daemon_grow_lbuf (struct MHD_Daemon *restrict d,
                      size_t grow_size,
                      struct mhd_Buffer *restrict buf)
MHD_FN_PAR_NONNULL_ALL_ MHD_FN_MUST_CHECK_RESULT_
  MHD_FN_PAR_INOUT_ (3);


/**
 * Free large buffer.
 * @param d the daemon to use
 * @param[in,out] buf the buffer to free
 */
MHD_INTERNAL void
mhd_daemon_free_lbuf (struct MHD_Daemon *restrict d,
                      struct mhd_Buffer *restrict buf)
MHD_FN_PAR_NONNULL_ALL_ MHD_FN_PAR_INOUT_ (2);


#endif /* ! MHD_DAEMON_FUNCS_H */
