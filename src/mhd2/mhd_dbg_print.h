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
 * @file src/mhd2/mhd_dbg_print.h
 * @brief  The declarations of interl debug-print helpers
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_DBG_PRINT_H
#define MHD_DBG_PRINT_H 1

#include "mhd_sys_options.h"

#ifdef mhd_DEBUG_POLLING_FDS
#  include "sys_bool_type.h"
#  include "mhd_socket_type.h"
#endif /* mhd_DEBUG_POLLING_FDS */


#if mhd_DEBUG_POLLING_FDS
/**
 * Debug-printf request of FD polling/monitoring
 * @param fd_name the name of FD ("ITC", "lstn" or "conn")
 * @param fd the FD value
 * @param r_ready the request for read (or receive) readiness
 * @param w_ready the request for write (or send) readiness
 * @param e_ready the request for exception (or error) readiness
 * @note Implemented in src/mhd2/events_process.c
 */
MHD_INTERNAL void
mhd_dbg_print_fd_mon_req (const char *fd_name,
                          MHD_Socket fd,
                          bool r_ready,
                          bool w_ready,
                          bool e_ready)
MHD_FN_PAR_NONNULL_ALL_;

#else  /* ! mhd_DEBUG_POLLING_FDS */
#  define dbg_print_fd_state_update(fd_n,fd,r_ready,w_ready,e_ready) ((void) 0)
#endif /* ! mhd_DEBUG_POLLING_FDS */


#endif /* ! MHD_DBG_PRINT_H */
