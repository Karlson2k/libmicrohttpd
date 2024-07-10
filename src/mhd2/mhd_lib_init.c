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
 * @file src/mhd2/mhd_lib_init_impl.c
 * @brief  Library global initialisers and de-initialisers
 * @author Karlson2k (Evgeny Grin)
 */
#include "mhd_sys_options.h"
#include "mhd_lib_init.h"
#include "mhd_panic.h"
#include "mhd_mono_clock.h"
#include "mhd_socket_type.h"
#include "mhd_send.h"
#ifdef MHD_WINSOCK_SOCKETS
#  include <winsock2.h>
#endif

void
mhd_lib_global_init (void)
{
  mhd_panic_init_default ();

#if defined(MHD_WINSOCK_SOCKETS)
  if (1)
  {
    WSADATA wsd;
    if ((0 != WSAStartup (MAKEWORD (2, 2), &wsd)) || (MAKEWORD (2, 2) != wsd.
                                                      wVersion))
      MHD_PANIC ("Failed to initialise WinSock.");
  }
#endif /* MHD_WINSOCK_SOCKETS */
  MHD_monotonic_msec_counter_init();
  mhd_send_init_static_vars();
}


void
mhd_lib_global_deinit (void)
{
  MHD_monotonic_msec_counter_finish();
#if defined(MHD_WINSOCK_SOCKETS)
  (void) WSACleanup ();
#endif /* MHD_WINSOCK_SOCKETS */
}


#ifndef _AUTOINIT_FUNCS_ARE_SUPPORTED
static volatile int mhd_lib_global_inited = 0;
static volatile int mhd_lib_global_not_inited = ! 0;

MHD_EXTERN_ void
MHD_lib_global_check_init (void)
{
  if ((! mhd_lib_global_inited) || (mhd_lib_global_not_inited))
    mhd_lib_global_init ();
  mhd_lib_global_inited = ! 0;
  mhd_lib_global_not_inited = 0;
}


MHD_EXTERN_ void
MHD_lib_global_check_deinit (void)
{
  if ((mhd_lib_global_inited) && (! mhd_lib_global_not_inited))
    mhd_lib_global_deinit ();
  mhd_lib_global_inited = 0;
  mhd_lib_global_not_inited = ! 0;
}


#endif /* ! _AUTOINIT_FUNCS_ARE_SUPPORTED */
