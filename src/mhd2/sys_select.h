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
 * @file src/mhd2/sys_select.h
 * @brief  The header for the system 'select()' function and related data types
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_SYS_SELECT_H
#define MHD_SYS_SELECT_H 1

#include "mhd_sys_options.h"

#ifdef MHD_USE_SELECT
#  include "mhd_socket_type.h"
#  if defined(MHD_POSIX_SOCKETS)
#    ifdef HAVE_SYS_SELECT_H
#      include <sys/select.h>
#    else
#      ifdef HAVE_SYS_TIME_H
#        include <sys/time.h>
#      endif
#      ifdef HAVE_SYS_TYPES_H
#        include <sys/types.h>
#      endif
#      ifdef HAVE_UNISTD_H
#        include <unistd.h>
#      else
#        include <stdlib.h>
#      endif
#      ifdef HAVE_SELECTLIB_H
#        include  <selectLib.h>
#      endif
#    endif
#  elif defined(MHD_WINSOCK_SOCKETS)
#    include <winsock2.h>
#  else
#error Uknown sockets type
#  endif

#endif /* MHD_USE_SELECT */

#endif /* ! MHD_SYS_SELECT_H */
