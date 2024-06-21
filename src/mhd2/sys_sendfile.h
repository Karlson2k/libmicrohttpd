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
 * @file src/mhd2/sys_sendfile.h
 * @brief  The system headers for sendfile() function (if any)
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_SYS_SENDFILE_H
#define MHD_SYS_SENDFILE_H 1

#include "mhd_sys_options.h"

#if defined(HAVE_LINUX_SENDFILE)
#  include <sys/sendfile.h>
#elif defined(HAVE_FREEBSD_SENDFILE) || defined(HAVE_DARWIN_SENDFILE)
#  ifdef HAVE_SYS_TYPES_H
#    include <sys/types.h>
#  endif
#  ifdef HAVE_UNISTD_H
#    include <unistd.h>
#  endif
#  ifdef HAVE_SYS_SOCKET_H
#    include <sys/socket.h>
#  endif
#  include <sys/uio.h>
#elif defined(MHD_USE_SENDFILE)
#error MHD_USE_SENDFILE is defined, while no HAVE_xxx_SENDFILE defined
#endif

#endif /* ! MHD_SYS_SENDFILE_H */
