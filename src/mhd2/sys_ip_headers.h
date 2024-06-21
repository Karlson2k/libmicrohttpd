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
 * @file src/mhd2/sys_ip_headers.h
 * @brief  The header for system headers related to TCP/IP
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_SYS_IP_HEADERS_H
#define MHD_SYS_IP_HEADERS_H 1

#include "mhd_sys_options.h"

#include "mhd_socket_type.h"
#include "sys_sockets_headers.h"

#ifdef MHD_POSIX_SOCKETS
#  ifdef HAVE_INETLIB_H
#    include <inetLib.h>
#  endif /* HAVE_INETLIB_H */
#  ifdef HAVE_NETINET_IN_H
#    include <netinet/in.h>
#  endif /* HAVE_NETINET_IN_H */
#  ifdef HAVE_ARPA_INET_H
#    include <arpa/inet.h>
#  endif
#  if ! defined(HAVE_NETINET_IN_H) && ! defined(HAVE_ARPA_INET_H) \
  && defined(HAVE_NETDB_H)
#    include <netdb.h>
#  endif
#  ifdef HAVE_NETINET_TCP_H
#    include <netinet/tcp.h>
#  endif
#else
#  include <ws2tcpip.h>
#endif

#endif /* ! MHD_SYS_IP_HEADERS_H */
