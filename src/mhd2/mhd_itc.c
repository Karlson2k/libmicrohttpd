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
 * @file src/mhd2/mhd_itc.c
 * @brief  Implementation of inter-thread communication functions
 * @author Karlson2k (Evgeny Grin)
 */

#include "mhd_itc.h"
#if defined(MHD_ITC_PIPE_)
#  ifdef MHD_HAVE_MHD_ITC_NONBLOCKING
#    include "mhd_sockets_funcs.h"
#    ifndef MHD_POSIX_SOCKETS
#error Pipe-based ITC can be used only with POSIX sockets
#    endif

MHD_INTERNAL bool
mhd_itc_nonblocking (struct mhd_itc *pitc)
{
  return mhd_socket_nonblocking ((MHD_Socket) pitc->sk[0]) &&
         mhd_socket_nonblocking ((MHD_Socket) pitc->sk[1]);
}


#  endif /* ! MHD_HAVE_MHD_ITC_NONBLOCKING */
#endif /* MHD_ITC_PIPE_ */
