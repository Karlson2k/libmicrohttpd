/*
  This file is part of libmicrohttpd
  Copyright (C) 2015-2023 Karlson2k (Evgeny Grin)

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

/**
 * @file microhttpd/sysfdsetsize.c
 * @brief  Helper for obtaining FD_SETSIZE system default value
 * @author Karlson2k (Evgeny Grin)
 */


#include "mhd_options.h"

#ifndef MHD_SYS_FD_SETSIZE_

#include "sysfdsetsize.h"

#ifdef FD_SETSIZE
/* FD_SETSIZE was defined before system headers. */
/* To get system value of FD_SETSIZE, undefine FD_SETSIZE
   here. */
#undef FD_SETSIZE
#endif /* FD_SETSIZE */

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif /* HAVE_STDLIB_H */
#if defined(__VXWORKS__) || defined(__vxworks) || defined(OS_VXWORKS)
#include <sockLib.h>
#endif /* OS_VXWORKS */
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif /* HAVE_SYS_SELECT_H */
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif /* HAVE_SYS_TYPES_H */
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif /* HAVE_SYS_TIME_H */
#ifdef HAVE_TIME_H
#include <time.h>
#endif /* HAVE_TIME_H */
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /* HAVE_UNISTD_H */
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif /* HAVE_SYS_SOCKET_H */

#if defined(_WIN32) && ! defined(__CYGWIN__)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif /* !WIN32_LEAN_AND_MEAN */
#include <winsock2.h>
#endif /* _WIN32 && !__CYGWIN__ */

#ifndef FD_SETSIZE
#error FD_SETSIZE must be defined in system headers
#endif /* !FD_SETSIZE */


/**
 * Get system default value of FD_SETSIZE
 * @return system default value of FD_SETSIZE
 */
unsigned int
get_system_fdsetsize_value (void)
{
  return (unsigned int) FD_SETSIZE;
}


#endif /* ! MHD_SYS_FD_SETSIZE_ */
