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
 * @file src/mhd2/mhd_iovec.h
 * @brief  The definition of the tristate type and helper macros
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_IOVEC_H
#define MHD_IOVEC_H 1

#include "mhd_sys_options.h"
#include "mhd_socket_type.h"
#include "sys_base_types.h"

#if defined(HAVE_WRITEV) || defined(HAVE_SENDMSG)
#  ifdef HAVE_SYS_TYPES_H
#    include <sys/types.h>
#  endif
#  ifdef HAVE_SYS_SOCKET_H
#    include <sys/socket.h>
#  elif defined(HAVE_UNISTD_H)
#    include <unistd.h>
#  endif
#  ifdef HAVE_SOCKLIB_H
#    include <sockLib.h>
#  endif
#  ifdef HAVE_SYS_UIO_H
#    include <sys/uio.h>
#  endif
#endif

#include "mhd_limits.h"

#if defined(MHD_WINSOCK_SOCKETS)
/**
 * Internally used I/O vector type for use with winsock.
 * Binary matches system "WSABUF".
 */
struct mhd_w32_iovec
{
  unsigned long iov_len;
  char *iov_base;
};
typedef struct mhd_w32_iovec mhd_iovec;
#define mhd_IOV_ELMN_MAX_SIZE    ULONG_MAX
typedef unsigned long mhd_iov_elmn_size;
#define mhd_IOV_RET_MAX_SIZE    LONG_MAX
typedef long mhd_iov_ret_type;
#elif defined(HAVE_SENDMSG) || defined(HAVE_WRITEV)
/**
 * Internally used I/O vector type for use when writev or sendmsg
 * is available. Matches system "struct iovec".
 */
typedef struct iovec mhd_iovec;
#define mhd_IOV_ELMN_MAX_SIZE    SIZE_MAX
typedef size_t mhd_iov_elmn_size;
#define mhd_IOV_RET_MAX_SIZE     SSIZE_MAX
typedef ssize_t mhd_iov_ret_type;
#else
/**
 * Internally used I/O vector type for use when writev or sendmsg
 * is not available.
 */
typedef struct MHD_IoVec mhd_iovec;
#define mhd_IOV_ELMN_MAX_SIZE    SIZE_MAX
typedef size_t mhd_iov_elmn_size;
#define mhd_IOV_RET_MAX_SIZE     SSIZE_MAX
typedef ssize_t mhd_iov_ret_type;
#endif


struct mhd_iovec_track
{
  /**
   * The copy of array of iovec elements.
   * The copy of elements are updated during sending.
   * The number of elements is not changed during lifetime.
   */
  mhd_iovec *iov;

  /**
   * The number of elements in @a iov.
   * This value is not changed during lifetime.
   */
  size_t cnt;

  /**
   * The number of sent elements.
   * At the same time, it is the index of the next (or current) element
   * to send.
   */
  size_t sent;
};

#endif /* ! MHD_IOVEC_H */
