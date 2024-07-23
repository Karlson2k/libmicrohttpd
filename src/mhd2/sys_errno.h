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
 * @file src/mhd2/sys_errno.h
 * @brief  The wrapper for system <errno.h>. Includes MHD helper macros.
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_SYS_ERRNO_H
#define MHD_SYS_ERRNO_H 1

#include "mhd_sys_options.h"
#include <errno.h>

#ifdef EBADF
#  define mhd_EBADF_OR_ZERO EBADF
#else
#  define mhd_EBADF_OR_ZERO (0)
#endif

#ifdef EFAULT
#  define mhd_EFAULT_OR_ZERO EFAULT
#else
#  define mhd_EFAULT_OR_ZERO (0)
#endif

#ifdef EINVAL
#  define mhd_EINVAL_OR_ZERO EINVAL
#else
#  define mhd_EINVAL_OR_ZERO (0)
#endif

#ifdef EINTR
#  define mhd_EINTR_OR_ZERO EINTR
#else
#  define mhd_EINTR_OR_ZERO (0)
#endif

#ifdef ENOMEM
#  define mhd_ENOMEM_OR_ZERO ENOMEM
#else
#  define mhd_ENOMEM_OR_ZERO (0)
#endif

#ifdef EMFILE
#  define mhd_EMFILE_OR_ZERO EMFILE
#else
#  define mhd_EMFILE_OR_ZERO (0)
#endif

#ifdef ENFILE
#  define mhd_ENFILE_OR_ZERO ENFILE
#else
#  define mhd_ENFILE_OR_ZERO (0)
#endif

#ifdef ENOBUFS
#  define mhd_ENOBUFS_OR_ZERO ENOBUFS
#else
#  define mhd_ENOBUFS_OR_ZERO (0)
#endif

#ifdef EHOSTUNREACH
#  define mhd_EHOSTUNREACH_OR_ZERO EHOSTUNREACH
#else
#  define mhd_EHOSTUNREACH_OR_ZERO (0)
#endif

#ifdef ETIMEDOUT
#  define mhd_ETIMEDOUT_OR_ZERO ETIMEDOUT
#else
#  define mhd_ETIMEDOUT_OR_ZERO (0)
#endif

#ifdef ENETUNREACH
#  define mhd_ENETUNREACH_OR_ZERO ENETUNREACH
#else
#  define mhd_ENETUNREACH_OR_ZERO (0)
#endif

#endif /* ! MHD_SYS_ERRNO_H */
