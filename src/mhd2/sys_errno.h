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

#ifdef EFAULT
#  define MHD_EFAULT_OR_ZERO EFAULT
#else
#  define MHD_EFAULT_OR_ZERO (0)
#endif

#ifdef EINVAL
#  define MHD_EINVAL_OR_ZERO EINVAL
#else
#  define MHD_EINVAL_OR_ZERO (0)
#endif

#ifdef EINTR
#  define MHD_EINTR_OR_ZERO EINTR
#else
#  define MHD_EINTR_OR_ZERO (0)
#endif


#endif /* ! MHD_SYS_ERRNO_H */
