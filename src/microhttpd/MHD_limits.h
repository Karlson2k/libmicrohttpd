/*
  This file is part of libmicrohttpd
  Copyright (C) 2015 Karlson2k (Evgeny Grin)

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
 * @file microhttpd/MHD_limits.h
 * @brief  limits values definitions
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_LIMITS_H
#define MHD_LIMITS_H

#include "platform.h"

#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif /* HAVE_LIMITS_H */


#ifndef INT32_MAX
#define INT32_MAX ((int32_t)0x7FFFFFFF)
#endif /* !INT32_MAX */

#ifndef OFF_T_MAX
#define OFF_T_MAX ((off_t) ~(((uint64_t) 1) << (8 * sizeof(off_t) - 1)))
#endif /* !OFF_T_MAX */

#if defined(_LARGEFILE64_SOURCE) && !defined(OFF64_T_MAX)
#define OFF64_T_MAX ((off64_t) ~(((uint64_t) 1) << (8 * sizeof(off64_t) - 1)))
#endif /* _LARGEFILE64_SOURCE && !OFF64_T_MAX */


#endif /* MHD_LIMITS_H */
