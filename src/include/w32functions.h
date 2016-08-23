/*
  This file is part of libmicrohttpd
  Copyright (C) 2014 Karlson2k (Evgeny Grin)

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library.
  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @file include/w32functions.h
 * @brief  internal functions for W32 systems
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_W32FUNCTIONS_H
#define MHD_W32FUNCTIONS_H
#ifndef _WIN32
#error w32functions.h is designed only for W32 systems
#endif

#include "platform.h"
#include <errno.h>
#include <winsock2.h>
#include "platform_interface.h"

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * Generate 31-bit pseudo random number.
 * Function initialize itself at first call to current time.
 * @return 31-bit pseudo random number.
 */
int MHD_W32_random_(void);

/* Emulate snprintf function on W32 */
int W32_snprintf(char *__restrict s, size_t n, const char *__restrict format, ...);

#ifdef __cplusplus
}
#endif
#endif /* MHD_W32FUNCTIONS_H */
