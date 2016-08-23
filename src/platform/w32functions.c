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
 * @file platform/w32functions.h
 * @brief  internal functions for W32 systems
 * @author Karlson2k (Evgeny Grin)
 */

#include "w32functions.h"
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <stdio.h>
#include <stdarg.h>

/**
 * Static variable used by pseudo random number generator
 */
static int32_t rnd_val = 0;
/**
 * Generate 31-bit pseudo random number.
 * Function initialize itself at first call to current time.
 * @return 31-bit pseudo random number.
 */
int MHD_W32_random_(void)
{
  if (0 == rnd_val)
    rnd_val = (int32_t)time(NULL);
  /* stolen from winsup\cygwin\random.cc */
  rnd_val = (16807 * (rnd_val % 127773) - 2836 * (rnd_val / 127773))
               & 0x7fffffff;
  return (int)rnd_val;
}

/* Emulate snprintf function on W32 */
int W32_snprintf(char *__restrict s, size_t n, const char *__restrict format, ...)
{
  int ret;
  va_list args;
  if (0 != n && NULL != s )
  {
    va_start(args, format);
    ret = _vsnprintf(s, n, format, args);
    va_end(args);
    if ((int)n == ret)
      s[n - 1] = 0;
    if (ret >= 0)
      return ret;
  }
  va_start(args, format);
  ret = _vscprintf(format, args);
  va_end(args);
  if (0 <= ret && 0 != n && NULL == s)
    return -1;

  return ret;
}
