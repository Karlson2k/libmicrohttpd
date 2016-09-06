/*
  This file is part of libmicrohttpd
  Copyright (C) 2014-2016 Karlson2k (Evgeny Grin)

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
 * @file microhttpd/mhd_compat.c
 * @brief  Implementation of platform missing functions.
 * @author Karlson2k (Evgeny Grin)
 */

#include "mhd_compat.h"
#if defined(_WIN32) && !defined(__CYGWIN__)
#include <stdint.h>
#include <time.h>
#ifndef HAVE_SNPRINTF
#include <stdio.h>
#include <stdarg.h>
#endif  /* HAVE_SNPRINTF */
#endif /* _WIN32  && !__CYGWIN__ */


#if defined(_WIN32) && !defined(__CYGWIN__)

#ifndef HAVE_SNPRINTF
/* Emulate snprintf function on W32 */
int
W32_snprintf (char *__restrict s,
              size_t n,
              const char *__restrict format,
              ...)
{
  int ret;
  va_list args;

  if ( (0 != n) &&
       (NULL != s) )
  {
    va_start (args,
              format);
    ret = _vsnprintf (s,
                      n,
                      format,
                      args);
    va_end (args);
    if ((int)n == ret)
      s[n - 1] = 0;
    if (ret >= 0)
      return ret;
  }
  va_start(args,
           format);
  ret = _vscprintf (format,
                    args);
  va_end(args);
  if ( (0 <= ret) &&
       (0 != n) &&
       (NULL == s) )
    return -1;

  return ret;
}

#endif  /* HAVE_SNPRINTF */
#endif /* _WIN32  && !__CYGWIN__ */
