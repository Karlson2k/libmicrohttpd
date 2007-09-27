/*
     This file is part of libmicrohttpd
     (C) 2007 Daniel Pittman and Christian Grothoff

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
 * @file internal.h
 * @brief  internal shared structures
 * @author Daniel Pittman
 * @author Christian Grothoff
 */

#include "internal.h"

#if HAVE_MESSAGES
/**
 * fprintf-like helper function for logging debug
 * messages.
 */
void
MHD_DLOG (const struct MHD_Daemon *daemon, const char *format, ...)
{
  va_list va;

  if ((daemon->options & MHD_USE_DEBUG) == 0)
    return;
  va_start (va, format);
  VFPRINTF (stderr, format, va);
  va_end (va);
}
#endif

/**
 * Process escape sequences ('+'=space, %HH)
 */
void
MHD_http_unescape (char *val)
{
  char *esc;
  unsigned int num;

  while (NULL != (esc = strstr (val, "+")))
    *esc = ' ';
  while (NULL != (esc = strstr (val, "%")))
    {
      if ((1 == sscanf (&esc[1],
                        "%2x", &num)) || (1 == sscanf (&esc[1], "%2X", &num)))
        {
          esc[0] = (unsigned char) num;
          memmove (&esc[1], &esc[3], strlen (&esc[3]) + 1);
        }
      val = esc + 1;
    }
}
