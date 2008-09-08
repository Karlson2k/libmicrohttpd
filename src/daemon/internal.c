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
 * State to string dictionary.
 */
char *
MHD_state_to_string (enum MHD_CONNECTION_STATE state)
{
  switch (state)
    {
    case MHD_CONNECTION_INIT:
      return "connection init";
    case MHD_CONNECTION_URL_RECEIVED:
      return "connection url received";
    case MHD_CONNECTION_HEADER_PART_RECEIVED:
      return "header partially received";
    case MHD_CONNECTION_HEADERS_RECEIVED:
      return "headers received";
    case MHD_CONNECTION_HEADERS_PROCESSED:
      return "headers processed";
    case MHD_CONNECTION_CONTINUE_SENDING:
      return "continue sending";
    case MHD_CONNECTION_CONTINUE_SENT:
      return "continue sent";
    case MHD_CONNECTION_BODY_RECEIVED:
      return "body received";
    case MHD_CONNECTION_FOOTER_PART_RECEIVED:
      return "footer partially received";
    case MHD_CONNECTION_FOOTERS_RECEIVED:
      return "footers received";
    case MHD_CONNECTION_HEADERS_SENDING:
      return "headers sending";
    case MHD_CONNECTION_HEADERS_SENT:
      return "headers sent";
    case MHD_CONNECTION_NORMAL_BODY_READY:
      return "normal body ready";
    case MHD_CONNECTION_NORMAL_BODY_UNREADY:
      return "normal body unready";
    case MHD_CONNECTION_CHUNKED_BODY_READY:
      return "chunked body ready";
    case MHD_CONNECTION_CHUNKED_BODY_UNREADY:
      return "chunked body unready";
    case MHD_CONNECTION_BODY_SENT:
      return "body sent";
    case MHD_CONNECTION_FOOTERS_SENDING:
      return "footers sending";
    case MHD_CONNECTION_FOOTERS_SENT:
      return "footers sent";
    case MHD_CONNECTION_CLOSED:
      return "closed";
    case MHD_TLS_CONNECTION_INIT:
      return "secure connection init";
    case MHD_TLS_HELLO_REQUEST:
      return "secure hello request";
    case MHD_TLS_HANDSHAKE_FAILED:
      return "secure handshake failed";
    case MHD_TLS_HANDSHAKE_COMPLETE:
      return "secure handshake _complete";
    default:
      return "unrecognized connection state";
    }
}
#endif

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
void
MHD_tls_log_func (int level, const char *str)
{
#ifdef DEBUG
  FPRINTF (stdout, "|<%d>| %s", level, str);
#endif
}

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
      if ((1 == SSCANF (&esc[1],
                        "%2x", &num)) || 
	  (1 == SSCANF (&esc[1],
			"%2X", &num)))
        {
          esc[0] = (unsigned char) num;
          memmove (&esc[1], &esc[3], strlen (&esc[3]) + 1);
        }
      val = esc + 1;
    }
}

/* end of internal.c */
