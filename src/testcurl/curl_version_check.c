/*
     This file is part of libmicrohttpd
     (C) 2007 Christian Grothoff

     libmicrohttpd is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
     option) any later version.

     libmicrohttpd is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with libmicrohttpd; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

/**
 * @file curl_version_check.c
 * @brief  verify required cURL version is available to run tests
 * @author Sagie Amir
 */

#include "config.h"
#include <curl/curl.h>
#include <microhttpd.h>
#include <stdlib.h>
#include <string.h>
#include "internal.h"

#ifndef WINDOWS
#include <unistd.h>
#endif

static int
parse_version_number (const char **s)
{
  int i = 0;
  char num[16];

  while (i < 16 && ((**s >= '0') & (**s <= '9')))
    {
      num[i] = **s;
      (*s)++;
      i++;
    }

  num[i] = '\0';

  return atoi (num);
}

const char *
parse_version_string (const char *s, int *major, int *minor, int *micro)
{
  *major = parse_version_number (&s);
  if (!s || *s != '.')
    return NULL;
  s++;
  *minor = parse_version_number (&s);
  if (!s || *s != '.')
    return NULL;
  s++;
  *micro = parse_version_number (&s);
  if (!s)
    return NULL;
  return s;
}


/*
 * check local libcurl version matches required version
 */
int
curl_check_version (const char *req_version, ...)
{
  va_list ap;
  const char *ver;
  const char *curl_ver;
  const char *ssl_ver;
  const char *req_ssl_ver;

  int loc_major, loc_minor, loc_micro;
  int rq_major, rq_minor, rq_micro;

  ver = curl_version ();
  /*
   * this call relies on the cURL string to be of the format :
   * 'libcurl/7.16.4 OpenSSL/0.9.8g zlib/1.2.3.3 libidn/0.6.5'
   */
  curl_ver = strchr (ver, '/') + 1;
  ssl_ver = strchr (curl_ver, '/') + 1;

  /* Parse version numbers */
  parse_version_string (req_version, &rq_major, &rq_minor, &rq_micro);
  parse_version_string (curl_ver, &loc_major, &loc_minor, &loc_micro);

  /* Compare version numbers.  */
  if ((loc_major > rq_major
       || (loc_major == rq_major && loc_minor > rq_minor)
       || (loc_major == rq_major && loc_minor == rq_minor
           && loc_micro > rq_micro) || (loc_major == rq_major
                                        && loc_minor == rq_minor
                                        && loc_micro == rq_micro)) == 0)
    {
      fprintf (stderr,
               "Error: running curl test depends on local libcurl version > %s\n",
               req_version);
      return -1;
    }

#if HTTPS_SUPPORT
  va_start (ap, req_version);
  req_ssl_ver = va_arg (ap, void *);

  parse_version_string (req_ssl_ver, &rq_major, &rq_minor, &rq_micro);
  parse_version_string (ssl_ver, &loc_major, &loc_minor, &loc_micro);

  if ((loc_major > rq_major
       || (loc_major == rq_major && loc_minor > rq_minor)
       || (loc_major == rq_major && loc_minor == rq_minor
           && loc_micro > rq_micro) || (loc_major == rq_major
                                        && loc_minor == rq_minor
                                        && loc_micro == rq_micro)) == 0)
    {
      fprintf (stderr,
               "Error: running curl test depends on local libcurl-openssl version > %s\n",
               req_ssl_ver);
      return -1;
    }
#endif
  return 0;
}
