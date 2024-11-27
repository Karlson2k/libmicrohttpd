/*
  This file is part of GNU libmicrohttpd
  Copyright (C) 2024 Christian Grothoff

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
 * @file libtest_convenience.c
 * @brief convenience functions for libtest users
 * @author Christian Grothoff
 */
#include <pthread.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include "libtest.h"
#include <curl/curl.h>


const char *
MHDT_server_setup_minimal (const void *cls,
                           struct MHD_Daemon *d)
{
  const struct MHD_DaemonOptionAndValue *options = cls;

  if (MHD_SC_OK !=
      MHD_daemon_set_options (
        d,
        options,
        MHD_OPTIONS_ARRAY_MAX_SIZE))
    return "Failed to configure threading mode!";
  if (MHD_SC_OK !=
      MHD_DAEMON_SET_OPTIONS (
        d,
        MHD_D_OPTION_BIND_PORT (MHD_AF_AUTO,
                                0)))
    return "Failed to bind to port 0!";
  return NULL;
}


/**
 * Setup TLS at @a d for the given backend @a be.
 *
 * @return NULL on success, otherwise error message
 */
static const char *
server_setup_tls (struct MHD_Daemon *d,
                  enum MHD_TlsBackend be)
{
  static const char *mem_cert =
    "-----BEGIN CERTIFICATE-----\n\
MIIFJjCCAw6gAwIBAgIBBTANBgkqhkiG9w0BAQsFADCBgTELMAkGA1UEBhMCUlUx\n\
DzANBgNVBAgMBk1vc2NvdzEPMA0GA1UEBwwGTW9zY293MRswGQYDVQQKDBJ0ZXN0\n\
LWxpYm1pY3JvaHR0cGQxITAfBgkqhkiG9w0BCQEWEm5vYm9keUBleGFtcGxlLm9y\n\
ZzEQMA4GA1UEAwwHdGVzdC1DQTAgFw0yMjA0MjAxODQ1MDVaGA8yMTIyMDMyNjE4\n\
NDUwNVowXzELMAkGA1UEBhMCUlUxDzANBgNVBAgMBk1vc2NvdzEPMA0GA1UEBwwG\n\
TW9zY293MRswGQYDVQQKDBJ0ZXN0LWxpYm1pY3JvaHR0cGQxETAPBgNVBAMMCG1o\n\
ZGhvc3QxMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxb5LkwTfvNtW\n\
eFSYAPoEzqwVARWxDDR2PfQmmBtrHhMNEQyUCTg+Na00hEQbcZbz7fgS0FOY1hjy\n\
MFJamNGP031HvMS7zHNQJ4HbEz0d1EuePgjEvWaFMFncTKGn07Cn9e3Rcv2ihJ/I\n\
I8wf3ph/k/UTOv62YhIs2fMQM5LD6oX9ulKJhAaOvFT6hyrB1xe3nVhPT0PsrUXl\n\
ky253k7XXEAIWO6dLZnK377UiRDJInFS9FN/hojFb+8gcByo/n39LHMBtp5WGM5+\n\
xGwEHyYkwtnaM8IEKofbUNERQT3cgPv4zN7ny3LwljR2A1c5gHXmKO7G245tbfqb\n\
VtOh3+1bJQIDAQABo4HHMIHEMAsGA1UdDwQEAwIFoDAMBgNVHRMBAf8EAjAAMBYG\n\
A1UdJQEB/wQMMAoGCCsGAQUFBwMBMBMGA1UdEQQMMAqCCG1oZGhvc3QxMB0GA1Ud\n\
DgQWBBTTxzQ/fcuT83JlCzPx8qJzuHCG4jAnBglghkgBhvhCAQ0EGhYYVGVzdCBs\n\
aWJtaWNyb2h0dHBkIGhvc3QxMBEGCWCGSAGG+EIBAQQEAwIGQDAfBgNVHSMEGDAW\n\
gBRYdUPApWoxw4U13Rqsjf9AHdbpLDANBgkqhkiG9w0BAQsFAAOCAgEAMdHjWHxt\n\
51LH3V8Um3djUh+QYVnYhxFVX4CIXMq2DAg7iYw6tg2S1SOm3R+qEB/rAHxRw/cd\n\
nekjx0zm2rAnn4SsIQg5rXzniM4dJ2UQJrn7m88fb/czjXCrvf6hGIXCSAw/YyU0\n\
IkxXlOYv1mYNZBuVvFREUbqqK2Fn+ooIi816Q2UCQFMd+QI8+mn8eqK8XeJElKkt\n\
SR0WCLW7UkwYxOk73FCdrr1TlX9hAF76gTAK71OJN3F35hzg+pTAEe3nwFMZbG/k\n\
xHmVob51L+Op4Y15j1HoJxW0Ox+PuxVcp9EpC7Qb8UmtExAsYOuN2PP8hU+pmtE4\n\
iYpCDckx6kT66ssjndaKziRmoxX/czvKCAwVDder6Ofl4SwGUEpE+0oO2ux6iNrl\n\
iKxRCvyBqErFlzlEj7oO3agqe83jtTH8bXzOCtx36lNVjCuADYI4o7r5NVHaGIx6\n\
1q5BiZ5pj22EYgBZbRAgE1ZPxVBIZJKoHewmQqpcR5WsSeBIf8XDuytnadhv8NDN\n\
tpLMDry8KkUh7rtjrQIGb66BqCt0n1tz1/6nLlL9OF5kUt4902wCtN3SbotssfV3\n\
NCX9X4udquRdcFwNLCSfZ505FqhYbeSLraDHJ46/96V//Vx4oAnULdcCm4QgGQmP\n\
EGEJDJkaCKKTGMHAvZAtgRchc/RTf59jhoc=\n\
-----END CERTIFICATE-----";
  static const char *mem_key  =
    "-----BEGIN PRIVATE KEY-----\n\
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDFvkuTBN+821Z4\n\
VJgA+gTOrBUBFbEMNHY99CaYG2seEw0RDJQJOD41rTSERBtxlvPt+BLQU5jWGPIw\n\
UlqY0Y/TfUe8xLvMc1AngdsTPR3US54+CMS9ZoUwWdxMoafTsKf17dFy/aKEn8gj\n\
zB/emH+T9RM6/rZiEizZ8xAzksPqhf26UomEBo68VPqHKsHXF7edWE9PQ+ytReWT\n\
LbneTtdcQAhY7p0tmcrfvtSJEMkicVL0U3+GiMVv7yBwHKj+ff0scwG2nlYYzn7E\n\
bAQfJiTC2dozwgQqh9tQ0RFBPdyA+/jM3ufLcvCWNHYDVzmAdeYo7sbbjm1t+ptW\n\
06Hf7VslAgMBAAECggEALshrttezW0oFNijFYY3FL2Q0//Gy1nFe/B9UNi5edFoL\n\
gFoad+fvh+F3iEdYutH82fMT+GeexCBYxCfnuTnzLhT4sOdWivNJJl+phe6yrPRK\n\
9uA6M5kar6rC3Ppt6z5jLmLaZ7ssBPaMcjOr4ozvugCEUTPL0H3+UH4Z+imh4kzw\n\
MgLsF8QkWPCF/fxsVhCwC3y3Dctl3oLh6qQFudYKtymRjk2I7zFAuQGsGoYonPbF\n\
1LZ6xHOjegXtqhC0pK8Kpn4N7LgYVVNPT1TAckQ9GDDi0IgMYwIsSQb/ncaV5Cwb\n\
9tPqBv1Oi2ayINeXrG5J/G8S1cEbIzdSL8ZqG+CcjQKBgQD1c89Rh/Hbc0zxxgdR\n\
eGx6oOtNjAZ3zgnNyVnXiZ7mXtbCcjMHJhcW41RL8lg+mhKfj9MgXamDP/R4X2In\n\
H358dEekfN4wjogeXs9lmh48cGC7zez4/RS752OmrwmhOqkKDa7dy+SLR5QJ3L2n\n\
4k/2eQwTlXpuPIMrBT1hUvsA3wKBgQDOPaTy03oXX1bwwX6sHUTrQTKAC52v4hQl\n\
bya+6t+VGpj+cdWzxRFoR5mN85b9Kkj1nAFx+6zioOPLUOZhnnqihlQBwm06gH1p\n\
v3qkxuXOhnMPJsNg4lltUq/18UlSQwFZuKr7G2vDhckHwZdlu06P/rlA9K5Kxjzi\n\
gX3I+XoQewKBgQDrn/YYXXmW4jOuMR0bX5A7lDjuY4pd/iO5Mh6V453vpoFhfoFv\n\
zmgB588nbQi7Z+qS1F2nx2IQBhgoaeBukDQ7QuD3jYs6b8lJ5lgQQAfgmzyxbPic\n\
+U6rJ3CpNYT4Crj1VrdUYgQOlHMPmKFUBdQfVop6TleOdXaxmMEYqbEdXwKBgQCz\n\
xZwQZjJYSSyZc7CdCm5Wul/wqS9sbp6s+rRFWqpFaAfQUx26M582zKKWz6vfRYqP\n\
PMsttfk/Gos1YHFQyjmPjZOQbQ+VHQc0tEmNdCpA2YVVwa4wt1zIJHlo4kfNQsbc\n\
lFHFzGMk7WsMLb1wWdLjRV/ptN5wI1hTABjKpFu4HQKBgExQNTHMxzpAAh9XFiJ3\n\
oGvf+9+JtjmrgKsR0T7q60xjOYH0E2rznvvBVNeZlAc+tjawmedxiuiitmjQUteG\n\
hW4ncX0UcqFPm7Ahqo9+NDemJlV7DYHRcvL/xVNUbr8yV7OpHILd4Hk/s8J4QGl/\n\
bC1zEehy8q0jMywvSR8vsS1v\n\
    -----END PRIVATE KEY-----";

  if (MHD_SC_OK !=
      MHD_DAEMON_SET_OPTIONS (
        d,
        MHD_D_OPTION_TLS (be)))
    return "Failed to enable TLS!";
  if (MHD_SC_OK !=
      MHD_DAEMON_SET_OPTIONS (
        d,
        MHD_D_OPTION_TLS_CERT_KEY (mem_cert,
                                   mem_key,
                                   NULL)))
    return "Failed to enable TLS!";
  return NULL;
}


const char *
MHDT_server_setup_tls (const void *cls,
                       struct MHD_Daemon *d)
{
  const struct MHD_DaemonOptionAndValue *options = cls;
  const char *err;

  err = MHDT_server_setup_minimal (options,
                                   d);
  if (NULL != err)
    return err;
  err = server_setup_tls (d,
                          MHD_TLS_BACKEND_ANY);
  if (NULL != err)
    return err;
  return NULL;
}


const char *
MHDT_server_setup_gnutls (const void *cls,
                          struct MHD_Daemon *d)
{
  const struct MHD_DaemonOptionAndValue *options = cls;
  const char *err;

  err = MHDT_server_setup_minimal (options,
                                   d);
  if (NULL != err)
    return err;
  err = server_setup_tls (d,
                          MHD_TLS_BACKEND_GNUTLS);
  if (NULL != err)
    return err;
  return NULL;
}


void
MHDT_server_run_minimal (void *cls,
                         int finsig,
                         struct MHD_Daemon *d)
{
  fd_set r;
  char c;

  (void) cls; /* Unused */
  (void) d;   /* Unused */

  FD_ZERO (&r);
  FD_SET (finsig, &r);
  while (1)
  {
    if ( (-1 ==
          select (finsig + 1,
                  &r,
                  NULL,
                  NULL,
                  NULL)) &&
         (EAGAIN != errno) )
    {
      fprintf (stderr,
               "Failure waiting on termination signal: %s\n",
               strerror (errno));
      break;
    }
    if (FD_ISSET (finsig,
                  &r))
      break;
  }
  if ( (FD_ISSET (finsig,
                  &r)) &&
       (1 != read (finsig,
                   &c,
                   1)) )
  {
    fprintf (stderr,
             "Failed to drain termination signal\n");
  }
}


void
MHDT_server_run_blocking (void *cls,
                          int finsig,
                          struct MHD_Daemon *d)
{
  fd_set r;
  char c;

  (void) cls; /* Unused */
  (void) d;   /* Unused */

  FD_ZERO (&r);
  FD_SET (finsig, &r);
  while (1)
  {
    struct timeval timeout = {
      .tv_usec = 1000 /* 1000 microseconds */
    };

    if ( (-1 ==
          select (finsig + 1,
                  &r,
                  NULL,
                  NULL,
                  &timeout)) &&
         (EAGAIN != errno) )
    {
      fprintf (stderr,
               "Failure waiting on termination signal: %s\n",
               strerror (errno));
      break;
    }
#if FIXME
    if (MHD_SC_OK !=
        MHD_daemon_process_blocking (d,
                                     1000))
    {
      fprintf (stderr,
               "Failure running MHD_daemon_process_blocking()\n");
      break;
    }
#else
    abort ();
#endif
  }
  if ( (FD_ISSET (finsig,
                  &r)) &&
       (1 != read (finsig,
                   &c,
                   1)) )
  {
    fprintf (stderr,
             "Failed to drain termination signal\n");
  }
}
