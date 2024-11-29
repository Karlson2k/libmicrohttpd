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
#include "libtest.h"
#include <pthread.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
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
MIIDjTCCAnWgAwIBAgIUKkxAx2lVnvYcaNqBpJmTgXh1/VgwDQYJKoZIhvcNAQEL\n\
BQAwVjELMAkGA1UEBhMCVVMxFjAUBgNVBAgMDU1hc3NhY2h1c2V0dHMxDzANBgNV\n\
BAcMBkJvc3RvbjENMAsGA1UECgwEUm9vdDEPMA0GA1UEAwwGY2EuZ251MB4XDTI0\n\
MTEyOTEyNDUyOFoXDTM0MTEyNzEyNDUyOFowVjELMAkGA1UEBhMCVVMxFjAUBgNV\n\
BAgMDU1hc3NhY2h1c2V0dHMxDzANBgNVBAcMBkJvc3RvbjENMAsGA1UECgwEUm9v\n\
dDEPMA0GA1UEAwwGY2EuZ251MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC\n\
AQEA23YSrcGIBgZf9bbzTnmYFy+4tM82kUhsVFKxWCNEMdKmhaeVvXogyd6Evq4P\n\
NvBGdUABDtHp4pSEijrxWbn8sxddTznoT/8IOuHI0/PtwXYP/sHQ/HzekEUVKN2Z\n\
NMbMUzQfaJyiIV5TrZlaBwHjQ+sRs8E56C3cQjkwuyjll2zDsEfmEnPimZRAL3kb\n\
wW8VFfBcR2Id+a9xKjwlnB4eXQFAgYINoRgCtUOUxSeFgNnwkOUSqDknO6Xi47YZ\n\
EdLlHyUnv5eX547xUkrYhfQuQwaqpGrjHf3GFoysN8P9kd2f1qsJKtQcUbF9DDeZ\n\
6ya47X/LBO8QflMsVjb1V3oz9QIDAQABo1MwUTAdBgNVHQ4EFgQUsvdZoX3RxdN6\n\
wrONr31SOA9Qbc4wHwYDVR0jBBgwFoAUsvdZoX3RxdN6wrONr31SOA9Qbc4wDwYD\n\
VR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAS3PyV7crGk9brqU90aML\n\
2TWkjgzFb3/nASnpvVYiqyiV4neGiEjtDy7eVlqP6GlD2pYcVodY+ly9wNlo85/h\n\
YfgCFFl37tMG7PpRac2qBqaSn1DpwsCb08LjRrOvoaRffWUikSoZmsYDlaCgl9nT\n\
pGtIrz0BSoyu5mHalIZTVQOrbkNBNK6ZgnYy2iWuiLa5Z1xzKpsRBRaKJc1pcQE/\n\
QVbPdCiyGQMPEVn/KHxitlycFoee/fA+izXVdstVwfig2DoMvrlGZvEkN1ER3Yz4\n\
QPJ6HzOsBQL1F+YhnMCQfc2rpcwxAWf8JMy6jsCq42KGq53tkWqHyQ6Zu2SiLRYk\n\
CA==\n\
-----END CERTIFICATE-----";
  static const char *mem_key  =
    "-----BEGIN ENCRYPTED PRIVATE KEY-----\n\
MIIFJDBWBgkqhkiG9w0BBQ0wSTAxBgkqhkiG9w0BBQwwJAQQJ1VSHi+akaaVYO3O\n\
H7I0EAICCAAwDAYIKoZIhvcNAgkFADAUBggqhkiG9w0DBwQIZlNzQR1bh4IEggTI\n\
8U86bfGmyAXXSi/R/l3G8ziZFyHrRE5Q/Q3uUW/jyUpe+S0gMRPqwW3V542ForbH\n\
IH/Aa+KVxlwmsq0jlheCQewj9qZMQGuqa3iTl/OfCcuGMfsuQs2HsutoDMdEYuBI\n\
6yOqNIrRvSHunZILLDpKz/AmCO6JnRiAwiSqPBixE5M+cm1qc7dy024REiW9l9K6\n\
Hth9A0iYc94CUyUfHFj4CEkCNqk533Z2Ktkk3RQJnx5ORQG0iBJvoFiVODFKnoAk\n\
Ge2HNrJH3bVvhQ+p8A/L4VmnWUCfcTyqgzo887WXRxORya6gcWWtrcEJGUbLh8sL\n\
/mXFYj/0kEllIY+fHOmSx94I3GwBkQKER/CeOCIp+C392Pujgzrz23pdq20uIt3d\n\
FCgbnIB+5IwOwQcqCkTYa1+Y5qCa6eFLgd8PXGTDyFwP4BHfG6WT/ctHQFi8vnXV\n\
D1S726do1mA6CFE3DYmi45sf+Te2Xb346xk1GTSWtxGh9y4FblFDAWva4oTuvxPR\n\
IDseBhXBsIqnOy1gb/5cGj0SIOQzqR1qlg4igv3UZFC8cVl+fNnngDBiX+nTYQVm\n\
rDyxTzcX9txPSNpLyYRdNHwLGpzZAMoN46bUFnxt0cvRWN6MA7j1r0TYWBZKJ7b7\n\
Yt/SuYsqSE0UJQEJz4QcQnlxu3qu4HJl7dOlto3fa42MWTkOcNr9XinHmKCZ9oYZ\n\
PYNTggRGMXlqm66KmHWDqXqw9CeufprHq15SIJJR8v4SlvEZr+YlYQeHRI4E+FDA\n\
mEFZy/U3ZL7ZHSDsEvpeBzIJkWxHobt57BIxYHE8KN0ZIz/mJZTxljacblFWnJRb\n\
AUXTfrRZn3lGX+4WA6Biilwyxb71slCKaiz28C55Hnj1UwoUF8vNA3G2FGAX5Wk0\n\
m3J2SoCHtJQYc/3lEC7zR9i3/F/7vgRxZMUWt/y6KRYq8ZnoQl3Eo2yvJYX/z7I6\n\
JyqexAx3OvA+frN3rbO/o/k6w9333Smi0QxZzDM9tHn1BAgAtmyC1lizzKn7hDYK\n\
o/eaPeatILbS0a/bHJBbP/R53keVr0hJ3MWK2nb/DV5Dl9j4Z6sHpo3P9L+Kq06y\n\
G9q7NhBd7cxGq4AkCp+eSjqTvwgOX1PtAry00TUmzisLz8gIYutwJqbfZGL8WpR/\n\
/wnLQXuM/tPLdQNy+PZeTQnPFwWQeZz4VgkMRhHV2xDw0mpzE+cdD204+YjHVdMH\n\
D4MNrDlUmKM0OVoYgXd9YyLKzYVgW95GvY1X0SxTlIUuDiRv/SqRsurPFkSG457d\n\
zmTUny1NRsnbv9bTXqt1Xewqsylyu02N1dZvjIzBnYMVYXl0r4aej1VNEXozQtWO\n\
YRfWaZ29dXwZqUzd83ETQvhI4mZbwAlHbqm/CoyY6Vw4Am8hGa7II134lz2b3tkr\n\
F1zBkvzzl6+HXewGOEjm+YorDMtfADiU/hkkykWq01NG3QSwk7jaKieb5Rlou53d\n\
IXJQBw0KW5UrgbIFqMjpSZz1jdALBKsV+dw0wvCQ8BVXZm3zZpsV+0E4Z0sdj3TI\n\
UbkFqQ6GpoxB25UUUlLZhBbtKy7dheuPBk0HowitYlo1kLVA/JiFB4qbdf5X/9Tm\n\
XRkN+T0orEgy7rBQa7dJN9bdLj+dS5q8\n\
    -----END ENCRYPTED PRIVATE KEY-----";

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
                                   "masterword")))
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
