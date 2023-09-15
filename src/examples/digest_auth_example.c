/*
     This file is part of libmicrohttpd
     Copyright (C) 2010 Christian Grothoff (and other contributing authors)
     Copyright (C) 2016-2022 Evgeny Grin (Karlson2k)

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
 * @file digest_auth_example.c
 * @brief minimal example for how to use digest auth with libmicrohttpd
 * @author Amr Ali
 * @author Karlson2k (Evgeny Grin)
 */

#include "platform.h"
#include <microhttpd.h>
#include <stdlib.h>
#include <errno.h>

#define PAGE \
  "<html><head><title>libmicrohttpd demo</title></head>" \
  "<body>Access granted</body></html>"

#define DENIED \
  "<html><head><title>libmicrohttpd demo</title></head>" \
  "<body>Access denied</body></html>"

#define MY_OPAQUE_STR "11733b200778ce33060f31c9af70a870ba96ddd4"

static enum MHD_Result
ahc_echo (void *cls,
          struct MHD_Connection *connection,
          const char *url,
          const char *method,
          const char *version,
          const char *upload_data, size_t *upload_data_size, void **req_cls)
{
  struct MHD_Response *response;
  char *username;
  const char *password = "testpass";
  const char *realm = "test@example.com";
  enum MHD_DigestAuthResult res_e;
  enum MHD_Result ret;
  static int already_called_marker;
  (void) cls;               /* Unused. Silent compiler warning. */
  (void) url;               /* Unused. Silent compiler warning. */
  (void) method;            /* Unused. Silent compiler warning. */
  (void) version;           /* Unused. Silent compiler warning. */
  (void) upload_data;       /* Unused. Silent compiler warning. */
  (void) upload_data_size;  /* Unused. Silent compiler warning. */

  if (&already_called_marker != *req_cls)
  { /* Called for the first time, request not fully read yet */
    *req_cls = &already_called_marker;
    /* Wait for complete request */
    return MHD_YES;
  }

  username = MHD_digest_auth_get_username (connection);
  if (NULL == username)
  {
    response =
      MHD_create_response_from_buffer_static (strlen (DENIED),
                                              DENIED);
    ret = MHD_queue_auth_fail_response2 (connection, realm,
                                         MY_OPAQUE_STR,
                                         response,
                                         MHD_NO,
                                         MHD_DIGEST_ALG_MD5);
    MHD_destroy_response (response);
    return ret;
  }
  res_e = MHD_digest_auth_check3 (connection, realm,
                                  username,
                                  password,
                                  300, 60, MHD_DIGEST_AUTH_MULT_QOP_AUTH,
                                  MHD_DIGEST_AUTH_MULT_ALGO3_MD5);
  MHD_free (username);
  if (res_e != MHD_DAUTH_OK)
  {
    response =
      MHD_create_response_from_buffer_static (strlen (DENIED),
                                              DENIED);
    if (NULL == response)
      return MHD_NO;
    ret = MHD_queue_auth_fail_response2 (connection, realm,
                                         MY_OPAQUE_STR,
                                         response,
                                         (res_e == MHD_DAUTH_NONCE_STALE) ?
                                         MHD_YES : MHD_NO,
                                         MHD_DIGEST_ALG_MD5);
    MHD_destroy_response (response);
    return ret;
  }
  response = MHD_create_response_from_buffer_static (strlen (PAGE), PAGE);
  ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
  MHD_destroy_response (response);
  return ret;
}


int
main (int argc, char *const *argv)
{
  int fd;
  char rnd[8];
  ssize_t len;
  size_t off;
  struct MHD_Daemon *d;
  unsigned int port;

  if ( (argc != 2) ||
       (1 != sscanf (argv[1], "%u", &port)) ||
       (65535 < port) )
  {
    printf ("%s PORT\n", argv[0]);
    return 1;
  }

  fd = open ("/dev/urandom", O_RDONLY);
  if (-1 == fd)
  {
    fprintf (stderr, "Failed to open `%s': %s\n",
             "/dev/urandom",
             strerror (errno));
    return 1;
  }
  off = 0;
  while (off < 8)
  {
    len = read (fd, rnd, 8);
    if (0 > len)
    {
      fprintf (stderr, "Failed to read `%s': %s\n",
               "/dev/urandom",
               strerror (errno));
      (void) close (fd);
      return 1;
    }
    off += (size_t) len;
  }
  (void) close (fd);
  d = MHD_start_daemon (MHD_USE_THREAD_PER_CONNECTION
                        | MHD_USE_INTERNAL_POLLING_THREAD | MHD_USE_ERROR_LOG,
                        (uint16_t) port,
                        NULL, NULL, &ahc_echo, NULL,
                        MHD_OPTION_DIGEST_AUTH_RANDOM, sizeof(rnd), rnd,
                        MHD_OPTION_NONCE_NC_SIZE, 300,
                        MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int) 120,
                        MHD_OPTION_END);
  if (d == NULL)
    return 1;
  (void) getc (stdin);
  MHD_stop_daemon (d);
  return 0;
}


/* end of digest_auth_example.c */
