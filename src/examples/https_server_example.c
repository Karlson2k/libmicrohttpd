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
 * @file https_server_example.c
 * @brief a simple https file server using TLS.
 * 
 * This example assumes the existence of a private key file named "key.pem"
 * and a server certificate file named "cert.pem". File path for these should be
 * provided as command-line arguments. 'certtool' may be used to generate these if
 * missing. 
 * 
 * Access server with your browser of choice or with curl : 
 * 
 *   curl --insecure --tlsv1 --ciphers AES256-SHA <url>
 * 
 * @author LV-426
 */

#include "config.h"
#include <microhttpd.h>
#include <sys/stat.h>

#include <stdlib.h>
#ifndef MINGW
#include <unistd.h>
#endif
#include <string.h>
#include <stdio.h>
#include "gnutls.h"
#include <gcrypt.h>

#define BUF_SIZE 1024
#define MAX_URL_LEN 255

#define KEYFILE "key.pem"
#define CERTFILE "cert.pem"


// TODO remove if unused
#define CAFILE "ca.pem"
#define CRLFILE "crl.pem"

#define PAGE_NOT_FOUND "<html><head><title>File not found</title></head><body>File not found</body></html>"

static int
file_reader (void *cls, size_t pos, char *buf, int max)
{
  FILE *file = cls;

  fseek (file, pos, SEEK_SET);
  return fread (buf, 1, max, file);
}

/* HTTP access handler call back */
static int
http_ahc (void *cls,
          struct MHD_Connection *connection,
          const char *url,
          const char *method,
          const char *upload_data,
          const char *version, unsigned int *upload_data_size, void **ptr)
{
  static int aptr;
  struct MHD_Response *response;
  int ret;
  FILE *file;
  struct stat buf;

  if (0 != strcmp (method, MHD_HTTP_METHOD_GET))
    return MHD_NO;              /* unexpected method */
  if (&aptr != *ptr)
    {
      /* do never respond on first call */
      *ptr = &aptr;
      return MHD_YES;
    }
  *ptr = NULL;                  /* reset when done */
  
  file = fopen (url, "r");
  if (file == NULL)
    {
      response = MHD_create_response_from_data (strlen (PAGE_NOT_FOUND),
                                                (void *) PAGE_NOT_FOUND,
                                                MHD_NO, MHD_NO);
      ret = MHD_queue_response (connection, MHD_HTTP_NOT_FOUND, response);
      MHD_destroy_response (response);
    }
  else
    {
      stat (&url[1], &buf);
      response = MHD_create_response_from_callback (buf.st_size, 32 * 1024,     /* 32k PAGE_NOT_FOUND size */
                                                    &file_reader, file,
                                                    (MHD_ContentReaderFreeCallback)
                                                    & fclose);
      ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
      MHD_destroy_response (response);
    }
  return ret;
}
 
int
main (int argc, char *const *argv)
{
  char keyfile[255] = KEYFILE;
  char certfile[255] = CERTFILE;
  struct MHD_Daemon *TLS_daemon;

  /* look for HTTPS arguments */
  if (argc < 5)
    {
      printf
        ("Usage : %s HTTP-PORT SECONDS-TO-RUN HTTPS-PORT KEY-FILE CERT-FILE\n",
         argv[0]);
      return 1;
    }

  // TODO check if this is truly necessary -  disallow usage of the blocking /dev/random */
  // gcry_control(GCRYCTL_ENABLE_QUICK_RANDOM, 0);

  TLS_daemon = MHD_start_daemon (MHD_USE_THREAD_PER_CONNECTION | MHD_USE_DEBUG
                                 | MHD_USE_SSL, atoi (argv[3]),
                                 NULL,
                                 NULL, &http_ahc,
                                 NULL, MHD_OPTION_CONNECTION_TIMEOUT, 256,
                                 MHD_OPTION_HTTPS_KEY_PATH, argv[4],
                                 MHD_OPTION_HTTPS_CERT_PATH, argv[5],
                                 MHD_OPTION_END);

  if (TLS_daemon == NULL)
    {
      printf ("Error: failed to start TLS_daemon");
      return 1;
    }

  sleep (atoi (argv[2]));

  MHD_stop_daemon (TLS_daemon);

  return 0;
}
