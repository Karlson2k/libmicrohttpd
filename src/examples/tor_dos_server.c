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
 * @file tor_dos_server.c
 * @brief serve up random data forever
 * @author Meh
 */

#include "config.h"
#include <microhttpd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifndef MINGW
#include <unistd.h>
#endif
#include <string.h>
#include <stdio.h>
#include <sys/time.h>

#define PAGE "<html><head><title>File not found</title></head><body>File not found</body></html>"

static int
random_data_feeder (void *cls, size_t pos, char *buf, int max)
{
  
  memset(buf,'d',max);
  
  return 1;
}

static int
ahc_echo (void *cls,
          struct MHD_Connection *connection,
          const char *url,
          const char *method,
          const char *upload_data,
          const char *version, unsigned int *upload_data_size, void **ptr)
{
  static int aptr;
  struct MHD_Response *response;
  int ret;
  struct stat buf;
  
  fprintf(stderr,"received request!\n");
  if (0 != strcmp (method, MHD_HTTP_METHOD_GET))
  {
    fprintf(stderr,"Unknown method! %s\n",method);
    return MHD_NO;              /* unexpected method */
  }
  if (&aptr != *ptr)
  {
    /* do never respond on first call */
    *ptr = &aptr;
    return MHD_YES;
  }
  
  response = MHD_create_response_from_callback (-1, 32 * 1024,     /* 32k page size */
                                                    &random_data_feeder,
                                                    NULL,
                                                    (MHD_ContentReaderFreeCallback)
                                                    & fclose);
  ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
  MHD_destroy_response (response);
  
  
  return ret;
}

int
main (int argc, char *const *argv)
{
  struct MHD_Daemon *d;

  if (argc != 3)
    {
      printf ("%s PORT SECONDS-TO-RUN\n", argv[0]);
      return 1;
    }
  d = MHD_start_daemon (MHD_USE_THREAD_PER_CONNECTION | MHD_USE_DEBUG,
                        atoi (argv[1]),
                        NULL, NULL, &ahc_echo, PAGE, MHD_OPTION_CONNECTION_MEMORY_LIMIT, 1024 * 1024 * 10, MHD_OPTION_END);
  if (d == NULL)
    return 1;
  
  sleep(atoi(argv[2])); 


  MHD_stop_daemon (d);
  return 0;
}
