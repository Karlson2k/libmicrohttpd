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
 * @file minimal_example.c
 * @brief minimal example for how to use libmicrohttpd
 * @author Christian Grothoff
 */

#include "config.h"
#include <microhttpd.h>
#include <stdlib.h>
#ifndef MINGW
#include <unistd.h>
#endif
#include <string.h>
#include <stdio.h>

#define PAGE "<html><head><title>libmicrohttpd demo</title></head><body>libmicrohttpd demo</body></html>"

static int apc_all(void * cls,
		   const struct sockaddr * addr,
		   socklen_t addrlen) {
  return MHD_YES;
}

static int ahc_echo(void * cls,
		    struct MHD_Session * session,
		    const char * url,
		    const char * method,
		    const char * upload_data,
		    unsigned int * upload_data_size) {
  const char * me = cls;
  struct MHD_Response * response;
  int ret;

  if (0 != strcmp(method, "GET"))
    return MHD_NO; /* unexpected method */
  response = MHD_create_response_from_data(strlen(me),
					   (void*) me,
					   MHD_NO,
					   MHD_NO);
  ret = MHD_queue_response(session,
			   MHD_HTTP_OK,
			   response);
  MHD_destroy_response(response);
  return ret;
}

int main(int argc,
	 char * const * argv) {
  struct MHD_Daemon * d;

  if (argc != 3) {
    printf("%s PORT SECONDS-TO-RUN\n",
	   argv[0]);
    return 1;
  }
  d = MHD_start_daemon(MHD_USE_THREAD_PER_CONNECTION | MHD_USE_IPv4 | MHD_USE_DEBUG,
		       atoi(argv[1]),
		       &apc_all,
		       NULL,
		       &ahc_echo,
		       PAGE);
  if (d == NULL)
    return 1;
  sleep(atoi(argv[2]));
  MHD_stop_daemon(d);
  return 0;
}

