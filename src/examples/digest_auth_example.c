/*
     This file is part of libmicrohttpd
     (C) 2010 Christian Grothoff (and other contributing authors)

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
 */

#include "platform.h"
#include <microhttpd.h>
#include <stdlib.h>

#define PAGE "<html><head><title>libmicrohttpd demo</title></head><body>libmicrohttpd demo</body></html>"

#define OPAQUE "11733b200778ce33060f31c9af70a870ba96ddd4"

static int
ahc_echo (void *cls,
          struct MHD_Connection *connection,
          const char *url,
          const char *method,
          const char *version,
          const char *upload_data, size_t *upload_data_size, void **ptr)
{
  struct MHD_Response *response;
  char *username;
  const char *password = "testpass";
  const char *realm = "test@example.com";
  int ret;

  username = MHD_digest_auth_get_username(connection);

  if (username == NULL) {
	  ret = MHD_queue_auth_fail_response(connection, realm,
					     password, 
					     OPAQUE,
					     MHD_NO);

	  return ret;
  }

  ret = MHD_digest_auth_check(connection, realm,
		  username, password, 300);

  free(username);

  if (ret == MHD_INVALID_NONCE) {
	  ret = MHD_queue_auth_fail_response(connection, realm,
					     password,
					     OPAQUE, MHD_YES);

	  return ret;
  }

  if (ret == MHD_NO) {
	  ret = MHD_queue_auth_fail_response(connection, realm,
					     password, OPAQUE, MHD_NO);
	  
	  return ret;
  }
  
  response = MHD_create_response_from_data(strlen(PAGE), PAGE,
		  MHD_NO, MHD_NO);

  ret = MHD_queue_response(connection, MHD_HTTP_OK, response);

  MHD_destroy_response(response);
  return ret;
}

int
main (int argc, char *const *argv)
{
  struct MHD_Daemon *d;

  if (argc != 2)
    {
      printf ("%s PORT\n", argv[0]);
      return 1;
    }
  d = MHD_start_daemon (MHD_USE_THREAD_PER_CONNECTION | MHD_USE_DEBUG,
                        atoi (argv[1]),
                        NULL, NULL, &ahc_echo, PAGE, MHD_OPTION_END);
  if (d == NULL)
    return 1;
  (void) getc (stdin);
  MHD_stop_daemon (d);
  return 0;
}
