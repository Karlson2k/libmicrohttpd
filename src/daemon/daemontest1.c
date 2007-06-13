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
 * @file daemontest1.c
 * @brief  Testcase for libmicrohttpd GET operations
 *         TODO: external select
 * @author Christian Grothoff
 */

#include "config.h"
#include <curl/curl.h>
#include <microhttpd.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

static int apc_all(void * cls,
		   const struct sockaddr * addr,
		   socklen_t addrlen) {
  return MHD_YES;
}

struct CBC {
  char * buf;
  size_t pos;
  size_t size;
};

static size_t copyBuffer(void * ptr,
			 size_t size,
			 size_t nmemb,
			 void * ctx) {
  struct CBC * cbc = ctx;

  if (cbc->pos + size * nmemb > cbc->size)
    return 0; /* overflow */
  memcpy(&cbc->buf[cbc->pos],
	 ptr,
	 size * nmemb);
  cbc->pos += size * nmemb;
  return size * nmemb;
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

  if (0 != strcmp(me, method))
    return MHD_NO; /* unexpected method */
  response = MHD_create_response_from_data(strlen(url),
					   (void*) url,
					   MHD_NO,
					   MHD_YES);
  ret = MHD_queue_response(session,
			   MHD_HTTP_OK,
			   response);
  MHD_destroy_response(response);
  return ret;
}


static int testInternalGet() {
  struct MHD_Daemon * d;
  CURL * c;
  char buf[2048];
  struct CBC cbc;

  cbc.buf = buf;
  cbc.size = 2048;
  cbc.pos = 0;
  d = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY | MHD_USE_IPv4 | MHD_USE_DEBUG,
		       1080,
		       &apc_all,
		       NULL,
		       &ahc_echo,
		       "GET");
  if (d == NULL)
    return 1;
  c = curl_easy_init();
  curl_easy_setopt(c,
		   CURLOPT_URL,
		   "http://localhost:1080/hello_world");
  curl_easy_setopt(c,
		   CURLOPT_WRITEFUNCTION,
		   &copyBuffer);
  curl_easy_setopt(c,
		   CURLOPT_WRITEDATA,
		   &cbc);
  curl_easy_setopt(c,
		   CURLOPT_FAILONERROR,
		   1);
  curl_easy_setopt(c,
		   CURLOPT_TIMEOUT,
		   2L);
  curl_easy_setopt(c,
		   CURLOPT_CONNECTTIMEOUT,
		   2L);
  // NOTE: use of CONNECTTIMEOUT without also
  //   setting NOSIGNAL results in really weird
  //   crashes on my system!
  curl_easy_setopt(c,
		   CURLOPT_NOSIGNAL,
		   1);  
  if (CURLE_OK != curl_easy_perform(c)) {
    curl_easy_cleanup(c);  
    MHD_stop_daemon(d);  
    return 2;
  }    
  curl_easy_cleanup(c);  
  if (cbc.pos != strlen("hello_world")) {
    MHD_stop_daemon(d);
    return 4;
  }
  
  if (0 != strncmp("hello_world",
		   cbc.buf,
		   strlen("hello_world"))) {
    MHD_stop_daemon(d);
    return 8;
  }
  
  MHD_stop_daemon(d);
  
  return 0;
}

static int testMultithreadedGet() {
  struct MHD_Daemon * d;
  CURL * c;
  char buf[2048];
  struct CBC cbc;

  cbc.buf = buf;
  cbc.size = 2048;
  cbc.pos = 0;
  d = MHD_start_daemon(MHD_USE_THREAD_PER_CONNECTION | MHD_USE_IPv4 | MHD_USE_DEBUG,
		       1081,
		       &apc_all,
		       NULL,
		       &ahc_echo,
		       "GET");
  if (d == NULL)
    return 16;
  c = curl_easy_init();
  curl_easy_setopt(c,
		   CURLOPT_URL,
		   "http://localhost:1081/hello_world");
  curl_easy_setopt(c,
		   CURLOPT_WRITEFUNCTION,
		   &copyBuffer);
  curl_easy_setopt(c,
		   CURLOPT_WRITEDATA,
		   &cbc);
  curl_easy_setopt(c,
		   CURLOPT_FAILONERROR,
		   1);
  curl_easy_setopt(c,
		   CURLOPT_TIMEOUT,
		   2L);
  curl_easy_setopt(c,
		   CURLOPT_CONNECTTIMEOUT,
		   2L);
  // NOTE: use of CONNECTTIMEOUT without also
  //   setting NOSIGNAL results in really weird
  //   crashes on my system!
  curl_easy_setopt(c,
		   CURLOPT_NOSIGNAL,
		   1);  
  if (CURLE_OK != curl_easy_perform(c))
    return 32;
  curl_easy_cleanup(c);
  if (cbc.pos != strlen("hello_world")) {
    MHD_stop_daemon(d);  
    return 64;
  }  
  if (0 != strncmp("hello_world",
		   cbc.buf,
		   strlen("hello_world"))) {
    MHD_stop_daemon(d);
    return 128;
  }
  MHD_stop_daemon(d);
  
  return 0;
}

int main(int argc,
	 char * const * argv) {
  unsigned int errorCount = 0;

  if (0 != curl_global_init(CURL_GLOBAL_WIN32)) 
    return 2;  
  errorCount += testInternalGet();
  errorCount += testMultithreadedGet();  
  if (errorCount != 0)
    fprintf(stderr, 
	    "Error (code: %u)\n", 
	    errorCount);
  curl_global_cleanup();
  return errorCount != 0; /* 0 == pass */
}
