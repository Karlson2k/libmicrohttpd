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
 * @file daemontest.c
 * @brief  Testcase for libmicrohttpd
 * @author Christian Grothoff
 */

#include "config.h"
#include "curl/curl.h"
#include "microhttpd.h"
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

static int testStartError() {
  struct MHD_Daemon * d;

  d = MHD_start_daemon(MHD_USE_DEBUG, 0, NULL, NULL, NULL, NULL);

  if(d == NULL) {
     return 0;
  } else {
     return 1;
  }
}

static int apc_nothing(void * cls,
		       const struct sockaddr * addr,
		       socklen_t addrlen) {
  return MHD_NO;
}

static int apc_all(void * cls,
		   const struct sockaddr * addr,
		   socklen_t addrlen) {
  return MHD_YES;
}

static int ahc_nothing(void * cls,
		       struct MHD_Session * session,
		       const char * url,
		       const char * method,
               const char * upload_data,
               unsigned int * upload_data_size) {
  return MHD_NO;
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

static int testStartStop() {
  struct MHD_Daemon * d;

  d = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY | MHD_USE_IPv4 | MHD_USE_DEBUG,
		       1080,
		       &apc_nothing,
		       NULL,
		       &ahc_nothing,
		       NULL);
  if (d == NULL) {
    return 1;
  }
  MHD_stop_daemon(d);
  return 0;
}

static int testRun() {
  struct MHD_Daemon * d;
  fd_set read;
  int maxfd;
  int i;

  d = MHD_start_daemon(MHD_USE_IPv4 | MHD_USE_DEBUG,
		       1080,
		       &apc_all,
		       NULL,
		       &ahc_nothing,
		       NULL);

  if(d == NULL) {
	  return 1;
  }
  fprintf(stderr, "Testing external select!\n");
  i = 0;
  while(i < 15) {
     MHD_get_fdset(d, &read, &read, &read, &maxfd);
     if(MHD_run(d) == MHD_NO) {
        MHD_stop_daemon(d);
        return 1;
     }
	  sleep(1);
	  i++;
  }
  return 0;
}

static int testThread() {
  struct MHD_Daemon * d;
  d = MHD_start_daemon(MHD_USE_IPv4 | MHD_USE_DEBUG | MHD_USE_SELECT_INTERNALLY,
		       1081,
		       &apc_all,
		       NULL,
		       &ahc_nothing,
		       NULL);

  if(d == NULL) {
	  return 1;
  }

  fprintf(stderr, "Testing internal select!\n");  
  if (MHD_run(d) == MHD_NO) {
     return 1;
  } else {
	  sleep(15);
	  MHD_stop_daemon(d);
  }
  return 0;
}

static int testMultithread() {
  struct MHD_Daemon * d;
  d = MHD_start_daemon(MHD_USE_IPv4 | MHD_USE_DEBUG | MHD_USE_THREAD_PER_CONNECTION,
		       1082,
		       &apc_all,
		       NULL,
		       &ahc_nothing,
		       NULL);

  if(d == NULL) {
	  return 1;
  }

  fprintf(stderr, "Testing thread per connection!\n");  
  if (MHD_run(d) == MHD_NO) {
     return 1;
  } else {
	  sleep(15);
	  MHD_stop_daemon(d);
  }
  return 0;
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
		       1083,
		       &apc_all,
		       NULL,
		       &ahc_echo,
		       "GET");
  if (d == NULL)
    return 1;

  if(MHD_run(d) == MHD_NO) {
    MHD_stop_daemon(d);
    return 2;
  }
  
  c = curl_easy_init();
  curl_easy_setopt(c,
		   CURLOPT_URL,
		   "http://localhost:1083/hello_world");
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
		   CURLOPT_CONNECTTIMEOUT,
		   15L);
  // NOTE: use of CONNECTTIMEOUT without also
  //   setting NOSIGNAL results in really weird
  //   crashes on my system!
  curl_easy_setopt(c,
		   CURLOPT_NOSIGNAL,
		   1);  
  if (CURLE_OK != curl_easy_perform(c))
    return 3;
    
  curl_easy_cleanup(c);
  
  if (cbc.pos != strlen("hello_world"))
    return 4;
  
  if (0 != strncmp("hello_world",
		   cbc.buf,
		   strlen("hello_world")))
    return 5;
  
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
		       1084,
		       &apc_all,
		       NULL,
		       &ahc_echo,
		       "GET");
  if (d == NULL)
    return 1;

  if(MHD_run(d) == MHD_NO)
    return 2;
 
  
  c = curl_easy_init();
  curl_easy_setopt(c,
		   CURLOPT_URL,
		   "http://localhost:1084/hello_world");
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
		   CURLOPT_CONNECTTIMEOUT,
		   15L);
  // NOTE: use of CONNECTTIMEOUT without also
  //   setting NOSIGNAL results in really weird
  //   crashes on my system!
  curl_easy_setopt(c,
		   CURLOPT_NOSIGNAL,
		   1);  
  if (CURLE_OK != curl_easy_perform(c))
    return 3;
  curl_easy_cleanup(c);
  if (cbc.pos != strlen("hello_world"))
    return 4;
  
  if (0 != strncmp("hello_world",
		   cbc.buf,
		   strlen("hello_world")))
    return 5;
    
  MHD_stop_daemon(d);
  
  return 0;
}

int main(int argc,
	 char * const * argv) {
  unsigned int errorCount = 0;
  fprintf(stderr, "***testStartError()***\n");
  fprintf(stderr, "***This test verifies the start function responds to bad arguments correctly***\n");
  errorCount += testStartError();
  fprintf(stderr, "errorCount is %i\n", errorCount);
  fprintf(stderr, "***testStartStop()***\n");
  fprintf(stderr, "***This test verifies that the daemon can be started and stopped normally***\n");
  errorCount += testStartStop();
  fprintf(stderr, "errorCount is %i\n", errorCount);
  fprintf(stderr, "***testInternalGet()***\n");  
  fprintf(stderr, "***This test verifies the functionality of internal select using a canned request***\n");  
  errorCount += testInternalGet();
  fprintf(stderr, "errorCount is %i\n", errorCount);
  fprintf(stderr, "***testMultithreadedGet()***\n");  
  fprintf(stderr, "***This test verifies the functionality of multithreaded connections using a canned request***\n");  
  errorCount += testMultithreadedGet();
  fprintf(stderr, "errorCount is %i\n", errorCount);
  fprintf(stderr, "***testRun()***\n");
  fprintf(stderr, "***This test verifies the functionality of external select***\n");
  fprintf(stderr, "***The sever will sit on the announced port for 15 seconds and wait for external messages***\n");  
  errorCount += testRun();
  fprintf(stderr, "errorCount is %i\n", errorCount);
  fprintf(stderr, "***testThread()***\n");
  fprintf(stderr, "***This test verifies the functionality of internal select***\n");  
  fprintf(stderr, "***The sever will sit on the announced port for 15 seconds and wait for external messages***\n");  
  errorCount += testThread();  
  fprintf(stderr, "errorCount is %i\n", errorCount);
  fprintf(stderr, "***testMultithread()***\n");
  fprintf(stderr, "***This test verifies the functionality of multithreaded connections***\n");  
  fprintf(stderr, "***The sever will sit on the announced port for 15 seconds and wait for external messages***\n");  
  errorCount += testMultithread();  
  fprintf(stderr, "errorCount is %i\n", errorCount);
  return errorCount != 0; /* 0 == pass */
}
