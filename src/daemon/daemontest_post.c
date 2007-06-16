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
 * @file daemontest_post.c
 * @brief  Testcase for libmicrohttpd POST operations
 *         TODO: use curl_formadd to produce POST data and 
 *               add that to the CURL operation; then check
 *               on the server side if the headers arrive
 *               nicely (need to implement parsing POST data
 *               first!)
 * @author Christian Grothoff
 */

#include "config.h"
#include <curl/curl.h>
#include <microhttpd.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

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
  struct MHD_Response * response;
  int ret;

  if (0 != strcmp("POST", method)) {
    printf("METHOD: %s\n", method);
    return MHD_NO; /* unexpected method */
  }
  /* FIXME: check session headers... */
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


static int testInternalPost() {
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
		       NULL);
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
		   CURLOPT_HTTPPOST,
		   NULL); /* FIXME! */
  curl_easy_setopt(c,
		   CURLOPT_POST,
		   1L);
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
  if (cbc.pos != strlen("/hello_world")) {
    MHD_stop_daemon(d);
    return 4;
  }
  
  if (0 != strncmp("/hello_world",
		   cbc.buf,
		   strlen("/hello_world"))) {
    MHD_stop_daemon(d);
    return 8;
  }
  MHD_stop_daemon(d);
  
  return 0;
}

static int testMultithreadedPost() {
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
		       NULL);
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
		   CURLOPT_HTTPPOST,
		   NULL); /* FIXME! */
  curl_easy_setopt(c,
		   CURLOPT_POST,
		   1L);
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
    return 32;
  }
  curl_easy_cleanup(c);
  if (cbc.pos != strlen("/hello_world")) {
    MHD_stop_daemon(d);  
    return 64;
  }  
  if (0 != strncmp("/hello_world",
		   cbc.buf,
		   strlen("/hello_world"))) {
    MHD_stop_daemon(d);
    return 128;
  }
  MHD_stop_daemon(d);
  
  return 0;
}


static int testExternalPost() {
  struct MHD_Daemon * d;
  CURL * c;
  char buf[2048];
  struct CBC cbc;
  CURLM * multi;
  CURLMcode mret;
  fd_set rs;
  fd_set ws;
  fd_set es;
  int max;
  int running;
  struct CURLMsg * msg;
  time_t start;
  struct timeval tv;

  multi = NULL;
  cbc.buf = buf;
  cbc.size = 2048;
  cbc.pos = 0;
  d = MHD_start_daemon(MHD_USE_IPv4 | MHD_USE_DEBUG,
		       1082,
		       &apc_all,
		       NULL,
		       &ahc_echo,
		       NULL);
  if (d == NULL)
    return 256;
  c = curl_easy_init();
  curl_easy_setopt(c,
		   CURLOPT_URL,
		   "http://localhost:1082/hello_world");
  curl_easy_setopt(c,
		   CURLOPT_WRITEFUNCTION,
		   &copyBuffer);
  curl_easy_setopt(c,
		   CURLOPT_WRITEDATA,
		   &cbc);
  curl_easy_setopt(c,
		   CURLOPT_HTTPPOST,
		   NULL); /* FIXME! */
  curl_easy_setopt(c,
		   CURLOPT_POST,
		   1L);
  curl_easy_setopt(c,
		   CURLOPT_FAILONERROR,
		   1);
  curl_easy_setopt(c,
		   CURLOPT_TIMEOUT,
		   5L);
  curl_easy_setopt(c,
		   CURLOPT_CONNECTTIMEOUT,
		   5L);
  // NOTE: use of CONNECTTIMEOUT without also
  //   setting NOSIGNAL results in really weird
  //   crashes on my system!
  curl_easy_setopt(c,
		   CURLOPT_NOSIGNAL,
		   1);  


  multi = curl_multi_init();
  if (multi == NULL) {
    curl_easy_cleanup(c);  
    MHD_stop_daemon(d);  
    return 512;
  }
  mret = curl_multi_add_handle(multi, c);
  if (mret != CURLM_OK) {
    curl_multi_cleanup(multi);
    curl_easy_cleanup(c);  
    MHD_stop_daemon(d);  
    return 1024;
  }
  start = time(NULL);
  while ( (time(NULL) - start < 5) &&
	  (multi != NULL) ) {
    max = 0;
    FD_ZERO(&rs);
    FD_ZERO(&ws);
    FD_ZERO(&es);
    curl_multi_perform(multi, &running);
    mret = curl_multi_fdset(multi,
			    &rs,
			    &ws,
			    &es,
			    &max);
    if (mret != CURLM_OK) {
      curl_multi_remove_handle(multi, c);
      curl_multi_cleanup(multi);
      curl_easy_cleanup(c);  
      MHD_stop_daemon(d);  
      return 2048;    
    }
    if (MHD_YES != MHD_get_fdset(d,
				 &rs,
				 &ws,
				 &es,
				 &max)) {
      curl_multi_remove_handle(multi, c);
      curl_multi_cleanup(multi);
      curl_easy_cleanup(c);        
      MHD_stop_daemon(d);  
      return 4096;
    }
    tv.tv_sec = 0;
    tv.tv_usec = 1000;
    select(max + 1,
	   &rs,
	   &ws,
	   &es,
	   &tv);  
    curl_multi_perform(multi, &running);
    if (running == 0) {
      msg = curl_multi_info_read(multi,
				 &running);
      if (msg == NULL)
	break;
      if (msg->msg == CURLMSG_DONE) {
	if (msg->data.result != CURLE_OK)
	  printf("%s failed at %s:%d: `%s'\n",
		 "curl_multi_perform",
		 __FILE__,
		 __LINE__,
		 curl_easy_strerror(msg->data.result));
	curl_multi_remove_handle(multi, c);
	curl_multi_cleanup(multi);
	curl_easy_cleanup(c);
	c = NULL;
	multi = NULL;
      }
    }	
    MHD_run(d);
  }
  if (multi != NULL) {
    curl_multi_remove_handle(multi, c);
    curl_easy_cleanup(c);  
    curl_multi_cleanup(multi);
  }
  MHD_stop_daemon(d);
  if (cbc.pos != strlen("/hello_world")) 
    return 8192;
  if (0 != strncmp("/hello_world",
		   cbc.buf,
		   strlen("/hello_world"))) 
    return 16384;
  return 0;
}



int main(int argc,
	 char * const * argv) {
  unsigned int errorCount = 0;

  if (0 != curl_global_init(CURL_GLOBAL_WIN32)) 
    return 2;  
  errorCount += testInternalPost();
  errorCount += testMultithreadedPost();  
  errorCount += testExternalPost();
  if (errorCount != 0)
    fprintf(stderr, 
	    "Error (code: %u)\n", 
	    errorCount);
  curl_global_cleanup();
  return errorCount != 0; /* 0 == pass */
}
