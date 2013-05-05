/*
    This file is part of libmicrospdy
    Copyright (C) 2013 Andrey Uzunov

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @file proxy.c
 * @brief   Translates incoming SPDY requests to http server on localhost.
 * 			Uses libcurl.
 * @author Andrey Uzunov
 */
 
#include "platform.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include "microspdy.h"
#include <curl/curl.h>
#include <assert.h>


#define PRINT_INFO(msg) do{\
	printf("%i:%s\n", __LINE__, msg);\
	fflush(stdout);\
	}\
	while(0)


#define PRINT_INFO2(fmt, ...) do{\
	printf("%i\n", __LINE__);\
	printf(fmt,##__VA_ARGS__);\
	printf("\n");\
	fflush(stdout);\
	}\
	while(0)


#define CURL_SETOPT(handle, opt, val) do{\
	int ret; \
	if(CURLE_OK != (ret = curl_easy_setopt(handle, opt, val))) \
	{ \
		PRINT_INFO2("curl_easy_setopt failed (%i = %i)", opt, ret); \
		abort(); \
	} \
	}\
	while(0)


int run = 1;
char* http_host;
CURLM *multi_handle;
int still_running = 0; /* keep number of running handles */
int http10=0;

struct Proxy
{
	char *path;
	struct SPDY_Request *request;
	struct SPDY_Response *response;
	CURL *curl_handle;
	struct curl_slist *curl_headers;
	struct SPDY_NameValue *headers;
	char *version;
	char *status_msg;
	void *http_body;
	size_t http_body_size;
	ssize_t length;
	int status;
};


ssize_t
response_callback (void *cls,
						void *buffer,
						size_t max,
						bool *more)
{
	int ret;
	struct Proxy *proxy = (struct Proxy *)cls;
	void *newbody;
	
	//printf("response_callback\n");
	
	assert(0 != proxy->length);
	
	*more = true;
	if(!proxy->http_body_size)//nothing to write now
		return 0;
	
	if(max >= proxy->http_body_size)
	{
		ret = proxy->http_body_size;
		newbody = NULL;
	}
	else
	{
		ret = max;
		if(NULL == (newbody = malloc(proxy->http_body_size - max)))
		{
			PRINT_INFO("no memory");
			return -1;
		}
		memcpy(newbody, proxy->http_body + max, proxy->http_body_size - max);
	}
	memcpy(buffer, proxy->http_body, ret);
	free(proxy->http_body);
	proxy->http_body = newbody;
	proxy->http_body_size -= ret;
	
	if(proxy->length >= 0)
	{
		proxy->length -= ret;
		//printf("pr len %i", proxy->length);
		if(proxy->length <= 0)
		{
			*more = false;
			//last frame
			proxy->length = 0;
		}
	}
	
	return ret;
}


void
response_done_callback(void *cls,
						struct SPDY_Response *response,
						struct SPDY_Request *request,
						enum SPDY_RESPONSE_RESULT status,
						bool streamopened)
{
	(void)streamopened;
	struct Proxy *proxy = (struct Proxy *)cls;
	int ret;
	
	//printf("response_done_callback\n");
	
	//printf("answer for %s was sent\n", (char *)cls);
	
	if(SPDY_RESPONSE_RESULT_SUCCESS != status)
	{
		printf("answer was NOT sent, %i\n",status);
	}
	if(CURLM_OK != (ret = curl_multi_remove_handle(multi_handle, proxy->curl_handle)))
	{
		PRINT_INFO2("curl_multi_remove_handle failed (%i)", ret);
	}
	curl_slist_free_all(proxy->curl_headers);
	curl_easy_cleanup(proxy->curl_handle);
	
	SPDY_destroy_request(request);
	SPDY_destroy_response(response);
	if(!strcmp("/close",proxy->path)) run = 0;
	free(proxy->path);
	free(proxy);
}


static size_t
curl_header_cb(void *ptr, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	struct Proxy *proxy = (struct Proxy *)userp;
	char *line = (char *)ptr;
	char *name;
	char *value;
	char *status;
	const char *const*length;
	int i;
	int pos;
	
	//printf("curl_header_cb\n");

	if('\r' == line[0])
	{
		//all headers were already handled; prepare spdy frames
		if(NULL == (proxy->response = SPDY_build_response_with_callback(proxy->status,
							proxy->status_msg,
							proxy->version,
							proxy->headers,
							&response_callback,
							proxy,
							0)))
		{
			PRINT_INFO("no response");
			abort();
		}
		if(NULL != (length = SPDY_name_value_lookup(proxy->headers,
						SPDY_HTTP_HEADER_CONTENT_LENGTH,
						&i)))
			proxy->length = atoi(length[0]);
		else
			proxy->length = -1;
		SPDY_name_value_destroy(proxy->headers);
		free(proxy->status_msg);
		free(proxy->version);
		
		if(SPDY_YES != SPDY_queue_response(proxy->request,
							proxy->response,
							true,
							false,
							&response_done_callback,
							proxy))
		{
			PRINT_INFO("no queue");
			abort();
		}
		//printf("spdy headers queued %i\n");
		
		return realsize;
	}
	
	pos = 0;
	if(NULL == proxy->version)
	{
		//first line from headers
		//version
		for(i=pos; i<realsize && ' '!=line[i]; ++i);
		if(i == realsize)
		{
			PRINT_INFO("error on parsing headers");
			abort();
		}
		if(NULL == (proxy->version = strndup(line, i - pos)))
		{
			PRINT_INFO("no memory");
			abort();
		}
		pos = i+1;
		
		//status (number)
		for(i=pos; i<realsize && ' '!=line[i] && '\r'!=line[i]; ++i);
		if(NULL == (status = strndup(&(line[pos]), i - pos)))
		{
			PRINT_INFO("no memory");
			abort();
		}
		proxy->status = atoi(status);
		free(status);
		if(i<realsize && '\r'!=line[i])
		{
			//status (message)
			pos = i+1;
			for(i=pos; i<realsize && '\r'!=line[i]; ++i);
			if(NULL == (proxy->status_msg = strndup(&(line[pos]), i - pos)))
			{
				PRINT_INFO("no memory");
				abort();
			}
		}
		return realsize;
	}
	
	//other lines
	//header name
	for(i=pos; i<realsize && ':'!=line[i] && '\r'!=line[i]; ++i)
		line[i] = tolower(line[i]); //spdy requires lower case
	if(NULL == (name = strndup(line, i - pos)))
	{
		PRINT_INFO("no memory");
		abort();
	}
	if(0 == strcmp(SPDY_HTTP_HEADER_CONNECTION, name)
		|| 0 == strcmp(SPDY_HTTP_HEADER_KEEP_ALIVE, name))
	{
		//forbidden in spdy, ignore
		free(name);
		return realsize;
	}
	if(i == realsize || '\r'==line[i])
	{
		//no value. is it possible?
		if(SPDY_YES != SPDY_name_value_add(proxy->headers, name, ""))
		{
			PRINT_INFO("SPDY_name_value_add failed");
			abort();
		}
		return realsize;
	}
	
	//header value
	pos = i+1;
	while(pos<realsize && isspace(line[pos])) ++pos; //remove leading space
	for(i=pos; i<realsize && '\r'!=line[i]; ++i);
	if(NULL == (value = strndup(&(line[pos]), i - pos)))
	{
		PRINT_INFO("no memory");
		abort();
	}
	if(SPDY_YES != SPDY_name_value_add(proxy->headers, name, value))
	{
		PRINT_INFO("SPDY_name_value_add failed");
		abort();
	}
	free(name);
	free(value);

	return realsize;
}


static size_t
curl_write_cb(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	struct Proxy *proxy = (struct Proxy *)userp;
	
	//printf("curl_write_cb %i\n", realsize);
	
	if(NULL == proxy->http_body)
		proxy->http_body = malloc(realsize);
	else
		proxy->http_body = realloc(proxy->http_body, proxy->http_body_size + realsize);
	if(NULL == proxy->http_body)
	{
		PRINT_INFO("not enough memory (realloc returned NULL)");
		return 0;
	}

	memcpy(proxy->http_body + proxy->http_body_size, contents, realsize);
	proxy->http_body_size += realsize;

	return realsize;
}


int
iterate_cb (void *cls, const char *name, const char * const * value, int num_values)
{
	struct Proxy *proxy = (struct Proxy *)cls;
    struct curl_slist **curl_headers = (&(proxy->curl_headers));
    char *line;
    int line_len = strlen(name) + 3; //+ ": \0"
    int i;
    
    for(i=0; i<num_values; ++i)
    {
		if(i) line_len += 2; //", "
		line_len += strlen(value[i]);
	}
	
	if(NULL == (line = malloc(line_len)))
	{
		//no recovory
		PRINT_INFO("no memory");
		abort();
	}
	line[0] = 0;
    
    strcat(line, name);
    strcat(line, ": ");
    //all spdy header names are lower case;
    //for simplicity here we just capitalize the first letter
    line[0] = toupper(line[0]);
    
	for(i=0; i<num_values; ++i)
	{
		if(i) strcat(line, ", ");
		strcat(line, value[i]);
	}
    if(NULL == (*curl_headers = curl_slist_append(*curl_headers, line)))
    {
		PRINT_INFO("curl_slist_append failed");
		abort();
	}
	free(line);
	
	return SPDY_YES;
}


void
standard_request_handler(void *cls,
						struct SPDY_Request * request,
						uint8_t priority,
                        const char *method,
                        const char *path,
                        const char *version,
                        const char *host,
                        const char *scheme,
						struct SPDY_NameValue * headers)
{
	(void)cls;
	(void)priority;
	(void)host;
	(void)scheme;
	
	char *url;
	struct Proxy *proxy;
	int ret;
	
	//printf("received request for '%s %s %s'\n", method, path, version);
	if(NULL == (proxy = malloc(sizeof(struct Proxy))))
	{
		PRINT_INFO("No memory");
		abort();
	}
	memset(proxy, 0, sizeof(struct Proxy));
	proxy->request = request;
	if(NULL == (proxy->headers = SPDY_name_value_create()))
	{
		PRINT_INFO("No memory");
		abort();
	}
	
	if(-1 == asprintf(&url,"%s%s%s","http://", http_host, path))
	{
		PRINT_INFO("No memory");
		abort();
	}
	
	if(NULL == (proxy->path = strdup(path)))
	{
		PRINT_INFO("No memory");
		abort();
	}
    
    SPDY_name_value_iterate(headers, &iterate_cb, proxy);
	
	if(NULL == (proxy->curl_handle = curl_easy_init()))
    {
		PRINT_INFO("curl_easy_init failed");
		abort();
	}
	
	//CURL_SETOPT(proxy->curl_handle, CURLOPT_VERBOSE, 1);
	CURL_SETOPT(proxy->curl_handle, CURLOPT_URL, url);
	free(url);
	if(http10)
		CURL_SETOPT(proxy->curl_handle, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
	CURL_SETOPT(proxy->curl_handle, CURLOPT_WRITEFUNCTION, curl_write_cb);
	CURL_SETOPT(proxy->curl_handle, CURLOPT_WRITEDATA, proxy);
	CURL_SETOPT(proxy->curl_handle, CURLOPT_HEADERFUNCTION, curl_header_cb);
	CURL_SETOPT(proxy->curl_handle, CURLOPT_HEADERDATA, proxy);
	CURL_SETOPT(proxy->curl_handle, CURLOPT_HTTPHEADER, proxy->curl_headers);
    CURL_SETOPT(proxy->curl_handle, CURLOPT_SSL_VERIFYPEER, 0L);
    CURL_SETOPT(proxy->curl_handle, CURLOPT_SSL_VERIFYHOST, 0L);
	
	if(CURLM_OK != (ret = curl_multi_add_handle(multi_handle, proxy->curl_handle)))
	{
		PRINT_INFO2("curl_multi_add_handle failed (%i)", ret);
		abort();
	}
	
	if(CURLM_OK != (ret = curl_multi_perform(multi_handle, &still_running))
		&& CURLM_CALL_MULTI_PERFORM != ret)
	{
		PRINT_INFO2("curl_multi_perform failed (%i)", ret);
		abort();
	}
}

int
main (int argc, char *const *argv)
{	
	unsigned long long timeoutlong=0;
    long curl_timeo = -1;
	struct timeval timeout;
	int ret;
	fd_set rs;
	fd_set ws;
	fd_set es;
	fd_set curl_rs;
	fd_set curl_ws;
	fd_set curl_es;
	int maxfd = -1;
	struct SPDY_Daemon *daemon;
	
	//signal(SIGPIPE, SIG_IGN);
	
	if(argc != 6)
	{
		printf("Usage: %s cert-file key-file host port http/1.0(yes/no)\n", argv[0]);
		return 1;
	}
	
	SPDY_init();
	
	daemon = SPDY_start_daemon(atoi(argv[4]),
								argv[1],
								argv[2],
								NULL,
								NULL,
								&standard_request_handler,
								NULL,
								NULL,
								SPDY_DAEMON_OPTION_SESSION_TIMEOUT,
								1800,
								SPDY_DAEMON_OPTION_END);
	
	if(NULL==daemon){
		printf("no daemon\n");
		return 1;
	}
	
	multi_handle = curl_multi_init();
	
	if(NULL==multi_handle){
		PRINT_INFO("no multi_handle");
		abort();
	}
	
	if(!strcmp("yes", argv[5]))
		http10 = 1;
	
	http_host = argv[3];
	timeout.tv_usec = 0;

	do
	{
		//printf("still %i\n", still_running);
		FD_ZERO(&rs);
		FD_ZERO(&ws);
		FD_ZERO(&es);
		FD_ZERO(&curl_rs);
		FD_ZERO(&curl_ws);
		FD_ZERO(&curl_es);

		if(still_running > 0)
			timeout.tv_sec = 0; //return immediately
		else
		{
			ret = SPDY_get_timeout(daemon, &timeoutlong);
			if(SPDY_NO == ret)
				timeout.tv_sec = 1;
			else
				timeout.tv_sec = timeoutlong;
		}
		timeout.tv_usec = 0;
		
		maxfd = SPDY_get_fdset (daemon,
								&rs,
								&ws, 
								&es);	
		assert(-1 != maxfd);
		
		ret = select(maxfd+1, &rs, &ws, &es, &timeout);
		
		switch(ret) {
			case -1:
				PRINT_INFO2("select error: %i", errno);
				break;
			case 0:
				break;
			default:
				SPDY_run(daemon);
			break;
		}
		
		timeout.tv_sec = 0;
		if(still_running > 0)
		{
			if(CURLM_OK != (ret = curl_multi_timeout(multi_handle, &curl_timeo)))
			{
				PRINT_INFO2("curl_multi_timeout failed (%i)", ret);
				abort();
			}
			if(curl_timeo >= 0 && curl_timeo < 500)
				timeout.tv_usec = curl_timeo * 1000;
			else
				timeout.tv_usec = 500000;
		}
		else continue;
		//else timeout.tv_usec = 500000;

		if(CURLM_OK != (ret = curl_multi_fdset(multi_handle, &curl_rs, &curl_ws, &curl_es, &maxfd)))
		{
			PRINT_INFO2("curl_multi_fdset failed (%i)", ret);
			abort();
		}
		if(-1 == maxfd)
		{
			PRINT_INFO("maxfd is -1");
			//continue;
			ret = 0;
		}
		else
		ret = select(maxfd+1, &curl_rs, &curl_ws, &curl_es, &timeout);

		switch(ret) {
			case -1:
				PRINT_INFO2("select error: %i", errno);
				break;
			case 0: /* timeout */
				//break or not
			default: /* action */
				if(CURLM_OK != (ret = curl_multi_perform(multi_handle, &still_running))
					&& CURLM_CALL_MULTI_PERFORM != ret)
				{
					PRINT_INFO2("curl_multi_perform failed (%i)", ret);
					abort();
				}
				break;
		}
	}
	while(run);
	
	curl_multi_cleanup(multi_handle);

	SPDY_stop_daemon(daemon);
	
	SPDY_deinit();
	
	return 0;
}

