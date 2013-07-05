/*
    This file is part of libmicrospdy
    Copyright (C) 2012 Andrey Uzunov

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
 * @file tls.c
 * @brief  TLS handling using libssl. The current code assumes that
 * 			blocking I/O is in use.
 * @author Andrey Uzunov
 */

#include "platform.h"
#include "internal.h"
#include "session.h"
#include "tls.h"


/**
 * Callback to advertise spdy ver. 3 in Next Protocol Negotiation
 *
 * @param ssl openssl context for a connection
 * @param out must be set to the raw data that is advertised in NPN
 * @param outlen must be set to size of out
 * @param arg
 * @return SSL_TLSEXT_ERR_OK to do advertising
 */
static int
spdyf_next_protos_advertised_cb (SSL *ssl, const unsigned char **out, unsigned int *outlen, void *arg)
{
	(void)ssl;
	(void)arg;
	static unsigned char npn_spdy3[] = {0x06, // length of "spdy/3"
		0x73,0x70,0x64,0x79,0x2f,0x33};// spdy/3
	
	*out = npn_spdy3;
	*outlen = 7; // total length of npn_spdy3
	return SSL_TLSEXT_ERR_OK;
}


void
SPDYF_tls_global_init()
{
	//error strings are now not used by the lib
    //SSL_load_error_strings();
    //init libssl
    SSL_library_init(); //always returns 1
    //the table for looking up algos is not used now by the lib
    //OpenSSL_add_all_algorithms();
}


void
SPDYF_tls_global_deinit()
{
	//if SSL_load_error_strings was called
    //ERR_free_strings();
    //if OpenSSL_add_all_algorithms was called
    //EVP_cleanup();
}


int
SPDYF_tls_init(struct SPDY_Daemon *daemon)
{
    //create ssl context. TLSv1 used
    if(NULL == (daemon->io_context = SSL_CTX_new(TLSv1_server_method())))
    {
		SPDYF_DEBUG("Couldn't create ssl context");
		return SPDY_NO;
	}
	//set options for tls
	//TODO DH is not enabled for easier debugging
    //SSL_CTX_set_options(daemon->io_context, SSL_OP_SINGLE_DH_USE);
    
    //TODO here session tickets are disabled for easier debuging with 
    //wireshark when using Chrome
    //SSL_OP_NO_COMPRESSION disables TLS compression to avoid CRIME attack
    SSL_CTX_set_options(daemon->io_context, SSL_OP_NO_TICKET | SSL_OP_NO_COMPRESSION);
    if(1 != SSL_CTX_use_certificate_file(daemon->io_context, daemon->certfile , SSL_FILETYPE_PEM))
    {
		SPDYF_DEBUG("Couldn't load the cert file");
		SSL_CTX_free(daemon->io_context);
		return SPDY_NO;
	}
    if(1 != SSL_CTX_use_PrivateKey_file(daemon->io_context, daemon->keyfile, SSL_FILETYPE_PEM))
    {
		SPDYF_DEBUG("Couldn't load the name file");
		SSL_CTX_free(daemon->io_context);
		return SPDY_NO;
	}
    SSL_CTX_set_next_protos_advertised_cb(daemon->io_context, &spdyf_next_protos_advertised_cb, NULL);
	//TODO only RC4-SHA is used to make it easy to debug with wireshark
    if (1 != SSL_CTX_set_cipher_list(daemon->io_context, "RC4-SHA"))
    {
		SPDYF_DEBUG("Couldn't set the desired cipher list");
		SSL_CTX_free(daemon->io_context);
		return SPDY_NO;
	}
	
	return SPDY_YES;
}


void
SPDYF_tls_deinit(struct SPDY_Daemon *daemon)
{
    SSL_CTX_free(daemon->io_context);
}


int
SPDYF_tls_new_session(struct SPDY_Session *session)
{
	int ret;
	
	if(NULL == (session->io_context = SSL_new(session->daemon->io_context)))
    {
		SPDYF_DEBUG("Couldn't create ssl structure");
		return SPDY_NO;
	}
	if(1 != (ret = SSL_set_fd(session->io_context, session->socket_fd)))
    {
		SPDYF_DEBUG("SSL_set_fd %i",ret);
		SSL_free(session->io_context);
		session->io_context = NULL;
		return SPDY_NO;
	}
	
	//for non-blocking I/O SSL_accept may return -1
	//and this function won't work
	if(1 != (ret = SSL_accept(session->io_context)))
    {
		SPDYF_DEBUG("SSL_accept %i",ret);
		SSL_free(session->io_context);
		session->io_context = NULL;
		return SPDY_NO;
	}
	/* alternatively 
	SSL_set_accept_state(session->io_context);
	* may be called and then the negotiation will be done on reading
	*/
	
	return SPDY_YES;
}


void
SPDYF_tls_close_session(struct SPDY_Session *session)
{
	//SSL_shutdown sends TLS "close notify" as in TLS standard.
	//The function may fail as it waits for the other party to also close
	//the TLS session. The lib just sends it and will close the socket
	//after that because the browsers don't seem to care much about
	//"close notify"
	SSL_shutdown(session->io_context);
	
	SSL_free(session->io_context);
}


int
SPDYF_tls_recv(struct SPDY_Session *session,
				void * buffer,
				size_t size)
{
	int ret;
	int n = SSL_read(session->io_context, 
					buffer,
					size);
	//if(n > 0) SPDYF_DEBUG("recvd: %i",n);
	if (n <= 0)
	{
		ret = SSL_get_error(session->io_context, n);
		switch(ret)
		{
			case SSL_ERROR_ZERO_RETURN:
				return 0;
				
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
				return SPDY_TLS_ERROR_AGAIN;
				
			case SSL_ERROR_SYSCALL:
				if(EINTR == errno)
					return SPDY_TLS_ERROR_AGAIN;
				
			default:
				return SPDY_TLS_ERROR_ERROR;
		}
	}

	return n;
}


int
SPDYF_tls_send(struct SPDY_Session *session,
				const void * buffer,
				size_t size)
{
	int ret;
	
	int n = SSL_write(session->io_context, 
					buffer,
					size);
	//if(n > 0) SPDYF_DEBUG("sent: %i",n);
	if (n <= 0)
	{
		ret = SSL_get_error(session->io_context, n);
		switch(ret)
		{
			case SSL_ERROR_ZERO_RETURN:
				return 0;
				
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
				return SPDY_TLS_ERROR_AGAIN;
				
			case SSL_ERROR_SYSCALL:
				if(EINTR == errno)
					return SPDY_TLS_ERROR_AGAIN;
				
			default:
				return SPDY_TLS_ERROR_ERROR;
		}
	}
	
	return n;
}


int
SPDYF_tls_is_pending(struct SPDY_Session *session)
{
	/* From openssl docs:
	 * BUGS
SSL_pending() takes into account only bytes from the TLS/SSL record that is currently being processed (if any). If the SSL object's read_ahead flag is set, additional protocol bytes may have been read containing more TLS/SSL records; these are ignored by SSL_pending().
	 */
	return SSL_pending(session->io_context) > 0 ? SPDY_YES : SPDY_NO;
}
