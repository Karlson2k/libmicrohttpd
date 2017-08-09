/*
     This file is part of libmicrohttpd
     Copyright (C) 2006-2017 Christian Grothoff, Karlson2k (Evgeny Grin)
     (and other contributing authors)

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
 * Just includes the NEW definitions for the NG-API.
 * Note that we do not indicate which of the OLD APIs
 * simply need to be kept vs. deprecated.
 *
 * The goal is to provide a basis for discussion!
 * None of this is implemented yet.
 *
 * Main goals:
 * - simplify application callbacks by splitting header/upload/post
 *   functionality currently provided by calling the same 
 *   MHD_AccessHandlerCallback 3+ times into separate callbacks.
 * - avoid repeated scans for URL matches via the new
 *   struct MHD_RequestHandlerCallbacks construction
 * - provide default logarithmic implementation of URL scan
 *   => reduce strcmp(url) from >= 3n operations to "log n"
 *      per request.
 * - better types, in particular avoid varargs for options
 * - make it harder to pass inconsistent options
 * - combine options and flags into more uniform API (at least
 *   exterally!)
 * - simplify API use by using sane defaults (benefiting from
 *   breaking backwards compatibility) and making all options
 *   really optional, and where applicable avoid having options
 *   where the default works if nothing is specified
 * - simplify API by moving rarely used http_version into
 *   MHD_request_get_information()
 * - avoid 'int' for MHD_YES/MHD_NO by introducing `enum MHD_Bool`
 * - improve terminology by eliminating confusion between
 *   'request' and 'connection'
 * - prepare API for having multiple TLS backends
 * - use more consistent prefixes for related functions
 *   by using MHD_subject_verb_object naming convention, also
 *   at the same time avoid symbol conflict with legacy names
 *   (so we can have one binary implementing old and new 
 *   library API at the same time via compatibility layer).
 * - improve thread-safety
 */


/**
 * Representation of 'bool' in the public API as stdbool.h may not
 * always be available.
 */
enum MHD_Bool
{

  /**
   * MHD-internal return code for "NO".
   */
  MHD_NO = 0,

  /**
   * MHD-internal return code for "YES".
   */
  MHD_YES = 1
};


/**
 * @brief Handle for a connection / HTTP request.
 *
 * With HTTP/1.1, multiple requests can be run over the same
 * connection.  However, MHD will only show one request per TCP
 * connection to the client at any given time.
 *
 * Replaces `struct MHD_Connection`, renamed to better reflect
 * what this object truly represents to the application using
 * MHD.
 *
 * @ingroup request
 */
struct MHD_Request;


/**
 * Enumeration used to define options in 
 * `struct MHD_Option`. Opaque to the application.
 */
enum MHD_OptionValue;


/**
 * Option configuring the service.
 */
struct MHD_Option
{
  /**
   * Which option is being given.  #MHD_OPTION_VALUE_END
   * terminates the array.
   */
  enum MHD_OptionValue option;

  /**
   * Option value.
   */
  intptr_t value1;

  /**
   * Option value.
   */
  intptr_t value2;
  
  /**
   * Option value.
   */
  intptr_t value3;

};


/**
 * Returns terminating element of an option array.
 *
 * @return MHD option array terminator
 */
_MHD_EXTERN struct MHD_Option
MHD_option_end (void);


/**
 * Set logging method.  Specify NULL to disable logging entirely.  By
 * default (if this option is not given), we log error messages to
 * stderr.
 *
 * @return MHD option
 */
_MHD_EXTERN struct MHD_Option
MHD_option_log (MHD_LogCallback logger,
		void *cls logger_cls);


/**
 * Convenience macro used to disable logging.
 *
 * @return MHD option that disables logging
 */
#define MHD_option_disable_logging() MHD_option_log (NULL, NULL)


/**
 * Suppress use of "Date" header as this system has no RTC.
 *
 * @return MHD option
 */
_MHD_EXTERN struct MHD_Option
MHD_option_suppress_date_no_clock (void);


/**
 * Use inter-thread communication channel.  #MHD_option_enable_itc()
 * can be used with #MHD_option_thread_internal() and is ignored with
 * any "external" mode.  It's required for use of
 * #MHD_daemon_quiesce() or #MHD_connection_add().  This option is
 * enforced by #MHD_option_allow_suspend_resume() and if there is no
 * listen socket.  #MHD_option_enable_itc() is always used
 * automatically on platforms where select()/poll()/other ignore
 * shutdown of listen socket.
 *
 * @return MHD option
 */
_MHD_EXTERN struct MHD_Option
MHD_option_enable_itc (void);


/**
 * Enable `turbo`.  Disables certain calls to `shutdown()`,
 * enables aggressive non-blocking optimistic reads and
 * other potentially unsafe optimizations.
 * Most effects only happen with #MHD_ELS_EPOLL.
 *
 * @return MHD option
 */
_MHD_EXTERN struct MHD_Option
MHD_option_enable_turbo (void);


/**
 * Enable suspend/resume functions, which also implies setting up
 * #MHD_option_enable_itc() to signal resume.
 *
 * @return MHD option
 */
_MHD_EXTERN struct MHD_Option
MHD_option_allow_suspend_resume (void);


/**
 * You need to set this option if you want to use HTTP "Upgrade".
 * "Upgrade" may require usage of additional internal resources,
 * which we do not want to use unless necessary.
 *
 * @return MHD option
 */
_MHD_EXTERN struct MHD_Option
MHD_option_allow_upgrade (void);


/**
 * Possible levels of enforcement for TCP_FASTOPEN.
 */
enum MHD_FastOpenMethod
{
  /** 
   * Disable use of TCP_FASTOPEN.
   */
  MHD_FOM_DISABLE = -1,
  
  /**
   * Enable TCP_FASTOPEN where supported (Linux with a kernel >= 3.6).
   * This is the default.
   */
  MHD_FOM_AUTO = 0,

  /**
   * If TCP_FASTOPEN is not available, cause #MHD_daemon_start() to
fail.
  */
  MHD_FOM_REQUIRE = 1
};


/**
 * Configure TCP_FASTOPEN option, including setting a 
 * custom @a queue_length.
 *
 * Note that having a larger queue size can cause resource exhaustion
 * attack as the TCP stack has to now allocate resources for the SYN
 * packet along with its DATA. 
 *
 * @param fom under which conditions should we use TCP_FASTOPEN?
 * @param queue_length queue length to use, default is 50 if this
 *        option is never given.
 * @return MHD option
 */
_MHD_EXTERN struct MHD_Option
MHD_option_tcp_fastopen (enum MHD_FastOpenMethod fom,
			 unsigned int queue_length);


/**
 * Bind to the given TCP port.
 * Ineffective in conjunction with #MHD_option_listen_socket().
 * Ineffective in conjunction with #MHD_option_bind_sa().
 *
 * If neither this option nor the other two mentioned above
 * is specified, MHD will simply not listen on any socket!
 *
 * @param port port to use, 0 to bind to a random (free) port
 * @return MHD option
 */
_MHD_EXTERN struct MHD_Option
MHD_option_bind_port (uint16_t port);


/**
 * Bind to the given socket address.
 * Ineffective in conjunction with #MHD_option_listen_socket().
 *
 * @return MHD option
 */
_MHD_EXTERN struct MHD_Option
MHD_option_bind_socket_address (const struct sockaddr *sa);


/**
 * Use the given backlog for the listen() call.
 * Ineffective in conjunction with #MHD_option_listen_socket().
 *
 * @param listen_backlog backlog to use
 * @return MHD option
 */
_MHD_EXTERN struct MHD_Option
MHD_option_listen_queue (int listen_backlog);


/**
 * If present true, allow reusing address:port socket (by using
 * SO_REUSEPORT on most platform, or platform-specific ways).  If
 * present and set to false, disallow reusing address:port socket
 * (does nothing on most plaform, but uses SO_EXCLUSIVEADDRUSE on
 * Windows).
 * Ineffective in conjunction with #MHD_option_listen_socket().
 *
 * @return MHD option
 */
_MHD_EXTERN struct MHD_Option
MHD_option_listen_allow_address_reuse (void);


/**
 * Accept connections from the given socket.  Socket
 * must be a TCP or UNIX domain (stream) socket.
 * 
 * Disables other listen options, including
 * #MHD_option_bind_sa(), #MHD_option_bind_port(),
 * #MHD_option_listen_queue() and
 * #MHD_option_listen_allow_address_reuse().
 *
 * @param listen_socket listen socket to use
 * @return MHD option
 */
_MHD_EXTERN struct MHD_Option
MHD_option_listen_socket (int listen_socket);


/**
 * Event loop syscalls supported by MHD.
 */
enum MHD_EventLoopSyscall
{
  /**
   * Automatic selection of best-available method. This is also the
   * default.
   */ 
  MHD_ELS_AUTO = 0,

  /**
   * Use select().
   */
  MHD_ELS_SELECT = 1,
  
  /**
   * Use poll().
   */
  MHD_ELS_POLL = 2,
  
  /**
   * Use epoll().
   */
  MHD_ELS_EPOLL = 3
};


/**
 * Force use of a particular event loop system call.
 * 
 * @param els event loop syscall to use
 * @return MHD option
 */
_MHD_EXTERN struct MHD_Option
MHD_option_event_loop (enum MHD_EventLoopSyscall els);


/**
 * Protocol strictness enforced by MHD on clients.
 */
enum MHD_ProtocolStrictLevel
{
  /**
   * Be particularly permissive about the protocol, allowing slight
   * deviations that are technically not allowed by the
   * RFC. Specifically, at the moment, this flag causes MHD to allow
   * spaces in header field names. This is disallowed by the standard.
   * It is not recommended to set this value on publicly available
   * servers as it may potentially lower level of protection.
   */
  MHD_SL_PERMISSIVE = -1,

  /**
   * Sane level of protocol enforcement for production use.
   */
  MHD_SL_DEFAULT = 0,

  /**
   * Be strict about the protocol (as opposed to as tolerant as
   * possible).  Specifically, at the moment, this flag causes MHD to
   * reject HTTP 1.1 connections without a "Host" header.  This is
   * required by the standard, but of course in violation of the "be
   * as liberal as possible in what you accept" norm.  It is
   * recommended to set this if you are testing clients against
   * MHD, and to use default in production.
   */
  MHD_SL_STRICT = 1
};


/**
 * Set how strictly MHD will enforce the HTTP protocol.
 * 
 * @param sl how strict should we be
 * @return MHD option
 */
_MHD_EXTERN struct MHD_Option
MHD_option_protocol_strict_level (enum MHD_ProtocolStrictLevel sl);


/**
 * Enable TLS.
 *
 * @param tls_backend which TLS backend should be used,
 *    currently only "gnutls" is supported.  You can
 *    also specify "NULL" for best-available (which is the default).
 */
_MHD_EXTERN struct MHD_Option
MHD_option_tls (const char *tls_backend);


/**
 * Provide TLS key and certificate data in-memory.
 *
 * @param mem_key private key (key.pem) to be used by the
 *     HTTPS daemon.  Must be the actual data in-memory, not a filename.
 * @param mem_cert certificate (cert.pem) to be used by the
 *     HTTPS daemon.  Must be the actual data in-memory, not a filename.
 * @return MHD option
 */
_MHD_EXTERN struct MHD_Option
MHD_option_tls_key_and_cert_from_memory (const char *mem_key,
					 const char *mem_cert);


/**
 * Provide passphrase to decrypt 'key.pem' (if required).
 *
 * @param pass passphrase phrase to decrypt 'key.pem'
 */
_MHD_EXTERN struct MHD_Option
MHD_option_tls_key_passphrase (const char *pass);


/**
 * Configure TLS ciphers to use.  Default is "NORMAL".
 *
 * @param ciphers which ciphers should be used by TLS
 */
_MHD_EXTERN struct MHD_Option
MHD_option_tls_ciphers (const char *ciphers);


/**
 * Configure DH parameters (dh.pem) to use for the TLS key
 * exchange. 
 *
 * @param dh parameters to use
 */
_MHD_EXTERN struct MHD_Option
MHD_option_tls_mem_dhparams (const char *dh);


/**
 * Memory pointer for the certificate (ca.pem) to be used by the
 * HTTPS daemon for client authentification.  
 *
 * @param mem_trust memory pointer to the certificate
 */
_MHD_EXTERN struct MHD_Option
MHD_option_tls_mem_trust (const char *mem_trust);


/**
 * Configure daemon credentials type for GnuTLS.
 *
 * @param gnutls_credentials must be a value of
 *   type `gnutls_credentials_type_t`
 */
_MHD_EXTERN struct MHD_Option
MHD_option_gnutls_credentials (int gnutls_credentials);


/**
 * Provide TLS key and certificate data via callback.
 *
 * Use a callback to determine which X.509 certificate should be used
 * for a given HTTPS connection.  This option provides an alternative
 * to #MHD_option_tls_key_and_cert_from_memory().  You must use this
 * version if multiple domains are to be hosted at the same IP address
 * using TLS's Server Name Indication (SNI) extension.  In this case,
 * the callback is expected to select the correct certificate based on
 * the SNI information provided.  The callback is expected to access
 * the SNI data using `gnutls_server_name_get()`.  Using this option
 * requires GnuTLS 3.0 or higher.
   *
 * @param cb must be of type `gnutls_certificate_retrieve_function2 *`.
 * @return MHD option
 */
_MHD_EXTERN struct MHD_Option
MHD_option_gnutls_key_and_cert_from_callback (void *cb);


/**
 * Run using a specific address family (by default, MHD will support
 * dual stack if supported by the operating system).
 *
 * @param af address family to use, i.e. #AF_INET or #AF_INET6,
 *           or #AF_UNSPEC for dual stack
 * @return MHD option
 */
_MHD_EXTERN struct MHD_Option
MHD_option_address_family (int af);


/**
 * Enable use of one thread per connection.
 *
 * @return MHD option
 */
_MHD_EXTERN struct MHD_Option
MHD_option_thread_per_connection (void);


/**
 * Enable use of MHD-internal worker thread.
 *
 * Run using an internal thread (or thread pool) for sockets sending
 * and receiving and data processing. Without this flag MHD will not
 * run automatically in background thread(s).  If this option is set,
 * #MHD_run() and #MHD_run_from_select() cannot be used.   
 *
 * @return MHD option
 */
_MHD_EXTERN struct MHD_Option
MHD_option_thread_iternal (void);


/**
 * Enable use of a thread pool of the given size.
 *
 * @param num_threads number of threads to run in the pool
 * @return MHD option
 */
_MHD_EXTERN struct MHD_Option
MHD_option_thread_pool_size (unsigned int num_threads);


/**
 * Allow or deny a client to connect.
 *
 * @param cls closure
 * @param addr address information from the client
 * @param addrlen length of @a addr
 * @see #MHD_option_accept_policy()
 * @return #MHD_YES if connection is allowed, #MHD_NO if not
 */
typedef enum MHD_Bool
(*MHD_AcceptPolicyCallback) (void *cls,
                             const struct sockaddr *addr,
                             socklen_t addrlen);


/**
 * Return option setting a policy that accepts/rejects connections
 * based on the client's IP address.  This function will be called
 * before a connection object is created.
 *
 * @param apc function to call to check the policy
 * @param apc_cls closure for @a apc
 */
_MHD_EXTERN struct MHD_Option
MHD_option_accept_policy (MHD_AcceptPolicyCallback apc,
			  void *apc_cls);


/**
 * Signature of the callback used by MHD to notify the
 * application about started/stopped connections
 *
 * @param cls client-defined closure
 * @param connection connection handle
 * @param socket_context socket-specific pointer where the
 *                       client can associate some state specific
 *                       to the TCP connection; note that this is
 *                       different from the "con_cls" which is per
 *                       HTTP request.  The client can initialize
 *                       during #MHD_CONNECTION_NOTIFY_STARTED and
 *                       cleanup during #MHD_CONNECTION_NOTIFY_CLOSED
 *                       and access in the meantime using
 *                       #MHD_CONNECTION_INFO_SOCKET_CONTEXT.
 * @param toe reason for connection notification
 * @see #MHD_OPTION_NOTIFY_CONNECTION
 * @ingroup request
 */
typedef void
(*MHD_ConnectionCompletedCallback) (void *cls,
				    struct MHD_Connection *connection,
				    enum MHD_ConnectionNotificationCode toe);


/**
 * Register a function that should be called whenever a connection is
 * started or closed.
 *
 * @param ncc function to call to check the policy
 * @param ncc_cls closure for @a apc
 */
_MHD_EXTERN struct MHD_Option
MHD_option_set_notify_connection (MHD_NotifyConnectionCallback ncc,
				  void *ncc_cls);


/**
 * Maximum memory size per connection (followed by a `size_t`).
 * Default is 32 kb (#MHD_POOL_SIZE_DEFAULT).
 * Values above 128k are unlikely to result in much benefit, as half
 * of the memory will be typically used for IO, and TCP buffers are
 * unlikely to support window sizes above 64k on most systems.
 *
 * @param memory_limit_b connection memory limit to use in bytes
 * @return MHD option
 */
_MHD_EXTERN struct MHD_Option
MHD_option_connection_memory_limit (size_t memory_limit_b);


/**
 * Increment to use for growing the read buffer (followed by a
 * `size_t`). Must fit within #MHD_option_connection_memory_limit()).
 *
 * @param memory_limit_b connection memory limit to use in bytes
 * @return MHD option
 */
_MHD_EXTERN struct MHD_Option
MHD_option_connection_memory_increment (size_t memory_increment_b);


/**
 * Desired size of the stack for threads created by MHD.  Use 0 for
 * system default.
 *
 * @param stack_limit_b stack size to use in bytes
 * @return MHD option
 */
_MHD_EXTERN struct MHD_Option
MHD_option_thread_stack_size (size_t stack_limit_b);


/**
 * Set maximum number of concurrent connections to accept.  If not
 * given, MHD will not enforce any global limit (modulo running into
 * OS limits).
 *
 * @param connection_limit maximum number of concurrent connections
 * @return MHD option
 */
_MHD_EXTERN struct MHD_Option
MHD_option_connection_global_limit (unsigned int connection_limit);


/**
 * Limit on the number of (concurrent) connections made to the
 * server from the same IP address.  Can be used to prevent one
 * IP from taking over all of the allowed connections.  If the
 * same IP tries to establish more than the specified number of
 * connections, they will be immediately rejected.  The default is
 * zero, which means no limit on the number of connections
 * from the same IP address.
 *
 * @param connection_limit maximum number of concurrent connections
 * @return MHD option
 */
_MHD_EXTERN struct MHD_Option
MHD_option_connection_ip_limit (unsigned int connection_limit);


/**
 * After how many seconds of inactivity should a
 * connection automatically be timed out? 
 * Use zero for no timeout, which is also the (unsafe!) default.
 *
 * @param timeout_s number of seconds of timeout to use
 * @return MHD option
 */
_MHD_EXTERN struct MHD_Option
MHD_option_connection_default_timeout (unsigned int timeout_s);


/**
 * Signature of functions performing unescaping of strings.
 * The return value must be "strlen(s)" and @a s  should be
 * updated.  Note that the unescape function must not lengthen @a s
 * (the result must be shorter than the input and still be
 * 0-terminated).  
 *
 * @param cls closure
 * @param req the request for which unescaping is performed
 * @param[in,out] s string to unescape
 * @return number of characters in @a s (excluding 0-terminator)
 */
typedef size_t
MHD_UnescapeCallback (void *cls,
		      struct MHD_Request *req,
		      char *s);


/**
 * Specify a function that should be called for unescaping escape
 * sequences in URIs and URI arguments.  Note that this function
 * will NOT be used by the `struct MHD_PostProcessor`.  If this
 * option is not specified, the default method will be used which
 * decodes escape sequences of the form "%HH". 
 *
 * @param unescape_cb function to use, NULL for default
 * @param unescape_cb_cls closure for @a unescape_cb
 * @return MHD option
 */
_MHD_EXTERN struct MHD_Option
MHD_option_unescape_cb (MHD_UnescapeCallback unescape_cb,
			void *unescape_cb_cls);


/**
 * Set random values to be used by the Digest Auth module.  Note that
 * the application must ensure that @a buf remains allocated and
 * unmodified while the deamon is running.
 *
 * @param buf_size number of bytes in @a buf
 * @param buf entropy buffer
 * @return MHD option
 */
_MHD_EXTERN struct MHD_Option
MHD_option_digest_auth_random (size_t buf_size,
			       const void *buf);


/**
 * Size of the internal array holding the map of the nonce and
 * the nonce counter. 
 *
 * @param nc_length desired array length
 * @return MHD option
 */
_MHD_EXTERN struct MHD_Option
MHD_option_digest_auth_nc_size (size_t stack_limit_b);


/**
 * Return option setting a callback to call upon connection
 * completion.
 *
 * @param ccc function to call
 * @param ccc_cls closure for @a ccc
 */
_MHD_EXTERN struct MHD_Option
MHD_option_connection_completion (MHD_ConnectionCompledCallback ccc,
				  void *ccc_cls;)

  
/**
 * Signature of the callback used by MHD to notify the application
 * that we have received the full header of a request.  Can be used to
 * send error responses to a "Expect: 100-continue" request.
 * Note that regular responses should be set in the
 * #MHD_RequestCompletedCallback.
 *
 * @param cls client-defined closure
 * @ingroup request
 * @return #MHD_YES if the upload was handled successfully,
 *         #MHD_NO if the socket must be closed due to a serios
 *         error while handling the request
 */
typedef enum MHD_Bool
(*MHD_RequestHeaderCallback) (void *cls);


/**
 * A client has uploaded data.
 *
 * @param cls argument given together with the function
 *        pointer when the handler was registered with MHD
 * @param upload_data the data being uploaded (excluding HEADERS,
 *        for a POST that fits into memory and that is encoded
 *        with a supported encoding, the POST data will NOT be
 *        given in upload_data and is instead available as
 *        part of #MHD_get_connection_values; very large POST
 *        data *will* be made available incrementally in
 *        @a upload_data)
 * @param[in,out] upload_data_size set initially to the size of the
 *        @a upload_data provided; the method must update this
 *        value to the number of bytes NOT processed;
 * @return #MHD_YES if the upload was handled successfully,
 *         #MHD_NO if the socket must be closed due to a serios
 *         error while handling the request
 */
typedef enum MHD_Bool
(*MHD_UploadCallback) (void *cls,
		       const char *upload_data,
		       size_t *upload_data_size);


/**
 * Signature of the callback used by MHD to notify the application
 * that we now expect a response.  The application can either
 * call #MHD_response_queue() or suspend the request and return
 * NULL to resume processing later, or return NULL without suspending
 * to close the connection (hard error).
 *
 * @param cls client-defined closure
 * @ingroup request
 * @return response object to return, NULL if processing was
 *         suspended or on hard errors; the response object
 *         will be "consumed" at this point (i.e. the RC decremented)
 */
typedef struct MHD_Response *
(*MHD_RequestFetchResponseCallback) (void *cls);


/**
 * Signature of the callback used by MHD to notify the
 * application about completed requests.
 *
 * @param cls client-defined closure
 * @param toe reason for request termination
 * @see #MHD_option_request_completion()
 * @ingroup request
 */
typedef void
(*MHD_RequestCompletedCallback) (void *cls,
                                 enum MHD_RequestTerminationCode toe);


/**
 * Functions called for an MHD request to process it.
 * Not all functions must be implemented for each request.
 */
struct MHD_RequestHandlerCallbacks
{
  /**
   * Closure argument passed to all callbacks in this struct.
   */
  void *cls;

  /** 
   * Function called after we have received the full HTTP header.
   */
  MHD_RequestHeaderCallback header_cb;

  /**
   * Function called if we receive uploaded data.
   */
  MHD_UploadCallback upload_cb;

  /**
   * Function called when we expect the application to
   * generate a response (mandatory to be set; if not
   * set and #MHD_NO is not returned, MHD will generate
   * 500 internal error and log an error).
   */
  MHD_RequestFetchResponseCallback fetch_response_cb;

  /**
   * Function called last to clean up.  Gives the
   * application a chance to check on the final status of
   * the request (and to clean up @e cls).
   */
  MHD_RequestCompletedCallback completed_cb;

};


/**
 * A client has requested the given url using the given method
 * (#MHD_HTTP_METHOD_GET, #MHD_HTTP_METHOD_PUT,
 * #MHD_HTTP_METHOD_DELETE, #MHD_HTTP_METHOD_POST, etc).  The callback
 * must initialize @a rhp to provide further callbacks which will
 * process the request further and ultimately to provide the response
 * to give back to the client.
 *
 * @param cls argument given together with the function
 *        pointer when the handler was registered with MHD
 * @param url the requested url (without arguments after "?")
 * @param method the HTTP method used (#MHD_HTTP_METHOD_GET,
 *        #MHD_HTTP_METHOD_PUT, etc.)
 * @param[out] must be set to function pointers to be used to
 *        handle the request further; can be assumed to have
 *        been initialized to all-NULL values already.
 * @return #MHD_YES if the request was handled successfully,
 *         #MHD_NO if the socket must be closed due to a serios
 *         error while handling the request
 */
typedef enum MHD_Bool
(*MHD_RequestCallback) (void *cls,
			struct MHD_Request *request,
			const char *url,
			const char *method,
			struct MHD_RequestHandlerCallbacks *rhp);


/**
 * Generic option to set a global URL handler which
 * will be called for all requests.  You may prefer the
 * more convenient, but less generic #MHD_option_url_table().
 *
 * @param rc function to call for requests
 * @param rc_cls closure to give to @a rc
 */
_MHD_EXTERN struct MHD_Option
MHD_option_url_handler (MHD_RequestCallback rc,
			void *rc_cls);


/**
 * A client has requested the given url using the given method
 * (#MHD_HTTP_METHOD_GET, #MHD_HTTP_METHOD_PUT,
 * #MHD_HTTP_METHOD_DELETE, #MHD_HTTP_METHOD_POST, etc).  The callback
 * must initialize @a rhp to provide further callbacks which will
 * process the request further and ultimately to provide the response
 * to give back to the client.
 *
 * @param cls argument given together with the function
 *        pointer when the handler was registered with MHD
 * @param request HTTP request handle
 * @param[out] must be set to function pointers to be used to
 *        handle the request further; can be assumed to have
 *        been initialized to all-NULL values already.
 * @return #MHD_YES if the request was handled successfully,
 *         #MHD_NO if the socket must be closed due to a serious
 *         error while handling the request
 */
typedef enum MHD_Bool
(*MHD_RequestStartCallback) (void *cls,
			     struct MHD_Request *request,
			     struct MHD_RequestHandlerCallbacks *rhp);


/**
 * Definition of a request handler for a URL and method.
 */
struct MHD_UrlHandler;


/**
 * Create URL handler array terminator.
 */
_MHD_EXTERN struct MHD_UrlHandler
MHD_url_handler_end (void);


/**
 * Create a generic URL handler array entry.
 *
 * @param method HTTP method to which this handler
 *   matches. Case-insensitive, i.e. "GET".
 * @param url Which URL does this handler match. Case-sensitive,
 *   i.e. "/favicon.ico".
 * @param start_cb function to call for matching requests
 * @param start_cb_cls closure for @a start_cb
 * @return url handler array entry
 */
_MHD_EXTERN struct MHD_UrlHandler
MHD_url_handler_generic (const char *method,
			 const char *url,
			 MHD_RequestStartCallback start_cb,
			 void *start_cb_cls);


/**
 * Create a simple URL handler array entry for requests
 * where the application simply returns a response and
 * has no state to initialize or clean up and where there
 * is no upload.
 *
 * @param method HTTP method to which this handler
 *   matches. Case-insensitive, i.e. "GET".
 * @param url Which URL does this handler match. Case-sensitive,
 *   i.e. "/favicon.ico".
 * @param fetch_cb function to call for matching requests
 * @param fetch_cb_cls closure for @a fetch_cb
 * @return url handler array entry
 */
_MHD_EXTERN struct MHD_UrlHandler
MHD_url_handler_simple (const char *method,
			const char *url,
			MHD_RequestFetchResponseCallback fetch_cb,
			void *fetch_cb_cls);


/**
 * Set a table of @a handlers to process requests of matching methods
 * and URLs.  Requests that do not match any entry will yield a 404
 * NOT FOUND response.  Note that this function may sort the @a
 * handlers array in-place for faster (logarithmic) lookups later,
 * hence the argument must be muteable.  The @a handlers array must
 * remain allocated by the application throughout the lifetime of the
 * daemon!
 *
 * @param[in,out] handlers url handler table, terminated
 *     by #MHD_url_handler_end()
 * @return option array entry
 */
_MHD_EXTERN struct MHD_Option
MHD_option_url_table (struct MHD_UrlHandler handlers[]);


/* **************** Daemon handling functions ***************** */

/**
 * Start a webserver on the given port.
 *
 * @param options array of options, does NOT have to
 *        persist in memory past this call (note that individual
 *        arguments passed to the functions may need to
 *        be preserved)
 * @return NULL on error, handle to daemon on success
 * @ingroup event
 */
_MHD_EXTERN struct MHD_Daemon *
MHD_daemon_start (const struct MHD_Option options[]);


/**
 * Stop accepting connections from the listening socket.  Allows
 * clients to continue processing, but stops accepting new
 * connections.  Note that the caller is responsible for closing the
 * returned socket; however, if MHD is run using threads (anything but
 * external select mode), it must not be closed until AFTER
 * #MHD_stop_daemon has been called (as it is theoretically possible
 * that an existing thread is still using it).
 *
 * Note that some thread modes require the caller to have passed
 * #MHD_USE_ITC when using this API.  If this daemon is
 * in one of those modes and this option was not given to
 * #MHD_start_daemon, this function will return #MHD_INVALID_SOCKET.
 *
 * @param daemon daemon to stop accepting new connections for
 * @return old listen socket on success, #MHD_INVALID_SOCKET if
 *         the daemon was already not listening anymore
 * @ingroup specialized
 */
_MHD_EXTERN MHD_socket
MHD_daemon_quiesce (struct MHD_Daemon *daemon);


/**
 * Shutdown an HTTP daemon.
 *
 * @param daemon daemon to stop
 * @ingroup event
 */
_MHD_EXTERN void
MHD_daemon_stop (struct MHD_Daemon *daemon);


/* ********************* connection options ************** */

/**
 * MHD connection options.  Given to #MHD_set_connection_option() to
 * set custom options for a particular connection.
 */
struct MHD_ConnectionOption;


/**
 * Generate array terminator for connection options.
 */
struct MHD_ConnectionOption
MHD_connection_option_end (void);


/**
 * Generate option to set a custom timeout for the given connection.
 * Specified as the number of seconds.  Use zero for no timeout.  If
 * timeout was set to zero (or unset) before, setting of a new value
 * by MHD_connection_set_option() will reset timeout timer.
 * 
 * @param timeout_s new timeout in seconds
 */
struct MHD_ConnectionOption
MHD_connection_option_timeout (unsigned int timeout_s);


/**
 * Set a custom option for the given connection, overriding defaults.
 *
 * @param connection connection to modify
 * @param options array of options to set, does NOT have to
 *        persist past this call
 * @ingroup specialized
 * @return #MHD_YES on success
 */
_MHD_EXTERN enum MHD_Bool
MHD_connection_set_options (struct MHD_Connection *connection,
			    struct MHD_ConnectionOption options[]);


/* **************** Request handling functions ***************** */

/**
 * Get all of the headers from the request.
 *
 * @param request request to get values from
 * @param kind types of values to iterate over, can be a bitmask
 * @param iterator callback to call on each header;
 *        maybe NULL (then just count headers)
 * @param iterator_cls extra argument to @a iterator
 * @return number of entries iterated over
 * @ingroup request
 */
_MHD_EXTERN unsigned int
MHD_request_get_values (struct MHD_Request *request,
			enum MHD_ValueKind kind,
			MHD_KeyValueIterator iterator,
			void *iterator_cls);


/**
 * This function can be used to add an entry to the HTTP headers of a
 * request (so that the #MHD_request_get_values function will
 * return them -- and the `struct MHD_PostProcessor` will also see
 * them).  This maybe required in certain situations (see Mantis
 * #1399) where (broken) HTTP implementations fail to supply values
 * needed by the post processor (or other parts of the application).
 *
 * This function MUST only be called from within the
 * request callbacks (otherwise, access maybe improperly
 * synchronized).  Furthermore, the client must guarantee that the key
 * and value arguments are 0-terminated strings that are NOT freed
 * until the connection is closed.  (The easiest way to do this is by
 * passing only arguments to permanently allocated strings.).
 *
 * @param request the request for which a
 *  value should be set
 * @param kind kind of the value
 * @param key key for the value
 * @param value the value itself
 * @return #MHD_NO if the operation could not be
 *         performed due to insufficient memory;
 *         #MHD_YES on success
 * @ingroup request
 */
_MHD_EXTERN enum MHD_Bool
MHD_request_set_value (struct MHD_Request *request,
		       enum MHD_ValueKind kind,
		       const char *key,
		       const char *value);


/**
 * Get a particular header value.  If multiple
 * values match the kind, return any one of them.
 *
 * @param request request to get values from
 * @param kind what kind of value are we looking for
 * @param key the header to look for, NULL to lookup 'trailing' value without a key
 * @return NULL if no such item was found
 * @ingroup request
 */
_MHD_EXTERN const char *
MHD_request_lookup_value (struct MHD_Request *request,
			  enum MHD_ValueKind kind,
			  const char *key);



/**
 * @defgroup httpcode HTTP response codes.
 * These are the status codes defined for HTTP responses.
 * @{
 */
/* See http://www.iana.org/assignments/http-status-codes/http-status-codes.xhtml */
enum MHD_HTTP_StatusCode {
  MHD_HTTP_CONTINUE = 100,
  MHD_HTTP_SWITCHING_PROTOCOLS = 101,
  MHD_HTTP_PROCESSING = 102,

  MHD_HTTP_OK = 200,
  MHD_HTTP_CREATED = 201,
  MHD_HTTP_ACCEPTED = 202,
  MHD_HTTP_NON_AUTHORITATIVE_INFORMATION = 203,
  MHD_HTTP_NO_CONTENT = 204,
  MHD_HTTP_RESET_CONTENT = 205,
  MHD_HTTP_PARTIAL_CONTENT = 206,
  MHD_HTTP_MULTI_STATUS = 207,
  MHD_HTTP_ALREADY_REPORTED = 208,

  MHD_HTTP_IM_USED = 226,

  MHD_HTTP_MULTIPLE_CHOICES = 300,
  MHD_HTTP_MOVED_PERMANENTLY = 301,
  MHD_HTTP_FOUND = 302,
  MHD_HTTP_SEE_OTHER = 303,
  MHD_HTTP_NOT_MODIFIED = 304,
  MHD_HTTP_USE_PROXY = 305,
  MHD_HTTP_SWITCH_PROXY = 306,
  MHD_HTTP_TEMPORARY_REDIRECT = 307,
  MHD_HTTP_PERMANENT_REDIRECT = 308,

  MHD_HTTP_BAD_REQUEST = 400,
  MHD_HTTP_UNAUTHORIZED = 401,
  MHD_HTTP_PAYMENT_REQUIRED = 402,
  MHD_HTTP_FORBIDDEN = 403,
  MHD_HTTP_NOT_FOUND = 404,
  MHD_HTTP_METHOD_NOT_ALLOWED = 405,
  MHD_HTTP_NOT_ACCEPTABLE = 406,
/** @deprecated */
#define MHD_HTTP_METHOD_NOT_ACCEPTABLE \
  _MHD_DEPR_IN_MACRO("Value MHD_HTTP_METHOD_NOT_ACCEPTABLE is deprecated, use MHD_HTTP_NOT_ACCEPTABLE") MHD_HTTP_NOT_ACCEPTABLE 
  MHD_HTTP_PROXY_AUTHENTICATION_REQUIRED = 407,
  MHD_HTTP_REQUEST_TIMEOUT = 408,
  MHD_HTTP_CONFLICT = 409,
  MHD_HTTP_GONE = 410,
  MHD_HTTP_LENGTH_REQUIRED = 411,
  MHD_HTTP_PRECONDITION_FAILED = 412,
  MHD_HTTP_PAYLOAD_TOO_LARGE = 413,
/** @deprecated */
#define MHD_HTTP_REQUEST_ENTITY_TOO_LARGE \
  _MHD_DEPR_IN_MACRO("Value MHD_HTTP_REQUEST_ENTITY_TOO_LARGE is deprecated, use MHD_HTTP_PAYLOAD_TOO_LARGE") MHD_HTTP_PAYLOAD_TOO_LARGE
  MHD_HTTP_URI_TOO_LONG = 414,
/** @deprecated */
#define MHD_HTTP_REQUEST_URI_TOO_LONG \
  _MHD_DEPR_IN_MACRO("Value MHD_HTTP_REQUEST_URI_TOO_LONG is deprecated, use MHD_HTTP_URI_TOO_LONG") MHD_HTTP_URI_TOO_LONG
  MHD_HTTP_UNSUPPORTED_MEDIA_TYPE = 415,
  MHD_HTTP_RANGE_NOT_SATISFIABLE = 416,
/** @deprecated */
#define MHD_HTTP_REQUESTED_RANGE_NOT_SATISFIABLE \
  _MHD_DEPR_IN_MACRO("Value MHD_HTTP_REQUESTED_RANGE_NOT_SATISFIABLE is deprecated, use MHD_HTTP_RANGE_NOT_SATISFIABLE") MHD_HTTP_RANGE_NOT_SATISFIABLE
  MHD_HTTP_EXPECTATION_FAILED = 417,

  MHD_HTTP_MISDIRECTED_REQUEST = 421,
  MHD_HTTP_UNPROCESSABLE_ENTITY = 422,
  MHD_HTTP_LOCKED = 423,
  MHD_HTTP_FAILED_DEPENDENCY = 424,
  MHD_HTTP_UNORDERED_COLLECTION = 425,
  MHD_HTTP_UPGRADE_REQUIRED = 426,

  MHD_HTTP_PRECONDITION_REQUIRED = 428,
  MHD_HTTP_TOO_MANY_REQUESTS = 429,
  MHD_HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE = 431,

  MHD_HTTP_NO_RESPONSE = 444,

  MHD_HTTP_RETRY_WITH = 449,
  MHD_HTTP_BLOCKED_BY_WINDOWS_PARENTAL_CONTROLS = 450,
  MHD_HTTP_UNAVAILABLE_FOR_LEGAL_REASONS = 451,

  MHD_HTTP_INTERNAL_SERVER_ERROR = 500,
  MHD_HTTP_NOT_IMPLEMENTED = 501,
  MHD_HTTP_BAD_GATEWAY = 502,
  MHD_HTTP_SERVICE_UNAVAILABLE = 503,
  MHD_HTTP_GATEWAY_TIMEOUT = 504,
  MHD_HTTP_HTTP_VERSION_NOT_SUPPORTED = 505,
  MHD_HTTP_VARIANT_ALSO_NEGOTIATES = 506,
  MHD_HTTP_INSUFFICIENT_STORAGE = 507,
  MHD_HTTP_LOOP_DETECTED = 508,
  MHD_HTTP_BANDWIDTH_LIMIT_EXCEEDED = 509,
  MHD_HTTP_NOT_EXTENDED = 510,
  MHD_HTTP_NETWORK_AUTHENTICATION_REQUIRED 511

};
/** @} */ /* end of group httpcode */


/**
 * Suspend handling of network data for a given request.  This can
 * be used to dequeue a request from MHD's event loop for a while.
 *
 * If you use this API in conjunction with a internal select or a
 * thread pool, you must set the option #MHD_USE_ITC to
 * ensure that a resumed request is immediately processed by MHD.
 *
 * Suspended requests continue to count against the total number of
 * requests allowed (per daemon, as well as per IP, if such limits
 * are set).  Suspended requests will NOT time out; timeouts will
 * restart when the request handling is resumed.  While a
 * request is suspended, MHD will not detect disconnects by the
 * client.
 *
 * The only safe time to suspend a request is from the
 * #MHD_AccessHandlerCallback.
 *
 * Finally, it is an API violation to call #MHD_stop_daemon while
 * having suspended requests (this will at least create memory and
 * socket leaks or lead to undefined behavior).  You must explicitly
 * resume all requests before stopping the daemon.
 *
 * @param request the request to suspend
 */
_MHD_EXTERN void
MHD_request_suspend (struct MHD_Request *request);


/**
 * Resume handling of network data for suspended request.  It is
 * safe to resume a suspended request at any time.  Calling this
 * function on a request that was not previously suspended will
 * result in undefined behavior.
 *
 * If you are using this function in ``external'' select mode, you must
 * make sure to run #MHD_run() afterwards (before again calling
 * #MHD_get_fdset(), as otherwise the change may not be reflected in
 * the set returned by #MHD_get_fdset() and you may end up with a
 * request that is stuck until the next network activity.
 *
 * @param request the request to resume
 */
_MHD_EXTERN void
MHD_request_resume (struct MHD_Request *request);


/* **************** Response manipulation functions ***************** */


/**
 * MHD response option.
 */
struct MHD_ResponseOption;


/**
 * End of options array.
 */
struct MHD_ResponseOption
MHD_response_option_end (void);


/**
 * Only respond in conservative HTTP 1.0-mode.   In particular,
 * do not (automatically) sent "Connection" headers and always
 * close the connection after generating the response.
 */
struct MHD_ResponseOption
MHD_response_option_v10_only (void);


/**
 * Set special @a options for a @a response.
 *
 * @param response the response to modify
 * @param options options to set for the response
 * @return #MHD_YES on success, #MHD_NO on error
 */
_MHD_EXTERN enum MHD_Bool
MHD_response_set_options (struct MHD_Response *response,
                          enum MHD_ResponseOption options[]);


/**
 * Create a response object.  The response object can be extended with
 * header information and then be used any number of times.
 *
 * @param sc status code to return
 * @param size size of the data portion of the response, #MHD_SIZE_UNKNOWN for unknown
 * @param block_size preferred block size for querying crc (advisory only,
 *                   MHD may still call @a crc using smaller chunks); this
 *                   is essentially the buffer size used for IO, clients
 *                   should pick a value that is appropriate for IO and
 *                   memory performance requirements
 * @param crc callback to use to obtain response data
 * @param crc_cls extra argument to @a crc
 * @param crfc callback to call to free @a crc_cls resources
 * @return NULL on error (i.e. invalid arguments, out of memory)
 * @ingroup response
 */
_MHD_EXTERN struct MHD_Response *
MHD_response_from_callback (enum MHD_HTTP_StatusCode sc,
			    uint64_t size,
			    size_t block_size,
			    MHD_ContentReaderCallback crc,
			    void *crc_cls,
			    MHD_ContentReaderFreeCallback crfc);


/**
 * Specification for how MHD should treat the memory buffer
 * given for the response.
 * @ingroup response
 */
enum MHD_ResponseMemoryMode
{

  /**
   * Buffer is a persistent (static/global) buffer that won't change
   * for at least the lifetime of the response, MHD should just use
   * it, not free it, not copy it, just keep an alias to it.
   * @ingroup response
   */
  MHD_RESPMEM_PERSISTENT,

  /**
   * Buffer is heap-allocated with `malloc()` (or equivalent) and
   * should be freed by MHD after processing the response has
   * concluded (response reference counter reaches zero).
   * @ingroup response
   */
  MHD_RESPMEM_MUST_FREE,

  /**
   * Buffer is in transient memory, but not on the heap (for example,
   * on the stack or non-`malloc()` allocated) and only valid during the
   * call to #MHD_create_response_from_buffer.  MHD must make its
   * own private copy of the data for processing.
   * @ingroup response
   */
  MHD_RESPMEM_MUST_COPY

};


/**
 * Create a response object.  The response object can be extended with
 * header information and then be used any number of times.
 *
 * @param sc status code to use for the response;
 *           #MHD_HTTP_NO_CONTENT is only valid if @a size is 0;
 * @param size size of the data portion of the response
 * @param buffer size bytes containing the response's data portion
 * @param mode flags for buffer management
 * @return NULL on error (i.e. invalid arguments, out of memory)
 * @ingroup response
 */
_MHD_EXTERN struct MHD_Response *
MHD_response_from_buffer (enum MHD_HTTP_StatusCode sc,
			  size_t size,
			  void *buffer,
			  enum MHD_ResponseMemoryMode mode);


/**
 * Create a response object based on an @a fd from which
 * data is read.  The response object can be extended with
 * header information and then be used any number of times.
 *
 * @param sc status code to return
 * @param fd file descriptor referring to a file on disk with the
 *        data; will be closed when response is destroyed;
 *        fd should be in 'blocking' mode
 * @param offset offset to start reading from in the file;
 *        reading file beyond 2 GiB may be not supported by OS or
 *        MHD build; see ::MHD_FEATURE_LARGE_FILE
 * @param size size of the data portion of the response;
 *        sizes larger than 2 GiB may be not supported by OS or
 *        MHD build; see ::MHD_FEATURE_LARGE_FILE
 * @return NULL on error (i.e. invalid arguments, out of memory)
 * @ingroup response
 */
_MHD_EXTERN struct MHD_Response *
MHD_response_from_fd (enum MHD_HTTP_StatusCode sc,
		      int fd,
		      uint64_t offset,
		      uint64_t size);


/**
 * Enumeration for actions MHD should perform on the underlying socket
 * of the upgrade.  This API is not finalized, and in particular
 * the final set of actions is yet to be decided. This is just an
 * idea for what we might want.
 */
enum MHD_UpgradeAction
{

  /**
   * Close the socket, the application is done with it.
   *
   * Takes no extra arguments.
   */
  MHD_UPGRADE_ACTION_CLOSE = 0

};


/**
 * Handle given to the application to manage special
 * actions relating to MHD responses that "upgrade"
 * the HTTP protocol (i.e. to WebSockets).
 */
struct MHD_UpgradeResponseHandle;


/**
 * This connection-specific callback is provided by MHD to
 * applications (unusual) during the #MHD_UpgradeHandler.
 * It allows applications to perform 'special' actions on
 * the underlying socket from the upgrade.
 *
 * @param urh the handle identifying the connection to perform
 *            the upgrade @a action on.
 * @param action which action should be performed
 * @param ... arguments to the action (depends on the action)
 * @return #MHD_NO on error, #MHD_YES on success
 */
_MHD_EXTERN enum MHD_Bool
MHD_upgrade_action (struct MHD_UpgradeResponseHandle *urh,
                    enum MHD_UpgradeAction action,
                    ...);


/**
 * Function called after a protocol "upgrade" response was sent
 * successfully and the socket should now be controlled by some
 * protocol other than HTTP.
 *
 * Any data already received on the socket will be made available in
 * @e extra_in.  This can happen if the application sent extra data
 * before MHD send the upgrade response.  The application should
 * treat data from @a extra_in as if it had read it from the socket.
 *
 * Note that the application must not close() @a sock directly,
 * but instead use #MHD_upgrade_action() for special operations
 * on @a sock.
 *
 * Data forwarding to "upgraded" @a sock will be started as soon
 * as this function return.
 *
 * Except when in 'thread-per-connection' mode, implementations
 * of this function should never block (as it will still be called
 * from within the main event loop).
 *
 * @param cls closure, whatever was given to #MHD_response_create_for_upgrade().
 * @param connection original HTTP connection handle,
 *                   giving the function a last chance
 *                   to inspect the original HTTP request
 * @param con_cls last value left in `con_cls` of the `MHD_AccessHandlerCallback`
 * @param extra_in if we happened to have read bytes after the
 *                 HTTP header already (because the client sent
 *                 more than the HTTP header of the request before
 *                 we sent the upgrade response),
 *                 these are the extra bytes already read from @a sock
 *                 by MHD.  The application should treat these as if
 *                 it had read them from @a sock.
 * @param extra_in_size number of bytes in @a extra_in
 * @param sock socket to use for bi-directional communication
 *        with the client.  For HTTPS, this may not be a socket
 *        that is directly connected to the client and thus certain
 *        operations (TCP-specific setsockopt(), getsockopt(), etc.)
 *        may not work as expected (as the socket could be from a
 *        socketpair() or a TCP-loopback).  The application is expected
 *        to perform read()/recv() and write()/send() calls on the socket.
 *        The application may also call shutdown(), but must not call
 *        close() directly.
 * @param urh argument for #MHD_upgrade_action()s on this @a connection.
 *        Applications must eventually use this callback to (indirectly)
 *        perform the close() action on the @a sock.
 */
typedef void
(*MHD_UpgradeHandler)(void *cls,
                      struct MHD_Connection *connection,
                      void *con_cls,
                      const char *extra_in,
                      size_t extra_in_size,
                      MHD_socket sock,
                      struct MHD_UpgradeResponseHandle *urh);


/**
 * Create a response object that can be used for 101 UPGRADE
 * responses, for example to implement WebSockets.  After sending the
 * response, control over the data stream is given to the callback (which
 * can then, for example, start some bi-directional communication).
 * If the response is queued for multiple connections, the callback
 * will be called for each connection.  The callback
 * will ONLY be called after the response header was successfully passed
 * to the OS; if there are communication errors before, the usual MHD
 * connection error handling code will be performed.
 *
 * MHD will automatically set the correct HTTP status
 * code (#MHD_HTTP_SWITCHING_PROTOCOLS).
 * Setting correct HTTP headers for the upgrade must be done
 * manually (this way, it is possible to implement most existing
 * WebSocket versions using this API; in fact, this API might be useful
 * for any protocol switch, not just WebSockets).  Note that
 * draft-ietf-hybi-thewebsocketprotocol-00 cannot be implemented this
 * way as the header "HTTP/1.1 101 WebSocket Protocol Handshake"
 * cannot be generated; instead, MHD will always produce "HTTP/1.1 101
 * Switching Protocols" (if the response code 101 is used).
 *
 * As usual, the response object can be extended with header
 * information and then be used any number of times (as long as the
 * header information is not connection-specific).
 *
 * @param upgrade_handler function to call with the "upgraded" socket
 * @param upgrade_handler_cls closure for @a upgrade_handler
 * @return NULL on error (i.e. invalid arguments, out of memory)
 */
_MHD_EXTERN struct MHD_Response *
MHD_response_for_upgrade (MHD_UpgradeHandler upgrade_handler,
			  void *upgrade_handler_cls);


/**
 * Decrease reference counter of a response object.  If the counter
 * hits zero, destroys a response object and associated resources.
 *
 * @param response response to decrement RC of
 * @ingroup response
 */
_MHD_EXTERN void
MHD_response_decref (struct MHD_Response *response);


/**
 * Increases reference counter of a response object. Used so that
 * the same response object can be queued repeatedly.
 *
 * @param response response to increment RC for
 * @ingroup response
 */
_MHD_EXTERN void
MHD_response_incref (struct MHD_Response *response);


/**
 * Add a header line to the response.
 *
 * @param response response to add a header to
 * @param header the header to add
 * @param content value to add
 * @return #MHD_NO on error (i.e. invalid header or content format),
 *         or out of memory
 * @ingroup response
 */
_MHD_EXTERN enum MHD_Bool
MHD_response_add_header (struct MHD_Response *response,
                         const char *header,
			 const char *content);


/**
 * Add a footer line to the response.
 *
 * @param response response to remove a header from
 * @param footer the footer to delete
 * @param content value to delete
 * @return #MHD_NO on error (i.e. invalid footer or content format).
 * @ingroup response
 */
_MHD_EXTERN enum MHD_Bool
MHD_response_add_footer (struct MHD_Response *response,
                         const char *footer,
			 const char *content);


/**
 * Delete a header (or footer) line from the response.
 *
 * @param response response to remove a header from
 * @param header the header to delete
 * @param content value to delete
 * @return #MHD_NO on error (no such header known)
 * @ingroup response
 */
_MHD_EXTERN enum MHD_Bool
MHD_response_del_header (struct MHD_Response *response,
                         const char *header,
			 const char *content);


/**
 * Get all of the headers (and footers) added to a response.
 *
 * @param response response to query
 * @param iterator callback to call on each header;
 *        maybe NULL (then just count headers)
 * @param iterator_cls extra argument to @a iterator
 * @return number of entries iterated over
 * @ingroup response
 */
_MHD_EXTERN unsigned int
MHD_response_get_headers (struct MHD_Response *response,
                          MHD_KeyValueIterator iterator,
			  void *iterator_cls);


/**
 * Get a particular header (or footer) from the response.
 *
 * @param response response to query
 * @param key which header to get
 * @return NULL if header does not exist
 * @ingroup response
 */
_MHD_EXTERN const char *
MHD_response_get_header (struct MHD_Response *response,
			 const char *key);


/* ********************** PostProcessor functions ********************** */

/**
 * Create a `struct MHD_PostProcessor`.
 *
 * A `struct MHD_PostProcessor` can be used to (incrementally) parse
 * the data portion of a POST request.  Note that some buggy browsers
 * fail to set the encoding type.  If you want to support those, you
 * may have to call #MHD_set_connection_value with the proper encoding
 * type before creating a post processor (if no supported encoding
 * type is set, this function will fail).
 *
 * @param connection the connection on which the POST is
 *        happening (used to determine the POST format)
 * @param buffer_size maximum number of bytes to use for
 *        internal buffering (used only for the parsing,
 *        specifically the parsing of the keys).  A
 *        tiny value (256-1024) should be sufficient.
 *        Do NOT use a value smaller than 256.  For good
 *        performance, use 32 or 64k (i.e. 65536).
 * @param iter iterator to be called with the parsed data,
 *        Must NOT be NULL.
 * @param iter_cls first argument to @a iter
 * @return NULL on error (out of memory, unsupported encoding),
 *         otherwise a PP handle
 * @ingroup request
 */
_MHD_EXTERN struct MHD_PostProcessor *
MHD_post_processor_create (struct MHD_Connection *connection,
			   size_t buffer_size,
			   MHD_PostDataIterator iter,
			   void *iter_cls);


/**
 * Parse and process POST data.  Call this function when POST data is
 * available (usually during an #MHD_AccessHandlerCallback) with the
 * "upload_data" and "upload_data_size".  Whenever possible, this will
 * then cause calls to the #MHD_PostDataIterator.
 *
 * @param pp the post processor
 * @param post_data @a post_data_len bytes of POST data
 * @param post_data_len length of @a post_data
 * @return #MHD_YES on success, #MHD_NO on error
 *         (out-of-memory, iterator aborted, parse error)
 * @ingroup request
 */
_MHD_EXTERN enum MHD_Bool
MHD_post_processor_run (struct MHD_PostProcessor *pp,
			const char *post_data,
			size_t post_data_len);


/**
 * Release PostProcessor resources.
 *
 * @param pp the PostProcessor to destroy
 * @return #MHD_YES if processing completed nicely,
 *         #MHD_NO if there were spurious characters / formatting
 *                problems; it is common to ignore the return
 *                value of this function
 * @ingroup request
 */
_MHD_EXTERN enum MHD_Bool
MHD_post_processor_destroy (struct MHD_PostProcessor *pp);


/* ********************** generic query functions ********************** */


/**
 * Select which member of the `struct ConnectionInformation`
 * union is desired to be returned by #MHD_connection_get_info().
 */
enum MHD_ConnectionInformationType
{
  /**
   * What cipher algorithm is being used.
   * Takes no extra arguments.
   * @ingroup request
   */
  MHD_CONNECTION_INFORMATION_CIPHER_ALGO,

  /**
   *
   * Takes no extra arguments.
   * @ingroup request
   */
  MHD_CONNECTION_INFORMATION_PROTOCOL,

  /**
   * Obtain IP address of the client.  Takes no extra arguments.
   * Returns essentially a `struct sockaddr **` (since the API returns
   * a `union MHD_ConnectionInfo *` and that union contains a `struct
   * sockaddr *`).
   * @ingroup request
   */
  MHD_CONNECTION_INFORMATION_CLIENT_ADDRESS,

  /**
   * Get the gnuTLS session handle.
   * @ingroup request
   */
  MHD_CONNECTION_INFORMATION_GNUTLS_SESSION,

  /**
   * Get the gnuTLS client certificate handle.  Dysfunctional (never
   * implemented, deprecated).  Use #MHD_CONNECTION_INFORMATION_GNUTLS_SESSION
   * to get the `gnutls_session_t` and then call
   * gnutls_certificate_get_peers().
   */
  MHD_CONNECTION_INFORMATION_GNUTLS_CLIENT_CERT,

  /**
   * Get the `struct MHD_Daemon *` responsible for managing this connection.
   * @ingroup request
   */
  MHD_CONNECTION_INFORMATION_DAEMON,

  /**
   * Request the file descriptor for the connection socket.
   * No extra arguments should be passed.
   * @ingroup request
   */
  MHD_CONNECTION_INFORMATION_CONNECTION_FD,

  /**
   * Returns the client-specific pointer to a `void *` that was (possibly)
   * set during a #MHD_NotifyConnectionCallback when the socket was
   * first accepted.  Note that this is NOT the same as the "con_cls"
   * argument of the #MHD_AccessHandlerCallback.  The "con_cls" is
   * fresh for each HTTP request, while the "socket_context" is fresh
   * for each socket.
   */
  MHD_CONNECTION_INFORMATION_SOCKET_CONTEXT,

  /**
   * Get connection timeout
   * @ingroup request
   */
  MHD_CONNECTION_INFORMATION_CONNECTION_TIMEOUT

};


/**
 * Information about a connection.
 */
union MHD_ConnectionInformation
{

  /**
   * Cipher algorithm used, of type "enum gnutls_cipher_algorithm".
   */
  int /* enum gnutls_cipher_algorithm */ cipher_algorithm;

  /**
   * Protocol used, of type "enum gnutls_protocol".
   */
  int /* enum gnutls_protocol */ protocol;

  /**
   * Amount of second that connection could spend in idle state
   * before automatically disconnected.
   * Zero for no timeout (unlimited idle time).
   */
  unsigned int connection_timeout;

  /**
   * Connect socket
   */
  MHD_socket connect_fd;

  /**
   * GNUtls session handle, of type "gnutls_session_t".
   */
  void * /* gnutls_session_t */ tls_session;

  /**
   * GNUtls client certificate handle, of type "gnutls_x509_crt_t".
   */
  void * /* gnutls_x509_crt_t */ client_cert;

  /**
   * Address information for the client.
   */
  struct sockaddr *client_addr;

  /**
   * Which daemon manages this connection (useful in case there are many
   * daemons running).
   */
  struct MHD_Daemon *daemon;

  /**
   * Socket-specific client context.  Points to the same address as
   * the "socket_context" of the #MHD_NotifyConnectionCallback.
   */
  void *socket_context;
};


/**
 * Obtain information about the given connection.
 * Use wrapper macro #MHD_connection_get_information() instead of direct use
 * of this function.
 *
 * @param connection what connection to get information about
 * @param info_type what information is desired?
 * @param[out] return_value pointer to union where requested information will
 *                          be stored
 * @param return_value_size size of union MHD_DaemonInformation at compile
 *                          time
 * @return #MHD_YES on success, #MHD_NO on error
 *         (@a info_type is unknown, NULL pointer etc.)
 * @ingroup specialized
 */
_MHD_EXTERN enum MHD_Bool
MHD_connection_get_information_sz (struct MHD_Connection *connection,
				   enum MHD_ConnectionInformationType info_type,
				   union MHD_ConnectionInformation *return_value,
				   size_t return_value_size);


/**
 * Obtain information about the given connection.
 *
 * @param connection what connection to get information about
 * @param info_type what information is desired?
 * @param[out] return_value pointer to union where requested information will
 *                          be stored
 * @return #MHD_YES on success, #MHD_NO on error
 *         (@a info_type is unknown, NULL pointer etc.)
 * @ingroup specialized
 */
#define MHD_connection_get_information(connection,   \
                                       info_type,    \
                                       return_value) \
        MHD_connection_get_information_sz ((connection),(info_type),(return_value),sizeof(enum MHD_ConnectionInformationType))


/**
 * Information we return about a request.
 */
union MHD_RequestInformation
{

  /**
   * Connection via which we received the request.
   */
  struct MHD_Connection *connection;

  /**
   * The suspended status of a request.
   */
  enum MHD_Bool suspended;

  /**
   * HTTP version requested by the client.
   */
  const char *http_version;
  
  /**
   * Size of the client's HTTP header.
   */
  size_t header_size;

};


/**
 * Select which member of the `struct RequestInformation`
 * union is desired to be returned by #MHD_request_get_info().
 */
enum MHD_RequestInformationType
{
  /**
   * Return which connection the request is associated with.
   */
  MHD_REQUEST_INFORMATION_CONNECTION,
  
  /**
   * Check whether the connection is suspended.
   * @ingroup request
   */
  MHD_REQUEST_INFORMATION_SUSPENDED,
  
  /**
   * Return the HTTP version string given by the client.
   * @ingroup request
   */
  MHD_REQUEST_INFORMATION_HTTP_VERSION,
  
  /**
   * Return length of the client's HTTP request header.
   * @ingroup request
   */
  MHD_REQUEST_INFORMATION_HEADER_SIZE
};


/**
 * Obtain information about the given request.
 * Use wrapper macro #MHD_request_get_information() instead of direct use
 * of this function.
 *
 * @param request what request to get information about
 * @param info_type what information is desired?
 * @param[out] return_value pointer to union where requested information will
 *                          be stored
 * @param return_value_size size of union MHD_DaemonInformation at compile
 *                          time
 * @return #MHD_YES on success, #MHD_NO on error
 *         (@a info_type is unknown, NULL pointer etc.)
 * @ingroup specialized
 */
_MHD_EXTERN enum MHD_Bool
MHD_request_get_information_sz (struct MHD_Request *request,
			        enum MHD_RequestInformationType info_type,
			        union MHD_RequestInformation *return_value,
			        size_t return_value_size);


/**
 * Obtain information about the given request.
 *
 * @param request what request to get information about
 * @param info_type what information is desired?
 * @param[out] return_value pointer to union where requested information will
 *                          be stored
 * @return #MHD_YES on success, #MHD_NO on error
 *         (@a info_type is unknown, NULL pointer etc.)
 * @ingroup specialized
 */
#define MHD_request_get_information (request,      \
                                     info_type,    \
                                     return_value) \
        MHD_request_get_information_sz ((request), (info_type), (return_value), sizeof(union MHD_RequestInformation))


/**
 * Values of this enum are used to specify what
 * information about a deamon is desired.
 */
enum MHD_DaemonInformationType
{

  /**
   * Request the file descriptor for the listening socket.
   * No extra arguments should be passed.
   */
  MHD_DAEMON_INFORMATION_LISTEN_FD,

  /**
   * Request the file descriptor for the external epoll.
   * No extra arguments should be passed.
   */
  MHD_DAEMON_INFORMATION_EPOLL_FD,

  /**
   * Request the number of current connections handled by the daemon.
   * No extra arguments should be passed.
   * Note: when using MHD in external polling mode, this type of request
   * could be used only when #MHD_run()/#MHD_run_from_select is not
   * working in other thread at the same time.
   */
  MHD_DAEMON_INFORMATION_CURRENT_CONNECTIONS,

  /**
   * Request the port number of daemon's listen socket.
   * No extra arguments should be passed.
   * Note: if port '0' was specified for #MHD_option_port(), returned
   * value will be real port number.
   */
  MHD_DAEMON_INFORMATION_BIND_PORT
};


/**
 * Information about an MHD daemon.
 */
union MHD_DaemonInformation
{

  /**
   * Socket, returned for #MHD_DAEMON_INFORMATION_LISTEN_FD.
   */
  MHD_socket listen_fd;

  /**
   * Bind port number, returned for #MHD_DAEMON_INFORMATION_BIND_PORT.
   */
  uint16_t port;

  /**
   * epoll FD, returned for #MHD_DAEMON_INFORMATION_EPOLL_FD.
   */
  int epoll_fd;

  /**
   * Number of active connections, for #MHD_DAEMON_INFORMATION_CURRENT_CONNECTIONS.
   */
  unsigned int num_connections;

};


/**
 * Obtain information about the given daemon.
 * Use wrapper macro #MHD_daemon_get_information() instead of direct use
 * of this function.
 *
 * @param daemon what daemon to get information about
 * @param info_type what information is desired?
 * @param[out] return_value pointer to union where requested information will
 *                          be stored
 * @param return_value_size size of union MHD_DaemonInformation at compile
 *                          time
 * @return #MHD_YES on success, #MHD_NO on error
 *         (@a info_type is unknown, NULL pointer etc.)
 * @ingroup specialized
 */
_MHD_EXTERN enum MHD_Bool
MHD_daemon_get_information_sz (struct MHD_Daemon *daemon,
			       enum MHD_DaemonInformationType info_type,
			       union MHD_DaemonInformation *return_value,
			       size_t return_value_size);

/**
 * Obtain information about the given daemon.
 *
 * @param daemon what daemon to get information about
 * @param info_type what information is desired?
 * @param[out] return_value pointer to union where requested information will
 *                          be stored
 * @return #MHD_YES on success, #MHD_NO on error
 *         (@a info_type is unknown, NULL pointer etc.)
 * @ingroup specialized
 */
#define MHD_daemon_get_information(daemon,       \
                                   info_type,    \
                                   return_value) \
	MHD_daemon_get_information_sz((daemon), (info_type), (return_value), sizeof(union MHD_DaemonInformation));
