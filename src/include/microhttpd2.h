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
 * - keep the API very simple for simple requests, but allow
 *   more complex logic to be incrementally introduced
 *   (via new struct MHD_Action construction)
 * - avoid repeated scans for URL matches via the new
 *   struct MHD_Action construction
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
 * - make it impossible to queue a response at the wrong time
 * - make it impossible to suspend a connection/request at the
 *   wrong time (improves thread-safety)
 * - make it clear which response status codes are "properly"
 *   supported (include the descriptive string) by using an enum;
 * - simplify API for common-case of one-shot responses by
 *   eliminating need for destroy response in most cases;
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
   * MHD-internal return code for "YES".  All non-zero values
   * will be interpreted as "YES", but MHD will only ever
   * return #MHD_YES or #MHD_NO.
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
 * Return values for reporting errors, also used
 * for logging.
 *
 * A value of 0 indicates success (as a return value).
 * Values between 1 and 10000 must not be used.
 * Values from 10000-19999 are informational.
 * Values from 20000-29999 indicate successful operations.
 * Values from 30000-39999 indicate unsuccessful (normal) operations.
 * Values from 40000-49999 indicate client errors.
 * Values from 50000-59999 indicate server errors.
 */
enum MHD_StatusCode
{

  /**
   * Successful operation (not used for logging).
   */
  MHD_SC_OK = 0,

  /**
   * Informational event, MHD started.
   */
  MHD_SC_DAEMON_STARTED = 10000,

  /**
   * This build of MHD does not support TLS, but the application
   * requested TLS.
   */
  MHD_TLS_DISABLED = 50000,

  /**
   * The application requested an unsupported TLS backend to be used.
   */
  MHD_TLS_BACKEND_UNSUPPORTED = 50001,

  /**
   * The application requested a TLS cipher suite which is not
   * supported by the selected backend.
   */
  MHD_TLS_CIPHERS_INVALID = 50002

};


/**
 * Actions are returned by the application to drive the request
 * handling of MHD.
 */
struct MHD_Action;


/**
 * HTTP methods explicitly supported by MHD.  Note that for
 * non-canonical methods, MHD will return #MHD_METHOD_UNKNOWN
 * and you can use #MHD_REQUEST_INFORMATION_HTTP_METHOD to get
 * the original string.
 *
 * However, applications must check for "#MHD_METHOD_UNKNOWN" *or* any
 * enum-value above those in this list, as future versions of MHD may
 * add additional methods (as per IANA registry), thus even if the API
 * returns "unknown" today, it may return a method-specific header in
 * the future!
 */
enum MHD_Method
{

  /**
   * Method did not match any of the methods given below.
   */
  MHD_METHOD_UNKNOWN = 0,

  /**
   * "OPTIONS" method.
   */
  MHD_METHOD_OPTIONS = 1,

  /**
   * "GET" method.
   */
  MHD_METHOD_GET = 2,

  /**
   * "HEAD" method.
   */
  MHD_METHOD_HEAD = 3,

  /**
   * "POST" method.
   */
  MHD_METHOD_POST = 4,

  /**
   * "PUT" method.
   */
  MHD_METHOD_PUT = 5,

  /**
   * "DELETE" method.
   */
  MHD_METHOD_DELETE = 6,

  /**
   * "TRACE" method.
   */
  MHD_METHOD_TRACE = 7,

  /**
   * "CONNECT" method.
   */
  MHD_METHOD_CONNECT = 8,
  
  /**
   * "ACL" method.
   */
  MHD_METHOD_ACL = 9,
  
  /**
   * "BASELINE-CONTROL" method.
   */
  MHD_METHOD_BASELINE_CONTROL = 10,
  
  /**
   * "BIND" method.
   */
  MHD_METHOD_BIND = 11,
  
  /**
   * "CHECKIN" method.
   */
  MHD_METHOD_CHECKIN = 12,
  
  /**
   * "CHECKOUT" method.
   */
  MHD_METHOD_CHECKOUT = 13,
  
  /**
   * "COPY" method.
   */
  MHD_METHOD_COPY = 14,
  
  /**
   * "LABEL" method.
   */
  MHD_METHOD_LABEL = 15,
  
  /**
   * "LINK" method.
   */
  MHD_METHOD_LINK = 16,
  
  /**
   * "LOCK" method.
   */
  MHD_METHOD_LOCK = 17,
  
  /**
   * "MERGE" method.
   */
  MHD_METHOD_MERGE = 18,
  
  /**
   * "MKACTIVITY" method.
   */
  MHD_METHOD_MKACTIVITY = 19,
  
  /**
   * "MKCOL" method.
   */
  MHD_METHOD_MKCOL = 20,
  
  /**
   * "MKREDIRECTREF" method.
   */
  MHD_METHOD_MKREDIRECTREF = 21,
  
  /**
   * "MKWORKSPACE" method.
   */
  MHD_METHOD_MKWORKSPACE = 22,
  
  /**
   * "MOVE" method.
   */
  MHD_METHOD_MOVE = 23,
  
  /**
   * "ORDERPATCH" method.
   */
  MHD_METHOD_ORDERPATCH = 24,
  
  /**
   * "PATCH" method.
   */
  MHD_METHOD_PATH = 25,
  
  /**
   * "PRI" method.
   */
  MHD_METHOD_PRI = 26,
  
  /**
   * "PROPFIND" method.
   */
  MHD_METHOD_PROPFIND = 27,
  
  /**
   * "PROPPATCH" method.
   */
  MHD_METHOD_PROPPATCH = 28,
  
  /**
   * "REBIND" method.
   */
  MHD_METHOD_REBIND = 29,
  
  /**
   * "REPORT" method.
   */
  MHD_METHOD_REPORT = 30,
  
  /**
   * "SEARCH" method.
   */
  MHD_METHOD_SEARCH = 31,
  
  /**
   * "UNBIND" method.
   */
  MHD_METHOD_UNBIND = 32,
  
  /**
   * "UNCHECKOUT" method.
   */
  MHD_METHOD_UNCHECKOUT = 33,
  
  /**
   * "UNLINK" method.
   */
  MHD_METHOD_UNLINK = 34,
  
  /**
   * "UNLOCK" method.
   */
  MHD_METHOD_UNLOCK = 35,
  
  /**
   * "UPDATE" method.
   */
  MHD_METHOD_UPDATE = 36,
  
  /**
   * "UPDATEDIRECTREF" method.
   */
  MHD_METHOD_UPDATEDIRECTREF = 37,
  
  /**
   * "VERSION-CONTROL" method.
   */
  MHD_METHOD_VERSION_CONTROL = 38

  /* For more, check: 
     https://www.iana.org/assignments/http-methods/http-methods.xhtml */

};


/**
 * A client has requested the given url using the given method
 * (#MHD_HTTP_METHOD_GET, #MHD_HTTP_METHOD_PUT,
 * #MHD_HTTP_METHOD_DELETE, #MHD_HTTP_METHOD_POST, etc).  The callback
 * must initialize @a rhp to provide further callbacks which will
 * process the request further and ultimately to provide the response
 * to give back to the client, or return #MHD_NO.
 *
 * @param cls argument given together with the function
 *        pointer when the handler was registered with MHD
 * @param url the requested url (without arguments after "?")
 * @param method the HTTP method used (#MHD_HTTP_METHOD_GET,
 *        #MHD_HTTP_METHOD_PUT, etc.)
 * @return action how to proceed, NULL
 *         if the socket must be closed due to a serios
 *         error while handling the request
 */
typedef struct MHD_Action *
(*MHD_RequestCallback) (void *cls,
			struct MHD_Request *request,
			const char *url,
			enum MHD_Method method);


/**
 * Create (but do not yet start) an MHD daemon.
 * Usually, you will want to set various options before
 * starting the daemon with #MHD_daemon_start().
 *
 * @param cb function to be called for incoming requests
 * @param cb_cls closure for @a cb
 */
struct MHD_Daemon *
MHD_daemon_create (MHD_RequestCallback cb,
		   void *cb_cls);


/**
 * Start a webserver.
 *
 * @param daemon daemon to start; you can no longer set
 *        options on this daemon after this call!
 * @return #MHD_SC_OK on success
 * @ingroup event
 */
_MHD_EXTERN enum MHD_StatusCode
MHD_daemon_start (struct MHD_Daemon *daemon);


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
 *         the daemon was already not listening anymore, or
 *         was never started
 * @ingroup specialized
 */
_MHD_EXTERN MHD_socket
MHD_daemon_quiesce (struct MHD_Daemon *daemon);


/**
 * Shutdown and destroy an HTTP daemon.
 *
 * @param daemon daemon to stop
 * @ingroup event
 */
_MHD_EXTERN void
MHD_daemon_destroy (struct MHD_Daemon *daemon);


/* ********************* daemon options ************** */


/**
 * Type of a callback function used for logging by MHD.
 *
 * @param cls closure
 * @param sc status code of the event
 * @param fm format string (`printf()`-style)
 * @param ap arguments to @a fm
 * @ingroup logging
 */
typedef void
(*MHD_LoggingCallback)(void *cls,
		       enum MHD_StatusCode sc,
		       const char *fm,
		       va_list ap);


/**
 * Set logging method.  Specify NULL to disable logging entirely.  By
 * default (if this option is not given), we log error messages to
 * stderr.
 *
 * @param daemon which instance to setup logging for
 * @param logger function to invoke
 * @param logger_cls closure for @a logger
 */
_MHD_EXTERN void
MHD_daemon_set_logger (struct MHD_Daemon *daemon,
		       MHD_LoggingCallback logger,
		       void *logger_cls);


/**
 * Convenience macro used to disable logging.
 *
 * @param daemon which instance to disable logging for
 */
#define MHD_daemon_disable_logging(daemon) MHD_daemon_set_logger (daemon, NULL, NULL)


/**
 * Suppress use of "Date" header as this system has no RTC.
 *
 * @param daemon which instance to disable clock for.
 */
_MHD_EXTERN void
MHD_daemon_suppress_date_no_clock (struct MHD_Daemon *daemon);


/**
 * Disable use of inter-thread communication channel.
 * #MHD_daemon_disable_itc() can be used with
 * #MHD_daemon_thread_internal() to perform some additional
 * optimizations (in particular, not creating a pipe for IPC
 * signalling).  If it is used, certain functions like
 * #MHD_daemon_quiesce() or #MHD_connection_add() or
 * #MHD_action_suspend() cannot be used anymore.
 * #MHD_daemon_disable_itc() is not beneficial on platforms where
 * select()/poll()/other signal shutdown() of a listen socket.
 *
 * You should only use this function if you are sure you do
 * satisfy all of its requirements and need a generally minor
 * boost in performance.
 *
 * @param daemon which instance to disable itc for
 */
_MHD_EXTERN void
MHD_daemon_disable_itc (struct MHD_Daemon *daemon);


/**
 * Enable `turbo`.  Disables certain calls to `shutdown()`,
 * enables aggressive non-blocking optimistic reads and
 * other potentially unsafe optimizations.
 * Most effects only happen with #MHD_ELS_EPOLL.
 *
 * @param daemon which instance to enable turbo for
 */
_MHD_EXTERN void
MHD_daemon_enable_turbo (struct MHD_Daemon *daemon);


/**
 * Disable #MHD_action_suspend() functionality.
 *
 * You should only use this function if you are sure you do
 * satisfy all of its requirements and need a generally minor
 * boost in performance.
 *
 * @param daemon which instance to disable suspend for
 */
_MHD_EXTERN void
MHD_daemon_disallow_suspend_resume (struct MHD_Daemon *daemon);


/**
 * You need to set this option if you want to disable use of HTTP "Upgrade".
 * "Upgrade" may require usage of additional internal resources,
 * which we can avoid providing if they will not be used.
 *
 * You should only use this function if you are sure you do
 * satisfy all of its requirements and need a generally minor
 * boost in performance.
 *
 * @param daemon which instance to enable suspend/resume for
 */
_MHD_EXTERN void
MHD_daemon_disallow_upgrade (struct MHD_Daemon *daemon);


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
   * If TCP_FASTOPEN is not available, return #MHD_NO.
   * Also causes #MHD_daemon_start() to fail if setting
   * the option fails later.
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
 * @param daemon which instance to configure TCP_FASTOPEN for
 * @param fom under which conditions should we use TCP_FASTOPEN?
 * @param queue_length queue length to use, default is 50 if this
 *        option is never given.
 * @return #MHD_YES upon success, #MHD_NO if #MHD_FOM_REQUIRE was
 *         given, but TCP_FASTOPEN is not available on the platform
 */
_MHD_EXTERN enum MHD_Bool
MHD_daemon_tcp_fastopen (struct MHD_Daemon *daemon,
			 enum MHD_FastOpenMethod fom,
			 unsigned int queue_length);


/**
 * Address family to be used by MHD.
 */
enum MHD_AddressFamily
{
  /**
   * Pick "best" available method automatically.
   */
  MHD_AF_AUTO,

  /**
   * Use IPv4.
   */
  MHD_AF_INET4,

  /**
   * Use IPv6.
   */
  MHD_AF_INET6,

  /**
   * Use dual stack.
   */
  MHD_AF_DUAL
};


/**
 * Bind to the given TCP port and address family.
 *
 * Ineffective in conjunction with #MHD_daemon_listen_socket().
 * Ineffective in conjunction with #MHD_daemon_bind_sa().
 *
 * If neither this option nor the other two mentioned above
 * is specified, MHD will simply not listen on any socket!
 *
 * @param daemon which instance to configure the TCP port for
 * @param af address family to use, i.e. #AF_INET or #AF_INET6,
 *           or #AF_UNSPEC for dual stack
 * @param port port to use, 0 to bind to a random (free) port
 */
_MHD_EXTERN void
MHD_daemon_bind_port (struct MHD_Daemon *daemon,
		      enum MHD_AddressFamily af,
		      uint16_t port);


/**
 * Bind to the given socket address.
 * Ineffective in conjunction with #MHD_daemon_listen_socket().
 *
 * @param daemon which instance to configure the binding address for
 * @param sa address to bind to; can be IPv4 (AF_INET), IPv6 (AF_INET6)
 *        or even a UNIX domain socket (AF_UNIX)
 * @param sa_len number of bytes in @a sa
 */
_MHD_EXTERN void
MHD_daemon_bind_socket_address (struct MHD_Daemon *daemon,
				const struct sockaddr *sa,
				size_t sa_lem);


/**
 * Use the given backlog for the listen() call.
 * Ineffective in conjunction with #MHD_daemon_listen_socket().
 *
 * @param daemon which instance to configure the backlog for
 * @param listen_backlog backlog to use
 */
_MHD_EXTERN void
MHD_daemon_listen_queue (struct MHD_Daemon *daemon,
			 int listen_backlog);


/**
 * If present true, allow reusing address:port socket (by using
 * SO_REUSEPORT on most platform, or platform-specific ways).  If
 * present and set to false, disallow reusing address:port socket
 * (does nothing on most plaform, but uses SO_EXCLUSIVEADDRUSE on
 * Windows).
 * Ineffective in conjunction with #MHD_daemon_listen_socket().
 *
 * @param daemon daemon to configure address reuse for
 */
_MHD_EXTERN void
MHD_daemon_listen_allow_address_reuse (struct MHD_Daemon *daemon);


/**
 * Accept connections from the given socket.  Socket
 * must be a TCP or UNIX domain (stream) socket.
 *
 * Unless -1 is given, this disables other listen options, including
 * #MHD_daemon_bind_sa(), #MHD_daemon_bind_port(),
 * #MHD_daemon_listen_queue() and
 * #MHD_daemon_listen_allow_address_reuse().
 *
 * @param daemon daemon to set listen socket for
 * @param listen_socket listen socket to use,
 *        MHD_INVALID_SOCKET value will cause this call to be
 *        ignored (other binding options may still be effective)
 */
_MHD_EXTERN void
MHD_daemon_listen_socket (struct MHD_Daemon *daemon,
			  MHD_socket listen_socket);


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
 * @param daemon daemon to set event loop style for
 * @param els event loop syscall to use
 * @return #MHD_NO on failure, #MHD_YES on success
 */
_MHD_EXTERN enum MHD_Bool
MHD_daemon_event_loop (struct MHD_Daemon *daemon,
		       enum MHD_EventLoopSyscall els);


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
  MHD_PSL_PERMISSIVE = -1,

  /**
   * Sane level of protocol enforcement for production use.
   */
  MHD_PSL_DEFAULT = 0,

  /**
   * Be strict about the protocol (as opposed to as tolerant as
   * possible).  Specifically, at the moment, this flag causes MHD to
   * reject HTTP 1.1 connections without a "Host" header.  This is
   * required by the standard, but of course in violation of the "be
   * as liberal as possible in what you accept" norm.  It is
   * recommended to set this if you are testing clients against
   * MHD, and to use default in production.
   */
  MHD_PSL_STRICT = 1
};


/**
 * Set how strictly MHD will enforce the HTTP protocol.
 *
 * @param daemon daemon to configure strictness for
 * @param sl how strict should we be
 */
_MHD_EXTERN void
MHD_daemon_protocol_strict_level (struct MHD_Daemon *daemon,
				  enum MHD_ProtocolStrictLevel sl);


/**
 * Enable and configure TLS.
 *
 * @param daemon which instance should be configured
 * @param tls_backend which TLS backend should be used,
 *    currently only "gnutls" is supported.  You can
 *    also specify "NULL" for best-available (which is the default).
 * @param ciphers which ciphers should be used by TLS, default is
 *     "NORMAL"
 * @return status code, #MHD_SC_OK upon success
 *     #MHD_TLS_BACKEND_UNSUPPORTED if the @a backend is unknown
 *     #MHD_TLS_DISABLED if this build of MHD does not support TLS
 *     #MHD_TLS_CIPHERS_INVALID if the given @a ciphers are not supported
 *     by this backend
 */
_MHD_EXTERN enum MHD_StatusCode
MHD_daemon_set_tls_backend (struct MHD_Daemon *daemon,
			    const char *tls_backend,
			    const char *ciphers);


/**
 * Provide TLS key and certificate data in-memory.
 *
 * @param daemon which instance should be configured
 * @param mem_key private key (key.pem) to be used by the
 *     HTTPS daemon.  Must be the actual data in-memory, not a filename.
 * @param mem_cert certificate (cert.pem) to be used by the
 *     HTTPS daemon.  Must be the actual data in-memory, not a filename.
 * @param pass passphrase phrase to decrypt 'key.pem', NULL
 *     if @param mem_key is in cleartext already
 * @return #MHD_SC_OK upon success; TODO: define failure modes
 */
_MHD_EXTERN enum MHD_StatusCode
MHD_daemon_tls_key_and_cert_from_memory (struct MHD_Daemon *daemon,
					 const char *mem_key,
					 const char *mem_cert,
					 const char *pass);


/**
 * Configure DH parameters (dh.pem) to use for the TLS key
 * exchange.
 *
 * @param daemon daemon to configure tls for
 * @param dh parameters to use
 * @return #MHD_SC_OK upon success; TODO: define failure modes
 */
_MHD_EXTERN enum MHD_StatusCode
  MHD_daemon_tls_mem_dhparams (struct MHD_Daemon *daemon,
			       const char *dh);


/**
 * Memory pointer for the certificate (ca.pem) to be used by the
 * HTTPS daemon for client authentification.
 *
 * @param daemon daemon to configure tls for
 * @param mem_trust memory pointer to the certificate
 * @return #MHD_SC_OK upon success; TODO: define failure modes
 */
_MHD_EXTERN enum MHD_StatusCode
MHD_daemon_tls_mem_trust (struct MHD_Daemon *daemon,
			  const char *mem_trust);


/**
 * Configure daemon credentials type for GnuTLS.
 *
 * @param gnutls_credentials must be a value of
 *   type `gnutls_credentials_type_t`
 * @return #MHD_SC_OK upon success; TODO: define failure modes
 */
_MHD_EXTERN enum MHD_StatusCode
MHD_daemon_gnutls_credentials (struct MHD_Daemon *daemon,
			       int gnutls_credentials);


/**
 * Provide TLS key and certificate data via callback.
 *
 * Use a callback to determine which X.509 certificate should be used
 * for a given HTTPS connection.  This option provides an alternative
 * to #MHD_daemon_tls_key_and_cert_from_memory().  You must use this
 * version if multiple domains are to be hosted at the same IP address
 * using TLS's Server Name Indication (SNI) extension.  In this case,
 * the callback is expected to select the correct certificate based on
 * the SNI information provided.  The callback is expected to access
 * the SNI data using `gnutls_server_name_get()`.  Using this option
 * requires GnuTLS 3.0 or higher.
 *
 * @param daemon daemon to configure callback for
 * @param cb must be of type `gnutls_certificate_retrieve_function2 *`.
 */
_MHD_EXTERN void
MHD_daemon_gnutls_key_and_cert_from_callback (struct MHD_Daemon *daemon,
					      void *cb);


/**
 * Which threading model should be used by MHD?
 */
enum MHD_ThreadingModel
{

  /**
   * MHD should create its own thread for listening and furthermore
   * create another thread per connection to handle requests.  Use
   * this if handling requests is CPU-intensive or blocking, your
   * application is thread-safe and you have plenty of memory (per
   * request).
   */
  MHD_TM_THREAD_PER_CONNECTION = -1,

  /**
   * Use an external event loop. This is the default.
   */
  MHD_TM_EXTERNAL_EVENT_LOOP = 0,

  /**
   * Run with one or more worker threads.  Any positive value
   * means that MHD should start that number of worker threads
   * (so > 1 is a thread pool) and distributed processing of
   * requests among the workers.
   *
   * A good way to express the use of a thread pool
   * in your code would be to write "MHD_TM_THREAD_POOL(4)"
   * to indicate four threads.
   *
   * If a positive value is set, * #MHD_daemon_run() and
   * #MHD_daemon_run_from_select() cannot be used.
   */
  MHD_TM_WORKER_THREADS = 1

};


/**
 * Use a thread pool of size @a n.
 *
 * @return an `enum MHD_ThreadingModel` for a thread pool of size @a n
 */
#define MHD_TM_THREAD_POOL(n) ((enum MHD_ThreadingModel)(n))


/**
 * Specify threading model to use.
 *
 * @param daemon daemon to configure
 * @param tm model to use (positive values indicate the
 *        number of worker threads to be used)
 */
_MHD_EXTERN void
MHD_daemon_threading_model (struct MHD_Daemon *daemon,
			    enum MHD_ThreadingModel tm);


/**
 * Allow or deny a client to connect.
 *
 * @param cls closure
 * @param addr address information from the client
 * @param addrlen length of @a addr
 * @see #MHD_daemon_accept_policy()
 * @return #MHD_YES if connection is allowed, #MHD_NO if not
 */
typedef enum MHD_Bool
(*MHD_AcceptPolicyCallback) (void *cls,
                             const struct sockaddr *addr,
                             size_t addrlen);


/**
 * Set  a policy callback that accepts/rejects connections
 * based on the client's IP address.  This function will be called
 * before a connection object is created.
 *
 * @param daemon daemon to set policy for
 * @param apc function to call to check the policy
 * @param apc_cls closure for @a apc
 */
_MHD_EXTERN void
MHD_daemon_accept_policy (struct MHD_Daemon *daemon,
			  MHD_AcceptPolicyCallback apc,
			  void *apc_cls);


/**
 * Function called by MHD to allow the application to log
 * the full @a uri of a @a request.
 *
 * @param cls client-defined closure
 * @param uri the full URI from the HTTP request
 * @param request the HTTP request handle (headers are
 *         not yet available)
 * @return value to set for the "request_context" of @a request
 */
typedef void *
(MHD_EarlyUriLogCallback)(void *cls,
			  const char *uri,
			  struct MHD_Request *request);


/**
 * Register a callback to be called first for every request
 * (before any parsing of the header).  Makes it easy to 
 * log the full URL.
 *
 * @param daemon daemon for which to set the logger
 * @param cb function to call
 * @param cb_cls closure for @a cb
 */
_MHD_EXTERN void
MHD_daemon_set_early_uri_logger (struct MHD_Daemon *daemon,
				 MHD_EarlyUriLogCallback cb,
				 void *cb_cls);


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
 * @param daemon daemon to set callback for
 * @param ncc function to call to check the policy
 * @param ncc_cls closure for @a apc
 * @param ccc function to call upon completion, NULL for none
 * @param ccc_cls closure for @a ccc
 */
_MHD_EXTERN void
MHD_daemon_set_notify_connection (struct MHD_Daemon *daemon,
				  MHD_NotifyConnectionCallback ncc,
				  void *ncc_cls);


/**
 * Maximum memory size per connection (followed by a `size_t`).
 * Default is 32 kb (#MHD_POOL_SIZE_DEFAULT).
 * Values above 128k are unlikely to result in much benefit, as half
 * of the memory will be typically used for IO, and TCP buffers are
 * unlikely to support window sizes above 64k on most systems.
 *
 * @param daemon daemon to configure
 * @param memory_limit_b connection memory limit to use in bytes
 * @param memory_increment_b increment to use when growing the read buffer, must be smaller than @a memory_limit_b
 */
_MHD_EXTERN void
MHD_daemon_connection_memory_limit (struct MHD_Daemon *daemon,
				    size_t memory_limit_b,
				    size_t memory_increment_b);


/**
 * Desired size of the stack for threads created by MHD.  Use 0 for
 * system default.  Only useful if the selected threading model
 * is not #MHD_TM_EXTERNAL_EVENT_LOOP.
 *
 * @param daemon daemon to configure
 * @param stack_limit_b stack size to use in bytes
 */
_MHD_EXTERN void
MHD_daemon_thread_stack_size (struct MHD_Daemon *daemon,
			      size_t stack_limit_b);


/**
 * Set maximum number of concurrent connections to accept.  If not
 * given, MHD will not enforce any limits (modulo running into
 * OS limits).  Values of 0 mean no limit.
 *
 * @param daemon daemon to configure
 * @param global_connection_limit maximum number of (concurrent)
          connections
 * @param ip_connection_limit limit on the number of (concurrent)
 *        connections made to the server from the same IP address.
 *        Can be used to prevent one IP from taking over all of
 *        the allowed connections.  If the same IP tries to
 *        establish more than the specified number of
 *        connections, they will be immediately rejected.
 */
_MHD_EXTERN void
MHD_daemon_connection_limits (struct MHD_Daemon *daemon,
			      unsigned int global_connection_limit,
			      unsigned int ip_connection_limit);


/**
 * After how many seconds of inactivity should a
 * connection automatically be timed out?
 * Use zero for no timeout, which is also the (unsafe!) default.
 *
 * @param daemon daemon to configure
 * @param timeout_s number of seconds of timeout to use
 */
_MHD_EXTERN void
MHD_daemon_connection_default_timeout (struct MHD_Daemon *daemon,
				       unsigned int timeout_s);


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
 * @param daemon daemon to configure
 * @param unescape_cb function to use, NULL for default
 * @param unescape_cb_cls closure for @a unescape_cb
 */
_MHD_EXTERN void
MHD_daemon_unescape_cb (struct MHD_Daemon *daemon,
			MHD_UnescapeCallback unescape_cb,
			void *unescape_cb_cls);


/**
 * Set random values to be used by the Digest Auth module.  Note that
 * the application must ensure that @a buf remains allocated and
 * unmodified while the deamon is running.
 *
 * @param daemon daemon to configure
 * @param buf_size number of bytes in @a buf
 * @param buf entropy buffer
 */
_MHD_EXTERN void
MHD_daemon_digest_auth_random (struct MHD_Daemon *daemon,
			       size_t buf_size,
			       const void *buf);


/**
 * Size of the internal array holding the map of the nonce and
 * the nonce counter.
 *
 * @param daemon daemon to configure
 * @param nc_length desired array length
 */
_MHD_EXTERN void
MHD_daemon_digest_auth_nc_size (struct MHD_Daemon *daemon,
				size_t stack_limit_b);


/* ********************* connection options ************** */


/**
 * Generate option to set a custom timeout for the given connection.
 * Specified as the number of seconds.  Use zero for no timeout.  If
 * timeout was set to zero (or unset) before, setting of a new value
 * by MHD_connection_set_option() will reset timeout timer.
 *
 * @param connection connection to configure timeout for
 * @param timeout_s new timeout in seconds
 */
struct MHD_ConnectionOption
MHD_connection_timeout (struct MHD_Connection *connection,
			unsigned int timeout_s);


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
  MHD_HTTP_SWITCH_PROXY = 306, /* IANA: unused */
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
  MHD_HTTP_UNORDERED_COLLECTION = 425, /* IANA: unused */
  MHD_HTTP_UPGRADE_REQUIRED = 426,

  MHD_HTTP_PRECONDITION_REQUIRED = 428,
  MHD_HTTP_TOO_MANY_REQUESTS = 429,
  MHD_HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE = 431,

  MHD_HTTP_NO_RESPONSE = 444, /* IANA: unused */

  MHD_HTTP_RETRY_WITH = 449, /* IANA: unused */
  MHD_HTTP_BLOCKED_BY_WINDOWS_PARENTAL_CONTROLS = 450,  /* IANA: unused */
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
  MHD_HTTP_BANDWIDTH_LIMIT_EXCEEDED = 509,  /* IANA: unused */
  MHD_HTTP_NOT_EXTENDED = 510,
  MHD_HTTP_NETWORK_AUTHENTICATION_REQUIRED = 511

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
 * The only safe time to suspend a request is from either a
 * #MHD_RequestHeaderCallback, #MHD_UploadCallback, or a
 * #MHD_RequestfetchResponseCallback.  Suspending a request
 * at any other time will cause an assertion failure.
 *
 * Finally, it is an API violation to call #MHD_daemon_stop() while
 * having suspended requests (this will at least create memory and
 * socket leaks or lead to undefined behavior).  You must explicitly
 * resume all requests before stopping the daemon.
 *
 * @return action to cause a request to be suspended.
 */
_MHD_EXTERN struct MHD_Action *
MHD_action_suspend (void);


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
 * Converts a @a response to an action.  If @a consume
 * is set, the reference to the @a response is consumed
 * by the conversion. If @a consume is #MHD_NO, then
 * the response can be converted to actions in the future.
 * However, the @a response is frozen by this step and
 * must no longer be modified (i.e. by setting headers).
 *
 * @param response response to convert, not NULL
 * @param destroy_after_use should the response object be consumed?
 * @return corresponding action, never returns NULL
 *
 * Implementation note: internally, this is largely just
 * a cast (and possibly an RC increment operation),
 * as a response *is* an action.  As no memory is
 * allocated, this operation cannot fail.
 */
struct MHD_Action *
MHD_action_from_response (struct MHD_Response *response,
			  enum MHD_bool destroy_after_use);


/**
 * Only respond in conservative HTTP 1.0-mode.  In
 * particular, do not (automatically) sent "Connection" headers and
 * always close the connection after generating the response.
 *
 * @param request the request for which we force HTTP 1.0 to be used
 */
_MHD_EXTERN void
MHD_response_option_v10_only (struct MHD_Response *response);


/** 
 * Signature of the callback used by MHD to notify the
 * application about completed requests.
 *
 * @param cls client-defined closure
 * @param toe reason for request termination
 * @param request_context request context value, as originally
 *         returned by the #MHD_EarlyUriLogCallback
 * @see #MHD_option_request_completion()
 * @ingroup request
 */
typedef void
(*MHD_RequestTerminationCallback) (void *cls,
				   enum MHD_RequestTerminationCode toe,
				   void *request_context);


/**
 * Set a function to be called once MHD is finished with the
 * request.
 *
 * @param response which response to set the callback for
 * @param termination_cb function to call
 * @param termination_cb_cls closure for @e termination_cb
 */
void
MHD_response_option_termination_callback (struct MHD_Response *response,
					  MHD_RequestTerminationCallback termination_cb,
					  void *termination_cb_cls);


/**
 * Create a response action.  The response object can be extended with
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
 * Enumeration for operations MHD should perform on the underlying socket
 * of the upgrade.  This API is not finalized, and in particular
 * the final set of actions is yet to be decided. This is just an
 * idea for what we might want.
 */
enum MHD_UpgradeOperation
{

  /**
   * Close the socket, the application is done with it.
   *
   * Takes no extra arguments.
   */
  MHD_UPGRADE_OPERATION_CLOSE = 0

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
 * @param operation which operation should be performed
 * @param ... arguments to the action (depends on the action)
 * @return #MHD_NO on error, #MHD_YES on success
 */
_MHD_EXTERN enum MHD_Bool
MHD_upgrade_operation (struct MHD_UpgradeResponseHandle *urh,
		       enum MHD_UpgradeOperation operation,
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
 * Explicitly decrease reference counter of a response object.  If the
 * counter hits zero, destroys a response object and associated
 * resources.  Usually, this is implicitly done by converting a
 * response to an action and returning the action to MHD.
 *
 * @param response response to decrement RC of
 * @ingroup response
 */
_MHD_EXTERN void
MHD_response_queue_for_destroy (struct MHD_Response *response);


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
 * Add a tailer line to the response.
 *
 * @param response response to add a footer to
 * @param footer the footer to add
 * @param content value to add
 * @return #MHD_NO on error (i.e. invalid footer or content format),
 *         or out of memory
 * @ingroup response
 */
_MHD_EXTERN enum MHD_Bool
MHD_response_add_trailer (struct MHD_Response *response,
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


/* ************Upload and PostProcessor functions ********************** */

/**
 * Action telling MHD to continue processing the upload.
 *
 * @return action operation, never NULL
 */
_MHD_EXTERN struct MHD_Action *
MHD_action_continue (void);


/**
 * Function to process data uploaded by a client.
 *
 * @param cls argument given together with the function
 *        pointer when the handler was registered with MHD
 * @param upload_data the data being uploaded (excluding headers)
 *        POST data will typically be made available incrementally via
 *        multiple callbacks
 * @param[in,out] upload_data_size set initially to the size of the
 *        @a upload_data provided; the method must update this
 *        value to the number of bytes NOT processed;
 * @return action specifying how to proceed, often
 *         #MHD_action_continue() if all is well,
 *         #MHD_action_suspend() to stop reading the upload until
 *              the request is resumed,
 *         NULL to close the socket, or a response
 *         to discard the rest of the upload and return the data given
 */
typedef struct MHD_Action *
(*MHD_UploadCallback) (void *cls,
		       const char *upload_data,
		       size_t *upload_data_size);


/**
 * Create an action that handles an upload.
 *
 * @param uc function to call with uploaded data
 * @param uc_cls closure for @a uc
 * @return NULL on error (out of memory)
 * @ingroup action
 */
_MHD_EXTERN struct MHD_Action *
MHD_action_process_upload (MHD_UploadCallback uc,
			   void *uc_cls);


/**
 * Iterator over key-value pairs where the value maybe made available
 * in increments and/or may not be zero-terminated.  Used for
 * MHD parsing POST data.  To access "raw" data from POST or PUT
 * requests, use #MHD_action_process_upload() instead.
 *
 * @param cls user-specified closure
 * @param kind type of the value, always #MHD_POSTDATA_KIND when called from MHD
 * @param key 0-terminated key for the value
 * @param filename name of the uploaded file, NULL if not known
 * @param content_type mime-type of the data, NULL if not known
 * @param transfer_encoding encoding of the data, NULL if not known
 * @param data pointer to @a size bytes of data at the
 *              specified offset
 * @param off offset of data in the overall value
 * @param size number of bytes in @a data available
 * @return action specifying how to proceed, often
 *         #MHD_action_continue() if all is well,
 *         #MHD_action_suspend() to stop reading the upload until
 *              the request is resumed,
 *         NULL to close the socket, or a response
 *         to discard the rest of the upload and return the data given
 */
typedef struct MHD_Action *
(*MHD_PostDataIterator) (void *cls,
                         enum MHD_ValueKind kind,
                         const char *key,
                         const char *filename,
                         const char *content_type,
                         const char *transfer_encoding,
                         const char *data,
                         uint64_t off,
                         size_t size);


/**
 * Create an action that parses a POST request.
 *
 * This action can be used to (incrementally) parse the data portion
 * of a POST request.  Note that some buggy browsers fail to set the
 * encoding type.  If you want to support those, you may have to call
 * #MHD_set_connection_value with the proper encoding type before
 * returning this action (if no supported encoding type is detected,
 * returning this action will cause a bad request to be returned to
 * the client).
 *
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
_MHD_EXTERN struct MHD_Action *
MHD_action_parse_post (size_t buffer_size,
		       MHD_PostDataIterator iter,
		       void *iter_cls);



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
 * @param return_value_size size of union MHD_ConnectionInformation at compile
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
        MHD_connection_get_information_sz ((connection),(info_type),(return_value),sizeof(union MHD_ConnectionInformation))


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
   * Socket-specific client context.  Will also be given to
   * the application in a #MHD_RequestTerminationCallback.
   */
  void *request_context;

  /**
   * The suspended status of a request.
   */
  enum MHD_Bool suspended;

  /**
   * HTTP version requested by the client.
   */
  const char *http_version;

  /**
   * HTTP method of the request, as a string.  Particularly useful if
   * #MHD_HTTP_METHOD_UNKNOWN was given.
   */
  const char *http_method;

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
   * Return the HTTP method used by the request.
   * @ingroup request
   */
  MHD_REQUEST_INFORMATION_HTTP_METHOD,

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
 * @param return_value_size size of union MHD_RequestInformation at compile
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
