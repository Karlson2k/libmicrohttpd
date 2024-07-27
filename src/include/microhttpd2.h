/*
     This file is part of libmicrohttpd
     Copyright (C) 2006-2024 Christian Grothoff, Karlson2k (Evgeny Grin)
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

/*
  Main goals for the libmicrohttpd 2.0 API:

  - simplify application callbacks by splitting header/upload/post
    functionality currently provided by calling the same
    MHD_AccessHandlerCallback 3+ times into separate callbacks.
  - keep the API very simple for simple requests, but allow
    more complex logic to be incrementally introduced
    (via new struct MHD_Action construction)
  - avoid repeated scans for URL matches via the new
    struct MHD_Action construction
  - better types, in particular avoid varargs for options
  - make it harder to pass inconsistent options
  - combine options and flags into more uniform API (at least
    exterally!)
  - simplify API use by using sane defaults (benefiting from
    breaking backwards compatibility) and making all options
    really optional, and where applicable avoid having options
    where the default works if nothing is specified
  - simplify API by moving rarely used http_version into
    MHD_request_get_info_fixed()
  - avoid 'int' for MHD_YES/MHD_NO by introducing `enum MHD_Bool`
  - improve terminology by eliminating confusion between
    'request' and 'connection'; add 'session' for HTTP2/3;
    use clear separation between connection and request. Do not mix the kind
    data in the callbacks.  Currently we are mixing things in
    MHD_AccessHandlerCallback and MHD_RequestCompletedCallback. Instead of
    pointers to struct MHD_Connection we should use pointers to (new) struct
    MHD_Request.
  - prepare API for having multiple TLS backends
  - use more consistent prefixes for related functions
    by using MHD_subject_verb_object naming convention, also
    at the same time avoid symbol conflict with legacy names
    (so we can have one binary implementing old and new
    library API at the same time via compatibility layer).
  - make it impossible to queue a response at the wrong time
  - make it impossible to suspend a connection/request at the
    wrong time (improves thread-safety)
  - make it clear which response status codes are "properly"
    supported (include the descriptive string) by using an enum;
  - simplify API for common-case of one-shot responses by
    eliminating need for destroy response in most cases;
  - avoid fixed types, like uint32_t. They may not exist on some
    platforms. Instead use uint_fast32_t.
    It is also better for future-proof.
  - check portability for embedded platforms. Some of them support
    64 bits, but 'int' could be just 16 bits resulting of silently
    dropping enum values higher than 65535.
    => in general, more functions, fewer enums for setup
  - Avoid returning pointers to internal members. It is not thread-safe and
    even in single thread the value could change over the time. Prefer pointers to
    app-allocated memory with the size, like MHD_daemon_get_static_info(enum
    MHD_enum_name info_type, void *buf, size_t buf_size).
    => Except in cases where zero-copy matters.
  - Use separate app calls/functions for data the will not change for the
    lifetime of the object and dynamic data. The only difference should be the
    name. Like MHD_daemon_get_static_info(enum MHD_enum_name info_type, void *buf,
    size_t buf_size) MHD_daemon_get_dynamic_info(enum MHD_enum_name info_type,
    void *buf, size_t buf_size) Examples of static data: listen socket, number of
    workers, daemon flags.  Examples of dynamic data: number of connections,
    quiesce status.  It should give a clear idea whether the data could be changed
    over the time (could be not obvious for some data) and thus may change the
    approach how to use the data in app.  The same for: library, daemon,
    connection, request. Not sure that dynamic data makes sense for the library.
  - Define response code in response object. There are a very little
    chance that response body designed for 404 or 403 codes will be used with
    200 code. However, the responses body for 307 and 308 could be the same. So:
    Add default response code in response object.
  - Make responses unmodifiable after first use. It is not thread-safe.
    MHD-generated headers (Date, Connection/Keep-Alive) are again
    part of the *request* and do not count as part of the "response" here.
  - Remove "footers" from responses. With unmodifiable responses everything should
    be "headers". Add footers to *requests* instead.
  - Add API for adding request-specific response headers and footers. To
    simplify the things it should just copy the strings (to avoid dealing with
    complicated deinit of possible dynamic strings).  After this change it should
    be possible to simplify DAuth handling as response could be reused (currently
    403 responses are modified for each reply).
  - Control response behaviour mainly by response flags, not by additional
    headers (like MHD_RF_FORCE_CLOSE instead of "Connection: close").
    It is easier&faster for both: app and MHD.
  - Move response codes from MHD_HTTP_xxx namespace to MHD_HTTP_CODE_xxx
    namespace. It already may clash with other HTTP values.
  - Postprocessor is unusable night-mare when doing "stream processing"
    for tiny values where the application basically has to copy together
    the stream back into a single compact heap value, just making the
    parsing highly more complicated (see examples in Challenger)
  - non-stream processing variant for request bodies, give apps a
    way to request the full body in one buffer; give apps a way
    to request a 'large new allocation' for such buffers; give apps
    a way to specify a global quota for large allocations to ensure
    memory usage has a hard bound

  - Internals: carefully check where locking is really required. Probably
    separate locks. Check out-of-thread value reading. Currently code assumes
    atomic reading of values used in other threads, which mostly true on x86,
    but not OK on other arches. Probably use read/write locking to minimize
    the threads interference.
  - Internals: figure out how to do portable variant of cork/uncork
  - Internals: remove request data from memory pool when response is queued
    (IF no callbacks and thus data cannot be used anymore, or IF
     application permits explicitly per daemon) to get more space
    for building response;
  - Internals: Fix TCP FIN graceful closure issue for upgraded
    connections (API implications?)

*/

#ifndef MICROHTTPD2_H
#define MICROHTTPD2_H

#ifndef __cplusplus
#  define MHD_C_DECLRATIONS_START_HERE_   /* Empty */
#  define MHD_C_DECLRATIONS_FINISH_HERE_  /* Empty */
#else  /* __cplusplus */
/* *INDENT-OFF* */
#  define MHD_C_DECLRATIONS_START_HERE_   extern "C" {
#  define MHD_C_DECLRATIONS_FINISH_HERE_  }
/* *INDENT-ON* */
#endif /* __cplusplus */

#include "microhttpd2_portability.h"

/**
 * Current version of the library.
 * Packed BCD: 0x01093001 = 1.9.30-1.
 */
#define MHD_VERSION 0x01990001

/**
 * Representation of 'bool' in the public API as stdbool.h may not
 * always be available and presence of 'bool' keyword may depend on
 * used C version.
 * It is always safe to cast 'MHD_Bool' variable to 'bool' and vice versa.
 * Note: it may be UNSAFE to cast pointers 'MHD_Bool*' to 'bool*' and
 *       vice versa.
 */
enum MHD_Bool
{

  /**
   * MHD-internal return code for "NO".
   */
  MHD_NO = 0
  ,
  /**
   * MHD-internal return code for "YES".  All non-zero values
   * will be interpreted as "YES", but MHD will only ever
   * return #MHD_YES or #MHD_NO.
   */
  MHD_YES = 1
};

#ifndef MHD_STRINGS_DEFINED


/**
 * String with length data.
 * This type should always have valid @a cstr pointer.
 */
struct MHD_String
{
  /**
   * Number of characters in @e str, not counting 0-termination.
   */
  size_t len;

  /**
   * 0-terminated C-string.
   * Must not be NULL.
   */
  const char *cstr;
};

/**
 * String with length data.
 * This type of data may have NULL as the @a cstr pointer.
 */
struct MHD_StringNullable
{
  /**
   * Number of characters in @e str, not counting 0-termination.
   * If @a cstr is NULL, it must be zero.
   */
  size_t len;

  /**
   * 0-terminated C-string.
   * In some cases it could be NULL.
   */
  const char *cstr;
};

#define MHD_STRINGS_DEFINED 1
#endif /* ! MHD_STRINGS_DEFINED */

/**
 * Constant used to indicate unknown size (use when creating a response).
 * Any possible larger sizes are interpreted as the same value.
 */
#ifdef UINT64_MAX
#  define MHD_SIZE_UNKNOWN UINT64_MAX
#else
#  define MHD_SIZE_UNKNOWN \
        MHD_STATIC_CAST_ (uint_fast64_t,0xffffffffffffffffU)
#endif


/**
 * Constant used to indicate unlimited wait time.
 * Any possible larger values are interpreted as the this value.
 */
#ifdef UINT64_MAX
#  define MHD_WAIT_INDEFINITELY UINT64_MAX
#else
#  define MHD_WAIT_INDEFINITELY \
        MHD_STATIC_CAST_ (uint_fast64_t,0xffffffffffffffffU)
#endif


/* ********** (a) Core HTTP Processing ************ */


/**
 * @brief Handle for a daemon that listens for requests.
 *
 * Manages the listen socket, event loop, optional threads and server
 * settings.
 *
 * @defgroup daemon HTTP server handling client connections
 */
struct MHD_Daemon;


/**
 * @brief Handle/identifier of a network connection abstraction.
 *
 * A single network (i.e. TCP) connection can be used for
 * a single (in HTTP/1.1) data stream.
 *
 * @defgroup connection client connection with streams
 */
struct MHD_Connection;


/**
 * @brief Handle/identifier of a data stream over network
 * connection.
 *
 * A data stream may be used for multiple requests, which
 * in HTTP/1.1 must be processed sequentially.
 *
 * @defgroup stream stream of HTTP requests
 */
struct MHD_Stream;

/**
 * @brief Handle representing an HTTP request.
 *
 * With HTTP/1.1, multiple requests can be run over the same
 * stream.  However, MHD will only show one request per data
 * stream to the client at any given time.
 *
 * Replaces `struct MHD_Connection` in the API prior to version 2.0.0,
 * renamed to better reflect what this object truly represents to
 * the application using MHD.
 *
 * @defgroup request HTTP requests
 */
struct MHD_Request;


/**
 * @brief Actions are returned by the application when processed client header
 * to drive the request handling of MHD.
 *
 * @defgroup action Request actions
 */
struct MHD_Action;


/**
 * @brief Actions are returned by the application when processing client upload
 * to drive the request handling of MHD.
 *
 * @defgroup action Request actions
 */
struct MHD_UploadAction;

/**
 * @defgroup general Primary MHD functions and data
 */

/**
 * @defgroup specialized Introspection and other special control
 */

/**
 * @defgroup authentication Digest and other HTTP authentications
 */


/**
 * Return values for reporting errors, also used for logging.
 *
 * A value of 0 indicates success (as a return value).
 * Values between 0 and 10000 must be handled explicitly by the app.
 * Values from 10000-19999 are informational.
 * Values from 20000-29999 indicate successful operations.
 * Values from 30000-39999 indicate unsuccessful (normal) operations.
 * Values from 40000-49999 indicate client errors.
 * Values from 50000-59999 indicate MHD server errors.
 * Values from 60000-65535 indicate application errors.
 *
 * @ingroup general
 */
enum MHD_FIXED_ENUM_MHD_SET_ MHD_StatusCode
{

  /* 00000-level status codes indicate return values
     the application must act on. */

  /**
   * Successful operation (not used for logging).
   * The code is guaranteed to be always zero.
   */
  MHD_SC_OK = 0
  ,

  /* 10000-level status codes indicate intermediate
     results of some kind. */

  /**
   * Informational event, MHD started.
   */
  MHD_SC_DAEMON_STARTED = 10000
  ,
  /**
   * Informational event, we accepted a connection.
   */
  MHD_SC_CONNECTION_ACCEPTED = 10001
  ,
  /**
   * Informational event, thread processing connection terminates.
   */
  MHD_SC_THREAD_TERMINATING = 10002
  ,
  /**
   * Informational event, state machine status for a connection.
   */
  MHD_SC_STATE_MACHINE_STATUS_REPORT = 10003
  ,
  /**
   * accept() returned transient error.
   */
  MHD_SC_ACCEPT_FAILED_EAGAIN = 10004
  ,
  /**
   * Accepted socket is unknown type (probably non-IP).
   */
  MHD_SC_ACCEPTED_UNKNOWN_TYPE = 10040
  ,
  /**
   * The sockaddr for the accepted socket does not fit the buffer.
   * (Strange)
   */
  MHD_SC_ACCEPTED_SOCKADDR_TOO_LARGE = 10041
  ,

  /* 20000-level status codes indicate success of some kind. */

  /**
   * MHD is closing a connection after the client closed it
   * (perfectly normal end).
   */
  MHD_SC_CONNECTION_CLOSED = 20000
  ,
  /**
   * MHD is closing a connection because the application
   * logic to generate the response data completed.
   */
  MHD_SC_APPLICATION_DATA_GENERATION_FINISHED = 20001
  ,

  /* 30000-level status codes indicate transient failures
     that might go away if the client tries again. */


  /**
   * Resource limit in terms of number of parallel connections
   * hit.
   */
  MHD_SC_LIMIT_CONNECTIONS_REACHED = 30000
  ,
  /**
   * The operation failed because the respective
   * daemon is already too deep inside of the shutdown
   * activity.
   */
  MHD_SC_DAEMON_ALREADY_SHUTDOWN = 30020
  ,
  /**
   * Failed to start new thread because of system limits.
   */
  MHD_SC_CONNECTION_THREAD_SYS_LIMITS_REACHED = 30030
  ,
  /**
   * Failed to start a thread.
   */
  MHD_SC_CONNECTION_THREAD_LAUNCH_FAILURE = 30031
  ,
  /**
   * The operation failed because we either have no
   * listen socket or were already quiesced.
   */
  MHD_SC_DAEMON_ALREADY_QUIESCED = 30040
  ,
  /**
   * The operation failed because client disconnected
   * faster than we could accept().
   */
  MHD_SC_ACCEPT_FAST_DISCONNECT = 30040
  ,
  /**
   * Operating resource limits hit on accept().
   */
  MHD_SC_ACCEPT_SYSTEM_LIMIT_REACHED = 30060
  ,
  /**
   * Connection was refused by accept policy callback.
   */
  MHD_SC_ACCEPT_POLICY_REJECTED = 30070
  ,
  /**
   * Failed to allocate memory for the daemon resources.
   */
  MHD_SC_DAEMON_MALLOC_FAILURE = 30081
  ,
  /**
   * We failed to allocate memory for the connection.
   * (May be transient.)
   */
  MHD_SC_CONNECTION_MALLOC_FAILURE = 30082
  ,
  /**
   * We failed to allocate memory for the connection's memory pool.
   * (May be transient.)
   */
  MHD_SC_POOL_MALLOC_FAILURE = 30083
  ,
  /**
   * We failed to forward data from a Web socket to the
   * application to the remote side due to the socket
   * being closed prematurely. (May be transient.)
   */
  MHD_SC_UPGRADE_FORWARD_INCOMPLETE = 30100
  ,
  /**
   * Failed to allocate memory from our memory pool for processing
   * the request.  Likely the request fields are too large to leave
   * enough room.
   */
  MHD_SC_CONNECTION_POOL_MALLOC_FAILURE_REQ = 30130
  ,
  /**
   * Failed to allocate memory from our memory pool to store GET parameter.
   * Likely the request URI or header fields are too large to leave enough room.
   */
  MHD_SC_CONNECTION_POOL_NO_MEM_GET_PARAM = 30131
  ,
  /**
   * Failed to allocate memory from our memory pool to store parsed cookie.
   */
  MHD_SC_CONNECTION_POOL_NO_MEM_COOKIE = 30132
  ,
  /**
   * Detected jump back of system clock
   */
  MHD_SC_SYS_CLOCK_JUMP_BACK_LARGE = 30140
  ,
  /**
   * Detected correctable jump back of system clock
   */
  MHD_SC_SYS_CLOCK_JUMP_BACK_CORRECTED = 30141
  ,

  /* 40000-level errors are caused by the HTTP client
     (or the network) */

  /**
   * MHD is closing a connection because parsing the
   * request failed.
   */
  MHD_SC_CONNECTION_PARSE_FAIL_CLOSED = 40000
  ,
  /**
   * MHD is closing a connection because it was reset.
   */
  MHD_SC_CONNECTION_RESET_CLOSED = 40001
  ,
  /**
   * MHD is closing a connection because receiving the
   * request failed.
   */
  MHD_SC_CONNECTION_RECV_FAIL_CLOSED = 40002
  ,
  /**
   * MHD is closing a connection because sending the response failed.
   */
  MHD_SC_CONNECTION_SEND_FAIL_CLOSED = 40003
  ,
  /**
   * MHD is returning an error because the header provided
   * by the client is too big.
   */
  MHD_SC_CLIENT_HEADER_TOO_BIG = 40020
  ,
  /**
   * An HTTP/1.1 request was sent without the "Host:" header.
   */
  MHD_SC_HOST_HEADER_MISSING = 40060
  ,
  /**
   * Request has more than one "Host:" header.
   */
  MHD_SC_HOST_HEADER_SEVERAL = 40061
  ,
  /**
   * The given content length was not a number.
   */
  MHD_SC_CONTENT_LENGTH_MALFORMED = 40062
  ,
  /**
   * Request has more than one "Content-Length:" header with the same value.
   */
  MHD_SC_CONTENT_LENGTH_SEVERAL_SAME = 40063
  ,
  /**
   * Request has more than one "Content-Length:" header with the different
   * values.
   */
  MHD_SC_CONTENT_LENGTH_SEVERAL_DIFFERENT = 40064
  ,
  /**
   * The BOTH Content-Length and Transfer-Encoding headers are used.
   */
  MHD_SC_CONTENT_LENGTH_AND_TR_ENC = 40065
  ,
  /**
   * The Content-Length is too large to be handled.
   */
  MHD_SC_CONTENT_LENGTH_TOO_LARGE = 40066
  ,
  /**
   * Transfer encoding in request is unsupported or invalid.
   */
  MHD_SC_CHUNKED_ENCODING_UNSUPPORTED = 40067
  ,
  /**
   * The given uploaded, chunked-encoded body was malformed.
   */
  MHD_SC_CHUNKED_ENCODING_MALFORMED = 40080
  ,
  /**
   * The first header line has whitespace at the start
   */
  MHD_SC_REQ_FIRST_HEADER_LINE_SPACE_PREFIXED = 40100
  ,
  /**
   * The request target (URI) has whitespace character
   */
  MHD_SC_REQ_TARGET_HAS_WHITESPACE = 40101
  ,
  /**
   * Wrong bare CR characters has been replaced with space.
   */
  MHD_SC_REQ_HEADER_CR_REPLACED = 40120
  ,
  /**
   * Header line has not colon and skipped.
   */
  MHD_SC_REQ_HEADER_LINE_NO_COLON = 40121
  ,
  /**
   * Wrong bare CR characters has been replaced with space.
   */
  MHD_SC_REQ_FOOTER_CR_REPLACED = 40140
  ,
  /**
   * Footer line has not colon and skipped.
   */
  MHD_SC_REQ_FOOTER_LINE_NO_COLON = 40141
  ,
  /**
   * The request is malformed.
   */
  MHD_SC_REQ_MALFORMED = 40155
  ,
  /**
   * The cookie string has been parsed, but it is not fully compliant with
   * specifications
   */
  MHD_SC_REQ_COOKIE_PARSED_NOT_COMPLIANT = 40160
  ,
  /**
   * The cookie string has been parsed only partially
   */
  MHD_SC_REQ_COOKIE_PARSED_PARTIALLY = 40161
  ,
  /**
   * The cookie string is ignored, as it is not fully compliant with
   * specifications
   */
  MHD_SC_REQ_COOKIE_IGNORED_NOT_COMPLIANT = 40162
  ,
  /**
   * The cookie string has been ignored as it is invalid
   */
  MHD_SC_REQ_COOKIE_INVALID = 40163
  ,
  /**
   * The request cannot be processed. Sending error reply.
   */
  MHD_SC_REQ_PROCCESSING_ERR_REPLY = 40200
  ,

  /* 50000-level errors are because of an error internal
     to the MHD logic, possibly including our interaction
     with the operating system (but not the application) */

  /**
   * This build of MHD does not support TLS, but the application
   * requested TLS.
   */
  MHD_SC_TLS_DISABLED = 50000
  ,
  /**
   * The application attempted to setup TLS parameters before
   * enabling TLS.
   */
  MHD_SC_TLS_BACKEND_UNINITIALIZED = 50003
  ,
  /**
   * The selected TLS backend does not yet support this operation.
   */
  MHD_SC_TLS_BACKEND_OPERATION_UNSUPPORTED = 50004
  ,
  /**
   * Failed to setup ITC channel.
   */
  MHD_SC_ITC_INITIALIZATION_FAILED = 50005
  ,
  /**
   * File descriptor for ITC cannot be used because the FD number is higher
   * than the limit set by FD_SETSIZE (if internal polling with select is used)
   * or by application.
   */
  MHD_SC_ITC_FD_OUTSIDE_OF_SET_RANGE = 50006
  ,
  /**
   * The specified value for the NC length is way too large
   * for this platform (integer overflow on `size_t`).
   */
  MHD_SC_DIGEST_AUTH_NC_LENGTH_TOO_BIG = 50010
  ,
  /**
   * We failed to allocate memory for the specified nonce
   * counter array.  The option was not set.
   */
  MHD_SC_DIGEST_AUTH_NC_ALLOCATION_FAILURE = 50011
  ,
  /**
   * This build of the library does not support
   * digest authentication.
   */
  MHD_SC_DIGEST_AUTH_NOT_SUPPORTED_BY_BUILD = 50012
  ,
  /**
   * IPv6 requested but not supported by this build.
   * @sa #MHD_SC_AF_NOT_SUPPORTED_BY_BUILD
   */
  MHD_SC_IPV6_NOT_SUPPORTED_BY_BUILD = 50020
  ,
  /**
   * Specified address/protocol family is not supported by this build.
   * @sa MHD_SC_IPV6_NOT_SUPPORTED_BY_BUILD
   */
  MHD_SC_AF_NOT_SUPPORTED_BY_BUILD = 50021
  ,
  /**
   * The requested address/protocol family is rejected by the OS.
   * @sa #MHD_SC_AF_NOT_SUPPORTED_BY_BUILD
   */
  MHD_SC_AF_NOT_AVAILABLE = 500022
  ,
  /**
   * We failed to open the listen socket.
   */
  MHD_SC_FAILED_TO_OPEN_LISTEN_SOCKET = 50040
  ,
  /**
   * Failed to enable listen port reuse.
   */
  MHD_SC_LISTEN_PORT_REUSE_ENABLE_FAILED = 50041
  ,
  /**
   * Failed to enable listen port reuse.
   */
  MHD_SC_LISTEN_PORT_REUSE_ENABLE_NOT_SUPPORTED = 50042
  ,
  /**
   * Failed to enable listen address reuse.
   */
  MHD_SC_LISTEN_ADDRESS_REUSE_ENABLE_FAILED = 50043
  ,
  /**
   * Enabling listen address reuse is not supported by this platform.
   */
  MHD_SC_LISTEN_ADDRESS_REUSE_ENABLE_NOT_SUPPORTED = 50044
  ,
  /**
   * Failed to enable exclusive use of listen address.
   */
  MHD_SC_LISTEN_ADDRESS_EXCLUSIVE_ENABLE_FAILED = 50045
  ,
  /**
   * Dual stack configuration is not possible for provided sockaddr.
   */
  MHD_SC_LISTEN_DUAL_STACK_NOT_SUITABLE = 50046
  ,
  /**
   * Failed to enable or disable dual stack for the IPv6 listen socket.
   * The OS default dual-stack setting is different from what is requested.
   */
  MHD_SC_LISTEN_DUAL_STACK_CONFIGURATION_REJECTED = 50047
  ,
  /**
   * Failed to enable or disable dual stack for the IPv6 listen socket.
   * The socket will be used in whatever the default is the OS uses.
   */
  MHD_SC_LISTEN_DUAL_STACK_CONFIGURATION_UNKNOWN = 50048
  ,
  /**
   * On this platform, MHD does not support explicitly configuring
   * dual stack behaviour.
   */
  MHD_SC_LISTEN_DUAL_STACK_CONFIGURATION_NOT_SUPPORTED = 50049
  ,
  /**
   * Failed to enable TCP FAST OPEN option.
   */
  MHD_SC_LISTEN_FAST_OPEN_FAILURE = 50050
  ,
  /**
   * TCP FAST OPEN is not supported by the platform or by this MHD build.
   */
  MHD_SC_FAST_OPEN_NOT_SUPPORTED = 50051
  ,
  /**
   * We failed to set the listen socket to non-blocking.
   */
  MHD_SC_LISTEN_SOCKET_NONBLOCKING_FAILURE = 50052
  ,
  /**
   * Failed to configure listen socket to be non-inheritable.
   */
  MHD_SC_LISTEN_SOCKET_NOINHERIT_FAILED = 50053
  ,
  /**
   * Listen socket FD cannot be used because the FD number is higher than
   * the limit set by FD_SETSIZE (if internal polling with select is used) or
   * by application.
   */
  MHD_SC_LISTEN_FD_OUTSIDE_OF_SET_RANGE = 50054
  ,
  /**
   * We failed to bind the listen socket.
   */
  MHD_SC_LISTEN_SOCKET_BIND_FAILED = 50055
  ,
  /**
   * Failed to start listening on listen socket.
   */
  MHD_SC_LISTEN_FAILURE = 50056
  ,
  /**
   * Failed to detect the port number on the listening socket
   */
  MHD_SC_LISTEN_PORT_DETECT_FAILURE = 50057
  ,
  /**
   * We failed to create control socket for the epoll().
   */
  MHD_SC_EPOLL_CTL_CREATE_FAILED = 50060
  ,
  /**
   * We failed to configure control socket for the epoll()
   * to be non-inheritable.
   */
  MHD_SC_EPOLL_CTL_CONFIGURE_NOINHERIT_FAILED = 50061
  ,
  /**
   * The epoll() control FD cannot be used because the FD number is higher
   * than the limit set by application.
   */
  MHD_SC_EPOLL_CTL_OUTSIDE_OF_SET_RANGE = 50062
  ,
  /**
   * Failed to allocate memory for daemon's fd_sets
   */
  MHD_SC_FD_SET_MEMORY_ALLOCATE_FAILURE = 50063
  ,
  /**
   * Failed to allocate memory for poll() structures
   */
  MHD_SC_POLL_FDS_MEMORY_ALLOCATE_FAILURE = 50063
  ,
  /**
   * Failed to allocate memory for epoll data
   */
  MHD_SC_EPOLL_EVENTS_MEMORY_ALLOCATE_FAILURE = 50064
  ,
  /**
   * Failed to add daemon's FDs (ITC and/or listening) to the epoll monitoring
   */
  MHD_SC_EPOLL_ADD_DAEMON_FDS_FAILURE = 50065
  ,
  /**
   * The select() syscall is not available on this platform or in this MHD
   * build.
   */
  MHD_SC_SELECT_SYSCALL_NOT_AVAILABLE = 50070
  ,
  /**
   * The poll() syscall is not available on this platform or in this MHD
   * build.
   */
  MHD_SC_POLL_SYSCALL_NOT_AVAILABLE = 50071
  ,
  /**
   * The epoll syscalls are not available on this platform or in this MHD
   * build.
   */
  MHD_SC_EPOLL_SYSCALL_NOT_AVAILABLE = 50072
  ,
  /**
   * Failed to obtain our listen port via introspection.
   * FIXME: remove?
   */
  MHD_SC_LISTEN_PORT_INTROSPECTION_FAILURE = 50080
  ,
  /**
   * Failed to obtain our listen port via introspection
   * due to unsupported address family being used.
   */
  MHD_SC_LISTEN_PORT_INTROSPECTION_UNKNOWN_AF = 50081
  ,
  /**
   * Failed to initialise mutex.
   */
  MHD_SC_MUTEX_INIT_FAILURE = 50085
  ,
  /**
   * Failed to allocate memory for the thread pool.
   */
  MHD_SC_THREAD_POOL_MALLOC_FAILURE = 50090
  ,
  /**
   * We failed to allocate mutex for thread pool worker.
   */
  MHD_SC_THREAD_POOL_CREATE_MUTEX_FAILURE = 50093
  ,
  /**
   * Failed to start the main daemon thread.
   */
  MHD_SC_THREAD_MAIN_LAUNCH_FAILURE = 50095
  ,
  /**
   * Failed to start the daemon thread for listening.
   */
  MHD_SC_THREAD_LISTENING_LAUNCH_FAILURE = 50096
  ,
  /**
   * Failed to start the worker thread for the thread pool.
   */
  MHD_SC_THREAD_WORKER_LAUNCH_FAILURE = 50097
  ,
  /**
   * There was an attempt to upgrade a connection on
   * a daemon where upgrades are disallowed.
   */
  MHD_SC_UPGRADE_ON_DAEMON_WITH_UPGRADE_DISALLOWED = 50100
  ,
  /**
   * Failed to signal via ITC channel.
   */
  MHD_SC_ITC_USE_FAILED = 500101
  ,
  /**
   * Failed to check for the signal on the ITC channel.
   */
  MHD_SC_ITC_CHECK_FAILED = 500102
  ,
  /**
   * System reported error conditions on the ITC FD..
   */
  MHD_SC_ITC_STATUS_ERROR = 500104
  ,
  /**
   * Failed to add a socket to the epoll set.
   */
  MHD_SC_EPOLL_CTL_ADD_FAILED = 500110
  ,
  /**
   * Socket FD cannot be used because the FD number is higher than the limit set
   * by FD_SETSIZE (if internal polling with select is used) or by application.
   */
  MHD_SC_SOCKET_OUTSIDE_OF_SET_RANGE = 500111
  ,
  /**
   * The daemon cannot be started with the specified settings as no space
   * left for the connections sockets within limits set by FD_SETSIZE.
   * Consider use another sockets polling syscall (only select() has such
   * limitations)
   */
  MHD_SC_SYS_FD_SETSIZE_TOO_STRICT = 50112
  ,
  /**
   * This daemon was not configured with options that
   * would allow us to obtain a meaningful timeout.
   */
  MHD_SC_CONFIGURATION_MISMATCH_FOR_GET_TIMEOUT = 50113
  ,
  /**
   * This daemon was not configured with options that
   * would allow us to run with select() data.
   */
  MHD_SC_CONFIGURATION_MISMATCH_FOR_RUN_SELECT = 50114
  ,
  /**
   * This daemon was not configured to run with an
   * external event loop.
   */
  MHD_SC_CONFIGURATION_MISMATCH_FOR_RUN_EXTERNAL = 50115
  ,
  /**
   * Encountered an unexpected error from select()
   * (should never happen).
   */
  MHD_SC_UNEXPECTED_SELECT_ERROR = 50116
  ,
  /**
   * Failed to remove a socket to the epoll set.
   */
  MHD_SC_EPOLL_CTL_REMOVE_FAILED = 50117
  ,
  /**
   * poll() is not supported.
   */
  MHD_SC_POLL_NOT_SUPPORTED = 50120
  ,
  /**
   * Encountered a (potentially) recoverable error from poll().
   */
  MHD_SC_POLL_SOFT_ERROR = 50121
  ,
  /**
   * Encountered an unrecoverable error from poll().
   */
  MHD_SC_POLL_HARD_ERROR = 50122
  ,
  /**
   * Encountered a (potentially) recoverable error from select().
   */
  MHD_SC_SELECT_SOFT_ERROR = 50123
  ,
  /**
   * Encountered an unrecoverable error from select().
   */
  MHD_SC_SELECT_HARD_ERROR = 50124
  ,
  /**
   * System reported error conditions on the listening socket.
   */
  MHD_SC_LISTEN_STATUS_ERROR = 50129
  ,
  /**
   * Encountered an unrecoverable error from epoll function.
   */
  MHD_SC_EPOLL_HARD_ERROR = 50130
  ,
  /**
   * We failed to configure accepted socket
   * to not use a SIGPIPE.
   */
  MHD_SC_ACCEPT_CONFIGURE_NOSIGPIPE_FAILED = 50140
  ,
  /**
   * We failed to configure accepted socket
   * to be non-inheritable.
   */
  MHD_SC_ACCEPT_CONFIGURE_NOINHERIT_FAILED = 50141
  ,
  /**
   * We failed to configure accepted socket
   * to be non-blocking.
   */
  MHD_SC_ACCEPT_CONFIGURE_NONBLOCKING_FAILED = 50142
  ,
  /**
   * The accepted socket FD value is too large.
   */
  MHD_SC_ACCEPT_OUTSIDE_OF_SET_RANGE = 50143
  ,
  /**
   * accept() returned unexpected error.
   */
  MHD_SC_ACCEPT_FAILED_UNEXPECTEDLY = 50144
  ,
  /**
   * Operating resource limits hit on accept() while
   * zero connections are active. Oopsie.
   */
  MHD_SC_ACCEPT_SYSTEM_LIMIT_REACHED_INSTANTLY = 50145
  ,
  /**
   * The daemon sockets polling mode requires non-blocking sockets.
   */
  MHD_SC_NONBLOCKING_REQUIRED = 50146
  ,
  /**
   * Encountered an unexpected error from epoll_wait()
   * (should never happen).
   */
  MHD_SC_UNEXPECTED_EPOLL_WAIT_ERROR = 50150
  ,
  /**
   * epoll file descriptor is invalid (strange)
   */
  MHD_SC_EPOLL_FD_INVALID = 50151
  ,
  /**
   * Unexpected socket error (strange)
   */
  MHD_SC_UNEXPECTED_SOCKET_ERROR = 50152
  ,
  /**
   * Failed to add IP address to per-IP counter for
   * some reason.
   */
  MHD_SC_IP_COUNTER_FAILURE = 50160
  ,
  /**
   * Application violated our API by calling shutdown
   * while having an upgrade connection still open.
   */
  MHD_SC_SHUTDOWN_WITH_OPEN_UPGRADED_CONNECTION = 50180
  ,
  /**
   * Due to an unexpected internal error with the
   * state machine, we closed the connection.
   */
  MHD_SC_STATEMACHINE_FAILURE_CONNECTION_CLOSED = 50200
  ,
  /**
   * Failed to allocate memory in connection's pool
   * to parse the cookie header.
   */
  MHD_SC_COOKIE_POOL_ALLOCATION_FAILURE = 50220
  ,
  /**
   * MHD failed to build the response header.
   */
  MHD_SC_REPLY_FAILED_HEADER_GENERATION = 50230
  ,
  /**
   * Failed to allocate memory in connection's pool for the reply.
   */
  MHD_SC_REPLY_POOL_ALLOCATION_FAILURE = 50231
  ,
  /**
   * Failed to allocate memory in connection's pool for the reply.
   */
  MHD_SC_ERR_RESPONSE_ALLOCATION_FAILURE = 50250
  ,
  /**
   * The feature is not supported by this MHD build (either
   * disabled by configure parameters or build platform
   * did not support it, because headers are missing or
   * so kernel does not have such feature).
   * The feature will not be enabled if the same MHD binary
   * will be run on another kernel, computer or system
   * configuration.
   */
  MHD_SC_FEATURE_DISABLED = 50300
  ,
  /**
   * The feature is not supported by this platform, while
   * supported by MHD build.
   * The feature can be enabled by changing the kernel or
   * running on another computer or with other system
   * configuration.
   */
  MHD_SC_FEATURE_NOT_AVAILABLE = 50320
  ,
  /**
   * Failed to stop the thread
   */
  MHD_SC_DAEMON_THREAD_STOP_ERROR = 50350
  ,
  /**
   * Unexpected reasons for thread stop
   */
  MHD_SC_DAEMON_THREAD_STOP_UNEXPECTED = 50350
  ,
  /**
   * Failed to acquire response mutex lock
   */
  MHD_SC_RESPONSE_MUTEX_LOCK_FAILED = 50500
  ,
  /**
   * Failed to initialise response mutex
   */
  MHD_SC_RESPONSE_MUTEX_INIT_FAILED = 50501
  ,
  /**
   * Unable to clear "reusable" flag.
   * One this flag set, it cannot be removed for the response lifetime.
   */
  MHD_SC_RESPONSE_CANNOT_CLEAR_REUSE = 50520
  ,
  /**
   * Unable to allocate memory for the response header
   */
  MHD_SC_RESPONSE_HEADER_MALLOC_FAILED = 50540
  ,
  /**
   * Failed to switch TCP_NODELAY option for the socket
   */
  MHD_SC_SOCKET_TCP_NODELAY_FAILED = 50600
  ,
  /**
   * Failed to switch TCP_CORK or TCP_NOPUSH option for the socket
   */
  MHD_SC_SOCKET_TCP_CORK_NOPUSH_FAILED = 50601
  ,
  /**
   * Failed to force flush the last part of the response header or
   * the response content
   */
  MHD_SC_SOCKET_FLUSH_LAST_PART_FAILED = 50620
  ,
  /**
   * Failed to push buffered data by zero-sized send()
   */
  MHD_SC_SOCKET_ZERO_SEND_FAILED = 50621
  ,
  /**
   * Something wrong in the internal MHD logic.
   * This error should be never returned if MHD works as expected.
   * If this code is ever returned, please report to MHD maintainers.
   */
  MHD_SC_INTERNAL_ERROR = 51000
  ,

  /* 60000-level errors are because the application
     logic did something wrong or generated an error. */

  /**
   * MHD does not support the requested combination of
   * the sockets polling syscall and the work mode.
   */
  MHD_SC_SYSCALL_WORK_MODE_COMBINATION_INVALID = 60000
  ,
  /**
   * MHD does not support quiescing if ITC was disabled
   * and threads are used.
   */
  MHD_SC_SYSCALL_QUIESCE_REQUIRES_ITC = 60001
  ,
  /**
   * The application requested an unsupported TLS backend to be used.
   */
  MHD_SC_TLS_BACKEND_UNSUPPORTED = 60003
  ,
  /**
   * The application requested a TLS cipher suite which is not
   * supported by the selected backend.
   */
  MHD_SC_TLS_CIPHERS_INVALID = 60004
  ,
  /**
   * MHD is closing a connection because the application
   * logic to generate the response data failed.
   */
  MHD_SC_APPLICATION_DATA_GENERATION_FAILURE_CLOSED = 60005
  ,
  /**
   * MHD is closing a connection because the application
   * callback told it to do so.
   */
  MHD_SC_APPLICATION_CALLBACK_ABORT_ACTION = 60006
  ,
  /**
   * Application only partially processed upload and did
   * not suspend connection. This may result in a hung
   * connection.
   */
  MHD_SC_APPLICATION_HUNG_CONNECTION = 60007
  ,
  /**
   * Application only partially processed upload and did
   * not suspend connection and the read buffer was maxxed
   * out, so MHD closed the connection.
   */
  MHD_SC_APPLICATION_HUNG_CONNECTION_CLOSED = 60008
  ,
  /**
   * Application called function too late, for example because
   * MHD already changed state.
   */
  MHD_SC_TOO_LATE = 60009
  ,
  /**
   * Attempted to set an option that conflicts with another option
   * already set.
   */
  MHD_SC_OPTIONS_CONFLICT = 60010
  ,
  /**
   * Attempted to set an option that not recognised by MHD.
   */
  MHD_SC_OPTION_UNKNOWN = 60011
  ,
  /**
   * Parameter specified unknown work mode.
   */
  MHD_SC_CONFIGURATION_UNEXPECTED_WM = 60012
  ,
  /**
   * Parameter specified unknown socket poll syscall.
   */
  MHD_SC_CONFIGURATION_UNEXPECTED_SPS = 60013
  ,
  /**
   * The size of the provided sockaddr does not match address family.
   */
  MHD_SC_CONFIGURATION_WRONG_SA_SIZE = 60014
  ,
  /**
   * The number set by #MHD_D_O_FD_NUMBER_LIMIT is too strict to run
   * the daemon
   */
  MHD_SC_MAX_FD_NUMBER_LIMIT_TOO_STRICT = 60015
  ,
  /**
   * The number set by #MHD_D_O_GLOBAL_CONNECTION_LIMIT is too for the daemon
   * configuration
   */
  MHD_SC_CONFIGURATION_CONN_LIMIT_TOO_SMALL = 60016
  ,
  /**
   * The response header name has forbidden characters
   */
  MHD_SC_RESP_HEADER_NAME_INVALID = 60050
  ,
  /**
   * The response header value has forbidden characters
   */
  MHD_SC_RESP_HEADER_VALUE_INVALID = 60051
  ,
  /**
   * The provided MHD_Action is invalid
   */
  MHD_SC_ACTION_INVALID = 60080
  ,
  /**
   * The provided MHD_UploadAction is invalid
   */
  MHD_SC_UPLOAD_ACTION_INVALID = 60081
  ,
  /**
   * The provided Dynamic Content Creator action is invalid
   */
  MHD_SC_DCC_ACTION_INVALID = 60082
  ,
  /**
   * The response must be empty
   */
  MHD_SC_REPLY_NOT_EMPTY_RESPONSE = 60101
  ,
  /**
   * The "Content-Length" header is not allowed in the reply
   */
  MHD_SC_REPLY_CONTENT_LENGTH_NOT_ALLOWED = 60102
  ,
  /**
   * The new connection cannot be used because the FD number is higher than
   * the limit set by FD_SETSIZE (if internal polling with select is used) or
   * by application.
   */
  MHD_SC_NEW_CONN_FD_OUTSIDE_OF_SET_RANGE = 60140
  ,
  /**
   * The requested type of information is not recognised.
   */
  MHD_SC_INFO_TYPE_UNKNOWN = 60200
  ,
  /**
   * The requested type of information is not recognised.
   */
  MHD_SC_INFO_GET_INFO_TYPE_UNKNOWN = 60200
  ,
  /**
   * The information of the requested type is too large to fit into
   * the provided buffer.
   */
  MHD_SC_INFO_GET_BUFF_TOO_SMALL = 60201
  ,
  /**
   * The type of the information is not supported by this MHD build.
   * It can be information not supported on the current platform or related
   * to feature disabled for this build.
   */
  MHD_SC_INFO_GET_TYPE_NOT_SUPP_BY_BUILD = 60202
  ,
  /**
   * The type of the information is not available due to configuration
   * or state of the object.
   */
  MHD_SC_INFO_GET_TYPE_UNSUPPORTED = 60203
  ,
  /**
   * The type of the information should be available for the object, but
   * cannot be provided due to some error or other reasons.
   */
  MHD_SC_INFO_GET_TYPE_UNAVAILALBE = 60204
};

/**
 * Get text description for the MHD error code.
 *
 * This function works for @b MHD error codes, not for @b HTTP status codes.
 * @param code the MHD code to get description for
 * @return the pointer to the text description,
 *         NULL if MHD code in not known.
 *
 * @ingroup general
 */
MHD_EXTERN_ const struct MHD_String *
MHD_status_code_to_string (enum MHD_StatusCode code)
MHD_FN_CONST_;

/**
 * Get the pointer to the C string for the MHD error code, never NULL.
 */
#define MHD_status_code_to_string_lazy(code) \
        (MHD_status_code_to_string ((code)) ? \
         ((MHD_status_code_to_string (code))->cstr) : ("[No code]") )

#ifndef MHD_HTTP_METHOD_DEFINED

/**
 * @brief HTTP request methods
 *
 * @defgroup methods HTTP methods
 *
 * See: https://www.iana.org/assignments/http-methods/http-methods.xml
 * Registry export date: 2023-10-02
 * @{
 */

/**
 * HTTP methods explicitly supported by MHD.  Note that for non-canonical
 * methods, MHD will return #MHD_HTTP_METHOD_OTHER and you can use
 * #MHD_REQUEST_INFO_FIXED_HTTP_METHOD to get the original string.
 *
 * However, applications must check for #MHD_HTTP_METHOD_OTHER *or* any enum-value
 * above those in this list, as future versions of MHD may add additional
 * methods (as per IANA registry), thus even if the API returns
 * #MHD_HTTP_METHOD_OTHER today, it may return a method-specific header in the
 * future!
 */
enum MHD_FIXED_ENUM_MHD_SET_ MHD_HTTP_Method
{

  /**
   * Method did not match any of the methods given below.
   */
  MHD_HTTP_METHOD_OTHER = 255
  ,
  /* Main HTTP methods. */

  /**
   * "GET"
   * Safe.     Idempotent.     RFC9110, Section 9.3.1.
   */
  MHD_HTTP_METHOD_GET = 1
  ,
  /**
   * "HEAD"
   * Safe.     Idempotent.     RFC9110, Section 9.3.2.
   */
  MHD_HTTP_METHOD_HEAD = 2
  ,
  /**
   * "POST"
   * Not safe. Not idempotent. RFC9110, Section 9.3.3.
   */
  MHD_HTTP_METHOD_POST = 3
  ,
  /**
   * "PUT"
   * Not safe. Idempotent.     RFC9110, Section 9.3.4.
   */
  MHD_HTTP_METHOD_PUT = 4
  ,
  /**
   * "DELETE"
   * Not safe. Idempotent.     RFC9110, Section 9.3.5.
   */
  MHD_HTTP_METHOD_DELETE = 5
  ,
  /**
   * "CONNECT"
   * Not safe. Not idempotent. RFC9110, Section 9.3.6.
   */
  MHD_HTTP_METHOD_CONNECT = 6
  ,
  /**
   * "OPTIONS"
   * Safe.     Idempotent.     RFC9110, Section 9.3.7.
   */
  MHD_HTTP_METHOD_OPTIONS = 7
  ,
  /**
   * "TRACE"
   * Safe.     Idempotent.     RFC9110, Section 9.3.8.
   */
  MHD_HTTP_METHOD_TRACE = 8
  ,
  /**
   * "*"
   * Not safe. Not idempotent. RFC9110, Section 18.2.
   */
  MHD_HTTP_METHOD_ASTERISK = 9
};

#define MHD_HTTP_METHOD_DEFINED 1
#endif /* ! MHD_HTTP_METHOD_DEFINED */

/**
 * Get text version of the method name.
 * @param method the method to get the text version
 * @return the pointer to the text version,
 *         NULL if method is MHD_HTTP_METHOD_OTHER
 *         or not known.
 */
MHD_EXTERN_ const struct MHD_String *
MHD_http_method_to_string (enum MHD_HTTP_Method method)
MHD_FN_CONST_;


/* Main HTTP methods. */
/* Safe.     Idempotent.     RFC9110, Section 9.3.1. */
#define MHD_HTTP_METHOD_STR_GET      "GET"
/* Safe.     Idempotent.     RFC9110, Section 9.3.2. */
#define MHD_HTTP_METHOD_STR_HEAD     "HEAD"
/* Not safe. Not idempotent. RFC9110, Section 9.3.3. */
#define MHD_HTTP_METHOD_STR_POST     "POST"
/* Not safe. Idempotent.     RFC9110, Section 9.3.4. */
#define MHD_HTTP_METHOD_STR_PUT      "PUT"
/* Not safe. Idempotent.     RFC9110, Section 9.3.5. */
#define MHD_HTTP_METHOD_STR_DELETE   "DELETE"
/* Not safe. Not idempotent. RFC9110, Section 9.3.6. */
#define MHD_HTTP_METHOD_STR_CONNECT  "CONNECT"
/* Safe.     Idempotent.     RFC9110, Section 9.3.7. */
#define MHD_HTTP_METHOD_STR_OPTIONS  "OPTIONS"
/* Safe.     Idempotent.     RFC9110, Section 9.3.8. */
#define MHD_HTTP_METHOD_STR_TRACE    "TRACE"
/* Not safe. Not idempotent. RFC9110, Section 18.2. */
#define MHD_HTTP_METHOD_STR_ASTERISK  "*"

/* Additional HTTP methods. */
/* Not safe. Idempotent.     RFC3744, Section 8.1. */
#define MHD_HTTP_METHOD_STR_ACL            "ACL"
/* Not safe. Idempotent.     RFC3253, Section 12.6. */
#define MHD_HTTP_METHOD_STR_BASELINE_CONTROL "BASELINE-CONTROL"
/* Not safe. Idempotent.     RFC5842, Section 4. */
#define MHD_HTTP_METHOD_STR_BIND           "BIND"
/* Not safe. Idempotent.     RFC3253, Section 4.4, Section 9.4. */
#define MHD_HTTP_METHOD_STR_CHECKIN        "CHECKIN"
/* Not safe. Idempotent.     RFC3253, Section 4.3, Section 8.8. */
#define MHD_HTTP_METHOD_STR_CHECKOUT       "CHECKOUT"
/* Not safe. Idempotent.     RFC4918, Section 9.8. */
#define MHD_HTTP_METHOD_STR_COPY           "COPY"
/* Not safe. Idempotent.     RFC3253, Section 8.2. */
#define MHD_HTTP_METHOD_STR_LABEL          "LABEL"
/* Not safe. Idempotent.     RFC2068, Section 19.6.1.2. */
#define MHD_HTTP_METHOD_STR_LINK           "LINK"
/* Not safe. Not idempotent. RFC4918, Section 9.10. */
#define MHD_HTTP_METHOD_STR_LOCK           "LOCK"
/* Not safe. Idempotent.     RFC3253, Section 11.2. */
#define MHD_HTTP_METHOD_STR_MERGE          "MERGE"
/* Not safe. Idempotent.     RFC3253, Section 13.5. */
#define MHD_HTTP_METHOD_STR_MKACTIVITY     "MKACTIVITY"
/* Not safe. Idempotent.     RFC4791, Section 5.3.1; RFC8144, Section 2.3. */
#define MHD_HTTP_METHOD_STR_MKCALENDAR     "MKCALENDAR"
/* Not safe. Idempotent.     RFC4918, Section 9.3; RFC5689, Section 3; RFC8144, Section 2.3. */
#define MHD_HTTP_METHOD_STR_MKCOL          "MKCOL"
/* Not safe. Idempotent.     RFC4437, Section 6. */
#define MHD_HTTP_METHOD_STR_MKREDIRECTREF  "MKREDIRECTREF"
/* Not safe. Idempotent.     RFC3253, Section 6.3. */
#define MHD_HTTP_METHOD_STR_MKWORKSPACE    "MKWORKSPACE"
/* Not safe. Idempotent.     RFC4918, Section 9.9. */
#define MHD_HTTP_METHOD_STR_MOVE           "MOVE"
/* Not safe. Idempotent.     RFC3648, Section 7. */
#define MHD_HTTP_METHOD_STR_ORDERPATCH     "ORDERPATCH"
/* Not safe. Not idempotent. RFC5789, Section 2. */
#define MHD_HTTP_METHOD_STR_PATCH          "PATCH"
/* Safe.     Idempotent.     RFC9113, Section 3.4. */
#define MHD_HTTP_METHOD_STR_PRI            "PRI"
/* Safe.     Idempotent.     RFC4918, Section 9.1; RFC8144, Section 2.1. */
#define MHD_HTTP_METHOD_STR_PROPFIND       "PROPFIND"
/* Not safe. Idempotent.     RFC4918, Section 9.2; RFC8144, Section 2.2. */
#define MHD_HTTP_METHOD_STR_PROPPATCH      "PROPPATCH"
/* Not safe. Idempotent.     RFC5842, Section 6. */
#define MHD_HTTP_METHOD_STR_REBIND         "REBIND"
/* Safe.     Idempotent.     RFC3253, Section 3.6; RFC8144, Section 2.1. */
#define MHD_HTTP_METHOD_STR_REPORT         "REPORT"
/* Safe.     Idempotent.     RFC5323, Section 2. */
#define MHD_HTTP_METHOD_STR_SEARCH         "SEARCH"
/* Not safe. Idempotent.     RFC5842, Section 5. */
#define MHD_HTTP_METHOD_STR_UNBIND         "UNBIND"
/* Not safe. Idempotent.     RFC3253, Section 4.5. */
#define MHD_HTTP_METHOD_STR_UNCHECKOUT     "UNCHECKOUT"
/* Not safe. Idempotent.     RFC2068, Section 19.6.1.3. */
#define MHD_HTTP_METHOD_STR_UNLINK         "UNLINK"
/* Not safe. Idempotent.     RFC4918, Section 9.11. */
#define MHD_HTTP_METHOD_STR_UNLOCK         "UNLOCK"
/* Not safe. Idempotent.     RFC3253, Section 7.1. */
#define MHD_HTTP_METHOD_STR_UPDATE         "UPDATE"
/* Not safe. Idempotent.     RFC4437, Section 7. */
#define MHD_HTTP_METHOD_STR_UPDATEREDIRECTREF "UPDATEREDIRECTREF"
/* Not safe. Idempotent.     RFC3253, Section 3.5. */
#define MHD_HTTP_METHOD_STR_VERSION_CONTROL "VERSION-CONTROL"

/** @} */ /* end of group methods */

#ifndef MHD_HTTP_POSTENCODING_DEFINED


/**
 * @brief Possible encodings for HTML forms submitted as HTTP POST requests
 *
 * @defgroup postenc HTTP POST encodings
 * See also: https://html.spec.whatwg.org/multipage/form-control-infrastructure.html#form-submission-2
 * @{
 */

enum MHD_FIXED_ENUM_MHD_APP_SET_ MHD_HTTP_PostEncoding
{
  /**
   * No post encoding / broken data / unknown encoding
   */
  MHD_HTTP_POST_ENCODING_OTHER = 0
  ,
  /**
   * "application/x-www-form-urlencoded"
   * See https://html.spec.whatwg.org/multipage/form-control-infrastructure.html#url-encoded-form-data
   * See https://url.spec.whatwg.org/#application/x-www-form-urlencoded
   * See https://datatracker.ietf.org/doc/html/rfc3986#section-2
   */
  MHD_HTTP_POST_ENCODING_FORM_URLENCODED = 1
  ,
  /**
   * "multipart/form-data"
   * See https://html.spec.whatwg.org/multipage/form-control-infrastructure.html#multipart-form-data
   * See https://www.rfc-editor.org/rfc/rfc7578.html
   */
  MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA = 2
  ,
  /**
   * "text/plain"
   * Introduced by HTML5
   * See https://html.spec.whatwg.org/multipage/form-control-infrastructure.html#plain-text-form-data
   * @warning Format is ambiguous. Do not use unless there is a very strong reason.
   */
  MHD_HTTP_POST_ENCODING_TEXT_PLAIN = 3
};


/** @} */ /* end of group postenc */

#define MHD_HTTP_POSTENCODING_DEFINED 1
#endif /* ! MHD_HTTP_POSTENCODING_DEFINED */


/**
 * @brief Standard headers found in HTTP requests and responses.
 *
 * See: https://www.iana.org/assignments/http-fields/http-fields.xhtml
 *
 * @defgroup headers HTTP headers
 * Registry export date: 2023-10-02
 * @{
 */

/* Main HTTP headers. */
/* Permanent.     RFC9110, Section 12.5.1: HTTP Semantics */
#define MHD_HTTP_HEADER_ACCEPT       "Accept"
/* Deprecated.    RFC9110, Section 12.5.2: HTTP Semantics */
#define MHD_HTTP_HEADER_ACCEPT_CHARSET "Accept-Charset"
/* Permanent.     RFC9110, Section 12.5.3: HTTP Semantics */
#define MHD_HTTP_HEADER_ACCEPT_ENCODING "Accept-Encoding"
/* Permanent.     RFC9110, Section 12.5.4: HTTP Semantics */
#define MHD_HTTP_HEADER_ACCEPT_LANGUAGE "Accept-Language"
/* Permanent.     RFC9110, Section 14.3: HTTP Semantics */
#define MHD_HTTP_HEADER_ACCEPT_RANGES "Accept-Ranges"
/* Permanent.     RFC9111, Section 5.1: HTTP Caching */
#define MHD_HTTP_HEADER_AGE          "Age"
/* Permanent.     RFC9110, Section 10.2.1: HTTP Semantics */
#define MHD_HTTP_HEADER_ALLOW        "Allow"
/* Permanent.     RFC9110, Section 11.6.3: HTTP Semantics */
#define MHD_HTTP_HEADER_AUTHENTICATION_INFO "Authentication-Info"
/* Permanent.     RFC9110, Section 11.6.2: HTTP Semantics */
#define MHD_HTTP_HEADER_AUTHORIZATION "Authorization"
/* Permanent.     RFC9111, Section 5.2 */
#define MHD_HTTP_HEADER_CACHE_CONTROL "Cache-Control"
/* Permanent.     RFC9112, Section 9.6: HTTP/1.1 */
#define MHD_HTTP_HEADER_CLOSE        "Close"
/* Permanent.     RFC9110, Section 7.6.1: HTTP Semantics */
#define MHD_HTTP_HEADER_CONNECTION   "Connection"
/* Permanent.     RFC9110, Section 8.4: HTTP Semantics */
#define MHD_HTTP_HEADER_CONTENT_ENCODING "Content-Encoding"
/* Permanent.     RFC9110, Section 8.5: HTTP Semantics */
#define MHD_HTTP_HEADER_CONTENT_LANGUAGE "Content-Language"
/* Permanent.     RFC9110, Section 8.6: HTTP Semantics */
#define MHD_HTTP_HEADER_CONTENT_LENGTH "Content-Length"
/* Permanent.     RFC9110, Section 8.7: HTTP Semantics */
#define MHD_HTTP_HEADER_CONTENT_LOCATION "Content-Location"
/* Permanent.     RFC9110, Section 14.4: HTTP Semantics */
#define MHD_HTTP_HEADER_CONTENT_RANGE "Content-Range"
/* Permanent.     RFC9110, Section 8.3: HTTP Semantics */
#define MHD_HTTP_HEADER_CONTENT_TYPE "Content-Type"
/* Permanent.     RFC9110, Section 6.6.1: HTTP Semantics */
#define MHD_HTTP_HEADER_DATE         "Date"
/* Permanent.     RFC9110, Section 8.8.3: HTTP Semantics */
#define MHD_HTTP_HEADER_ETAG         "ETag"
/* Permanent.     RFC9110, Section 10.1.1: HTTP Semantics */
#define MHD_HTTP_HEADER_EXPECT       "Expect"
/* Permanent.     RFC9111, Section 5.3: HTTP Caching */
#define MHD_HTTP_HEADER_EXPIRES      "Expires"
/* Permanent.     RFC9110, Section 10.1.2: HTTP Semantics */
#define MHD_HTTP_HEADER_FROM         "From"
/* Permanent.     RFC9110, Section 7.2: HTTP Semantics */
#define MHD_HTTP_HEADER_HOST         "Host"
/* Permanent.     RFC9110, Section 13.1.1: HTTP Semantics */
#define MHD_HTTP_HEADER_IF_MATCH     "If-Match"
/* Permanent.     RFC9110, Section 13.1.3: HTTP Semantics */
#define MHD_HTTP_HEADER_IF_MODIFIED_SINCE "If-Modified-Since"
/* Permanent.     RFC9110, Section 13.1.2: HTTP Semantics */
#define MHD_HTTP_HEADER_IF_NONE_MATCH "If-None-Match"
/* Permanent.     RFC9110, Section 13.1.5: HTTP Semantics */
#define MHD_HTTP_HEADER_IF_RANGE     "If-Range"
/* Permanent.     RFC9110, Section 13.1.4: HTTP Semantics */
#define MHD_HTTP_HEADER_IF_UNMODIFIED_SINCE "If-Unmodified-Since"
/* Permanent.     RFC9110, Section 8.8.2: HTTP Semantics */
#define MHD_HTTP_HEADER_LAST_MODIFIED "Last-Modified"
/* Permanent.     RFC9110, Section 10.2.2: HTTP Semantics */
#define MHD_HTTP_HEADER_LOCATION     "Location"
/* Permanent.     RFC9110, Section 7.6.2: HTTP Semantics */
#define MHD_HTTP_HEADER_MAX_FORWARDS "Max-Forwards"
/* Permanent.     RFC9112, Appendix B.1: HTTP/1.1 */
#define MHD_HTTP_HEADER_MIME_VERSION "MIME-Version"
/* Deprecated.    RFC9111, Section 5.4: HTTP Caching */
#define MHD_HTTP_HEADER_PRAGMA       "Pragma"
/* Permanent.     RFC9110, Section 11.7.1: HTTP Semantics */
#define MHD_HTTP_HEADER_PROXY_AUTHENTICATE "Proxy-Authenticate"
/* Permanent.     RFC9110, Section 11.7.3: HTTP Semantics */
#define MHD_HTTP_HEADER_PROXY_AUTHENTICATION_INFO "Proxy-Authentication-Info"
/* Permanent.     RFC9110, Section 11.7.2: HTTP Semantics */
#define MHD_HTTP_HEADER_PROXY_AUTHORIZATION "Proxy-Authorization"
/* Permanent.     RFC9110, Section 14.2: HTTP Semantics */
#define MHD_HTTP_HEADER_RANGE        "Range"
/* Permanent.     RFC9110, Section 10.1.3: HTTP Semantics */
#define MHD_HTTP_HEADER_REFERER      "Referer"
/* Permanent.     RFC9110, Section 10.2.3: HTTP Semantics */
#define MHD_HTTP_HEADER_RETRY_AFTER  "Retry-After"
/* Permanent.     RFC9110, Section 10.2.4: HTTP Semantics */
#define MHD_HTTP_HEADER_SERVER       "Server"
/* Permanent.     RFC9110, Section 10.1.4: HTTP Semantics */
#define MHD_HTTP_HEADER_TE           "TE"
/* Permanent.     RFC9110, Section 6.6.2: HTTP Semantics */
#define MHD_HTTP_HEADER_TRAILER      "Trailer"
/* Permanent.     RFC9112, Section 6.1: HTTP Semantics */
#define MHD_HTTP_HEADER_TRANSFER_ENCODING "Transfer-Encoding"
/* Permanent.     RFC9110, Section 7.8: HTTP Semantics */
#define MHD_HTTP_HEADER_UPGRADE      "Upgrade"
/* Permanent.     RFC9110, Section 10.1.5: HTTP Semantics */
#define MHD_HTTP_HEADER_USER_AGENT   "User-Agent"
/* Permanent.     RFC9110, Section 12.5.5: HTTP Semantics */
#define MHD_HTTP_HEADER_VARY         "Vary"
/* Permanent.     RFC9110, Section 7.6.3: HTTP Semantics */
#define MHD_HTTP_HEADER_VIA          "Via"
/* Permanent.     RFC9110, Section 11.6.1: HTTP Semantics */
#define MHD_HTTP_HEADER_WWW_AUTHENTICATE "WWW-Authenticate"
/* Permanent.     RFC9110, Section 12.5.5: HTTP Semantics */
#define MHD_HTTP_HEADER_ASTERISK     "*"

/* Additional HTTP headers. */
/* Permanent.     RFC 3229: Delta encoding in HTTP */
#define MHD_HTTP_HEADER_A_IM         "A-IM"
/* Permanent.     RFC 2324: Hyper Text Coffee Pot Control Protocol (HTCPCP/1.0) */
#define MHD_HTTP_HEADER_ACCEPT_ADDITIONS "Accept-Additions"
/* Permanent.     RFC 8942, Section 3.1: HTTP Client Hints */
#define MHD_HTTP_HEADER_ACCEPT_CH    "Accept-CH"
/* Permanent.     RFC 7089: HTTP Framework for Time-Based Access to Resource States -- Memento */
#define MHD_HTTP_HEADER_ACCEPT_DATETIME "Accept-Datetime"
/* Permanent.     RFC 2295: Transparent Content Negotiation in HTTP */
#define MHD_HTTP_HEADER_ACCEPT_FEATURES "Accept-Features"
/* Permanent.     RFC 5789: PATCH Method for HTTP */
#define MHD_HTTP_HEADER_ACCEPT_PATCH "Accept-Patch"
/* Permanent.     Linked Data Platform 1.0 */
#define MHD_HTTP_HEADER_ACCEPT_POST  "Accept-Post"
/* Permanent.     RFC-ietf-httpbis-message-signatures-19, Section 5.1: HTTP Message Signatures */
#define MHD_HTTP_HEADER_ACCEPT_SIGNATURE "Accept-Signature"
/* Permanent.     Fetch */
#define MHD_HTTP_HEADER_ACCESS_CONTROL_ALLOW_CREDENTIALS \
        "Access-Control-Allow-Credentials"
/* Permanent.     Fetch */
#define MHD_HTTP_HEADER_ACCESS_CONTROL_ALLOW_HEADERS \
        "Access-Control-Allow-Headers"
/* Permanent.     Fetch */
#define MHD_HTTP_HEADER_ACCESS_CONTROL_ALLOW_METHODS \
        "Access-Control-Allow-Methods"
/* Permanent.     Fetch */
#define MHD_HTTP_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN \
        "Access-Control-Allow-Origin"
/* Permanent.     Fetch */
#define MHD_HTTP_HEADER_ACCESS_CONTROL_EXPOSE_HEADERS \
        "Access-Control-Expose-Headers"
/* Permanent.     Fetch */
#define MHD_HTTP_HEADER_ACCESS_CONTROL_MAX_AGE "Access-Control-Max-Age"
/* Permanent.     Fetch */
#define MHD_HTTP_HEADER_ACCESS_CONTROL_REQUEST_HEADERS \
        "Access-Control-Request-Headers"
/* Permanent.     Fetch */
#define MHD_HTTP_HEADER_ACCESS_CONTROL_REQUEST_METHOD \
        "Access-Control-Request-Method"
/* Permanent.     RFC 7639, Section 2: The ALPN HTTP Header Field */
#define MHD_HTTP_HEADER_ALPN         "ALPN"
/* Permanent.     RFC 7838: HTTP Alternative Services */
#define MHD_HTTP_HEADER_ALT_SVC      "Alt-Svc"
/* Permanent.     RFC 7838: HTTP Alternative Services */
#define MHD_HTTP_HEADER_ALT_USED     "Alt-Used"
/* Permanent.     RFC 2295: Transparent Content Negotiation in HTTP */
#define MHD_HTTP_HEADER_ALTERNATES   "Alternates"
/* Permanent.     RFC 4437: Web Distributed Authoring and Versioning (WebDAV) Redirect Reference Resources */
#define MHD_HTTP_HEADER_APPLY_TO_REDIRECT_REF "Apply-To-Redirect-Ref"
/* Permanent.     RFC 8053, Section 4: HTTP Authentication Extensions for Interactive Clients */
#define MHD_HTTP_HEADER_AUTHENTICATION_CONTROL "Authentication-Control"
/* Permanent.     RFC9211: The Cache-Status HTTP Response Header Field */
#define MHD_HTTP_HEADER_CACHE_STATUS "Cache-Status"
/* Permanent.     RFC 8607, Section 5.1: Calendaring Extensions to WebDAV (CalDAV): Managed Attachments */
#define MHD_HTTP_HEADER_CAL_MANAGED_ID "Cal-Managed-ID"
/* Permanent.     RFC 7809, Section 7.1: Calendaring Extensions to WebDAV (CalDAV): Time Zones by Reference */
#define MHD_HTTP_HEADER_CALDAV_TIMEZONES "CalDAV-Timezones"
/* Permanent.     RFC9297 */
#define MHD_HTTP_HEADER_CAPSULE_PROTOCOL "Capsule-Protocol"
/* Permanent.     RFC9213: Targeted HTTP Cache Control */
#define MHD_HTTP_HEADER_CDN_CACHE_CONTROL "CDN-Cache-Control"
/* Permanent.     RFC 8586: Loop Detection in Content Delivery Networks (CDNs) */
#define MHD_HTTP_HEADER_CDN_LOOP     "CDN-Loop"
/* Permanent.     RFC 8739, Section 3.3: Support for Short-Term, Automatically Renewed (STAR) Certificates in the Automated Certificate Management Environment (ACME) */
#define MHD_HTTP_HEADER_CERT_NOT_AFTER "Cert-Not-After"
/* Permanent.     RFC 8739, Section 3.3: Support for Short-Term, Automatically Renewed (STAR) Certificates in the Automated Certificate Management Environment (ACME) */
#define MHD_HTTP_HEADER_CERT_NOT_BEFORE "Cert-Not-Before"
/* Permanent.     Clear Site Data */
#define MHD_HTTP_HEADER_CLEAR_SITE_DATA "Clear-Site-Data"
/* Permanent.     RFC9440, Section 2: Client-Cert HTTP Header Field */
#define MHD_HTTP_HEADER_CLIENT_CERT  "Client-Cert"
/* Permanent.     RFC9440, Section 2: Client-Cert HTTP Header Field */
#define MHD_HTTP_HEADER_CLIENT_CERT_CHAIN "Client-Cert-Chain"
/* Permanent.     RFC-ietf-httpbis-digest-headers-13, Section 2: Digest Fields */
#define MHD_HTTP_HEADER_CONTENT_DIGEST "Content-Digest"
/* Permanent.     RFC 6266: Use of the Content-Disposition Header Field in the Hypertext Transfer Protocol (HTTP) */
#define MHD_HTTP_HEADER_CONTENT_DISPOSITION "Content-Disposition"
/* Permanent.     The HTTP Distribution and Replication Protocol */
#define MHD_HTTP_HEADER_CONTENT_ID   "Content-ID"
/* Permanent.     Content Security Policy Level 3 */
#define MHD_HTTP_HEADER_CONTENT_SECURITY_POLICY "Content-Security-Policy"
/* Permanent.     Content Security Policy Level 3 */
#define MHD_HTTP_HEADER_CONTENT_SECURITY_POLICY_REPORT_ONLY \
        "Content-Security-Policy-Report-Only"
/* Permanent.     RFC 6265: HTTP State Management Mechanism */
#define MHD_HTTP_HEADER_COOKIE       "Cookie"
/* Permanent.     HTML */
#define MHD_HTTP_HEADER_CROSS_ORIGIN_EMBEDDER_POLICY \
        "Cross-Origin-Embedder-Policy"
/* Permanent.     HTML */
#define MHD_HTTP_HEADER_CROSS_ORIGIN_EMBEDDER_POLICY_REPORT_ONLY \
        "Cross-Origin-Embedder-Policy-Report-Only"
/* Permanent.     HTML */
#define MHD_HTTP_HEADER_CROSS_ORIGIN_OPENER_POLICY "Cross-Origin-Opener-Policy"
/* Permanent.     HTML */
#define MHD_HTTP_HEADER_CROSS_ORIGIN_OPENER_POLICY_REPORT_ONLY \
        "Cross-Origin-Opener-Policy-Report-Only"
/* Permanent.     Fetch */
#define MHD_HTTP_HEADER_CROSS_ORIGIN_RESOURCE_POLICY \
        "Cross-Origin-Resource-Policy"
/* Permanent.     RFC 5323: Web Distributed Authoring and Versioning (WebDAV) SEARCH */
#define MHD_HTTP_HEADER_DASL         "DASL"
/* Permanent.     RFC 4918: HTTP Extensions for Web Distributed Authoring and Versioning (WebDAV) */
#define MHD_HTTP_HEADER_DAV          "DAV"
/* Permanent.     RFC 3229: Delta encoding in HTTP */
#define MHD_HTTP_HEADER_DELTA_BASE   "Delta-Base"
/* Permanent.     RFC 4918: HTTP Extensions for Web Distributed Authoring and Versioning (WebDAV) */
#define MHD_HTTP_HEADER_DEPTH        "Depth"
/* Permanent.     RFC 4918: HTTP Extensions for Web Distributed Authoring and Versioning (WebDAV) */
#define MHD_HTTP_HEADER_DESTINATION  "Destination"
/* Permanent.     The HTTP Distribution and Replication Protocol */
#define MHD_HTTP_HEADER_DIFFERENTIAL_ID "Differential-ID"
/* Permanent.     RFC9449: OAuth 2.0 Demonstrating Proof of Possession (DPoP) */
#define MHD_HTTP_HEADER_DPOP         "DPoP"
/* Permanent.     RFC9449: OAuth 2.0 Demonstrating Proof of Possession (DPoP) */
#define MHD_HTTP_HEADER_DPOP_NONCE   "DPoP-Nonce"
/* Permanent.     RFC 8470: Using Early Data in HTTP */
#define MHD_HTTP_HEADER_EARLY_DATA   "Early-Data"
/* Permanent.     RFC9163: Expect-CT Extension for HTTP */
#define MHD_HTTP_HEADER_EXPECT_CT    "Expect-CT"
/* Permanent.     RFC 7239: Forwarded HTTP Extension */
#define MHD_HTTP_HEADER_FORWARDED    "Forwarded"
/* Permanent.     RFC 7486, Section 6.1.1: HTTP Origin-Bound Authentication (HOBA) */
#define MHD_HTTP_HEADER_HOBAREG      "Hobareg"
/* Permanent.     RFC 4918: HTTP Extensions for Web Distributed Authoring and Versioning (WebDAV) */
#define MHD_HTTP_HEADER_IF           "If"
/* Permanent.      RFC 6338: Scheduling Extensions to CalDAV */
#define MHD_HTTP_HEADER_IF_SCHEDULE_TAG_MATCH "If-Schedule-Tag-Match"
/* Permanent.     RFC 3229: Delta encoding in HTTP */
#define MHD_HTTP_HEADER_IM           "IM"
/* Permanent.     RFC 8473: Token Binding over HTTP */
#define MHD_HTTP_HEADER_INCLUDE_REFERRED_TOKEN_BINDING_ID \
        "Include-Referred-Token-Binding-ID"
/* Permanent.     RFC 2068: Hypertext Transfer Protocol -- HTTP/1.1 */
#define MHD_HTTP_HEADER_KEEP_ALIVE   "Keep-Alive"
/* Permanent.     RFC 3253: Versioning Extensions to WebDAV: (Web Distributed Authoring and Versioning) */
#define MHD_HTTP_HEADER_LABEL        "Label"
/* Permanent.     HTML */
#define MHD_HTTP_HEADER_LAST_EVENT_ID "Last-Event-ID"
/* Permanent.     RFC 8288: Web Linking */
#define MHD_HTTP_HEADER_LINK         "Link"
/* Permanent.     RFC 4918: HTTP Extensions for Web Distributed Authoring and Versioning (WebDAV) */
#define MHD_HTTP_HEADER_LOCK_TOKEN   "Lock-Token"
/* Permanent.     RFC 7089: HTTP Framework for Time-Based Access to Resource States -- Memento */
#define MHD_HTTP_HEADER_MEMENTO_DATETIME "Memento-Datetime"
/* Permanent.     RFC 2227: Simple Hit-Metering and Usage-Limiting for HTTP */
#define MHD_HTTP_HEADER_METER        "Meter"
/* Permanent.     RFC 2295: Transparent Content Negotiation in HTTP */
#define MHD_HTTP_HEADER_NEGOTIATE    "Negotiate"
/* Permanent.     Network Error Logging */
#define MHD_HTTP_HEADER_NEL          "NEL"
/* Permanent.     OData Version 4.01 Part 1: Protocol; OASIS; Chet_Ensign */
#define MHD_HTTP_HEADER_ODATA_ENTITYID "OData-EntityId"
/* Permanent.     OData Version 4.01 Part 1: Protocol; OASIS; Chet_Ensign */
#define MHD_HTTP_HEADER_ODATA_ISOLATION "OData-Isolation"
/* Permanent.     OData Version 4.01 Part 1: Protocol; OASIS; Chet_Ensign */
#define MHD_HTTP_HEADER_ODATA_MAXVERSION "OData-MaxVersion"
/* Permanent.     OData Version 4.01 Part 1: Protocol; OASIS; Chet_Ensign */
#define MHD_HTTP_HEADER_ODATA_VERSION "OData-Version"
/* Permanent.     RFC 8053, Section 3: HTTP Authentication Extensions for Interactive Clients */
#define MHD_HTTP_HEADER_OPTIONAL_WWW_AUTHENTICATE "Optional-WWW-Authenticate"
/* Permanent.     RFC 3648: Web Distributed Authoring and Versioning (WebDAV) Ordered Collections Protocol */
#define MHD_HTTP_HEADER_ORDERING_TYPE "Ordering-Type"
/* Permanent.     RFC 6454: The Web Origin Concept */
#define MHD_HTTP_HEADER_ORIGIN       "Origin"
/* Permanent.     HTML */
#define MHD_HTTP_HEADER_ORIGIN_AGENT_CLUSTER "Origin-Agent-Cluster"
/* Permanent.     RFC 8613, Section 11.1: Object Security for Constrained RESTful Environments (OSCORE) */
#define MHD_HTTP_HEADER_OSCORE       "OSCORE"
/* Permanent.     OASIS Project Specification 01; OASIS; Chet_Ensign */
#define MHD_HTTP_HEADER_OSLC_CORE_VERSION "OSLC-Core-Version"
/* Permanent.     RFC 4918: HTTP Extensions for Web Distributed Authoring and Versioning (WebDAV) */
#define MHD_HTTP_HEADER_OVERWRITE    "Overwrite"
/* Permanent.     HTML */
#define MHD_HTTP_HEADER_PING_FROM    "Ping-From"
/* Permanent.     HTML */
#define MHD_HTTP_HEADER_PING_TO      "Ping-To"
/* Permanent.     RFC 3648: Web Distributed Authoring and Versioning (WebDAV) Ordered Collections Protocol */
#define MHD_HTTP_HEADER_POSITION     "Position"
/* Permanent.     RFC 7240: Prefer Header for HTTP */
#define MHD_HTTP_HEADER_PREFER       "Prefer"
/* Permanent.     RFC 7240: Prefer Header for HTTP */
#define MHD_HTTP_HEADER_PREFERENCE_APPLIED "Preference-Applied"
/* Permanent.     RFC9218: Extensible Prioritization Scheme for HTTP */
#define MHD_HTTP_HEADER_PRIORITY     "Priority"
/* Permanent.     RFC9209: The Proxy-Status HTTP Response Header Field */
#define MHD_HTTP_HEADER_PROXY_STATUS "Proxy-Status"
/* Permanent.     RFC 7469: Public Key Pinning Extension for HTTP */
#define MHD_HTTP_HEADER_PUBLIC_KEY_PINS "Public-Key-Pins"
/* Permanent.     RFC 7469: Public Key Pinning Extension for HTTP */
#define MHD_HTTP_HEADER_PUBLIC_KEY_PINS_REPORT_ONLY \
        "Public-Key-Pins-Report-Only"
/* Permanent.     RFC 4437: Web Distributed Authoring and Versioning (WebDAV) Redirect Reference Resources */
#define MHD_HTTP_HEADER_REDIRECT_REF "Redirect-Ref"
/* Permanent.     HTML */
#define MHD_HTTP_HEADER_REFRESH      "Refresh"
/* Permanent.     RFC 8555, Section 6.5.1: Automatic Certificate Management Environment (ACME) */
#define MHD_HTTP_HEADER_REPLAY_NONCE "Replay-Nonce"
/* Permanent.     RFC-ietf-httpbis-digest-headers-13, Section 3: Digest Fields */
#define MHD_HTTP_HEADER_REPR_DIGEST  "Repr-Digest"
/* Permanent.     RFC 6638: Scheduling Extensions to CalDAV */
#define MHD_HTTP_HEADER_SCHEDULE_REPLY "Schedule-Reply"
/* Permanent.     RFC 6338: Scheduling Extensions to CalDAV */
#define MHD_HTTP_HEADER_SCHEDULE_TAG "Schedule-Tag"
/* Permanent.     Fetch */
#define MHD_HTTP_HEADER_SEC_PURPOSE  "Sec-Purpose"
/* Permanent.     RFC 8473: Token Binding over HTTP */
#define MHD_HTTP_HEADER_SEC_TOKEN_BINDING "Sec-Token-Binding"
/* Permanent.     RFC 6455: The WebSocket Protocol */
#define MHD_HTTP_HEADER_SEC_WEBSOCKET_ACCEPT "Sec-WebSocket-Accept"
/* Permanent.     RFC 6455: The WebSocket Protocol */
#define MHD_HTTP_HEADER_SEC_WEBSOCKET_EXTENSIONS "Sec-WebSocket-Extensions"
/* Permanent.     RFC 6455: The WebSocket Protocol */
#define MHD_HTTP_HEADER_SEC_WEBSOCKET_KEY "Sec-WebSocket-Key"
/* Permanent.     RFC 6455: The WebSocket Protocol */
#define MHD_HTTP_HEADER_SEC_WEBSOCKET_PROTOCOL "Sec-WebSocket-Protocol"
/* Permanent.     RFC 6455: The WebSocket Protocol */
#define MHD_HTTP_HEADER_SEC_WEBSOCKET_VERSION "Sec-WebSocket-Version"
/* Permanent.     Server Timing */
#define MHD_HTTP_HEADER_SERVER_TIMING "Server-Timing"
/* Permanent.     RFC 6265: HTTP State Management Mechanism */
#define MHD_HTTP_HEADER_SET_COOKIE   "Set-Cookie"
/* Permanent.     RFC-ietf-httpbis-message-signatures-19, Section 4.2: HTTP Message Signatures */
#define MHD_HTTP_HEADER_SIGNATURE    "Signature"
/* Permanent.     RFC-ietf-httpbis-message-signatures-19, Section 4.1: HTTP Message Signatures */
#define MHD_HTTP_HEADER_SIGNATURE_INPUT "Signature-Input"
/* Permanent.     RFC 5023: The Atom Publishing Protocol */
#define MHD_HTTP_HEADER_SLUG         "SLUG"
/* Permanent.     Simple Object Access Protocol (SOAP) 1.1 */
#define MHD_HTTP_HEADER_SOAPACTION   "SoapAction"
/* Permanent.     RFC 2518: HTTP Extensions for Distributed Authoring -- WEBDAV */
#define MHD_HTTP_HEADER_STATUS_URI   "Status-URI"
/* Permanent.     RFC 6797: HTTP Strict Transport Security (HSTS) */
#define MHD_HTTP_HEADER_STRICT_TRANSPORT_SECURITY "Strict-Transport-Security"
/* Permanent.     RFC 8594: The Sunset HTTP Header Field */
#define MHD_HTTP_HEADER_SUNSET       "Sunset"
/* Permanent.     Edge Architecture Specification */
#define MHD_HTTP_HEADER_SURROGATE_CAPABILITY "Surrogate-Capability"
/* Permanent.     Edge Architecture Specification */
#define MHD_HTTP_HEADER_SURROGATE_CONTROL "Surrogate-Control"
/* Permanent.     RFC 2295: Transparent Content Negotiation in HTTP */
#define MHD_HTTP_HEADER_TCN          "TCN"
/* Permanent.     RFC 4918: HTTP Extensions for Web Distributed Authoring and Versioning (WebDAV) */
#define MHD_HTTP_HEADER_TIMEOUT      "Timeout"
/* Permanent.     RFC 8030, Section 5.4: Generic Event Delivery Using HTTP Push */
#define MHD_HTTP_HEADER_TOPIC        "Topic"
/* Permanent.     Trace Context */
#define MHD_HTTP_HEADER_TRACEPARENT  "Traceparent"
/* Permanent.     Trace Context */
#define MHD_HTTP_HEADER_TRACESTATE   "Tracestate"
/* Permanent.     RFC 8030, Section 5.2: Generic Event Delivery Using HTTP Push */
#define MHD_HTTP_HEADER_TTL          "TTL"
/* Permanent.     RFC 8030, Section 5.3: Generic Event Delivery Using HTTP Push */
#define MHD_HTTP_HEADER_URGENCY      "Urgency"
/* Permanent.     RFC 2295: Transparent Content Negotiation in HTTP */
#define MHD_HTTP_HEADER_VARIANT_VARY "Variant-Vary"
/* Permanent.     RFC-ietf-httpbis-digest-headers-13, Section 4: Digest Fields */
#define MHD_HTTP_HEADER_WANT_CONTENT_DIGEST "Want-Content-Digest"
/* Permanent.     RFC-ietf-httpbis-digest-headers-13, Section 4: Digest Fields */
#define MHD_HTTP_HEADER_WANT_REPR_DIGEST "Want-Repr-Digest"
/* Permanent.     Fetch */
#define MHD_HTTP_HEADER_X_CONTENT_TYPE_OPTIONS "X-Content-Type-Options"
/* Permanent.     HTML */
#define MHD_HTTP_HEADER_X_FRAME_OPTIONS "X-Frame-Options"
/* Provisional.   AMP-Cache-Transform HTTP request header */
#define MHD_HTTP_HEADER_AMP_CACHE_TRANSFORM "AMP-Cache-Transform"
/* Provisional.   OSLC Configuration Management Version 1.0. Part 3: Configuration Specification */
#define MHD_HTTP_HEADER_CONFIGURATION_CONTEXT "Configuration-Context"
/* Provisional.   RFC 6017: Electronic Data Interchange - Internet Integration (EDIINT) Features Header Field */
#define MHD_HTTP_HEADER_EDIINT_FEATURES "EDIINT-Features"
/* Provisional.   OData Version 4.01 Part 1: Protocol; OASIS; Chet_Ensign */
#define MHD_HTTP_HEADER_ISOLATION    "Isolation"
/* Provisional.   Permissions Policy */
#define MHD_HTTP_HEADER_PERMISSIONS_POLICY "Permissions-Policy"
/* Provisional.   Repeatable Requests Version 1.0; OASIS; Chet_Ensign */
#define MHD_HTTP_HEADER_REPEATABILITY_CLIENT_ID "Repeatability-Client-ID"
/* Provisional.   Repeatable Requests Version 1.0; OASIS; Chet_Ensign */
#define MHD_HTTP_HEADER_REPEATABILITY_FIRST_SENT "Repeatability-First-Sent"
/* Provisional.   Repeatable Requests Version 1.0; OASIS; Chet_Ensign */
#define MHD_HTTP_HEADER_REPEATABILITY_REQUEST_ID "Repeatability-Request-ID"
/* Provisional.   Repeatable Requests Version 1.0; OASIS; Chet_Ensign */
#define MHD_HTTP_HEADER_REPEATABILITY_RESULT "Repeatability-Result"
/* Provisional.   Reporting API */
#define MHD_HTTP_HEADER_REPORTING_ENDPOINTS "Reporting-Endpoints"
/* Provisional.   Global Privacy Control (GPC) */
#define MHD_HTTP_HEADER_SEC_GPC      "Sec-GPC"
/* Provisional.   Resource Timing Level 1 */
#define MHD_HTTP_HEADER_TIMING_ALLOW_ORIGIN "Timing-Allow-Origin"
/* Deprecated.    PEP - an Extension Mechanism for HTTP; status-change-http-experiments-to-historic */
#define MHD_HTTP_HEADER_C_PEP_INFO   "C-PEP-Info"
/* Deprecated.    White Paper: Joint Electronic Payment Initiative */
#define MHD_HTTP_HEADER_PROTOCOL_INFO "Protocol-Info"
/* Deprecated.    White Paper: Joint Electronic Payment Initiative */
#define MHD_HTTP_HEADER_PROTOCOL_QUERY "Protocol-Query"
/* Obsoleted.     Access Control for Cross-site Requests */
#define MHD_HTTP_HEADER_ACCESS_CONTROL "Access-Control"
/* Obsoleted.     RFC 2774: An HTTP Extension Framework; status-change-http-experiments-to-historic */
#define MHD_HTTP_HEADER_C_EXT        "C-Ext"
/* Obsoleted.     RFC 2774: An HTTP Extension Framework; status-change-http-experiments-to-historic */
#define MHD_HTTP_HEADER_C_MAN        "C-Man"
/* Obsoleted.     RFC 2774: An HTTP Extension Framework; status-change-http-experiments-to-historic */
#define MHD_HTTP_HEADER_C_OPT        "C-Opt"
/* Obsoleted.     PEP - an Extension Mechanism for HTTP; status-change-http-experiments-to-historic */
#define MHD_HTTP_HEADER_C_PEP        "C-PEP"
/* Obsoleted.     RFC 2068: Hypertext Transfer Protocol -- HTTP/1.1; RFC 2616: Hypertext Transfer Protocol -- HTTP/1.1 */
#define MHD_HTTP_HEADER_CONTENT_BASE "Content-Base"
/* Obsoleted.     RFC 2616, Section 14.15: Hypertext Transfer Protocol -- HTTP/1.1; RFC 7231, Appendix B: Hypertext Transfer Protocol (HTTP/1.1): Semantics and Content */
#define MHD_HTTP_HEADER_CONTENT_MD5  "Content-MD5"
/* Obsoleted.     HTML 4.01 Specification */
#define MHD_HTTP_HEADER_CONTENT_SCRIPT_TYPE "Content-Script-Type"
/* Obsoleted.     HTML 4.01 Specification */
#define MHD_HTTP_HEADER_CONTENT_STYLE_TYPE "Content-Style-Type"
/* Obsoleted.     RFC 2068: Hypertext Transfer Protocol -- HTTP/1.1 */
#define MHD_HTTP_HEADER_CONTENT_VERSION "Content-Version"
/* Obsoleted.     RFC 2965: HTTP State Management Mechanism; RFC 6265: HTTP State Management Mechanism */
#define MHD_HTTP_HEADER_COOKIE2      "Cookie2"
/* Obsoleted.     HTML 4.01 Specification */
#define MHD_HTTP_HEADER_DEFAULT_STYLE "Default-Style"
/* Obsoleted.     RFC 2068: Hypertext Transfer Protocol -- HTTP/1.1 */
#define MHD_HTTP_HEADER_DERIVED_FROM "Derived-From"
/* Obsoleted.     RFC 3230: Instance Digests in HTTP; RFC-ietf-httpbis-digest-headers-13, Section 1.3: Digest Fields */
#define MHD_HTTP_HEADER_DIGEST       "Digest"
/* Obsoleted.     RFC 2774: An HTTP Extension Framework; status-change-http-experiments-to-historic */
#define MHD_HTTP_HEADER_EXT          "Ext"
/* Obsoleted.     Implementation of OPS Over HTTP */
#define MHD_HTTP_HEADER_GETPROFILE   "GetProfile"
/* Obsoleted.     RFC 7540, Section 3.2.1: Hypertext Transfer Protocol Version 2 (HTTP/2) */
#define MHD_HTTP_HEADER_HTTP2_SETTINGS "HTTP2-Settings"
/* Obsoleted.     RFC 2774: An HTTP Extension Framework; status-change-http-experiments-to-historic */
#define MHD_HTTP_HEADER_MAN          "Man"
/* Obsoleted.     Access Control for Cross-site Requests */
#define MHD_HTTP_HEADER_METHOD_CHECK "Method-Check"
/* Obsoleted.     Access Control for Cross-site Requests */
#define MHD_HTTP_HEADER_METHOD_CHECK_EXPIRES "Method-Check-Expires"
/* Obsoleted.     RFC 2774: An HTTP Extension Framework; status-change-http-experiments-to-historic */
#define MHD_HTTP_HEADER_OPT          "Opt"
/* Obsoleted.     The Platform for Privacy Preferences 1.0 (P3P1.0) Specification */
#define MHD_HTTP_HEADER_P3P          "P3P"
/* Obsoleted.     PEP - an Extension Mechanism for HTTP */
#define MHD_HTTP_HEADER_PEP          "PEP"
/* Obsoleted.     PEP - an Extension Mechanism for HTTP */
#define MHD_HTTP_HEADER_PEP_INFO     "Pep-Info"
/* Obsoleted.     PICS Label Distribution Label Syntax and Communication Protocols */
#define MHD_HTTP_HEADER_PICS_LABEL   "PICS-Label"
/* Obsoleted.     Implementation of OPS Over HTTP */
#define MHD_HTTP_HEADER_PROFILEOBJECT "ProfileObject"
/* Obsoleted.     PICS Label Distribution Label Syntax and Communication Protocols */
#define MHD_HTTP_HEADER_PROTOCOL     "Protocol"
/* Obsoleted.     PICS Label Distribution Label Syntax and Communication Protocols */
#define MHD_HTTP_HEADER_PROTOCOL_REQUEST "Protocol-Request"
/* Obsoleted.     Notification for Proxy Caches */
#define MHD_HTTP_HEADER_PROXY_FEATURES "Proxy-Features"
/* Obsoleted.     Notification for Proxy Caches */
#define MHD_HTTP_HEADER_PROXY_INSTRUCTION "Proxy-Instruction"
/* Obsoleted.     RFC 2068: Hypertext Transfer Protocol -- HTTP/1.1 */
#define MHD_HTTP_HEADER_PUBLIC       "Public"
/* Obsoleted.     Access Control for Cross-site Requests */
#define MHD_HTTP_HEADER_REFERER_ROOT "Referer-Root"
/* Obsoleted.     RFC 2310: The Safe Response Header Field; status-change-http-experiments-to-historic */
#define MHD_HTTP_HEADER_SAFE         "Safe"
/* Obsoleted.     RFC 2660: The Secure HyperText Transfer Protocol; status-change-http-experiments-to-historic */
#define MHD_HTTP_HEADER_SECURITY_SCHEME "Security-Scheme"
/* Obsoleted.     RFC 2965: HTTP State Management Mechanism; RFC 6265: HTTP State Management Mechanism */
#define MHD_HTTP_HEADER_SET_COOKIE2  "Set-Cookie2"
/* Obsoleted.     Implementation of OPS Over HTTP */
#define MHD_HTTP_HEADER_SETPROFILE   "SetProfile"
/* Obsoleted.     RFC 2068: Hypertext Transfer Protocol -- HTTP/1.1 */
#define MHD_HTTP_HEADER_URI          "URI"
/* Obsoleted.     RFC 3230: Instance Digests in HTTP; RFC-ietf-httpbis-digest-headers-13, Section 1.3: Digest Fields */
#define MHD_HTTP_HEADER_WANT_DIGEST  "Want-Digest"
/* Obsoleted.     RFC9111, Section 5.5: HTTP Caching */
#define MHD_HTTP_HEADER_WARNING      "Warning"

/* Headers removed from the registry. Do not use! */
/* Obsoleted.     RFC4229 */
#define MHD_HTTP_HEADER_COMPLIANCE   "Compliance"
/* Obsoleted.     RFC4229 */
#define MHD_HTTP_HEADER_CONTENT_TRANSFER_ENCODING "Content-Transfer-Encoding"
/* Obsoleted.     RFC4229 */
#define MHD_HTTP_HEADER_COST         "Cost"
/* Obsoleted.     RFC4229 */
#define MHD_HTTP_HEADER_MESSAGE_ID   "Message-ID"
/* Obsoleted.     RFC4229 */
#define MHD_HTTP_HEADER_NON_COMPLIANCE "Non-Compliance"
/* Obsoleted.     RFC4229 */
#define MHD_HTTP_HEADER_OPTIONAL     "Optional"
/* Obsoleted.     RFC4229 */
#define MHD_HTTP_HEADER_RESOLUTION_HINT "Resolution-Hint"
/* Obsoleted.     RFC4229 */
#define MHD_HTTP_HEADER_RESOLVER_LOCATION "Resolver-Location"
/* Obsoleted.     RFC4229 */
#define MHD_HTTP_HEADER_SUBOK        "SubOK"
/* Obsoleted.     RFC4229 */
#define MHD_HTTP_HEADER_SUBST        "Subst"
/* Obsoleted.     RFC4229 */
#define MHD_HTTP_HEADER_TITLE        "Title"
/* Obsoleted.     RFC4229 */
#define MHD_HTTP_HEADER_UA_COLOR     "UA-Color"
/* Obsoleted.     RFC4229 */
#define MHD_HTTP_HEADER_UA_MEDIA     "UA-Media"
/* Obsoleted.     RFC4229 */
#define MHD_HTTP_HEADER_UA_PIXELS    "UA-Pixels"
/* Obsoleted.     RFC4229 */
#define MHD_HTTP_HEADER_UA_RESOLUTION "UA-Resolution"
/* Obsoleted.     RFC4229 */
#define MHD_HTTP_HEADER_UA_WINDOWPIXELS "UA-Windowpixels"
/* Obsoleted.     RFC4229 */
#define MHD_HTTP_HEADER_VERSION      "Version"
/* Obsoleted.     W3C Mobile Web Best Practices Working Group */
#define MHD_HTTP_HEADER_X_DEVICE_ACCEPT "X-Device-Accept"
/* Obsoleted.     W3C Mobile Web Best Practices Working Group */
#define MHD_HTTP_HEADER_X_DEVICE_ACCEPT_CHARSET "X-Device-Accept-Charset"
/* Obsoleted.     W3C Mobile Web Best Practices Working Group */
#define MHD_HTTP_HEADER_X_DEVICE_ACCEPT_ENCODING "X-Device-Accept-Encoding"
/* Obsoleted.     W3C Mobile Web Best Practices Working Group */
#define MHD_HTTP_HEADER_X_DEVICE_ACCEPT_LANGUAGE "X-Device-Accept-Language"
/* Obsoleted.     W3C Mobile Web Best Practices Working Group */
#define MHD_HTTP_HEADER_X_DEVICE_USER_AGENT "X-Device-User-Agent"


/**
 * Predefined list of headers
 * To be filled with HPACK static data
 */
enum MHD_PredefinedHeader
{
  MHD_PREDEF_ACCEPT_CHARSET = 15,
  MHD_PREDEF_ACCEPT_LANGUAGE = 17
};

/**
 * Get text version of the predefined header.
 * @param stk the code of the predefined header
 * @return the pointer to the text version,
 *         NULL if method is MHD_HTTP_METHOD_OTHER
 *         or not known.
 */
MHD_EXTERN_ const struct MHD_String *
MHD_predef_header_to_string (enum MHD_PredefinedHeader stk)
MHD_FN_CONST_;

/** @} */ /* end of group headers */

/**
 * A client has requested the given url using the given method
 * (#MHD_HTTP_METHOD_GET, #MHD_HTTP_METHOD_PUT,
 * #MHD_HTTP_METHOD_DELETE, #MHD_HTTP_METHOD_POST, etc).
 * If @a upload_size is not zero and response action is provided by this
 * callback, then upload will be discarded and the stream (the connection for
 * HTTP/1.1) will be closed after sending the response.
 *
 * @param cls argument given together with the function
 *        pointer when the handler was registered with MHD
 * @param request the request object
 * @param path the requested uri (without arguments after "?")
 * @param method the HTTP method used (#MHD_HTTP_METHOD_GET,
 *        #MHD_HTTP_METHOD_PUT, etc.)
 * @param upload_size the size of the message upload content payload,
 *                    #MHD_SIZE_UNKNOWN for chunked uploads (if the
 *                    final chunk has not been processed yet)
 * @return action how to proceed, NULL
 *         if the request must be aborted due to a serious
 *         error while handling the request (implies closure
 *         of underling data stream, for HTTP/1.1 it means
 *         socket closure).
 */
typedef const struct MHD_Action *
(MHD_FN_PAR_NONNULL_ (2) MHD_FN_PAR_NONNULL_ (3)
 *MHD_RequestCallback)(void *cls,
                       struct MHD_Request *MHD_RESTRICT request,
                       const struct MHD_String *MHD_RESTRICT path,
                       enum MHD_HTTP_Method method,
                       uint_fast64_t upload_size);


/**
 * Create (but do not yet start) an MHD daemon.
 * Usually, various options are set before
 * starting the daemon with #MHD_daemon_start().
 *
 * @param req_cb the function to be called for incoming requests
 * @param req_cb_cls the closure for @a cb
 * @return the pointer to the new object on success,
 *         NULL on error (like out-of-memory)
 */
MHD_EXTERN_ struct MHD_Daemon *
MHD_daemon_create (MHD_RequestCallback req_cb,
                   void *req_cb_cls)
MHD_FN_MUST_CHECK_RESULT_;


/**
 * Start a webserver.
 * This function:
 * + checks the combination of set options,
 * + initialises the TLS library (if TLS is requested),
 * + creates the listen socket (if not provided and if allowed),
 * + starts the daemon internal threads (if allowed)
 *
 * @param[in,out] daemon daemon to start; you can no longer set
 *        options on this daemon after this call!
 * @return #MHD_SC_OK on success
 * @ingroup daemon
 */
MHD_EXTERN_ enum MHD_StatusCode
MHD_daemon_start (struct MHD_Daemon *daemon)
MHD_FN_PAR_NONNULL_ (1) MHD_FN_MUST_CHECK_RESULT_;


/**
 * Stop accepting connections from the listening socket.  Allows
 * clients to continue processing, but stops accepting new
 * connections.  Note that the caller is responsible for closing the
 * returned socket; however, if MHD is run using threads (anything but
 * external select mode), it must not be closed until AFTER
 * #MHD_daemon_destroy() has been called (as it is theoretically possible
 * that an existing thread is still using it).
 *
 * @param[in,out] daemon the daemon to stop accepting new connections for
 * @return the old listen socket on success, #MHD_INVALID_SOCKET if
 *         the daemon was already not listening anymore, or
 *         was never started, or has no listen socket.
 * @ingroup daemon
 */
MHD_EXTERN_ MHD_Socket
MHD_daemon_quiesce (struct MHD_Daemon *daemon)
MHD_FN_PAR_NONNULL_ALL_ MHD_FN_PAR_INOUT_ (1);


/**
 * Shutdown and destroy an HTTP daemon.
 *
 * @param[in] daemon daemon to stop
 * @ingroup daemon
 */
MHD_EXTERN_ void
MHD_daemon_destroy (struct MHD_Daemon *daemon)
MHD_FN_PAR_NONNULL_ALL_;

/* ******************* External event loop ************************ */

/**
 * @defgroup event External network events processing
 */

/**
 * The network status of the socket.
 * When set by MHD (by #MHD_SocketRegistrationUpdateCallback and
 * similar) it indicates a request to watch for specific socket state:
 * readiness for receiving the data, readiness for sending the data and/or
 * exception state of the socket.
 * When set by application (and provided for #MHD_daemon_event_update() and
 * similar) it must indicate the actual status of the socket.
 *
 * Any actual state is a bitwise OR combination of #MHD_FD_STATE_RECV,
 * #MHD_FD_STATE_SEND, #MHD_FD_STATE_EXCEPT.
 * @ingroup event
 */
enum MHD_FIXED_ENUM_ MHD_FdState
{
  /**
   * The socket is not ready for receiving or sending and
   * does not have any exceptional state.
   * The state never set by MHD, except de-registration of the sockets
   * in a #MHD_SocketRegistrationUpdateCallback.
   */
  MHD_FD_STATE_NONE = 0
  ,
  /* ** Three bit-flags ** */

  /**
   * Indicates that socket should be watched for incoming data
   * (when set by #MHD_SocketRegistrationUpdateCallback)
   * / socket has incoming data ready to read (when used for
   * #MHD_daemon_event_update())
   */
  MHD_FD_STATE_RECV = 1 << 0
  ,
  /**
   * Indicates that socket should be watched for availability for sending
   * (when set by #MHD_SocketRegistrationUpdateCallback)
   * / socket has ability to send data (when used for
   * #MHD_daemon_event_update())
   */
  MHD_FD_STATE_SEND = 1 << 1
  ,
  /**
   * Indicates that socket should be watched for disconnect, out-of-band
   * data available or high priority data available (when set by
   * #MHD_SocketRegistrationUpdateCallback)
   * / socket has been disconnected, has out-of-band data available or
   * has high priority data available (when used for
   * #MHD_daemon_event_update()). This status must not include "remote
   * peer shut down writing" status.
   * Note: #MHD_SocketRegistrationUpdateCallback() always set it as exceptions
   * must be always watched.
   */
  MHD_FD_STATE_EXCEPT = 1 << 2
  ,

  /* The rest of the list is a bit-wise combination of three main
   * states. Application may use three main states directly as
   * a bit-mask instead of using of following values
   */

  /**
   * Combination of #MHD_FD_STATE_RECV and #MHD_FD_STATE_SEND states.
   */
  MHD_FD_STATE_RECV_SEND = MHD_FD_STATE_RECV | MHD_FD_STATE_SEND
  ,
  /**
   * Combination of #MHD_FD_STATE_RECV and #MHD_FD_STATE_EXCEPT states.
   */
  MHD_FD_STATE_RECV_EXCEPT = MHD_FD_STATE_RECV | MHD_FD_STATE_EXCEPT
  ,
  /**
   * Combination of #MHD_FD_STATE_RECV and #MHD_FD_STATE_EXCEPT states.
   */
  MHD_FD_STATE_SEND_EXCEPT = MHD_FD_STATE_RECV | MHD_FD_STATE_EXCEPT
  ,
  /**
   * Combination of #MHD_FD_STATE_RECV, #MHD_FD_STATE_SEND and
   * #MHD_FD_STATE_EXCEPT states.
   */
  MHD_FD_STATE_RECV_SEND_EXCEPT = \
    MHD_FD_STATE_RECV | MHD_FD_STATE_SEND | MHD_FD_STATE_EXCEPT
};

/**
 * Checks whether specific @a state is enabled in @a var
 */
#define MHD_FD_STATE_IS_SET(var,state)          \
        (MHD_FD_STATE_NONE !=                         \
         (((enum MHD_FdState) (var)) & ((enum MHD_FdState) (state))))

/**
 * Checks whether RECV is enabled in @a var
 */
#define MHD_FD_STATE_IS_SET_RECV(var) \
        MHD_FD_STATE_IS_SET ((var),MHD_FD_STATE_RECV)
/**
 * Checks whether SEND is enabled in @a var
 */
#define MHD_FD_STATE_IS_SET_SEND(var) \
        MHD_FD_STATE_IS_SET ((var),MHD_FD_STATE_SEND)
/**
 * Checks whether EXCEPT is enabled in @a var
 */
#define MHD_FD_STATE_IS_SET_EXCEPT(var) \
        MHD_FD_STATE_IS_SET ((var),MHD_FD_STATE_EXCEPT)


/**
 * Enable specific @a state in @a var
 */
#define MHD_FD_STATE_SET(var,state) \
        (var) = (enum MHD_FdState) ((var) | (state))
/**
 * Enable RECV state in @a var
 */
#define MHD_FD_STATE_SET_RECV(var) MHD_FD_STATE_SET ((var),MHD_FD_STATE_RECV)
/**
 * Enable SEND state in @a var
 */
#define MHD_FD_STATE_SET_SEND(var) MHD_FD_STATE_SET ((var),MHD_FD_STATE_SEND)
/**
 * Enable EXCEPT state in @a var
 */
#define MHD_FD_STATE_SET_EXCEPT(var) \
        MHD_FD_STATE_SET ((var),MHD_FD_STATE_EXCEPT)

/**
 * Clear/disable specific @a state in @a var
 */
#define MHD_FD_STATE_CLEAR(var,state) \
        (var) = (enum MHD_FdState) ((var) & (((enum MHD_FdState))(~state)))
/**
 * Clear/disable RECV state in @a var
 */
#define MHD_FD_STATE_CLEAR_RECV(var) \
        MHD_FD_STATE_CLEAR ((var),MHD_FD_STATE_RECV)
/**
 * Clear/disable SEND state in @a var
 */
#define MHD_FD_STATE_CLEAR_SEND(var) \
        MHD_FD_STATE_CLEAR ((var),MHD_FD_STATE_SEND)
/**
 * Clear/disable EXCEPT state in @a var
 */
#define MHD_FD_STATE_CLEAR_EXCEPT(var) \
        MHD_FD_STATE_CLEAR ((var),MHD_FD_STATE_EXCEPT)


/**
 * The context data to be used for updates of the socket state
 */
struct MHD_EventUpdateContext;


/* Define MHD_APP_SOCKET_CNTX_TYPE to the socket context type before
 * including this header.
 * This is optional, but improves the types safety.
 * For example:
 * #define MHD_APP_SOCKET_CNTX_TYPE struct my_structure
 */
#ifndef MHD_APP_SOCKET_CNTX_TYPE
#  define MHD_APP_SOCKET_CNTX_TYPE void
#endif

/**
 * The callback for registration/de-registration of the sockets to watch.
 *
 * This callback must not call #MHD_daemon_destroy(), #MHD_daemon_quiesce(),
 * #MHD_daemon_add_connection().
 *
 * @param cls the closure
 * @param fd the socket to watch
 * @param watch_for the states of the @a fd to watch, if set to
 *                  #MHD_FD_STATE_NONE the socket must be de-registred
 * @param app_cntx_old the old application defined context for the socket,
 *                     NULL if @a fd socket was not registered before
 * @param ecb_cntx the context handle to be used
 *                 with #MHD_daemon_event_update()
 * @return NULL if error (to connection will be aborted),
 *         or the new socket context
 * @ingroup event
 */
typedef MHD_APP_SOCKET_CNTX_TYPE *
(MHD_FN_PAR_NONNULL_ (5)
 *MHD_SocketRegistrationUpdateCallback)(
  void *cls,
  MHD_Socket fd,
  enum MHD_FdState watch_for,
  MHD_APP_SOCKET_CNTX_TYPE *app_cntx_old,
  struct MHD_EventUpdateContext *ecb_cntx);


/**
 * Update the sockets state.
 * Must be called for every socket that got state updated.
 * For #MHD_D_OPTION_WM_EXTERNAL_EVENT_LOOP_CB_LEVEL() mode
 * should be called for each socket.
 * Available only for daemons stated in
 * #MHD_D_OPTION_WM_EXTERNAL_EVENT_LOOP_CB_LEVEL or
 * #MHD_D_OPTION_WM_EXTERNAL_EVENT_LOOP_CB_EDGE modes.
 * @param daemon the daemon handle
 * @param ecb_cntx the context handle provided
 *                 for #MHD_SocketRegistrationUpdateCallback
 * @param fd_current_state the current state of the socket
 * @ingroup event
 */
MHD_EXTERN_ void
MHD_daemon_event_update (
  struct MHD_Daemon *MHD_RESTRICT daemon,
  struct MHD_EventUpdateContext *MHD_RESTRICT ecb_cntx,
  enum MHD_FdState fd_current_state)
MHD_FN_PAR_NONNULL_ (1) MHD_FN_PAR_NONNULL_ (2);


/**
 * Perform sockets registration, process registered network events.
 *
 * This function first processes all registered (by MHD_daemon_event_update())
 * network events (if any) and then calls #MHD_SocketRegistrationUpdateCallback
 * callback for every socket that needs to be added/updated/removed.
 *
 * Available only for daemons stated in #MHD_WM_EXTERNAL_EVENT_LOOP_CB_LEVEL or
 * #MHD_WM_EXTERNAL_EVENT_LOOP_CB_EDGE modes.
 *
 * @param daemon the daemon handle
 * @param[out] next_max_wait the optional pointer to receive the next maximum
 *                           wait time in microseconds to be used for sockets
 *                           polling function, can be NULL
 * @return #MHD_SC_OK on success,
 *         error code otherwise
 * @ingroup event
 */
MHD_EXTERN_ enum MHD_StatusCode
MHD_deamon_process_reg_events (struct MHD_Daemon *MHD_RESTRICT daemon,
                               uint_fast64_t *MHD_RESTRICT next_max_wait)
MHD_FN_PAR_NONNULL_ (1);

/* ********************* daemon options ************** */


/**
 * Which threading and polling mode should be used by MHD?
 */
enum MHD_FIXED_ENUM_APP_SET_ MHD_WorkMode
{
  /**
   * Work mode with no internal threads.
   * The application periodically calls #MHD_daemon_process_blocking(), where
   * MHD internally checks all sockets automatically.
   * This is the default mode.
   * Use helper macro #MHD_D_OPTION_WM_EXTERNAL_PERIODIC() to enable
   * this mode.
   */
  MHD_WM_EXTERNAL_PERIODIC = 0
  ,
  /**
   * Work mode with an external event loop with level triggers.
   * Application uses #MHD_SocketRegistrationUpdateCallback, level triggered
   * sockets polling (like select() or poll()) and #MHD_daemon_event_update().
   * Use helper macro #MHD_D_OPTION_WM_EXTERNAL_EVENT_LOOP_CB_LEVEL() to enable
   * this mode.
   */
  MHD_WM_EXTERNAL_EVENT_LOOP_CB_LEVEL = 8
  ,
  /**
   * Work mode with an external event loop with edge triggers.
   * Application uses #MHD_SocketRegistrationUpdateCallback, edge triggered
   * sockets polling (like epoll with EPOLLET) and #MHD_daemon_event_update().
   * Use helper macro #MHD_D_OPTION_WM_EXTERNAL_EVENT_LOOP_CB_EDGE() to enable
   * this mode.
   */
  MHD_WM_EXTERNAL_EVENT_LOOP_CB_EDGE = 9
  ,
  /**
   * Work mode with no internal threads and aggregate watch FD.
   * Application uses #MHD_DAEMON_INFO_FIXED_AGGREAGATE_FD to get single FD
   * that gets triggered by any MHD event.
   * This FD can be watched as an aggregate indicator for all MHD events.
   * This mode is available only on selected platforms (currently
   * GNU/Linux and OpenIndiana only), see #MHD_LIB_INFO_FIXED_HAS_AGGREGATE_FD.
   * When the FD is triggered, #MHD_daemon_process_nonblocking() should
   * be called.
   * Use helper macro #MHD_D_OPTION_WM_EXTERNAL_SINGLE_FD_WATCH() to enable
   * this mode.
   */
  MHD_WM_EXTERNAL_SINGLE_FD_WATCH = 16
  ,
  /**
   * Work mode with one or more worker threads.
   * If specified number of threads is one, then daemon starts with single
   * worker thread that handles all connections.
   * If number of threads is larger than one, then that number of worker
   * threads, and handling of connection is distributed among the workers.
   * Use helper macro #MHD_D_OPTION_WM_WORKER_THREADS() to enable
   * this mode.
   */
  MHD_WM_WORKER_THREADS = 24
  ,
  /**
   * Work mode with one internal thread for listening and additional threads
   * per every connection.  Use this if handling requests is CPU-intensive or
   * blocking, your application is thread-safe and you have plenty of
   * memory (per connection).
   * Use helper macro #MHD_D_OPTION_WM_THREAD_PER_CONNECTION() to enable
   * this mode.
   */
  MHD_WM_THREAD_PER_CONNECTION = 32
};

/**
 * Work mode parameters for #MHD_WM_EXTERNAL_EVENT_LOOP_CB_LEVEL and
 * #MHD_WM_EXTERNAL_EVENT_LOOP_CB_EDGE modes
 */
struct MHD_WorkModeExternalEventLoopCBParam
{
  /**
   * Socket registration callback
   */
  MHD_SocketRegistrationUpdateCallback reg_cb;
  /**
   * Closure for the @a reg_cb
   */
  void *reg_cb_cls;
};

/**
 * MHD work mode parameters
 */
union MHD_WorkModeParam
{
  /**
   * Work mode parameters for #MHD_WM_EXTERNAL_EVENT_LOOP_CB_LEVEL and
   * #MHD_WM_EXTERNAL_EVENT_LOOP_CB_EDGE modes
   */
  struct MHD_WorkModeExternalEventLoopCBParam v_external_event_loop_cb;
  /**
   * Number of worker threads for #MHD_WM_WORKER_THREADS.
   * If set to one, then daemon starts with single worker thread that process
   * all connections.
   * If set to value larger than one, then that number of worker threads
   * and distributed handling of requests among the workers.
   * Zero is treated as one.
   */
  unsigned int num_worker_threads;
};

/**
 * Parameter for #MHD_D_O_WORK_MODE().
 * Not recommended to be used directly, better use macro/functions to create it:
 * #MHD_WM_OPTION_EXTERNAL_PERIODIC(),
 * #MHD_WM_OPTION_EXTERNAL_EVENT_LOOP_CB_LEVEL(),
 * #MHD_WM_OPTION_EXTERNAL_EVENT_LOOP_CB_EDGE(),
 * #MHD_WM_OPTION_EXTERNAL_SINGLE_FD_WATCH(),
 * #MHD_WM_OPTION_WORKER_THREADS(),
 * #MHD_WM_OPTION_THREAD_PER_CONNECTION()
 */
struct MHD_WorkModeWithParam
{
  /**
   * The work mode for MHD
   */
  enum MHD_WorkMode mode;
  /**
   * The parameters used for specified work mode
   */
  union MHD_WorkModeParam params;
};


#if defined(MHD_USE_COMPOUND_LITERALS) && defined(MHD_USE_DESIG_NEST_INIT)
/**
 * Create parameter for #MHD_D_O_WORK_MODE() for work mode with
 * no internal threads.
 * The application periodically calls #MHD_daemon_process_blocking(), where
 * MHD internally checks all sockets automatically.
 * This is the default mode.
 * @return the object of struct MHD_WorkModeWithParam with requested values
 */
#  define MHD_WM_OPTION_EXTERNAL_PERIODIC()     \
        MHD_NOWARN_COMPOUND_LITERALS_                 \
          (const struct MHD_WorkModeWithParam)          \
        {                                             \
          .mode = (MHD_WM_EXTERNAL_PERIODIC)          \
        }                                             \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_

/**
 * Create parameter for #MHD_D_O_WORK_MODE() for work mode with
 * an external event loop with level triggers.
 * Application uses #MHD_SocketRegistrationUpdateCallback, level triggered
 * sockets polling (like select() or poll()) and #MHD_daemon_event_update().
 * @param cb_val the callback for sockets registration
 * @param cb_cls_val the closure for the @a cv_val callback
 * @return the object of struct MHD_WorkModeWithParam with requested values
 */
#  define MHD_WM_OPTION_EXTERNAL_EVENT_LOOP_CB_LEVEL(cb_val,cb_cls_val) \
        MHD_NOWARN_COMPOUND_LITERALS_                                         \
          (const struct MHD_WorkModeWithParam)                                  \
        {                                                                     \
          .mode = (MHD_WM_EXTERNAL_EVENT_LOOP_CB_LEVEL),                      \
          .params.v_external_event_loop_cb.reg_cb = (cb_val),                 \
          .params.v_external_event_loop_cb.reg_cb_cls = (cb_cls_val)          \
        }                                                                     \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_

/**
 * Create parameter for #MHD_D_O_WORK_MODE() for work mode with
 * an external event loop with edge triggers.
 * Application uses #MHD_SocketRegistrationUpdateCallback, edge triggered
 * sockets polling (like epoll with EPOLLET) and #MHD_daemon_event_update().
 * @param cb_val the callback for sockets registration
 * @param cb_cls_val the closure for the @a cv_val callback
 * @return the object of struct MHD_WorkModeWithParam with requested values
 */
#  define MHD_WM_OPTION_EXTERNAL_EVENT_LOOP_CB_EDGE(cb_val,cb_cls_val)  \
        MHD_NOWARN_COMPOUND_LITERALS_                                         \
          (const struct MHD_WorkModeWithParam)                                  \
        {                                                                     \
          .mode = (MHD_WM_EXTERNAL_EVENT_LOOP_CB_EDGE),                       \
          .params.v_external_event_loop_cb.reg_cb = (cb_val),                 \
          .params.v_external_event_loop_cb.reg_cb_cls = (cb_cls_val)          \
        }                                                                     \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_

/**
 * Create parameter for #MHD_D_O_WORK_MODE() for work mode with
 * no internal threads and aggregate watch FD.
 * Application uses #MHD_DAEMON_INFO_FIXED_AGGREAGATE_FD to get single FD
 * that gets triggered by any MHD event.
 * This FD can be watched as an aggregate indicator for all MHD events.
 * This mode is available only on selected platforms (currently
 * GNU/Linux only), see #MHD_LIB_INFO_FIXED_HAS_AGGREGATE_FD.
 * When the FD is triggered, #MHD_daemon_process_nonblocking() should
 * be called.
 * @return the object of struct MHD_WorkModeWithParam with requested values
 */
#  define MHD_WM_OPTION_EXTERNAL_SINGLE_FD_WATCH()      \
        MHD_NOWARN_COMPOUND_LITERALS_                         \
          (const struct MHD_WorkModeWithParam)                  \
        {                                                     \
          .mode = (MHD_WM_EXTERNAL_SINGLE_FD_WATCH)           \
        }                                                     \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_

/**
 * Create parameter for #MHD_D_O_WORK_MODE() for work mode with
 * one or more worker threads.
 * If number of threads is one, then daemon starts with single worker thread
 * that handles all connections.
 * If number of threads is larger than one, then that number of worker threads,
 * and handling of connection is distributed among the workers.
 * @param num_workers the number of worker threads, zero is treated as one
 * @return the object of struct MHD_WorkModeWithParam with requested values
 */
#  define MHD_WM_OPTION_WORKER_THREADS(num_workers)     \
        MHD_NOWARN_COMPOUND_LITERALS_                         \
          (const struct MHD_WorkModeWithParam)                  \
        {                                                     \
          .mode = (MHD_WM_WORKER_THREADS),                    \
          .params.num_worker_threads = (num_workers)          \
        }                                                     \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_

/**
 * Create parameter for #MHD_D_O_WORK_MODE() for work mode with
 * one internal thread for listening and additional threads per every
 * connection.  Use this if handling requests is CPU-intensive or blocking,
 * your application is thread-safe and you have plenty of memory (per
 * connection).
 * @return the object of struct MHD_WorkModeWithParam with requested values
 */
#  define MHD_WM_OPTION_THREAD_PER_CONNECTION() \
        MHD_NOWARN_COMPOUND_LITERALS_                 \
          (const struct MHD_WorkModeWithParam)          \
        {                                             \
          .mode = (MHD_WM_THREAD_PER_CONNECTION)      \
        }                                             \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_

#else  /* !MHD_USE_COMPOUND_LITERALS || !MHD_USE_DESIG_NEST_INIT */
MHD_NOWARN_UNUSED_FUNC_

/**
 * Create parameter for #MHD_D_O_WORK_MODE() for work mode with
 * no internal threads.
 * The application periodically calls #MHD_daemon_process_blocking(), where
 * MHD internally checks all sockets automatically.
 * This is the default mode.
 * @return the object of struct MHD_WorkModeWithParam with requested values
 */
static MHD_INLINE struct MHD_WorkModeWithParam
MHD_WM_OPTION_EXTERNAL_PERIODIC (void)
{
  struct MHD_WorkModeWithParam wm_val;

  wm_val.mode = MHD_WM_EXTERNAL_PERIODIC;

  return wm_val;
}


/**
 * Create parameter for #MHD_D_O_WORK_MODE() for work mode with
 * an external event loop with level triggers.
 * Application uses #MHD_SocketRegistrationUpdateCallback, level triggered
 * sockets polling (like select() or poll()) and #MHD_daemon_event_update().
 * @param cb_val the callback for sockets registration
 * @param cb_cls_val the closure for the @a cv_val callback
 * @return the object of struct MHD_WorkModeWithParam with requested values
 */
static MHD_INLINE struct MHD_WorkModeWithParam
MHD_WM_OPTION_EXTERNAL_EVENT_LOOP_CB_LEVEL (
  MHD_SocketRegistrationUpdateCallback cb_val,
  void *cb_cls_val)
{
  struct MHD_WorkModeWithParam wm_val;

  wm_val.mode = MHD_WM_EXTERNAL_EVENT_LOOP_CB_LEVEL;
  wm_val.params.v_external_event_loop_cb.reg_cb = cb_val;
  wm_val.params.v_external_event_loop_cb.reg_cb_cls = cb_cls_val;

  return wm_val;
}


/**
 * Create parameter for #MHD_D_O_WORK_MODE() for work mode with
 * an external event loop with edge triggers.
 * Application uses #MHD_SocketRegistrationUpdateCallback, edge triggered
 * sockets polling (like epoll with EPOLLET) and #MHD_daemon_event_update().
 * @param cb_val the callback for sockets registration
 * @param cb_cls_val the closure for the @a cv_val callback
 * @return the object of struct MHD_WorkModeWithParam with requested values
 */
static MHD_INLINE struct MHD_WorkModeWithParam
MHD_WM_OPTION_EXTERNAL_EVENT_LOOP_CB_EDGE (
  MHD_SocketRegistrationUpdateCallback cb_val,
  void *cb_cls_val)
{
  struct MHD_WorkModeWithParam wm_val;

  wm_val.mode = MHD_WM_EXTERNAL_EVENT_LOOP_CB_EDGE;
  wm_val.params.v_external_event_loop_cb.reg_cb = cb_val;
  wm_val.params.v_external_event_loop_cb.reg_cb_cls = cb_cls_val;

  return wm_val;
}


/**
 * Create parameter for #MHD_D_O_WORK_MODE() for work mode with
 * no internal threads and aggregate watch FD.
 * Application uses #MHD_DAEMON_INFO_FIXED_AGGREAGATE_FD to get single FD
 * that gets triggered by any MHD event.
 * This FD can be watched as an aggregate indicator for all MHD events.
 * This mode is available only on selected platforms (currently
 * GNU/Linux only), see #MHD_LIB_INFO_FIXED_HAS_AGGREGATE_FD.
 * When the FD is triggered, #MHD_daemon_process_nonblocking() should
 * be called.
 * @return the object of struct MHD_WorkModeWithParam with requested values
 */
static MHD_INLINE struct MHD_WorkModeWithParam
MHD_WM_OPTION_EXTERNAL_SINGLE_FD_WATCH (void)
{
  struct MHD_WorkModeWithParam wm_val;

  wm_val.mode = MHD_WM_EXTERNAL_SINGLE_FD_WATCH;

  return wm_val;
}


/**
 * Create parameter for #MHD_D_O_WORK_MODE() for work mode with
 * one or more worker threads.
 * If number of threads is one, then daemon starts with single worker thread
 * that handles all connections.
 * If number of threads is larger than one, then that number of worker threads,
 * and handling of connection is distributed among the workers.
 * @param num_workers the number of worker threads, zero is treated as one
 * @return the object of struct MHD_WorkModeWithParam with requested values
 */
static MHD_INLINE struct MHD_WorkModeWithParam
MHD_WM_OPTION_WORKER_THREADS (unsigned int num_workers)
{
  struct MHD_WorkModeWithParam wm_val;

  wm_val.mode = MHD_WM_EXTERNAL_EVENT_LOOP_CB_EDGE;
  wm_val.params.num_worker_threads = num_workers;

  return wm_val;
}


/**
 * Create parameter for #MHD_D_O_WORK_MODE() for work mode with
 * one internal thread for listening and additional threads per every
 * connection.  Use this if handling requests is CPU-intensive or blocking,
 * your application is thread-safe and you have plenty of memory (per
 * connection).
 * @return the object of struct MHD_WorkModeWithParam with requested values
 */
static MHD_INLINE struct MHD_WorkModeWithParam
MHD_WM_OPTION_THREAD_PER_CONNECTION (void)
{
  struct MHD_WorkModeWithParam wm_val;

  wm_val.mode = MHD_WM_THREAD_PER_CONNECTION;

  return wm_val;
}


MHD_RESTORE_WARN_UNUSED_FUNC_
#endif /* !MHD_USE_COMPOUND_LITERALS || !MHD_USE_DESIG_NEST_INIT */

/**
 * @defgroup logging Log events and control
 */


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
(MHD_FN_PAR_NONNULL_ (3)
 MHD_FN_PAR_CSTR_ (3)
 *MHD_LoggingCallback)(void *cls,
                       enum MHD_StatusCode sc,
                       const char *fm,
                       va_list ap);

/**
 * Parameter for listen socket binding type
 */
enum MHD_FIXED_ENUM_APP_SET_ MHD_DaemonOptionBindType
{
  /**
   * The listen socket bind to the networks address with sharing the address.
   * Several sockets can bind to the same address.
   */
  MHD_D_OPTION_BIND_TYPE_SHARED = -1
  ,
  /**
   * The listen socket bind to the networks address without sharing the address,
   * except allowing binding to port/address which has TIME_WAIT state (the
   * state after closing connection).
   * On some platforms it may also allow to bind to specific address if other
   * socket already bond to the same port of wildcard address (or bind to
   * wildcard address when other socket already bond to specific address
   * with the same port).
   * Typically achieved by enabling 'SO_REUSEADDR' socket option.
   * Default.
   */
  MHD_D_OPTION_BIND_TYPE_NOT_SHARED = 0
  ,
  /**
   * The listen socket bind to the networks address without sharing the address.
   * The daemon way fail to start when any sockets still in "TIME_WAIT" state
   * on the same port, which effectively prevents quick restart of the daemon
   * on the same port.
   * On W32 systems it works like #MHD_D_OPTION_BIND_TYPE_NOT_SHARED due to
   * the OS limitations.
   */
  MHD_D_OPTION_BIND_TYPE_NOT_SHARED_STRICTER = 1
  ,
  /**
   * The list socket bind to the networks address in explicit exclusive mode.
   * Works as #MHD_D_OPTION_BIND_TYPE_NOT_SHARED_STRICTER on platforms without
   * support for the explicit exclusive socket use.
   */
  MHD_D_OPTION_BIND_TYPE_EXCLUSIVE = 2
};


/**
 * Possible levels of enforcement for TCP_FASTOPEN.
 */
enum MHD_FIXED_ENUM_APP_SET_ MHD_TCPFastOpenType
{
  /**
   * Disable use of TCP_FASTOPEN.
   */
  MHD_FOM_DISABLE = -1
  ,
  /**
   * Enable TCP_FASTOPEN where supported.
   * On GNU/Linux it works with a kernel >= 3.6.
   * This is the default.
   */
  MHD_FOM_AUTO = 0
  ,
  /**
   * Require TCP_FASTOPEN.
   * Also causes #MHD_daemon_start() to fail if TCP_FASTOPEN cannot be enabled.
   */
  MHD_FOM_REQUIRE = 1
};


/**
 * Address family to be used by MHD.
 */
enum MHD_FIXED_ENUM_APP_SET_ MHD_AddressFamily
{
  /**
   * Option not given, do not listen at all
   * (unless listen socket or address specified by
   * other means).
   */
  MHD_AF_NONE = 0
  ,
  /**
   * Pick "best" available method automatically.
   */
  MHD_AF_AUTO = 1
  ,
  /**
   * Use IPv4 only.
   */
  MHD_AF_INET4 = 2
  ,
  /**
   * Use IPv6 only.
   */
  MHD_AF_INET6 = 3
  ,
  /**
   * Use dual stack (IPv4 and IPv6 on the same socket).
   */
  MHD_AF_DUAL = 4
  ,
  /**
   * Use dual stack (IPv4 and IPv6 on the same socket),
   * fallback to pure IPv6 if dual stack is not possible.
   */
  MHD_AF_DUAL_v4_OPTIONAL = 5
  ,
  /**
   * Use dual stack (IPv4 and IPv6 on the same socket),
   * fallback to pure IPv4 if dual stack is not possible.
   */
  MHD_AF_DUAL_v6_OPTIONAL = 6

};


/**
 * Sockets polling internal syscalls used by MHD.
 */
enum MHD_FIXED_ENUM_APP_SET_ MHD_SockPollSyscall
{
  /**
   * Automatic selection of best-available method. This is also the
   * default.
   */
  MHD_SPS_AUTO = 0
  ,
  /**
   * Use select().
   */
  MHD_SPS_SELECT = 1
  ,
  /**
   * Use poll().
   */
  MHD_SPS_POLL = 2
  ,
  /**
   * Use epoll.
   */
  MHD_SPS_EPOLL = 3
};


/**
 * Protocol strictness enforced by MHD on clients.
 * All levels have different parsing settings for the headers.
 */
enum MHD_FIXED_ENUM_APP_SET_ MHD_ProtocolStrictLevel
{

  /* * Basic levels * */
  /**
   * Sane level of protocol enforcement for production use.
   * A balance between extra security and broader compatibility,
   * as allowed by RFCs for HTTP servers.
   */
  MHD_PSL_DEFAULT = 0
  ,
  /**
   * Be strict about the protocol (as opposed to as tolerant as
   * possible), within the limits set by RFCs for HTTP servers.
   * This level (and more strict) forbids use of bare LF as
   * CRLF. It also rejects requests with both "Transfer-Encoding:"
   * and "Content-Length:".
   * It is suitable for public servers.
   */
  MHD_PSL_STRICT = 1
  ,
  /**
   * Be particularly permissive about the protocol, within
   * the limits set by RFCs for HTTP servers.
   */
  MHD_PSL_PERMISSIVE = -1
  ,
  /* * Special levels * */
  /**
   * Stricter protocol interpretation, even stricter then allowed
   * by RFCs for HTTP servers.
   * However it should be absolutely compatible with clients
   * following at least RFCs' "MUST" type of requirements
   * for HTTP clients.
   * For chunked encoding parsing this level (and more strict)
   * forbids whitespace in chunk extension.
   * For cookies parsing this (and more strict) level rejects
   * cookie in full even if a single value is encoded incorrectly
   * in it.
   * This level is recommended for testing clients against
   * MHD. Also can be used for security-centric application,
   * however it is slight violation of RFCs' requirements.
   */
  MHD_PSL_VERY_STRICT = 2
  ,
  /**
   * The most strict interpretation of the HTTP protocol,
   * much stricter that defined for HTTP servers by RFC.
   * However it should be absolutely compatible with clients
   * following RFCs' "SHOULD" and "MUST" types of requirements
   * for HTTP clients.
   * This level can be used for testing clients against MHD.
   * It is not recommended for any public services as it may
   * reject legitimate clients (clients not following "SHOULD"
   * type of RFC requirements).
   */
  MHD_PSL_EXTRA_STRICT = 3
  ,
  /**
   * More relaxed protocol interpretation, violating RFCs'
   * "SHOULD" type of restrictions for HTTP servers.
   * For cookies parsing this (and more permissive) level
   * allows whitespaces in cookie values.
   * This level can be used in isolated environments.
   */
  MHD_PSL_VERY_PERMISSIVE = -2
  ,
  /**
   * The most flexible protocol interpretation, beyond
   * RFCs' "MUST" type of restrictions for HTTP server.
   * The level allow HTTP/1.1 requests without "Host:" header.
   * For cookies parsing this level adds allowance of
   * whitespaces before and after '=' character.
   * This level is not recommended unless it is absolutely
   * necessary to communicate with some client(s) with
   * badly broken HTTP implementation.
   */
  MHD_PSL_EXTRA_PERMISSIVE = -3,
};

/**
 * The way Strict Level is enforced.
 * MHD can be compiled with limited set of strictness levels.
 * These values instructs MHD how to apply the request level.
 */
enum MHD_FIXED_ENUM_APP_SET_ MHD_UseStictLevel
{
  /**
   * Use requested level if available or the nearest stricter
   * level.
   * Fail if only more permissive levels available.
   * Recommended value.
   */
  MHD_USL_THIS_OR_STRICTER = 0
  ,
  /**
   * Use requested level only.
   * Fail if this level is not available.
   */
  MHD_USL_PRECISE = 1
  ,
  /**
   * Use requested level if available or the nearest level (stricter
   * or more permissive).
   */
  MHD_USL_NEAREST = 2
};

/* ********************** (d) TLS support ********************** */

/**
 * The TLS backend choice
 */
enum MHD_FIXED_ENUM_APP_SET_ MHD_TlsBackend
{
  /**
   * Disable TLS, use plain TCP connections
   */
  MHD_TLS_BACKEND_NONE = 0
  ,
  /**
   * Use best available TLS backend.
   * Currently this is equivalent to GnuTLS (if TLS is enabled
   * for MHD build).
   */
  MHD_TLS_BACKEND_ANY = 1
  ,
  /**
   * Use GnuTLS as TLS backend.
   */
  MHD_TLS_BACKEND_GNUTLS = 2
};

/**
 * Values for #MHD_D_O_DAUTH_NONCE_BIND_TYPE.
 *
 * These values can limit the scope of validity of MHD-generated nonces.
 * Values can be combined with bitwise OR.
 * Any value, except #MHD_D_OPTION_VALUE_DAUTH_BIND_NONCE_NONE, enforce function
 * #MHD_digest_auth_check() (and similar functions) to check nonce by
 * re-generating it again with the same parameters, which is CPU-intensive
 * operation.
 */
enum MHD_FIXED_FLAGS_ENUM_APP_SET_ MHD_DaemonOptionValueDAuthBindNonce
{
  /**
   * Generated nonces are valid for any request from any client until expired.
   * This is default and recommended value.
   * #MHD_digest_auth_check() (and similar functions) would check only whether
   * the nonce value that is used by client has been generated by MHD and not
   * expired yet.
   * It is recommended because RFC 7616 allows clients to use the same nonce
   * for any request in the same "protection space".
   * When checking client's authorisation requests CPU is loaded less if this
   * value is used.
   * This mode gives MHD maximum flexibility for nonces generation and can
   * prevent possible nonce collisions (and corresponding log warning messages)
   * when clients' requests are intensive.
   * This value cannot be biwise-OR combined with other values.
   */
  MHD_D_OPTION_VALUE_DAUTH_BIND_NONCE_NONE = 0
  ,
  /**
   * Generated nonces are valid only for the same realm.
   */
  MHD_D_OPTION_VALUE_DAUTH_BIND_NONCE_REALM = (1 << 0)
  ,
  /**
   * Generated nonces are valid only for the same URI (excluding parameters
   * after '?' in URI) and request method (GET, POST etc).
   * Not recommended unless "protection space" is limited to a single URI as
   * RFC 7616 allows clients to reuse server-generated nonces for any URI
   * in the same "protection space" which by default consists of all server
   * URIs.
   */
  MHD_D_OPTION_VALUE_DAUTH_BIND_NONCE_URI = (1 << 1)
  ,

  /**
   * Generated nonces are valid only for the same URI including URI parameters
   * and request method (GET, POST etc).
   * This value implies #MHD_D_OPTION_VALUE_DAUTH_BIND_NONCE_URI.
   * Not recommended for that same reasons as
   * #MHD_D_OPTION_VALUE_DAUTH_BIND_NONCE_URI.
   */
  MHD_D_OPTION_VALUE_DAUTH_BIND_NONCE_URI_PARAMS = (1 << 2)
  ,

  /**
   * Generated nonces are valid only for the single client's IP.
   * While it looks like security improvement, in practice the same client may
   * jump from one IP to another (mobile or Wi-Fi handover, DHCP re-assignment,
   * Multi-NAT, different proxy chain and other reasons), while IP address
   * spoofing could be used relatively easily.
   */
  MHD_D_OPTION_VALUE_DAUTH_BIND_NONCE_CLIENT_IP = (1 << 3)
};


/**
 * Context required to provide a pre-shared key to the
 * server.
 *
 * @param ...
 * @param psk_size the number of bytes in @a psk
 * @param psk the pre-shared-key; should be allocated with malloc(),
 *                 will be freed by MHD
 */
struct MHD_ServerCredentialsContext;

MHD_EXTERN_ enum MHD_StatusCode
MHD_connection_set_psk (
  struct MHD_ServerCredentialsContext *mscc,
  size_t psk_size,
  const /*void? */ char psk[MHD_FN_PAR_DYN_ARR_SIZE_ (psk_size)]);

#define MHD_connection_set_psk_unavailable(mscc) \
        MHD_connection_set_psk (mscc, 0, NULL)


/**
 * Function called to lookup the pre-shared key (PSK) for a given
 * HTTP connection based on the @a username.  MHD will suspend handling of
 * the @a connection until the application calls #MHD_connection_set_psk().
 * If looking up the PSK fails, the application must still call
 * #MHD_connection_set_psk_unavailable().
 *
 * @param cls closure
 * @param connection the HTTPS connection
 * @param username the user name claimed by the other side
 * @param mscc context to pass to #MHD_connection_set_psk().
 * @return 0 on success, -1 on errors
 */
typedef void
(*MHD_PskServerCredentialsCallback)(
  void *cls,
  const struct MHD_Connection *MHD_RESTRICT connection,
  const struct MHD_String *MHD_RESTRICT username,
  struct MHD_ServerCredentialsContext *mscc);


/**
 * The specified callback will be called one time,
 * after network initialisation, TLS pre-initialisation, but before
 * the start of the internal threads (if allowed).
 *
 * This callback may use introspection call to retrieve and adjust
 * some of the daemon aspects. For example, TLS backend handler can be used
 * to configure some TLS aspects.
 * @param cls the callback closure
 */
typedef void
(*MHD_DaemonReadyCallback)(void *cls);


/**
 * Allow or deny a client to connect.
 *
 * @param cls closure
 * @param addr_len length of @a addr
 * @param addr address information from the client
 * @see #MHD_D_OPTION_ACCEPT_POLICY()
 * @return #MHD_YES if connection is allowed, #MHD_NO if not
 */
typedef enum MHD_Bool
(*MHD_AcceptPolicyCallback)(void *cls,
                            size_t addr_len,
                            const struct sockaddr *addr);


/**
 * The data for the #MHD_EarlyUriLogCallback
 */
struct MHD_EarlyUriCbData
{
  /**
   * The request handle.
   * Headers are not yet available.
   */
  struct MHD_Request *request;

  /**
   * Pointer to the application context for the request.
   * Modifiable. Initially to NULL.
   */
  void *request_app_context;
};

/**
 * Function called by MHD to allow the application to log the @a full_uri
 * of the new request.
 * If this callback is set then it is the first application function called
 * for the new request.
 * This is the only moment when unmodified URI is provided.
 * After this callback MHD parses the URI and modifies it by extracting
 * GET parameters in-place.
 * If #MHD_RequestTerminationCallback is set then it is guaranteed that
 * #MHD_RequestTerminationCallback is called for the same request. Application
 * may allocate request specific data in this callback and de-allocate
 * the data in #MHD_RequestTerminationCallback.
 *
 * @param cls client-defined closure
 * @param full_uri the full URI ("request target") from the HTTP request
 *                 including parameters (the part after '?')
 * @param[in,out] req_data the request data
 */
typedef void
(MHD_FN_PAR_NONNULL_ (2) MHD_FN_PAR_NONNULL_ (3) MHD_FN_PAR_INOUT_ (3)
 *MHD_EarlyUriLogCallback)(void *cls,
                           const struct MHD_String *full_uri,
                           struct MHD_EarlyUriCbData *req_data);


/**
 * The `enum MHD_ConnectionNotificationCode` specifies types
 * of connection notifications.
 * @ingroup request
 */
enum MHD_FIXED_ENUM_MHD_SET_ MHD_ConnectionNotificationCode
{

  /**
   * A new connection has been started.
   * @ingroup request
   */
  MHD_CONNECTION_NOTIFY_STARTED = 0
  ,
  /**
   * A connection is closed.
   * @ingroup request
   */
  MHD_CONNECTION_NOTIFY_CLOSED = 1

};

/**
 * Extra details for connection notifications.
 * Currently not used
 */
union MHD_ConnectionNotificationDetails
{
  /**
   * Unused
   */
  int reserved1;
};


/**
 * The connection notification data structure
 */
struct MHD_ConnectionNotificationData
{
  /**
   * The connection handle
   */
  struct MHD_Connection *connection;
  /**
   * The connection-specific application context data (opaque for MHD).
   * Initially set to NULL (for connections added by MHD) or set by
   * @a connection_cntx parameter for connections added by
   * #MHD_daemon_add_connection().
   */
  void *application_context;
  /**
   * The code of the event
   */
  enum MHD_ConnectionNotificationCode code;
  /**
   * Event details
   */
  union MHD_ConnectionNotificationDetails details;
};


/**
 * Signature of the callback used by MHD to notify the
 * application about started/stopped network connections
 *
 * @param cls client-defined closure
 * @param[in,out]  data the details about the event
 * @see #MHD_D_OPTION_NOTIFY_CONNECTION()
 * @ingroup request
 */
typedef void
(MHD_FN_PAR_NONNULL_ (2)
 *MHD_NotifyConnectionCallback)(void *cls,
                                struct MHD_ConnectionNotificationData *data);


/**
 * The type of stream notifications.
 * @ingroup request
 */
enum MHD_FIXED_ENUM_MHD_SET_ MHD_StreamNotificationCode
{
  /**
   * A new stream has been started.
   * @ingroup request
   */
  MHD_STREAM_NOTIFY_STARTED = 0
  ,
  /**
   * A stream is closed.
   * @ingroup request
   */
  MHD_STREAM_NOTIFY_CLOSED = 1
};

/**
 * Additional information about stream started event
 */
struct MHD_StreamNotificationDetailStarted
{
  /**
   * Set to #MHD_YES of the stream was started by client
   */
  enum MHD_Bool by_client;
};

/**
 * Additional information about stream events
 */
union MHD_StreamNotificationDetail
{
  /**
   * Information for event #MHD_STREAM_NOTIFY_STARTED
   */
  struct MHD_StreamNotificationDetailStarted started;
};

/**
 * Stream notification data structure
 */
struct MHD_StreamNotificationData
{
  /**
   * The handle of the stream
   */
  struct MHD_Stream *stream;
  /**
   * The code of the event
   */
  enum MHD_StreamNotificationCode code;
  /**
   * Detailed information about notification event
   */
  union MHD_StreamNotificationDetail details;
};


/**
 * Signature of the callback used by MHD to notify the
 * application about started/stopped data stream
 * For HTTP/1.1 it is the same like network connection
 * with 1:1 match.
 *
 * @param cls client-defined closure
 * @param data the details about the event
 * @see #MHD_D_OPTION_NOTIFY_STREAM()
 * @ingroup request
 */
typedef void
(MHD_FN_PAR_NONNULL_ (2)
 *MHD_NotifyStreamCallback)(
  void *cls,
  const struct MHD_StreamNotificationData *data);

#include "microhttpd2_generated_daemon_options.h"


/**
 * The `enum MHD_RequestTerminationCode` specifies reasons
 * why a request has been terminated (or completed).
 * @ingroup request
 */
enum MHD_FIXED_ENUM_MHD_SET_ MHD_RequestTerminationCode
{

  /**
   * The response was successfully sent.
   * @ingroup request
   */
  MHD_REQUEST_TERMINATED_COMPLETED_OK = 0
  ,
  /**
   * No activity on the connection for the number of seconds specified using
   * #MHD_C_OPTION_TIMEOUT().
   * @ingroup request
   */
  MHD_REQUEST_TERMINATED_TIMEOUT_REACHED = 10
  ,
  /**
   * The connection was broken or TLS protocol error.
   * @ingroup request
   */
  MHD_REQUEST_TERMINATED_CONNECTION_ERROR = 20
  ,
  /**
   * The client terminated the connection by closing the socket either
   * completely or for writing (TCP half-closed) before sending complete
   * request.
   * @ingroup request
   */
  MHD_REQUEST_TERMINATED_CLIENT_ABORT = 30
  ,
  /**
   * The request is not valid according to
   * HTTP specifications.
   * @ingroup request
   */
  MHD_REQUEST_TERMINATED_HTTP_PROTOCOL_ERROR = 31
  ,
  /**
   * The application aborted request without response.
   * @ingroup request
   */
  MHD_REQUEST_TERMINATED_BY_APP_ABORT = 40
  ,
  /**
   * The application aborted request without response.
   * @ingroup request
   */
  MHD_REQUEST_TERMINATED_BY_APP_ERROR = 41
  ,
  /**
   * Error handling the connection due to resources exhausted.
   * @ingroup request
   */
  MHD_REQUEST_TERMINATED_NO_RESOURCES = 50
  ,
  /**
   * Closing the session since MHD is being shut down.
   * @ingroup request
   */
  MHD_REQUEST_TERMINATED_DAEMON_SHUTDOWN = 60
};

/**
 * Additional information about request termination
 */
union MHD_RequestTerminationDetail
{
  /**
   * Reserved member.
   * Do not use.
   */
  void *reserved;
};

/**
 * Request termination data structure
 */
struct MHD_RequestTerminationData
{
  /**
   * The code of the event
   */
  enum MHD_RequestTerminationCode code;
  /**
   * Detailed information about termination event
   */
  union MHD_RequestTerminationDetail details;
  /**
   * Pointer to the application context for the request.
   * NULL unless other value set by application when processing the request.
   */
  void *request_app_context;
};


/**
 * Signature of the callback used by MHD to notify the application
 * about completed requests.
 *
 * @param cls client-defined closure
 * @param data the details about the event
 * @param request_context request context value, as originally
 *         returned by the #MHD_EarlyUriLogCallback
 * @see #MHD_R_OPTION_TERMINATION_CALLBACK()
 * @ingroup request
 */
typedef void
(*MHD_RequestTerminationCallback) (void *cls,
                                   struct MHD_RequestTerminationData *data);


#include "microhttpd2_generated_response_options.h"
/* Beginning of generated code documenting how to use options.
   You should treat the following functions *as if* they were
   part of the header/API. The actual declarations are more
   complex, so these here are just for documentation!
   We do not actually *build* this code... */
#if 0

/**
 * Set MHD work (threading and polling) mode.
 * Consider use of #MHD_D_OPTION_WM_EXTERNAL_PERIODIC(), #MHD_D_OPTION_WM_EXTERNAL_EVENT_LOOP_CB_LEVEL(), #MHD_D_OPTION_WM_EXTERNAL_EVENT_LOOP_CB_EDGE(), #MHD_D_OPTION_WM_EXTERNAL_SINGLE_FD_WATCH(), #MHD_D_OPTION_WM_WORKER_THREADS() or #MHD_D_OPTION_WM_THREAD_PER_CONNECTION() instead of direct use of this parameter.
 * @param wmp the object created by one of the next functions/macros: #MHD_WM_OPTION_EXTERNAL_PERIODIC(), #MHD_WM_OPTION_EXTERNAL_EVENT_LOOP_CB_LEVEL(), #MHD_WM_OPTION_EXTERNAL_EVENT_LOOP_CB_EDGE(), #MHD_WM_OPTION_EXTERNAL_SINGLE_FD_WATCH(), #MHD_WM_OPTION_WORKER_THREADS(), #MHD_WM_OPTION_THREAD_PER_CONNECTION()
 * @return structure with the requested setting
 */
struct MHD_DaemonOptionAndValue
MHD_D_OPTION_WORK_MODE (
  struct MHD_WorkModeWithParam wmp
  );

/**
 * Select a sockets watch system call used for internal polling.
 * @param els FIXME
 * @return structure with the requested setting
 */
struct MHD_DaemonOptionAndValue
MHD_D_OPTION_POLL_SYSCALL (
  enum MHD_SockPollSyscall els
  );

/**
 * Set a callback to use for logging
 * @param log_cb the callback to use for logging,
 *   NULL to disable logging
 * @param log_cb_cls the closure for the logging callback
 * @return structure with the requested setting
 */
struct MHD_DaemonOptionAndValue
MHD_D_OPTION_LOG_CALLBACK (
  MHD_LoggingCallback log_cb,
  void *log_cb_cls
  );

/**
 * Bind to the given TCP port and address family.
 *
Does not work with #MHD_D_OPTION_BIND_SA() or #MHD_D_OPTION_LISTEN_SOCKET().
 *
If no listen socket optins (#MHD_D_OPTION_BIND_PORT(), #MHD_D_OPTION_BIND_SA(), #MHD_D_OPTION_LISTEN_SOCKET()) are used, MHD does not listen for incoming connection.
 * @param af the address family to use,
 *   the #MHD_AF_NONE to disable listen socket (the same effect as if this option is not used)
 * @param port port to use, 0 to let system assign any free port,
 *   ignored if @a af is #MHD_AF_NONE
 * @return structure with the requested setting
 */
struct MHD_DaemonOptionAndValue
MHD_D_OPTION_BIND_PORT (
  enum MHD_AddressFamily af,
  uint_least16_t port
  );

/**
 * Bind to the given socket address.
 *
Does not work with #MHD_D_OPTION_BIND_PORT() or #MHD_D_OPTION_LISTEN_SOCKET().
 *
If no listen socket optins (#MHD_D_OPTION_BIND_PORT(), #MHD_D_OPTION_BIND_SA(), #MHD_D_OPTION_LISTEN_SOCKET()) are used, MHD does not listen for incoming connection.
 * @param sa_len the size of the socket address pointed by @a sa.
 * @param sa the address to bind to; can be IPv4 (AF_INET), IPv6 (AF_INET6) or even a UNIX domain socket (AF_UNIX)
 * @param dual When a previous version of the protocol exist (like IPv4 when @a v_sa is IPv6) bind to both protocols (IPv6 and IPv4).
 * @return structure with the requested setting
 */
struct MHD_DaemonOptionAndValue
MHD_D_OPTION_BIND_SA (
  size_t sa_len,
  /* const */ struct sockaddr *sa,
  enum MHD_Bool dual
  );

/**
 * Accept connections from the given socket.  Socket
 * must be a TCP or UNIX domain (SOCK_STREAM) socket.
 *
Does not work with #MHD_D_OPTION_BIND_PORT() or #MHD_D_OPTION_BIND_SA().
 *
If no listen socket optins (#MHD_D_OPTION_BIND_PORT(), #MHD_D_OPTION_BIND_SA(), #MHD_D_OPTION_LISTEN_SOCKET()) are used, MHD does not listen for incoming connection.
 * @param listen_fd the listen socket to use, ignored if set to #MHD_INVALID_SOCKET
 * @return structure with the requested setting
 */
struct MHD_DaemonOptionAndValue
MHD_D_OPTION_LISTEN_SOCKET (
  MHD_Socket listen_fd
  );

/**
 * Select mode of reusing address:port listen address.
 *
Works only when #MHD_D_OPTION_BIND_PORT() or #MHD_D_OPTION_BIND_SA() are used.
 * @param reuse_type FIXME
 * @return structure with the requested setting
 */
struct MHD_DaemonOptionAndValue
MHD_D_OPTION_LISTEN_ADDR_REUSE (
  enum MHD_DaemonOptionBindType reuse_type
  );

/**
 * Configure TCP_FASTOPEN option, including setting a
 * custom @a queue_length.
 *
Note that having a larger queue size can cause resource exhaustion
 * attack as the TCP stack has to now allocate resources for the SYN
 * packet along with its DATA.
 *
Works only when #MHD_D_OPTION_BIND_PORT() or #MHD_D_OPTION_BIND_SA() are used.
 * @param option the type use of of TCP FastOpen
 * @param queue_length the length of the queue, zero to use system or MHD default,
 *   silently ignored on platforms without support for custom queue size
 * @return structure with the requested setting
 */
struct MHD_DaemonOptionAndValue
MHD_D_OPTION_TCP_FASTOPEN (
  enum MHD_TCPFastOpenType option,
  unsigned int queue_length
  );

/**
 * Use the given backlog for the listen() call.
 *
Works only when #MHD_D_OPTION_BIND_PORT() or #MHD_D_OPTION_BIND_SA() are used.
 * Zero parameter treated as MHD/system default.
 * @param backlog_size FIXME
 * @return structure with the requested setting
 */
struct MHD_DaemonOptionAndValue
MHD_D_OPTION_LISTEN_BACKLOG (
  unsigned int backlog_size
  );

/**
 * Inform that SIGPIPE is suppressed or handled by application.
 * If suppressed/handled, MHD uses network functions that could generate SIGPIPE, like `sendfile()`.
 * Silently ignored when MHD creates internal threads as for them SIGPIPE is suppressed automatically.
 * @param val the value of the parameter * @return structure with the requested setting
 */
struct MHD_DaemonOptionAndValue
MHD_D_OPTION_SIGPIPE_SUPPRESSED (
  enum MHD_Bool val
  );

/**
 * Enable TLS (HTTPS) and select TLS backend
 * @param backend the TLS backend to use,
 *   #MHD_TLS_BACKEND_NONE for non-TLS (plain TCP) connections
 * @return structure with the requested setting
 */
struct MHD_DaemonOptionAndValue
MHD_D_OPTION_TLS (
  enum MHD_TlsBackend backend
  );

/**
 * Provide TLS key and certificate data in-memory.
 * Works only if TLS mode is enabled.
 * @param mem_key the private key loaded into memory (not a filename)
 * @param mem_cert the certificate loaded into memory (not a filename)
 * @param mem_pass the option passphrase phrase to decrypt the private key,
 *   could be NULL is private does not need a password
 * @return structure with the requested setting
 */
struct MHD_DaemonOptionAndValue
MHD_D_OPTION_TLS_KEY_CERT (
  const char *mem_key,
  const char *mem_cert,
  const char *mem_pass
  );

/**
 * Provide the certificate of the certificate authority (CA) to be used by the MHD daemon for client authentication.
 * Works only if TLS mode is enabled.
 * @param mem_client_ca the CA certificate in memory (not a filename)
 * @return structure with the requested setting
 */
struct MHD_DaemonOptionAndValue
MHD_D_OPTION_TLS_CLIENT_CA (
  const char *mem_client_ca
  );

/**
 * Configure PSK to use for the TLS key exchange.
 * @param psk_cb the function to call to obtain pre-shared key
 * @param psk_cb_cls the closure for @a psk_cb
 * @return structure with the requested setting
 */
struct MHD_DaemonOptionAndValue
MHD_D_OPTION_TLS_PSK_CALLBACK (
  MHD_PskServerCredentialsCallback psk_cb,
  void *psk_cb_cls
  );

/**
 * Control ALPN for TLS connection.
 * Silently ignored for non-TLS.
 * By default ALPN is automatically used for TLS connections.
 * @param val the value of the parameter * @return structure with the requested setting
 */
struct MHD_DaemonOptionAndValue
MHD_D_OPTION_NO_ALPN (
  enum MHD_Bool val
  );

/**
 * Specify inactivity timeout for connection.
 * When no activity for specified time on connection, it is closed automatically.
 * Use zero for no timeout, which is also the (unsafe!) default.
 * @param timeout the in seconds, zero for no timeout
 * @return structure with the requested setting
 */
struct MHD_DaemonOptionAndValue
MHD_D_OPTION_DEFAULT_TIMEOUT (
  unsigned int timeout
  );

/**
 * Maximum number of (concurrent) network connections served by daemon.
 * @note The real maximum number of network connections could be smaller
 *       than requested due to the system limitations, like FD_SETSIZE when
 *       polling by select() is used.
 * @param glob_limit FIXME
 * @return structure with the requested setting
 */
struct MHD_DaemonOptionAndValue
MHD_D_OPTION_GLOBAL_CONNECTION_LIMIT (
  unsigned int glob_limit
  );

/**
 * Limit on the number of (concurrent) network connections made to the server from the same IP address.
 * Can be used to prevent one IP from taking over all of the allowed connections. If the same IP tries to establish more than the specified number of connections, they will be immediately rejected.
 * @param limit FIXME
 * @return structure with the requested setting
 */
struct MHD_DaemonOptionAndValue
MHD_D_OPTION_PER_IP_LIMIT (
  unsigned int limit
  );

/**
 * Set a policy callback that accepts/rejects connections based on the client's IP address.  The callbeck function will be called before servicing any new incoming connection.
 * @param apc the accept policy callback
 * @param apc_cls the closure for the callback
 * @return structure with the requested setting
 */
struct MHD_DaemonOptionAndValue
MHD_D_OPTION_ACCEPT_POLICY (
  MHD_AcceptPolicyCallback apc,
  void *apc_cls
  );

/**
 * Set how strictly MHD will enforce the HTTP protocol.
 * @param sl the level of strictness
 * @param how the way how to use the requested level
 * @return structure with the requested setting
 */
struct MHD_DaemonOptionAndValue
MHD_D_OPTION_PROTOCOL_STRICT_LEVEL (
  enum MHD_ProtocolStrictLevel sl,
  enum MHD_UseStictLevel how
  );

/**
 * Set a callback to be called first for every request when the request line is received (before any parsing of the header).
 * This callback is the only way to get raw (unmodified) request URI as URI is parsed and modified by MHD in-place.
 * Mandatory URI modification may apply before this call, like binary zero replacement, as required by RFCs.
 * @param cb the early URI callback
 * @param cls the closure for the callback
 * @return structure with the requested setting
 */
struct MHD_DaemonOptionAndValue
MHD_D_OPTION_EARLY_URI_LOGGER (
  MHD_EarlyUriLogCallback cb,
  void *cls
  );

/**
 * Disable converting plus ('+') character to space in GET parameters (URI part after '?').
 * Plus conversion is not required by HTTP RFCs, however it required by HTML specifications, see https://url.spec.whatwg.org/#application/x-www-form-urlencoded for details.
 * By default plus is converted to space in the query part of URI.
 * @param val the value of the parameter * @return structure with the requested setting
 */
struct MHD_DaemonOptionAndValue
MHD_D_OPTION_DISABLE_URI_QUERY_PLUS_AS_SPACE (
  enum MHD_Bool val
  );

/**
 * Suppresse use of 'Date:' header.
 * According to RFC should be suppressed only if the system has no RTC.
 * The 'Date:' is not suppressed (the header is enabled) by default.
 * @param val the value of the parameter * @return structure with the requested setting
 */
struct MHD_DaemonOptionAndValue
MHD_D_OPTION_SUPPRESS_DATE_HEADER (
  enum MHD_Bool val
  );

/**
 * Use SHOUTcast for responses.
 * This will cause *all* responses to begin with the SHOUTcast 'ICY' line instead of 'HTTP'.
 * @param val the value of the parameter * @return structure with the requested setting
 */
struct MHD_DaemonOptionAndValue
MHD_D_OPTION_ENABLE_SHOUTCAST (
  enum MHD_Bool val
  );

/**
 * Maximum memory size per connection.
 * Default is 32kb.
 * Values above 128kb are unlikely to result in much performance benefit, as half of the memory will be typically used for IO, and TCP buffers are unlikely to support window sizes above 64k on most systems.
 * The size should be large enough to fit all request headers (together with internal parsing information).
 * @param val the value of the parameter * @return structure with the requested setting
 */
struct MHD_DaemonOptionAndValue
MHD_D_OPTION_CONN_MEMORY_LIMIT (
  size_t val
  );

/**
 * The size of the shared memory pool for accamulated upload processing.
 * The same large pool is shared for all connections server by MHD and used when application requests avoiding of incremental upload processing to accamulate complete content upload before giving it to the application.
 * Default is 8Mb.
 * Can be set to zero to disable share pool.
 * @param val the value of the parameter * @return structure with the requested setting
 */
struct MHD_DaemonOptionAndValue
MHD_D_OPTION_LARGE_POOL_SIZE (
  size_t val
  );

/**
 * Desired size of the stack for the threads started by MHD.
 * Use 0 for system default, which is also MHD default.
 * Works only with #MHD_D_OPTION_WM_WORKER_THREADS() or #MHD_D_OPTION_WM_THREAD_PER_CONNECTION().
 * @param val the value of the parameter * @return structure with the requested setting
 */
struct MHD_DaemonOptionAndValue
MHD_D_OPTION_STACK_SIZE (
  size_t val
  );

/**
 * The the maximum FD value.
 * The limit is applied to all sockets used by MHD.
 * If listen socket FD is equal or higher that specified value, the daemon fail to start.
 * If new connection FD is equal or higher that specified value, the connection is rejected.
 * Useful if application uses select() for polling the sockets, system FD_SETSIZE is good value for this option in such case.
 * Silently ignored on W32 (WinSock sockets).
 * @param max_fd FIXME
 * @return structure with the requested setting
 */
struct MHD_DaemonOptionAndValue
MHD_D_OPTION_FD_NUMBER_LIMIT (
  MHD_Socket max_fd
  );

/**
 * Enable `turbo`.
 * Disables certain calls to `shutdown()`, enables aggressive non-blocking optimistic reads and other potentially unsafe optimisations.
 * Most effects only happen with internal threads with epoll.
 * The 'turbo' mode is not enabled (mode is disabled) by default.
 * @param val the value of the parameter * @return structure with the requested setting
 */
struct MHD_DaemonOptionAndValue
MHD_D_OPTION_TURBO (
  enum MHD_Bool val
  );

/**
 * Disable some internal thread safety.
 * Indicates that MHD daemon will be used by application in single-threaded mode only.  When this flag is set then application must call any MHD function only within a single thread.
 * This flag turns off some internal thread-safety and allows MHD making some of the internal optimisations suitable only for single-threaded environment.
 * Not compatible with any internal threads modes.
 * If MHD is compiled with custom configuration for embedded projects without threads support, this option is mandatory.
 * Thread safety is not disabled (safety is enabled) by default.
 * @param val the value of the parameter * @return structure with the requested setting
 */
struct MHD_DaemonOptionAndValue
MHD_D_OPTION_DISABLE_THREAD_SAFETY (
  enum MHD_Bool val
  );

/**
 * You need to set this option if you want to disable use of HTTP Upgrade.
 * Upgrade may require usage of additional internal resources, which we can avoid providing if they will not be used.
 * You should only use this option if you do not use upgrade functionality and need a generally minor boost in performance and resources saving.
 * The upgrade is not disallowed (upgrade is allowed) by default.
 * @param val the value of the parameter * @return structure with the requested setting
 */
struct MHD_DaemonOptionAndValue
MHD_D_OPTION_DISALLOW_UPGRADE (
  enum MHD_Bool val
  );

/**
 * Disable #MHD_action_suspend() functionality.
 *
You should only use this function if you do not use suspend functionality and need a generally minor boost in performance.
 * The suspend is not disallowed (suspend is allowed) by default.
 * @param val the value of the parameter * @return structure with the requested setting
 */
struct MHD_DaemonOptionAndValue
MHD_D_OPTION_DISALLOW_SUSPEND_RESUME (
  enum MHD_Bool val
  );

/**
 * Set a callback to be called for pre-start finalisation.
 *
The specified callback will be called one time, after network initialisation, TLS pre-initialisation, but before the start of the internal threads (if allowed)
 * @param cb the pre-start callback
 * @param cb_cls the closure for the callback
 * @return structure with the requested setting
 */
struct MHD_DaemonOptionAndValue
MHD_D_OPTION_DAEMON_READY_CALLBACK (
  MHD_DaemonReadyCallback cb,
  void *cb_cls
  );

/**
 * Set a function that should be called whenever a connection is started or closed.
 * @param ncc the callback for notifications
 * @param cls the closure for the callback
 * @return structure with the requested setting
 */
struct MHD_DaemonOptionAndValue
MHD_D_OPTION_NOTIFY_CONNECTION (
  MHD_NotifyConnectionCallback ncc,
  void *cls
  );

/**
 * Register a function that should be called whenever a stream is started or closed.
 * For HTTP/1.1 this callback is called one time for every connection.
 * @param nsc the callback for notifications
 * @param cls the closure for the callback
 * @return structure with the requested setting
 */
struct MHD_DaemonOptionAndValue
MHD_D_OPTION_NOTIFY_STREAM (
  MHD_NotifyStreamCallback nsc,
  void *cls
  );

/**
 * Set strong random data to be used by MHD.
 * Currently the data is only needed for Digest Auth module.
 * The recommended size is between 8 and 32 bytes. Security can be lower for sizes less or equal four.
 * Sizes larger then 32 (or, probably, larger than 16 - debatable) will not increase the security.
 * @param buf_size the size of the buffer
 * @param buf the buffer with strong random data, the content will be copied by MHD
 * @return structure with the requested setting
 */
struct MHD_DaemonOptionAndValue
MHD_D_OPTION_RANDOM_ENTROPY (
  size_t buf_size,
  /* const */ void *buf
  );

/**
 * Specify the size of the internal hash map array that tracks generated digest nonces usage.
 * When the size of the map is too small then need to handle concurrent DAuth requests, a lot of stale nonce results will be produced.
 * By default the size is 8 bytes (very small).
 * @param size the size of the map array
 * @return structure with the requested setting
 */
struct MHD_DaemonOptionAndValue
MHD_D_OPTION_DAUTH_MAP_SIZE (
  size_t size
  );

/**
 * Control the scope of validity of MHD-generated nonces.
 * This regulates how nonces are generated and how nonces are checked by #MHD_digest_auth_check() and similar functions.
 * This option allows bitwise OR combination of #MHD_DaemonOptionValueDAuthBindNonce values.
 * When this option is not used then default value is #MHD_D_OPTION_VALUE_DAUTH_BIND_NONCE_NONE.
 * @param bind_type FIXME
 * @return structure with the requested setting
 */
struct MHD_DaemonOptionAndValue
MHD_D_OPTION_DAUTH_NONCE_BIND_TYPE (
  enum MHD_DaemonOptionValueDAuthBindNonce bind_type
  );

/**
 * Default nonce timeout value (in seconds) used for Digest Auth.
 * Silently ignored if followed by zero value.
 * @see #MHD_digest_auth_check(), MHD_digest_auth_check_digest()
 * @param timeout FIXME
 * @return structure with the requested setting
 */
struct MHD_DaemonOptionAndValue
MHD_D_OPTION_DAUTH_DEF_NONCE_TIMEOUT (
  unsigned int timeout
  );

/**
 * Default maximum nc (nonce count) value used for Digest Auth.
 * Silently ignored if followed by zero value.
 * @see #MHD_digest_auth_check(), MHD_digest_auth_check_digest()
 * @param max_nc FIXME
 * @return structure with the requested setting
 */
struct MHD_DaemonOptionAndValue
MHD_D_OPTION_DAUTH_DEF_MAX_NC (
  uint_fast32_t max_nc
  );

/* End of generated code documenting how to use options */
#endif

/* Beginning of generated code documenting how to use options.
   You should treat the following functions *as if* they were
   part of the header/API. The actual declarations are more
   complex, so these here are just for documentation!
   We do not actually *build* this code... */
#if 0

/**
 * Make the response object re-usable. (FIXME: not used in struct ResponseOptions; remove!?)
 * The response will not be consumed by MHD_action_from_response() and must be destroyed by MHD_response_destroy().
 * Useful if the same response is often used to reply.
 * @param val the value of the parameter * @return structure with the requested setting
 */
struct MHD_ResponseOptionAndValue
MHD_R_OPTION_REUSABLE (
  enum MHD_Bool val
  );

/**
 * Enable special processing of the response as body-less (with undefined body size). No automatic 'Content-Length' or 'Transfer-Encoding: chunked' headers are added when the response is used with #MHD_HTTP_STATUS_NOT_MODIFIED code or to respond to HEAD request.
 * The flag also allow to set arbitrary 'Content-Length' by #MHD_response_add_header() function.
 * This flag value can be used only with responses created without body (zero-size body).
 * Responses with this flag enabled cannot be used in situations where reply body must be sent to the client.
 * This flag is primarily intended to be used when automatic 'Content-Length' header is undesirable in response to HEAD requests.
 * @param val the value of the parameter * @return structure with the requested setting
 */
struct MHD_ResponseOptionAndValue
MHD_R_OPTION_HEAD_ONLY_RESPONSE (
  enum MHD_Bool val
  );

/**
 * Force use of chunked encoding even if the response content size is known.
 * Ignored when the reply cannot have body/content.
 * @param val the value of the parameter * @return structure with the requested setting
 */
struct MHD_ResponseOptionAndValue
MHD_R_OPTION_CHUNKED_ENC (
  enum MHD_Bool val
  );

/**
 * Force close connection after sending the response, prevents keep-alive connections and adds 'Connection: close' header.
 * @param val the value of the parameter * @return structure with the requested setting
 */
struct MHD_ResponseOptionAndValue
MHD_R_OPTION_CONN_CLOSE (
  enum MHD_Bool val
  );

/**
 * Only respond in conservative (dumb) HTTP/1.0-compatible mode.
 * Response still use HTTP/1.1 version in header, but always close the connection after sending the response and do not use chunked encoding for the response.
 * You can also set the #MHD_R_O_HTTP_1_0_SERVER flag to force HTTP/1.0 version in the response.
 * Responses are still compatible with HTTP/1.1.
 * Summary:
 * + declared reply version: HTTP/1.1
 * + keep-alive: no
 * + chunked: no
 *
This option can be used to communicate with some broken client, which does not implement HTTP/1.1 features, but advertises HTTP/1.1 support.
 * @param val the value of the parameter * @return structure with the requested setting
 */
struct MHD_ResponseOptionAndValue
MHD_R_OPTION_HTTP_1_0_COMPATIBLE_STRICT (
  enum MHD_Bool val
  );

/**
 * Only respond in HTTP/1.0-mode.
 * Contrary to the #MHD_R_O_HTTP_1_0_COMPATIBLE_STRICT flag, the response's HTTP version will always be set to 1.0 and keep-alive connections will be used if explicitly requested by the client.
 * The 'Connection:' header will be added for both 'close' and 'keep-alive' connections.
 * Chunked encoding will not be used for the response.
 * Due to backward compatibility, responses still can be used with HTTP/1.1 clients.
 * This option can be used to emulate HTTP/1.0 server (for response part only as chunked encoding in requests (if any) is processed by MHD).
 * Summary:
 * + declared reply version: HTTP/1.0
 * + keep-alive: possible
 * + chunked: no
 *
With this option HTTP/1.0 server is emulated (with support for 'keep-alive' connections).
 * @param val the value of the parameter * @return structure with the requested setting
 */
struct MHD_ResponseOptionAndValue
MHD_R_OPTION_HTTP_1_0_SERVER (
  enum MHD_Bool val
  );

/**
 * Disable sanity check preventing clients from manually setting the HTTP content length option.
 * Allow to set several 'Content-Length' headers. These headers will be used even with replies without body.
 * @param val the value of the parameter * @return structure with the requested setting
 */
struct MHD_ResponseOptionAndValue
MHD_R_OPTION_INSANITY_HEADER_CONTENT_LENGTH (
  enum MHD_Bool val
  );

/**
 * Set a function to be called once MHD is finished with the request.
 * @param term_cb the function to call,
 *   NULL to not use the callback
 * @param term_cb_cls the closure for the callback
 * @return structure with the requested setting
 */
struct MHD_ResponseOptionAndValue
MHD_R_OPTION_TERMINATION_CALLBACK (
  MHD_RequestTerminationCallback term_cb,
  void *term_cb_cls
  );

/* End of generated code documenting how to use options */
#endif

/**
 * Create parameter for #MHD_daemon_set_options() for work mode with
 * no internal threads.
 * The application periodically calls #MHD_daemon_process_blocking(), where
 * MHD internally checks all sockets automatically.
 * This is the default mode.
 * @return the object of struct MHD_DaemonOptionAndValue with requested values
 */
#define MHD_D_OPTION_WM_EXTERNAL_PERIODIC() \
        MHD_D_OPTION_WORK_MODE (MHD_WM_OPTION_EXTERNAL_PERIODIC ())

/**
* Create parameter for #MHD_daemon_set_options() for work mode with
* an external event loop with level triggers.
* Application uses #MHD_SocketRegistrationUpdateCallback, level triggered
* sockets polling (like select() or poll()) and #MHD_daemon_event_update().
* @param cb_val the callback for sockets registration
* @param cb_cls_val the closure for the @a cv_val callback
* @return the object of struct MHD_DaemonOptionAndValue with requested values
*/
#define MHD_D_OPTION_WM_EXTERNAL_EVENT_LOOP_CB_LEVEL(cb_val,cb_cls_val) \
        MHD_D_OPTION_WORK_MODE ( \
          MHD_WM_OPTION_EXTERNAL_EVENT_LOOP_CB_LEVEL ((cb_val),(cb_cls_val)))

/**
 * Create parameter for #MHD_daemon_set_options() for work mode with
 * an external event loop with edge triggers.
 * Application uses #MHD_SocketRegistrationUpdateCallback, edge triggered
 * sockets polling (like epoll with EPOLLET) and #MHD_daemon_event_update().
 * @param cb_val the callback for sockets registration
 * @param cb_cls_val the closure for the @a cv_val callback
 * @return the object of struct MHD_DaemonOptionAndValue with requested values
 */
#define MHD_D_OPTION_WM_EXTERNAL_EVENT_LOOP_CB_EDGE(cb_val,cb_cls_val) \
        MHD_D_OPTION_WORK_MODE ( \
          MHD_WM_OPTION_EXTERNAL_EVENT_LOOP_CB_EDGE ((cb_val),(cb_cls_val)))

/**
 * Create parameter for #MHD_daemon_set_options() for work mode with
 * no internal threads and aggregate watch FD.
 * Application uses #MHD_DAEMON_INFO_FIXED_AGGREAGATE_FD to get single FD
 * that gets triggered by any MHD event.
 * This FD can be watched as an aggregate indicator for all MHD events.
 * This mode is available only on selected platforms (currently
 * GNU/Linux only), see #MHD_LIB_INFO_FIXED_HAS_AGGREGATE_FD.
 * When the FD is triggered, #MHD_daemon_process_nonblocking() should
 * be called.
 * @return the object of struct MHD_DaemonOptionAndValue with requested values
 */
#define MHD_D_OPTION_WM_EXTERNAL_SINGLE_FD_WATCH() \
        MHD_D_OPTION_WORK_MODE (MHD_WM_OPTION_EXTERNAL_SINGLE_FD_WATCH ())

/**
 * Create parameter for #MHD_daemon_set_options() for work mode with
 * one or more worker threads.
 * If number of threads is one, then daemon starts with single worker thread
 * that handles all connections.
 * If number of threads is larger than one, then that number of worker threads,
 * and handling of connection is distributed among the workers.
 * @param num_workers the number of worker threads, zero is treated as one
 * @return the object of struct MHD_DaemonOptionAndValue with requested values
 */
#define MHD_D_OPTION_WM_WORKER_THREADS(num_workers) \
        MHD_D_OPTION_WORK_MODE (MHD_WM_OPTION_WORKER_THREADS (num_workers))

/**
 * Create parameter for #MHD_daemon_set_options() for work mode with
 * one internal thread for listening and additional threads per every
 * connection.  Use this if handling requests is CPU-intensive or blocking,
 * your application is thread-safe and you have plenty of memory (per
 * connection).
 * @return the object of struct MHD_DaemonOptionAndValue with requested values
 */
#define MHD_D_OPTION_WM_THREAD_PER_CONNECTION() \
        MHD_D_OPTION_WORK_MODE (MHD_WM_OPTION_THREAD_PER_CONNECTION ())

/**
 * Set the requested options for the daemon.
 *
 * If any option fail other options may be or may be not applied.
 * @param daemon the daemon to set the options
 * @param[in] options the pointer to the array with the options;
 *                    the array processing stops at the first ::MHD_D_O_END
 *                    option, but not later than after processing
 *                    @a options_max_num entries
 * @param options_max_num the maximum number of entries in the @a options,
 *                        use #MHD_OPTIONS_ARRAY_MAX_SIZE if options processing
 *                        must stop only at zero-termination option
 * @return ::MHD_SC_OK on success,
 *         error code otherwise
 */
MHD_EXTERN_ enum MHD_StatusCode
MHD_daemon_set_options (
  struct MHD_Daemon *MHD_RESTRICT daemon,
  const struct MHD_DaemonOptionAndValue *MHD_RESTRICT options,
  size_t options_max_num)
MHD_FN_PAR_NONNULL_ALL_;


/**
 * Set the requested single option for the daemon.
 *
 * @param daemon the daemon to set the option
 * @param[in] option_ptr the pointer to the option
 * @return ::MHD_SC_OK on success,
 *         error code otherwise
 */
#define MHD_daemon_set_option(daemon, option_ptr) \
        MHD_daemon_set_options (daemon, options_ptr, 1)


/* *INDENT-OFF* */
#ifdef MHD_USE_VARARG_MACROS
MHD_NOWARN_VARIADIC_MACROS_
#  if defined(MHD_USE_COMPOUND_LITERALS) && \
  defined(MHD_USE_COMP_LIT_FUNC_PARAMS)
/**
 * Set the requested options for the daemon.
 *
 * If any option fail other options may be or may be not applied.
 *
 * It should be used with helpers that creates required options, for example:
 *
 * MHD_DAEMON_SET_OPTIONS(d, MHD_D_OPTION_SUPPRESS_DATE_HEADER(MHD_YES),
 *                        MHD_D_OPTION_SOCK_ADDR(sa_len, sa))
 *
 * @param daemon the daemon to set the options
 * @param ... the list of the options, each option must be created
 *            by helpers MHD_D_OPTION_NameOfOption(option_value)
 * @return ::MHD_SC_OK on success,
 *         error code otherwise
 */
#    define MHD_DAEMON_SET_OPTIONS(daemon,...)          \
        MHD_NOWARN_COMPOUND_LITERALS_                   \
        MHD_daemon_set_options (                        \
          daemon,                                       \
          ((const struct MHD_DaemonOptionAndValue[])    \
           {__VA_ARGS__, MHD_D_OPTION_TERMINATE ()}),   \
          MHD_OPTIONS_ARRAY_MAX_SIZE)                   \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_
#  elif defined(MHD_USE_CPP_INIT_LIST)
MHD_C_DECLRATIONS_FINISH_HERE_
#    include <vector>
MHD_C_DECLRATIONS_START_HERE_
/**
 * Set the requested options for the daemon.
 *
 * If any option fail other options may be or may be not applied.
 *
 * It should be used with helpers that creates required options, for example:
 *
 * MHD_DAEMON_SET_OPTIONS(d, MHD_D_OPTION_SUPPRESS_DATE_HEADER(MHD_YES),
 *                        MHD_D_OPTION_SOCK_ADDR(sa_len, sa))
 *
 * @param daemon the daemon to set the options
 * @param ... the list of the options, each option must be created
 *            by helpers MHD_D_OPTION_NameOfOption(option_value)
 * @return ::MHD_SC_OK on success,
 *         error code otherwise
 */
#    define MHD_DAEMON_SET_OPTIONS(daemon,...)                  \
        MHD_NOWARN_CPP_INIT_LIST_                               \
        MHD_daemon_set_options (                                \
          daemon,                                               \
          (std::vector<struct MHD_DaemonOptionAndValue>         \
           {__VA_ARGS__,MHD_D_OPTION_TERMINATE ()}).data (),    \
          MHD_OPTIONS_ARRAY_MAX_SIZE)                           \
        MHD_RESTORE_WARN_CPP_INIT_LIST_
#  endif
MHD_RESTORE_WARN_VARIADIC_MACROS_
#endif /* MHD_USE_VARARG_MACROS && MHD_USE_COMP_LIT_FUNC_PARAMS */
/* *INDENT-ON* */


/* ******************* Event loop ************************ */


/**
 * Run websever operation with possible blocking.
 *
 * Supported only in #MHD_WM_EXTERNAL_PERIODIC and
 * #MHD_WM_EXTERNAL_SINGLE_FD_WATCH modes.
 *
 * This function does the following: waits for any network event not more than
 * specified number of microseconds, processes all incoming and outgoing data,
 * processes new connections, processes any timed-out connection, and does
 * other things required to run webserver.
 * Once all connections are processed, function returns.
 *
 * This function is useful for quick and simple (lazy) webserver implementation
 * if application needs to run a single thread only and does not have any other
 * network activity.
 *
 * In #MHD_WM_EXTERNAL_PERIODIC mode if @a microsec parameter is not zero
 * this function determines the internal daemon timeout and use returned value
 * as maximum wait time if it less than value of @a microsec parameter.
 *
 * @param daemon the daemon to run
 * @param microsec the maximum time in microseconds to wait for network and
 *                 other events. Note: there is no guarantee that function
 *                 blocks for the specified amount of time. The real processing
 *                 time can be shorter (if some data or connection timeout
 *                 comes earlier) or longer (if data processing requires more
 *                 time, especially in user callbacks).
 *                 If set to '0' then function does not block and processes
 *                 only already available data (if any). Zero value is
 *                 recommended when used in #MHD_WM_EXTERNAL_SINGLE_FD_WATCH
 *                 and the watched FD has been triggered.
 *                 If set to #MHD_WAIT_INDEFINITELY then function waits
 *                 for events indefinitely (blocks until next network activity
 *                 or connection timeout).
 *                 Always used as zero value in
 *                 #MHD_WM_EXTERNAL_SINGLE_FD_WATCH mode.
 * @return #MHD_SC_OK on success, otherwise
 *         an error code
 * @ingroup event
 */
MHD_EXTERN_ enum MHD_StatusCode
MHD_daemon_process_blocking (struct MHD_Daemon *daemon,
                             uint_fast64_t microsec)
MHD_FN_PAR_NONNULL_ (1);

/**
 * Run webserver operations (without blocking unless in client
 * callbacks).
 *
 * Supported only in #MHD_WM_EXTERNAL_SINGLE_FD_WATCH mode.
 *
 * This function does the following: processes all incoming and outgoing data,
 * processes new connections, processes any timed-out connection, and does
 * other things required to run webserver.
 * Once all connections are processed, function returns.
 *
 * @param daemon the daemon to run
 * @return #MHD_SC_OK on success, otherwise
 *         an error code
 * @ingroup event
 */
#define MHD_daemon_process_nonblocking(daemon) \
        MHD_daemon_process_blocking (daemon, 0)


/**
 * Add another client connection to the set of connections managed by
 * MHD.  This API is usually not needed (since MHD will accept inbound
 * connections on the server socket).  Use this API in special cases,
 * for example if your HTTP server is behind NAT and needs to connect
 * out to the HTTP client, or if you are building a proxy.
 *
 * The given client socket will be managed (and closed!) by MHD after
 * this call and must no longer be used directly by the application
 * afterwards.
 * The client socket will be closed by MHD even if error returned.
 *
 * @param daemon daemon that manages the connection
 * @param client_socket socket to manage (MHD will expect
 *        to receive an HTTP request from this socket next).
 * @param[in] addr IP address of the client
 * @param addrlen number of bytes in @a addr
 * @param connection_cntx meta data the application wants to
 *        associate with the new connection object
 * @return #MHD_SC_OK on success
 *         error on failure
 * @ingroup specialized
 */
MHD_EXTERN_ enum MHD_StatusCode
MHD_daemon_add_connection (struct MHD_Daemon *MHD_RESTRICT daemon,
                           MHD_Socket client_socket,
                           size_t addrlen,
                           const struct sockaddr *addr,
                           void *connection_cntx)
MHD_FN_PAR_NONNULL_ (1)
MHD_FN_PAR_IN_ (4);


/* ********************* connection options ************** */

enum MHD_FIXED_ENUM_APP_SET_ MHD_ConnectionOption
{
  /**
   * Not a real option.
   * Should not be used directly.
   * This value indicates the end of the list of the options.
   */
  MHD_C_O_END = 0
  ,
  /**
   * Set custom timeout for the given connection.
   * Specified as the number of seconds.  Use zero for no timeout.
   * Setting this option resets connection timeout timer.
   */
  MHD_C_O_TIMEOUT = 1
  ,


  /* * Sentinel * */
  /**
   * The sentinel value.
   * This value enforces specific underlying integer type for the enum.
   * Do not use.
   */
  MHD_C_O_SENTINEL = 65535
};


/**
 * Dummy-struct for space allocation.
 * Do not use in application logic.
 */
struct MHD_ReservedStruct
{
  uint_fast64_t reserved1;
  void *reserved2;
};


/**
 * Parameters for MHD connection options
 */
union MHD_ConnectionOptionValue
{
  /**
   * Value for #MHD_C_O_TIMEOUT
   */
  unsigned int v_timeout;
  /**
   * Reserved member. Do not use.
   */
  struct MHD_ReservedStruct reserved;
};

/**
 * Combination of MHD connection option with parameters values
 */
struct MHD_ConnectionOptionAndValue
{
  /**
   * The connection configuration option
   */
  enum MHD_ConnectionOption opt;
  /**
   * The value for the @a opt option
   */
  union MHD_ConnectionOptionValue val;
};

#if defined(MHD_USE_COMPOUND_LITERALS) && defined(MHD_USE_DESIG_NEST_INIT)
/**
 * Set custom timeout for the given connection.
 * Specified as the number of seconds.  Use zero for no timeout.
 * Setting this option resets connection timeout timer.
 * @param timeout the in seconds, zero for no timeout
 * @return the object of struct MHD_ConnectionOptionAndValue with the requested
 *         values
 */
#  define MHD_C_OPTION_TIMEOUT(timeout)         \
        MHD_NOWARN_COMPOUND_LITERALS_                 \
          (const struct MHD_ConnectionOptionAndValue) \
        {                                             \
          .opt = (MHD_C_O_TIMEOUT),                   \
          .val.v_timeout = (timeout)                  \
        }                                             \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_

/**
 * Terminate the list of the options
 * @return the terminating object of struct MHD_ConnectionOptionAndValue
 */
#  define MHD_C_OPTION_TERMINATE()              \
        MHD_NOWARN_COMPOUND_LITERALS_                 \
          (const struct MHD_ConnectionOptionAndValue) \
        {                                             \
          .opt = (MHD_C_O_END)                        \
        }                                             \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_

#else  /* !MHD_USE_COMPOUND_LITERALS || !MHD_USE_DESIG_NEST_INIT */
MHD_NOWARN_UNUSED_FUNC_

/**
 * Set custom timeout for the given connection.
 * Specified as the number of seconds.  Use zero for no timeout.
 * Setting this option resets connection timeout timer.
 * @param timeout the in seconds, zero for no timeout
 * @return the object of struct MHD_ConnectionOptionAndValue with the requested
 *         values
 */
static MHD_INLINE struct MHD_ConnectionOptionAndValue
MHD_C_OPTION_TIMEOUT (unsigned int timeout)
{
  struct MHD_ConnectionOptionAndValue opt_val;

  opt_val.opt = MHD_C_O_TIMEOUT;
  opt_val.val.v_timeout = timeout;

  return opt_val;
}


/**
 * Terminate the list of the options
 * @return the terminating object of struct MHD_ConnectionOptionAndValue
 */
static MHD_INLINE struct MHD_ConnectionOptionAndValue
MHD_C_OPTION_TERMINATE (void)
{
  struct MHD_ConnectionOptionAndValue opt_val;

  opt_val.opt = MHD_C_O_END;

  return opt_val;
}


MHD_RESTORE_WARN_UNUSED_FUNC_
#endif /* !MHD_USE_COMPOUND_LITERALS || !MHD_USE_DESIG_NEST_INIT */

/**
 * Set the requested options for the connection.
 *
 * If any option fail other options may be or may be not applied.
 * @param connection the connection to set the options
 * @param[in] options the pointer to the array with the options;
 *                    the array processing stops at the first ::MHD_D_O_END
 *                    option, but not later than after processing
 *                    @a options_max_num entries
 * @param options_max_num the maximum number of entries in the @a options,
 *                        use #MHD_OPTIONS_ARRAY_MAX_SIZE if options processing
 *                        must stop only at zero-termination option
 * @return ::MHD_SC_OK on success,
 *         error code otherwise
 */
MHD_EXTERN_ enum MHD_StatusCode
MHD_connection_set_options (
  struct MHD_Connection *MHD_RESTRICT connection,
  const struct MHD_ConnectionOptionAndValue *MHD_RESTRICT options,
  size_t options_max_num)
MHD_FN_PAR_NONNULL_ALL_;


/**
 * Set the requested single option for the connection.
 *
 * @param connection the connection to set the options
 * @param[in] option_ptr the pointer to the option
 * @return ::MHD_SC_OK on success,
 *         error code otherwise
 */
#define MHD_connection_set_option(connection, option_ptr) \
        MHD_connection_set_options (connection, options_ptr, 1)


/* *INDENT-OFF* */
#ifdef MHD_USE_VARARG_MACROS
MHD_NOWARN_VARIADIC_MACROS_
#  if defined(MHD_USE_COMPOUND_LITERALS) && defined(MHD_USE_COMP_LIT_FUNC_PARAMS \
                                                    )
/**
 * Set the requested options for the connection.
 *
 * If any option fail other options may be or may be not applied.
 *
 * It should be used with helpers that creates required options, for example:
 *
 * MHD_CONNECTION_SET_OPTIONS(d, MHD_C_OPTION_TIMEOUT(30))
 *
 * @param connection the connection to set the options
 * @param ... the list of the options, each option must be created
 *            by helpers MHD_C_OPTION_NameOfOption(option_value)
 * @return ::MHD_SC_OK on success,
 *         error code otherwise
 */
#    define MHD_CONNECTION_SET_OPTIONS(connection,...)          \
        MHD_NOWARN_COMPOUND_LITERALS_                           \
        MHD_connection_set_options (                            \
          daemon,                                               \
          ((const struct MHD_ConnectionOptionAndValue [])       \
           {__VA_ARGS__, MHD_C_OPTION_TERMINATE ()}),           \
          MHD_OPTIONS_ARRAY_MAX_SIZE)                           \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_
#  elif defined(MHD_USE_CPP_INIT_LIST)
MHD_C_DECLRATIONS_FINISH_HERE_
#    include <vector>
MHD_C_DECLRATIONS_START_HERE_
/**
 * Set the requested options for the connection.
 *
 * If any option fail other options may be or may be not applied.
 *
 * It should be used with helpers that creates required options, for example:
 *
 * MHD_CONNECTION_SET_OPTIONS(d, MHD_C_OPTION_TIMEOUT(30))
 *
 * @param connection the connection to set the options
 * @param ... the list of the options, each option must be created
 *            by helpers MHD_C_OPTION_NameOfOption(option_value)
 * @return ::MHD_SC_OK on success,
 *         error code otherwise
 */
#    define MHD_CONNECTION_SET_OPTIONS(daemon,...)              \
        MHD_NOWARN_CPP_INIT_LIST_                               \
        MHD_daemon_set_options (                                \
          daemon,                                               \
          (std::vector<struct MHD_ConnectionOptionAndValue>     \
           {__VA_ARGS__,MHD_C_OPTION_TERMINATE ()}).data (),    \
          MHD_OPTIONS_ARRAY_MAX_SIZE)                           \
        MHD_RESTORE_WARN_CPP_INIT_LIST_
#  endif
MHD_RESTORE_WARN_VARIADIC_MACROS_
#endif /* MHD_USE_VARARG_MACROS && MHD_USE_COMP_LIT_FUNC_PARAMS */
/* *INDENT-ON* */


/* **************** Request handling functions ***************** */


/**
 * The `enum MHD_ValueKind` specifies the source of
 * the name-value pairs in the HTTP protocol.
 */
enum MHD_FLAGS_ENUM_ MHD_ValueKind
{

  /**
   * HTTP header.
   */
  MHD_VK_HEADER = (1 << 0)
  ,
  /**
   * Cookies.  Note that the original HTTP header containing
   * the cookie(s) will still be available and intact.
   */
  MHD_VK_COOKIE = (1 << 1)
  ,
  /**
   * GET (URI) arguments.
   */
  MHD_VK_GET_ARGUMENT = (1 << 2)
  ,
  /**
   * POST data.
   * This is available only if a content encoding
   * supported by MHD is used, and only if the posted content
   * fits within the available memory pool.
   *
   * @warning The encoding "multipart/form-data" has more fields than just
   * "name" and "value". See #MHD_request_get_post_data_cb() and
   * #MHD_request_get_post_data_list(). In particular it could be important
   * to check used "Transfer-Encoding". While it is deprecated and not used
   * by modern clients, formally it can be used.
   */
  MHD_VK_POSTDATA = (1 << 3)
  ,
  /**
   * HTTP footer (only for HTTP 1.1 chunked encodings).
   */
  MHD_VK_FOOTER = (1 << 4)
  ,
  /**
   * Header and footer values
   */
  MHD_VK_HEADER_FOOTER = MHD_VK_HEADER | MHD_VK_FOOTER
  ,
  /**
   * Values from get arguments or post data
   */
  MHD_VK_GET_POST = MHD_VK_POSTDATA | MHD_VK_GET_ARGUMENT
};

/**
 * Name with value pair
 */
struct MHD_NameAndValue
{
  /**
   * The name (key) of the field.
   * The pointer to the C string must never be NULL.
   * Some types (kinds) allow empty strings.
   */
  struct MHD_String name;
  /**
   * The value of the field.
   * Some types (kinds) allow absence of the value. The absence is indicated
   * by NULL pointer to the C string.
   */
  struct MHD_StringNullable value;
};

/**
 * Name, value and kind (type) of data
 */
struct MHD_NameValueKind
{
  /**
   * The name and the value of the field
   */
  struct MHD_NameAndValue nv;
  /**
   * The kind (type) of the field
   */
  enum MHD_ValueKind kind;
};

/**
 * Iterator over name-value pairs.  This iterator can be used to
 * iterate over all of the cookies, headers, or POST-data fields of a
 * request, and also to iterate over the headers that have been added
 * to a response.
 *
 * The pointers to the strings in @a nvt are valid until the response
 * is queued. If the data is needed beyond this point, it should be copied.
 *
 * @param cls closure
 * @param nvt the name, the value and the kind of the element
 * @return #MHD_YES to continue iterating,
 *         #MHD_NO to abort the iteration
 * @ingroup request
 */
typedef enum MHD_Bool
(MHD_FN_PAR_NONNULL_ (2)
 *MHD_NameValueIterator)(void *cls,
                         const struct MHD_NameValueKind *nvt);


/**
 * Get all of the headers (or other kind of request data) via callback.
 *
 * @param[in,out] request request to get values from
 * @param kind types of values to iterate over, can be a bitmask
 * @param iterator callback to call on each header;
 *        maybe NULL (then just count headers)
 * @param iterator_cls extra argument to @a iterator
 * @return number of entries iterated over
 * @ingroup request
 */
MHD_EXTERN_ size_t
MHD_request_get_values_cb (struct MHD_Request *request,
                           enum MHD_ValueKind kind,
                           MHD_NameValueIterator iterator,
                           void *iterator_cls)
MHD_FN_PAR_NONNULL_ (1);


/**
 * Get all of the headers (or other kind of request data) from the request.
 *
 * The pointers to the strings in @a elements are valid until the response
 * is queued. If the data is needed beyond this point, it should be copied.
 *
 * @param[in] request request to get values from
 * @param kind the types of values to get, can be a bitmask
 * @param num_elements the number of elements in @a elements array
 * @param[out] elements the array of @a num_elements strings to be filled with
 *                      the key-value pairs; if @a request has more elements
 *                      than @a num_elements than any @a num_elements are
 *                      stored
 * @return the number of elements stored in @a elements, the
 *         number cannot be larger then @a num_elements,
 *         zero if there is no such values or any error occurs
 */
MHD_EXTERN_ size_t
MHD_request_get_values_list (
  struct MHD_Request *request,
  enum MHD_ValueKind kind,
  size_t num_elements,
  struct MHD_NameValueKind elements[MHD_FN_PAR_DYN_ARR_SIZE_ (num_elements)])
MHD_FN_PAR_NONNULL_ (1)
MHD_FN_PAR_NONNULL_ (4) MHD_FN_PAR_OUT_SIZE_ (4,3);


/**
 * Get a particular header (or other kind of request data) value.
 * If multiple values match the kind, return any one of them.
 *
 * The returned pointer is valid until the response is queued.
 * If the data is needed beyond this point, it should be copied.
 *
 * @param request request to get values from
 * @param kind what kind of value are we looking for
 * @param key the header to look for, empty to lookup 'trailing' value
 *            without a key
 * @return NULL if no such item was found
 * @ingroup request
 */
MHD_EXTERN_ const struct MHD_StringNullable *
MHD_request_get_value (struct MHD_Request *MHD_RESTRICT request,
                       enum MHD_ValueKind kind,
                       const char *MHD_RESTRICT key)
MHD_FN_PAR_NONNULL_ (1)
MHD_FN_PAR_NONNULL_ (3) MHD_FN_PAR_CSTR_ (3);


/**
 * @brief Status codes defined for HTTP responses.
 *
 * @defgroup httpcode HTTP response codes
 * @{
 */
/* Registry export date: 2023-09-29 */
/* See http://www.iana.org/assignments/http-status-codes/http-status-codes.xhtml */
enum MHD_FIXED_ENUM_APP_SET_ MHD_HTTP_StatusCode
{
  /* 100 "Continue".            RFC9110, Section 15.2.1. */
  MHD_HTTP_STATUS_CONTINUE =                    100
  ,
  /* 101 "Switching Protocols". RFC9110, Section 15.2.2. */
  MHD_HTTP_STATUS_SWITCHING_PROTOCOLS =         101
  ,
  /* 102 "Processing".          RFC2518. */
  MHD_HTTP_STATUS_PROCESSING =                  102
  ,
  /* 103 "Early Hints".         RFC8297. */
  MHD_HTTP_STATUS_EARLY_HINTS =                 103
  ,

  /* 200 "OK".                  RFC9110, Section 15.3.1. */
  MHD_HTTP_STATUS_OK =                          200
  ,
  /* 201 "Created".             RFC9110, Section 15.3.2. */
  MHD_HTTP_STATUS_CREATED =                     201
  ,
  /* 202 "Accepted".            RFC9110, Section 15.3.3. */
  MHD_HTTP_STATUS_ACCEPTED =                    202
  ,
  /* 203 "Non-Authoritative Information". RFC9110, Section 15.3.4. */
  MHD_HTTP_STATUS_NON_AUTHORITATIVE_INFORMATION = 203
  ,
  /* 204 "No Content".          RFC9110, Section 15.3.5. */
  MHD_HTTP_STATUS_NO_CONTENT =                  204
  ,
  /* 205 "Reset Content".       RFC9110, Section 15.3.6. */
  MHD_HTTP_STATUS_RESET_CONTENT =               205
  ,
  /* 206 "Partial Content".     RFC9110, Section 15.3.7. */
  MHD_HTTP_STATUS_PARTIAL_CONTENT =             206
  ,
  /* 207 "Multi-Status".        RFC4918. */
  MHD_HTTP_STATUS_MULTI_STATUS =                207
  ,
  /* 208 "Already Reported".    RFC5842. */
  MHD_HTTP_STATUS_ALREADY_REPORTED =            208
  ,

  /* 226 "IM Used".             RFC3229. */
  MHD_HTTP_STATUS_IM_USED =                     226
  ,

  /* 300 "Multiple Choices".    RFC9110, Section 15.4.1. */
  MHD_HTTP_STATUS_MULTIPLE_CHOICES =            300
  ,
  /* 301 "Moved Permanently".   RFC9110, Section 15.4.2. */
  MHD_HTTP_STATUS_MOVED_PERMANENTLY =           301
  ,
  /* 302 "Found".               RFC9110, Section 15.4.3. */
  MHD_HTTP_STATUS_FOUND =                       302
  ,
  /* 303 "See Other".           RFC9110, Section 15.4.4. */
  MHD_HTTP_STATUS_SEE_OTHER =                   303
  ,
  /* 304 "Not Modified".        RFC9110, Section 15.4.5. */
  MHD_HTTP_STATUS_NOT_MODIFIED =                304
  ,
  /* 305 "Use Proxy".           RFC9110, Section 15.4.6. */
  MHD_HTTP_STATUS_USE_PROXY =                   305
  ,
  /* 306 "Switch Proxy".        Not used! RFC9110, Section 15.4.7. */
  MHD_HTTP_STATUS_SWITCH_PROXY =                306
  ,
  /* 307 "Temporary Redirect".  RFC9110, Section 15.4.8. */
  MHD_HTTP_STATUS_TEMPORARY_REDIRECT =          307
  ,
  /* 308 "Permanent Redirect".  RFC9110, Section 15.4.9. */
  MHD_HTTP_STATUS_PERMANENT_REDIRECT =          308
  ,

  /* 400 "Bad Request".         RFC9110, Section 15.5.1. */
  MHD_HTTP_STATUS_BAD_REQUEST =                 400
  ,
  /* 401 "Unauthorized".        RFC9110, Section 15.5.2. */
  MHD_HTTP_STATUS_UNAUTHORIZED =                401
  ,
  /* 402 "Payment Required".    RFC9110, Section 15.5.3. */
  MHD_HTTP_STATUS_PAYMENT_REQUIRED =            402
  ,
  /* 403 "Forbidden".           RFC9110, Section 15.5.4. */
  MHD_HTTP_STATUS_FORBIDDEN =                   403
  ,
  /* 404 "Not Found".           RFC9110, Section 15.5.5. */
  MHD_HTTP_STATUS_NOT_FOUND =                   404
  ,
  /* 405 "Method Not Allowed".  RFC9110, Section 15.5.6. */
  MHD_HTTP_STATUS_METHOD_NOT_ALLOWED =          405
  ,
  /* 406 "Not Acceptable".      RFC9110, Section 15.5.7. */
  MHD_HTTP_STATUS_NOT_ACCEPTABLE =              406
  ,
  /* 407 "Proxy Authentication Required". RFC9110, Section 15.5.8. */
  MHD_HTTP_STATUS_PROXY_AUTHENTICATION_REQUIRED = 407
  ,
  /* 408 "Request Timeout".     RFC9110, Section 15.5.9. */
  MHD_HTTP_STATUS_REQUEST_TIMEOUT =             408
  ,
  /* 409 "Conflict".            RFC9110, Section 15.5.10. */
  MHD_HTTP_STATUS_CONFLICT =                    409
  ,
  /* 410 "Gone".                RFC9110, Section 15.5.11. */
  MHD_HTTP_STATUS_GONE =                        410
  ,
  /* 411 "Length Required".     RFC9110, Section 15.5.12. */
  MHD_HTTP_STATUS_LENGTH_REQUIRED =             411
  ,
  /* 412 "Precondition Failed". RFC9110, Section 15.5.13. */
  MHD_HTTP_STATUS_PRECONDITION_FAILED =         412
  ,
  /* 413 "Content Too Large".   RFC9110, Section 15.5.14. */
  MHD_HTTP_STATUS_CONTENT_TOO_LARGE =           413
  ,
  /* 414 "URI Too Long".        RFC9110, Section 15.5.15. */
  MHD_HTTP_STATUS_URI_TOO_LONG =                414
  ,
  /* 415 "Unsupported Media Type". RFC9110, Section 15.5.16. */
  MHD_HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE =      415
  ,
  /* 416 "Range Not Satisfiable". RFC9110, Section 15.5.17. */
  MHD_HTTP_STATUS_RANGE_NOT_SATISFIABLE =       416
  ,
  /* 417 "Expectation Failed".  RFC9110, Section 15.5.18. */
  MHD_HTTP_STATUS_EXPECTATION_FAILED =          417
  ,


  /* 421 "Misdirected Request". RFC9110, Section 15.5.20. */
  MHD_HTTP_STATUS_MISDIRECTED_REQUEST =         421
  ,
  /* 422 "Unprocessable Content". RFC9110, Section 15.5.21. */
  MHD_HTTP_STATUS_UNPROCESSABLE_CONTENT =       422
  ,
  /* 423 "Locked".              RFC4918. */
  MHD_HTTP_STATUS_LOCKED =                      423
  ,
  /* 424 "Failed Dependency".   RFC4918. */
  MHD_HTTP_STATUS_FAILED_DEPENDENCY =           424
  ,
  /* 425 "Too Early".           RFC8470. */
  MHD_HTTP_STATUS_TOO_EARLY =                   425
  ,
  /* 426 "Upgrade Required".    RFC9110, Section 15.5.22. */
  MHD_HTTP_STATUS_UPGRADE_REQUIRED =            426
  ,

  /* 428 "Precondition Required". RFC6585. */
  MHD_HTTP_STATUS_PRECONDITION_REQUIRED =       428
  ,
  /* 429 "Too Many Requests".   RFC6585. */
  MHD_HTTP_STATUS_TOO_MANY_REQUESTS =           429
  ,

  /* 431 "Request Header Fields Too Large". RFC6585. */
  MHD_HTTP_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE = 431
  ,

  /* 451 "Unavailable For Legal Reasons". RFC7725. */
  MHD_HTTP_STATUS_UNAVAILABLE_FOR_LEGAL_REASONS = 451
  ,

  /* 500 "Internal Server Error". RFC9110, Section 15.6.1. */
  MHD_HTTP_STATUS_INTERNAL_SERVER_ERROR =       500
  ,
  /* 501 "Not Implemented".     RFC9110, Section 15.6.2. */
  MHD_HTTP_STATUS_NOT_IMPLEMENTED =             501
  ,
  /* 502 "Bad Gateway".         RFC9110, Section 15.6.3. */
  MHD_HTTP_STATUS_BAD_GATEWAY =                 502
  ,
  /* 503 "Service Unavailable". RFC9110, Section 15.6.4. */
  MHD_HTTP_STATUS_SERVICE_UNAVAILABLE =         503
  ,
  /* 504 "Gateway Timeout".     RFC9110, Section 15.6.5. */
  MHD_HTTP_STATUS_GATEWAY_TIMEOUT =             504
  ,
  /* 505 "HTTP Version Not Supported". RFC9110, Section 15.6.6. */
  MHD_HTTP_STATUS_HTTP_VERSION_NOT_SUPPORTED =  505
  ,
  /* 506 "Variant Also Negotiates". RFC2295. */
  MHD_HTTP_STATUS_VARIANT_ALSO_NEGOTIATES =     506
  ,
  /* 507 "Insufficient Storage". RFC4918. */
  MHD_HTTP_STATUS_INSUFFICIENT_STORAGE =        507
  ,
  /* 508 "Loop Detected".       RFC5842. */
  MHD_HTTP_STATUS_LOOP_DETECTED =               508
  ,

  /* 510 "Not Extended".        (OBSOLETED) RFC2774; status-change-http-experiments-to-historic. */
  MHD_HTTP_STATUS_NOT_EXTENDED =                510
  ,
  /* 511 "Network Authentication Required". RFC6585. */
  MHD_HTTP_STATUS_NETWORK_AUTHENTICATION_REQUIRED = 511
  ,


  /* Not registered non-standard codes */
  /* 449 "Reply With".          MS IIS extension. */
  MHD_HTTP_STATUS_RETRY_WITH =                  449
  ,

  /* 450 "Blocked by Windows Parental Controls". MS extension. */
  MHD_HTTP_STATUS_BLOCKED_BY_WINDOWS_PARENTAL_CONTROLS = 450
  ,

  /* 509 "Bandwidth Limit Exceeded". Apache extension. */
  MHD_HTTP_STATUS_BANDWIDTH_LIMIT_EXCEEDED =    509
};


/**
 * Returns the string status for a response code.
 *
 * This function works for @b HTTP status code, not for @b MHD error codes/
 * @param code the HTTP code to get text representation for
 * @return the pointer to the text representation,
 *         NULL if HTTP status code in not known.
 */
MHD_EXTERN_ const struct MHD_String *
MHD_HTTP_status_code_to_string (enum MHD_HTTP_StatusCode code)
MHD_FN_CONST_;

/**
 * Get the pointer to the C string for the HTTP response code, never NULL.
 */
#define MHD_HTTP_status_code_to_string_lazy(code) \
        (MHD_HTTP_status_code_to_string ((code)) ? \
         ((MHD_HTTP_status_code_to_string (code))->cstr) : ("[No status]") )


/** @} */ /* end of group httpcode */

#ifndef MHD_HTTP_PROTOCOL_VER_DEFINED

/**
 * @brief HTTP protocol versions
 * @defgroup versions HTTP versions
 * @{
 */
enum MHD_FIXED_ENUM_MHD_SET_ MHD_HTTP_ProtocolVersion
{
  MHD_HTTP_VERSION_INVALID = 0
  ,
  MHD_HTTP_VERSION_1_0 = 1
  ,
  MHD_HTTP_VERSION_1_1 = 2
  ,
  MHD_HTTP_VERSION_2 = 3
  ,
  MHD_HTTP_VERSION_3 = 4
  ,
  MHD_HTTP_VERSION_FUTURE = 255
};

#define MHD_HTTP_PROTOCOL_VER_DEFINED 1
#endif /* ! MHD_HTTP_PROTOCOL_VER_DEFINED */

/**
 * Return the string representation of the requested HTTP version.
 * Note: this is suitable mainly for logging and similar proposes as
 * HTTP/2 (and later) is not used inside the HTTP protocol.
 * @param pv the protocol version
 * @return the string representation of the protocol version,
 *         NULL for invalid values
 */
MHD_EXTERN_ const struct MHD_String *
MHD_protocol_version_to_string (enum MHD_HTTP_ProtocolVersion pv)
MHD_FN_CONST_;

/**
 * HTTP/1.0 identification string
 */
#define MHD_HTTP_VERSION_1_0_STR "HTTP/1.0"
/**
 * HTTP/1.1 identification string
 */
#define MHD_HTTP_VERSION_1_1_STR "HTTP/1.1"
/**
 * HTTP/2 identification string.
 * Not used by the HTTP protocol (except non-TLS handshake), useful for logs and
 * similar proposes.
 */
#define MHD_HTTP_VERSION_2_STR "HTTP/2"
/**
 * HTTP/3 identification string.
 * Not used by the HTTP protocol, useful for logs and similar proposes.
 */
#define MHD_HTTP_VERSION_3_STR "HTTP/3"

/** @} */ /* end of group versions */


/**
 * Resume handling of network data for suspended request.  It is
 * safe to resume a suspended request at any time.  Calling this
 * function on a request that was not previously suspended will
 * result in undefined behaviour.
 *
 * If you are using this function in ``external'' select mode, you must make
 * sure to run #MHD_daemon_process_blocking() afterwards (as otherwise the
 * change may not be reflected in the set returned to your
 * MHD_SocketRegistrationUpdateCallback and you may end up with a request
 * that is stuck until the next network activity.
 *
 * @param[in,out] request the request to resume
 */
MHD_EXTERN_ void
MHD_request_resume (struct MHD_Request *request)
MHD_FN_PAR_NONNULL_ALL_;


/* ************** Action and Response manipulation functions **************** */

/**
 * @defgroup response Response objects control
 */


/**
 * Name with value pair as C strings
 */
struct MHD_NameValueCStr
{
  /**
   * The name (key) of the field.
   * Must never be NULL.
   * Some types (kinds) allow empty strings.
   */
  const char *name;
  /**
   * The value of the field.
   * Some types (kinds) allow absence of the value. The absence is indicated
   * by NULL pointer.
   */
  const char *value;
};

/**
 * Data transmitted in response to an HTTP request.
 * Usually the final action taken in response to
 * receiving a request.
 */
struct MHD_Response;


/**
 * Suspend handling of network data for a given request.  This can
 * be used to dequeue a request from MHD's event loop for a while.
 *
 * Suspended requests continue to count against the total number of
 * requests allowed (per daemon, as well as per IP, if such limits
 * are set).  Suspended requests will NOT time out; timeouts will
 * restart when the request handling is resumed.  While a
 * request is suspended, MHD may not detect disconnects by the
 * client.
 *
 * At most one action can be created for any request.
 *
 * @param[in,out] request the request for which the action is generated
 * @return action to cause a request to be suspended,
 *         NULL if any action has been already created for the @a request
 * @ingroup action
 */
MHD_EXTERN_ const struct MHD_Action *
MHD_action_suspend (struct MHD_Request *request)
MHD_FN_PAR_NONNULL_ALL_;


/**
 * Converts a @a response to an action.  If #MHD_R_O_REUSABLE
 * is not set, the reference to the @a response is consumed
 * by the conversion. If #MHD_R_O_REUSABLE is #MHD_YES,
 * then the @a response can be used again to create actions in
 * the future.
 * However, the @a response is frozen by this step and
 * must no longer be modified (i.e. by setting headers).
 *
 * At most one action can be created for any request.
 *
 * @param request the request to create the action for
 * @param[in] response the response to convert,
 *                     if NULL then this function is equivalent to
 *                     #MHD_action_abort_connection() call
 * @return pointer to the action, the action must be consumed
 *         otherwise response object may leak;
 *         NULL if failed (no memory) or if any action has been already
 *         created for the @a request;
 *         when failed the response object is consumed and need not
 *         to be "destroyed"
 * @ingroup action
 */
MHD_EXTERN_ const struct MHD_Action *
MHD_action_from_response (struct MHD_Request *MHD_RESTRICT request,
                          struct MHD_Response *MHD_RESTRICT response)
MHD_FN_PAR_NONNULL_ (1);


/**
 * Action telling MHD to close the connection hard
 * (kind-of breaking HTTP specification).
 *
 * @param req the request to make an action
 * @return action operation, always NULL
 * @ingroup action
 */
#define MHD_action_abort_request(req) \
        MHD_STATIC_CAST_ (const struct MHD_Action *, NULL)


/**
 * Set the requested options for the response.
 *
 * If any option fail other options may be or may be not applied.
 * @param response the response to set the options
 * @param[in] options the pointer to the array with the options;
 *                    the array processing stops at the first ::MHD_D_O_END
 *                    option, but not later than after processing
 *                    @a options_max_num entries
 * @param options_max_num the maximum number of entries in the @a options,
 *                        use #MHD_OPTIONS_ARRAY_MAX_SIZE if options processing
 *                        must stop only at zero-termination option
 * @return ::MHD_SC_OK on success,
 *         error code otherwise
 */
MHD_EXTERN_ enum MHD_StatusCode
MHD_response_set_options (
  struct MHD_Response *MHD_RESTRICT response,
  const struct MHD_ResponseOptionAndValue *MHD_RESTRICT options,
  size_t options_max_num)
MHD_FN_PAR_NONNULL_ALL_;


/**
 * Set the requested single option for the response.
 *
 * @param response the response to set the option
 * @param[in] option_ptr the pointer to the option
 * @return ::MHD_SC_OK on success,
 *         error code otherwise
 * @ingroup response
 */
#define MHD_response_set_option(response,option_ptr) \
        MHD_response_set_options (response,option_ptr,1)


/* *INDENT-OFF* */
#ifdef MHD_USE_VARARG_MACROS
MHD_NOWARN_VARIADIC_MACROS_
#  if defined(MHD_USE_COMPOUND_LITERALS) && \
  defined(MHD_USE_COMP_LIT_FUNC_PARAMS)
/**
 * Set the requested options for the response.
 *
 * If any option fail other options may be or may be not applied.
 *
 * It should be used with helpers that creates required options, for example:
 *
 * MHD_RESPONE_SET_OPTIONS(d, MHD_R_OPTION_REUSABLE(MHD_YES),
 *                         MHD_R_OPTION_TERMINATION_CALLBACK(func, cls))
 *
 * @param response the response to set the option
 * @param ... the list of the options, each option must be created
 *            by helpers MHD_RESPONSE_OPTION_NameOfOption(option_value)
 * @return ::MHD_SC_OK on success,
 *         error code otherwise
 */
#    define MHD_RESPONSE_SET_OPTIONS(response,...)              \
        MHD_NOWARN_COMPOUND_LITERALS_                           \
        MHD_response_set_options (                              \
          response,                                             \
          ((const struct MHD_ResponseOptionAndValue[])          \
           {__VA_ARGS__, MHD_R_OPTION_TERMINATE ()}),           \
          MHD_OPTIONS_ARRAY_MAX_SIZE)                           \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_
#  elif defined(MHD_USE_CPP_INIT_LIST)
MHD_C_DECLRATIONS_FINISH_HERE_
#    include <vector>
MHD_C_DECLRATIONS_START_HERE_
/**
 * Set the requested options for the response.
 *
 * If any option fail other options may be or may be not applied.
 *
 * It should be used with helpers that creates required options, for example:
 *
 * MHD_RESPONE_SET_OPTIONS(d, MHD_R_OPTION_REUSABLE(MHD_YES),
 *                         MHD_R_OPTION_TERMINATION_CALLBACK(func, cls))
 *
 * @param response the response to set the option
 * @param ... the list of the options, each option must be created
 *            by helpers MHD_RESPONSE_OPTION_NameOfOption(option_value)
 * @return ::MHD_SC_OK on success,
 *         error code otherwise
 */
#    define MHD_RESPONSE_SET_OPTIONS(response,...)              \
        MHD_NOWARN_CPP_INIT_LIST_                               \
        MHD_response_set_options (                              \
          response,                                             \
          (std::vector<struct MHD_ResponseOptionAndValue>       \
           {__VA_ARGS__,MHD_R_OPTION_TERMINATE ()}).data (),    \
          MHD_OPTIONS_ARRAY_MAX_SIZE)                           \
        MHD_RESTORE_WARN_CPP_INIT_LIST_
#  endif
MHD_RESTORE_WARN_VARIADIC_MACROS_
#endif /* MHD_USE_VARARG_MACROS && MHD_USE_COMP_LIT_FUNC_PARAMS */
/* *INDENT-ON* */

#ifndef MHD_FREECALLBACK_DEFINED

/**
 * This method is called by libmicrohttpd when response with dynamic content
 * is being destroyed.  It should be used to free resources associated
 * with the dynamic content.
 *
 * @param[in] free_cls closure
 * @ingroup response
 */
typedef void
(*MHD_FreeCallback) (void *free_cls);

#define MHD_FREECALLBACK_DEFINED 1
#endif /* ! MHD_FREECALLBACK_DEFINED */
#ifndef MHD_DYNCONTENTZCIOVEC_DEFINED


/**
 * Structure for iov type of the response.
 * Used for zero-copy response content data.
 */
struct MHD_DynContentZCIoVec
{
  /**
   * The number of elements in @a iov
   */
  unsigned int iov_count;
  /**
   * The pointer to the array with @a iov_count elements.
   */
  const struct MHD_IoVec *iov;
  /**
   * The callback to free resources.
   * It is called once the full array of iov elements is sent.
   * No callback is called if NULL.
   */
  MHD_FreeCallback iov_fcb;
  /**
   * The parameter for @a iov_fcb
   */
  void *iov_fcb_cls;
};

#define MHD_DYNCONTENTZCIOVEC_DEFINED 1
#endif /* ! MHD_DYNCONTENTZCIOVEC_DEFINED */

/**
 * The action type returned by Dynamic Content Creator callback
 */
struct MHD_DynamicContentCreatorAction;

/**
 * The context used for Dynamic Content Creator callback
 */
struct MHD_DynamicContentCreatorContext;


/**
 * Create "continue processing" action with optional chunk-extension.
 * The data is provided in the buffer and/or in the zero-copy @a iov_data.
 *
 * If data is provided both in the buffer and @a ivo_data then
 * data in the buffer sent first, following the iov data.
 * The total size of the data in the buffer and in @a iov_data must
 * be non-zero.
 * If response content size is known and total size of content provided earlier
 * for this request combined with the size provided by this action is larger
 * then known response content size, then NULL is returned.
 *
 * At most one DCC action can be created for one content callback.
 *
 * @param[in,out] ctx the pointer the context as provided to the callback
 * @param data_size the amount of the data placed to the provided buffer,
 *                  cannot be larger than provided buffer size,
 *                  must be non-zero if @a iov_data is NULL or has no data,
 * @param iov_data the optional pointer to the iov data,
 *                 must not be NULL and have non-zero size data if @a data_size
 *                 is zero,
 * @param chunk_ext the optional pointer to chunk extension string,
 *                  can be NULL to not use chunk extension,
 *                  ignored if chunked encoding is not used
 * @return the pointer to the action if succeed,
 *         NULL (equivalent of MHD_DCC_action_abort())in case of any error
 */
MHD_EXTERN_ const struct MHD_DynamicContentCreatorAction *
MHD_DCC_action_continue_zc (
  struct MHD_DynamicContentCreatorContext *ctx,
  size_t data_size,
  const struct MHD_DynContentZCIoVec *iov_data,
  const char *MHD_RESTRICT chunk_ext)
MHD_FN_PAR_NONNULL_ (1)
MHD_FN_PAR_CSTR_ (4);


/**
 * Create "continue processing" action with optional chunk-extension.
 * The data is provided in the buffer.
 *
 * At most one DCC action can be created for one content callback.
 *
 * @param[in,out] ctx the pointer the context as provided to the callback
 * @param data_size the amount of the data placed to the provided buffer (not @a iov_data),
 *                  cannot be larger than provided buffer size,
 *                  must be non-zero.
 * @param chunk_ext the optional pointer to chunk extension string,
 *                  can be NULL to not use chunk extension,
 *                  ignored if chunked encoding is not used
 * @return the pointer to the action if succeed,
 *         NULL (equivalent of MHD_DCC_action_abort())in case of any error
 */
#define MHD_DCC_action_continue_ce(ctx,data_size,chunk_ext) \
        MHD_DCC_action_continue_zc ((ctx), (data_size), NULL, (chunk_ext))


/**
 * Create "continue processing" action, the data is provided in the buffer.
 *
 * At most one DCC action can be created for one content callback.
 *
 * @param[in,out] ctx the pointer the context as provided to the callback
 * @param data_size the amount of the data placed to the provided buffer;
 *                  cannot be larger than provided buffer size,
 *                  must be non-zero.
 *
 * @return the pointer to the action if succeed,
 *         NULL (equivalent of MHD_DCC_action_abort())in case of any error
 */
#define MHD_DCC_action_continue(ctx,data_size) \
        MHD_DCC_action_continue_ce ((ctx), (data_size), NULL)


/**
 * Create "finished" action with optional footers.
 * If function failed for any reason, the action is automatically
 * set to "stop with error".
 *
 * At most one DCC action can be created for one content callback.
 *
 * @param[in,out] ctx the pointer the context as provided to the callback
 * @param num_footers number of elements in the @a footers array,
 *                    must be zero if @a footers is NULL
 * @param footers the optional pointer to the array of the footers (the strings
 *                are copied and does not need to be valid after return from
 *                this function),
 *                can be NULL if @a num_footers is zero
 * @return the pointer to the action if succeed,
 *         NULL (equivalent of MHD_DCC_action_abort())in case of any error
 */
MHD_EXTERN_ const struct MHD_DynamicContentCreatorAction *
MHD_DCC_action_finish_with_footer (
  struct MHD_DynamicContentCreatorContext *ctx,
  size_t num_footers,
  const struct MHD_NameValueCStr *MHD_RESTRICT footers)
MHD_FN_PAR_NONNULL_ (1);


/**
 * Create "finished" action.
 * If function failed for any reason, the action is automatically
 * set to "stop with error".
 *
 * At most one DCC action can be created for one content callback.
 *
 * @param[in,out] ctx the pointer the context as provided to the callback
 * @return the pointer to the action if succeed,
 *         NULL (equivalent of MHD_DCC_action_abort())in case of any error
 */
#define MHD_DCC_action_finish(ctx) \
        MHD_DCC_action_finish_with_footer ((ctx), 0, NULL)


/**
 * Create "suspend" action.
 * If function failed for any reason, the action is automatically
 * set to "stop with error".
 *
 * At most one DCC action can be created for one content callback.
 *
 * @param[in,out] ctx the pointer the context as provided to the callback
 * @return the pointer to the action if succeed,
 *         NULL (equivalent of MHD_DCC_action_abort())in case of any error
 */
MHD_EXTERN_ const struct MHD_DynamicContentCreatorAction *
MHD_DCC_action_suspend (struct MHD_DynamicContentCreatorContext *ctx)
MHD_FN_PAR_NONNULL_ (1)
MHD_FN_RETURNS_NONNULL_;

/**
 * Create "stop with error" action.
 * @param[in,out] ctx the pointer the context as provided to the callback
 * @return always NULL (the action "stop with error")
 */
#define MHD_DCC_action_abort(ctx) \
        MHD_STATIC_CAST_ (const struct MHD_DynamicContentCreatorAction *, NULL)

/**
 * Callback used by libmicrohttpd in order to obtain content.  The
 * callback is to copy at most @a max bytes of content into @a buf or
 * provide zero-copy data for #MHD_DCC_action_continue_zc().
 *
 * @param dyn_cont_cls closure argument to the callback
 * @param ctx the context to produce the action to return,
 *            the pointer is only valid until the callback returns
 * @param pos position in the datastream to access;
 *        note that if a `struct MHD_Response` object is re-used,
 *        it is possible for the same content reader to
 *        be queried multiple times for the same data;
 *        however, if a `struct MHD_Response` is not re-used,
 *        libmicrohttpd guarantees that "pos" will be
 *        the sum of all data sizes provided by this callback
 * @param[out] buf where to copy the data
 * @param max maximum number of bytes to copy to @a buf (size of @a buf),
              if the size of the content of the response is known then size
              of the buffer is never larger than amount of the content left
 * @return action to use,
 *         NULL in case of any error (the response will be aborted)
 */
typedef const struct MHD_DynamicContentCreatorAction *
(MHD_FN_PAR_NONNULL_ (2) MHD_FN_PAR_NONNULL_ (4)
 *MHD_DynamicContentCreator)(void *dyn_cont_cls,
                             struct MHD_DynamicContentCreatorContext *ctx,
                             uint_fast64_t pos,
                             void *buf,
                             size_t max);


/**
 * Create a response.  The response object can be extended with
 * header information.
 *
 * @param sc status code to return
 * @param size size of the data portion of the response, #MHD_SIZE_UNKNOWN for unknown
 * @param dyn_cont callback to use to obtain response data
 * @param dyn_cont_cls extra argument to @a crc
 * @param dyn_cont_fc callback to call to free @a dyn_cont_cls resources
 * @return NULL on error (i.e. invalid arguments, out of memory)
 * FIXME: Call free callback on error?
 * @ingroup response
 */
MHD_EXTERN_ struct MHD_Response *
MHD_response_from_callback (enum MHD_HTTP_StatusCode sc,
                            uint_fast64_t size,
                            MHD_DynamicContentCreator dyn_cont,
                            void *dyn_cont_cls,
                            MHD_FreeCallback dyn_cont_fc);


/**
 * Create a response object.  The response object can be extended with
 * header information.
 *
 * @param sc status code to use for the response;
 *           #MHD_HTTP_STATUS_NO_CONTENT is only valid if @a size is 0;
 * @param buffer_size the size of the data portion of the response
 * @param buffer the @a size bytes containing the response's data portion,
 *               needs to be valid while the response is used
 * @param free_cb the callback to free any allocated data, called
 *                when response is being destroyed, can be NULL
 *                to skip the free/cleanup callback
 * @param free_cb_cls the parameter for @a free_cb
 * @return NULL on error (i.e. invalid arguments, out of memory)
 * FIXME: Call free callback on error?
 * @ingroup response
 */
MHD_EXTERN_ struct MHD_Response *
MHD_response_from_buffer (
  enum MHD_HTTP_StatusCode sc,
  size_t buffer_size,
  const char buffer[MHD_FN_PAR_DYN_ARR_SIZE_ (buffer_size)],
  MHD_FreeCallback free_cb,
  void *free_cb_cls)
MHD_FN_PAR_IN_SIZE_ (3,2);


/**
 * Create a response object with body that is a
 * statically allocated buffer that never needs to
 * be freed as its lifetime exceeds that of the
 * daemon.
 *
 * The response object can be extended with header information and then be used
 * any number of times.
 * @param sc status code to use for the response
 * @param len number of bytes in @a buf
 * @param buf buffer with response payload
 */
#define MHD_response_from_buffer_static(sc, len, buf)       \
        MHD_response_from_buffer (sc, len, buf, NULL, NULL)


/**
 * Create a response object with empty (zero size) body.
 *
 * The response object can be extended with header information and then be used
 * any number of times.
 * @param sc status code to use for the response
 */
#define MHD_response_from_empty(sc) \
        MHD_response_from_buffer_static (sc, 0, "")


/**
 * Create a response object.  The response object can be extended with
 * header information.
 *
 * @param sc status code to use for the response
 * @param buffer_size the size of the data portion of the response
 * @param buffer the @a size bytes containing the response's data portion,
 *               an internal copy will be made, there is no need to
 *               keep this data after return from this function
 * @return NULL on error (i.e. invalid arguments, out of memory)
 * FIXME: Call free callback on error?
 * @ingroup response
 */
MHD_EXTERN_ struct MHD_Response *
MHD_response_from_buffer_copy (
  enum MHD_HTTP_StatusCode sc,
  size_t buffer_size,
  const char buffer[MHD_FN_PAR_DYN_ARR_SIZE_ (buffer_size)])
MHD_FN_PAR_IN_SIZE_ (3,2);


/**
 * I/O vector type. Provided for use with #MHD_response_from_iovec().
 * @ingroup response
 */
struct MHD_IoVec
{
  /**
   * The pointer to the memory region for I/O.
   */
  const void *iov_base;

  /**
   * The size in bytes of the memory region for I/O.
   */
  size_t iov_len;
};


/**
 * Create a response object with an array of memory buffers
 * used as the response body.
 *
 * The response object can be extended with header information.
 *
 * If response object is used to answer HEAD request then the body
 * of the response is not used, while all headers (including automatic
 * headers) are used.
 *
 * @param sc status code to use for the response
 * @param iov_count the number of elements in @a iov
 * @param iov the array for response data buffers, an internal copy of this
 *        will be made
 * @param free_cb the callback to clean up any data associated with @a iov when
 *        the response is destroyed.
 * @param free_cb_cls the argument passed to @a free_cb
 * @return NULL on error (i.e. invalid arguments, out of memory)
 * FIXME: Call free callback on error?
 * @ingroup response
 */
MHD_EXTERN_ struct MHD_Response *
MHD_response_from_iovec (
  enum MHD_HTTP_StatusCode sc,
  unsigned int iov_count,
  const struct MHD_IoVec iov[MHD_FN_PAR_DYN_ARR_SIZE_ (iov_count)],
  MHD_FreeCallback free_cb,
  void *free_cb_cls);


/**
 * Create a response object based on an @a fd from which
 * data is read.  The response object can be extended with
 * header information.
 *
 * @param sc status code to return
 * @param fd file descriptor referring to a file on disk with the
 *        data; will be closed when response is destroyed;
 *        fd should be in 'blocking' mode
 * @param offset offset to start reading from in the file;
 *        reading file beyond 2 GiB may be not supported by OS or
 *        MHD build; see #MHD_LIB_INFO_FIXED_HAS_LARGE_FILE
 * @param size size of the data portion of the response;
 *        sizes larger than 2 GiB may be not supported by OS or
 *        MHD build; see #MHD_LIB_INFO_FIXED_HAS_LARGE_FILE
 * @return NULL on error (i.e. invalid arguments, out of memory)
 * FIXME: Close FD on error?
 * @ingroup response
 */
MHD_EXTERN_ struct MHD_Response *
MHD_response_from_fd (enum MHD_HTTP_StatusCode sc,
                      int fd,
                      uint_fast64_t offset,
                      uint_fast64_t size)
MHD_FN_PAR_FD_READ_ (2);

/**
 * Create a response object with the response body created by reading
 * the provided pipe.
 *
 * The response object can be extended with header information and
 * then be used ONLY ONCE.
 *
 * If response object is used to answer HEAD request then the body
 * of the response is not used, while all headers (including automatic
 * headers) are used.
 *
 * @param sc status code to use for the response
 * @param fd file descriptor referring to a read-end of a pipe with the
 *        data; will be closed when response is destroyed;
 *        fd should be in 'blocking' mode
 * @return NULL on error (i.e. invalid arguments, out of memory)
 * FIXME: Close pipe FD on error?
 * @ingroup response
 */
MHD_EXTERN_ struct MHD_Response *
MHD_response_from_pipe (enum MHD_HTTP_StatusCode sc,
                        int fd)
MHD_FN_PAR_FD_READ_ (2);


/**
 * Destroy response.
 * Should be called if response was created but not consumed.
 * Also must be called if response has #MHD_R_O_REUSABLE set.
 * The actual destroy can be happen later, if the response
 * is still being used in any request.
 * The function does not block.
 *
 * @param[in] response the response to destroy
 * @ingroup response
 */
MHD_EXTERN_ void
MHD_response_destroy (struct MHD_Response *response)
MHD_FN_PAR_NONNULL_ (1);


/**
 * Add a header line to the response.
 *
 * @param response response to add a header to
 * @param name the name of the header to add,
 *             an internal copy of the string will be made
 * @param value the value of the header to add,
 *              an internal copy of the string will be made
 * @return #MHD_SC_OK on success,
 *         error code otherwise
 * @ingroup response
 */
MHD_EXTERN_ enum MHD_StatusCode
MHD_response_add_header (struct MHD_Response *MHD_RESTRICT response,
                         const char *name,
                         const char *value)
MHD_FN_PAR_NONNULL_ (1)
MHD_FN_PAR_NONNULL_ (2) MHD_FN_PAR_CSTR_ (2)
MHD_FN_PAR_NONNULL_ (3) MHD_FN_PAR_CSTR_ (3);


/**
 * Add a header with predefined (standard) name to the response.
 *
 * @param response response to add a header to
 * @param stk the code of the predefined header
 * @param content the value of the header to add,
 *              an internal copy of the string will be made
 * @return #MHD_SC_OK on success,
 *         error code otherwise
 * @ingroup response
 */
MHD_EXTERN_ enum MHD_StatusCode
MHD_response_add_predef_header (struct MHD_Response *MHD_RESTRICT response,
                                enum MHD_PredefinedHeader stk,
                                const char *MHD_RESTRICT content)
MHD_FN_PAR_NONNULL_ (1)
MHD_FN_PAR_NONNULL_ (3) MHD_FN_PAR_CSTR_ (3);


/* ************ (b) Upload and PostProcessor functions ********************** */


/**
 * Suspend handling of network data for a given request.  This can
 * be used to dequeue a request from MHD's event loop for a while.
 *
 * Suspended requests continue to count against the total number of
 * requests allowed (per daemon, as well as per IP, if such limits
 * are set).  Suspended requests will NOT time out; timeouts will
 * restart when the request handling is resumed.  While a
 * request is suspended, MHD may not detect disconnects by the
 * client.
 *
 * At most one upload action can be created for one upload callback.
 *
 * @param[in,out] request the request for which the action is generated
 * @return action to cause a request to be suspended,
 *         NULL if any action has been already created for the @a request
 * @ingroup action
 */
MHD_EXTERN_ const struct MHD_UploadAction *
MHD_upload_action_suspend (struct MHD_Request *request)
MHD_FN_RETURNS_NONNULL_ MHD_FN_PAR_NONNULL_ALL_;

/**
 * Converts a @a response to an action.  If #MHD_R_O_REUSABLE
 * is not set, the reference to the @a response is consumed
 * by the conversion. If #MHD_R_O_REUSABLE is #MHD_YES,
 * then the @a response can be used again to create actions in
 * the future.
 * However, the @a response is frozen by this step and
 * must no longer be modified (i.e. by setting headers).
 *
 * At most one upload action can be created for one upload callback.
 *
 * @param request the request to create the action for
 * @param[in] response the response to convert,
 *                     if NULL then this function is equivalent to
 *                     #MHD_upload_action_abort_request() call
 * @return pointer to the action, the action must be consumed
 *         otherwise response object may leak;
 *         NULL if failed (no memory) or if any action has been already
 *         created for the @a request;
 *         when failed the response object is consumed and need not
 *         to be "destroyed"
 * @ingroup action
 */
MHD_EXTERN_ const struct MHD_UploadAction *
MHD_upload_action_from_response (struct MHD_Request *MHD_RESTRICT request,
                                 struct MHD_Response *MHD_RESTRICT response)
MHD_FN_PAR_NONNULL_ (1);

/**
 * Action telling MHD to continue processing the upload.
 * Valid only for incremental upload processing.
 * Works as #MHD_upload_action_abort_request() if used for full upload callback
 * or for the final (with zero data) incremental callback.
 *
 * At most one upload action can be created for one upload callback.
 *
 * @param request the request to make an action
 * @return action operation,
 *         NULL if any action has been already created for the @a request
 * @ingroup action
 */
MHD_EXTERN_ const struct MHD_UploadAction *
MHD_upload_action_continue (struct MHD_Request *request)
MHD_FN_RETURNS_NONNULL_;


/**
 * Action telling MHD to close the connection hard
 * (kind-of breaking HTTP specification).
 *
 * @param req the request to make an action
 * @return action operation, always NULL
 * @ingroup action
 */
#define MHD_upload_action_abort_request(req) \
        MHD_STATIC_CAST_ (const struct MHD_UploadAction *, NULL)

#ifndef MHD_UPLOADCALLBACK_DEFINED

/**
 * Function to process data uploaded by a client.
 *
 * @param upload_cls the argument given together with the function
 *                   pointer when the handler was registered with MHD
 * @param request the request is being processed
 * @param content_data_size the size of the @a content_data,
 *                          zero when all data have been processed
 * @param[in] content_data the uploaded content data,
 *                         may be modified in the callback,
 *                         valid only until return from the callback,
 *                         NULL when all data have been processed
 * @return action specifying how to proceed:
 *         #MHD_upload_action_continue() to continue upload (for incremental
 *         upload processing only),
 *         #MHD_upload_action_suspend() to stop reading the upload until
 *         the request is resumed,
 *         #MHD_upload_action_abort_request() to close the socket,
 *         or a response to discard the rest of the upload and transmit
 *         the response
 * @ingroup action
 */
typedef const struct MHD_UploadAction *
(MHD_FN_PAR_NONNULL_ (2)  MHD_FN_PAR_INOUT_SIZE_ (4,3)
 *MHD_UploadCallback)(void *upload_cls,
                      struct MHD_Request *request,
                      size_t content_data_size,
                      void *content_data);

#define MHD_UPLOADCALLBACK_DEFINED 1
#endif /* ! MHD_UPLOADCALLBACK_DEFINED */

/**
 * Create an action that handles an upload.
 *
 * If @a uc_inc is NULL and upload cannot fit the allocated buffer
 * then request is aborted without response.
 *
 * At most one action can be created for any request.
 *
 * @param request the request to create action for
 * @param large_buffer_size how large should the upload buffer be.
 *                          May allocate memory from the shared "large"
 *                          memory pool if necessary and non-zero is given.
 *                          Must be zero if @a uc_full is NULL.
 * @param uc_full the function to call when complete upload
 *                is received (only if fit @a upload_buffer_size),
 *                can be NULL if uc_inc is not NULL,
 *                must be NULL is @a upload_buffer_size is zero.
 * @param uc_full_cls closure for @a uc_full
 * @param uc_inc the function to incrementally process the upload data
 *               if the upload if larger than @a upload_buffer_size or
 *               @a upload_buffer_size cannot be allocated or
 *               @a uc_full is NULL,
 *               can be NULL if uc_full is not NULL
 * @param uc_inc_cls closure for @a uc_inc
 * @return NULL on error (out of memory, invalid parameters)
 * @return pointer to the action,
 *         NULL if failed (no memory) or if any action has been already
 *         created for the @a request.
 * @sa #MHD_D_OPTION_LARGE_POOL_SIZE()
 * @ingroup action
 */
MHD_EXTERN_ const struct MHD_Action *
MHD_action_process_upload (
  struct MHD_Request *request,
  size_t large_buffer_size,
  MHD_UploadCallback uc_full,
  void *uc_full_cls,
  MHD_UploadCallback uc_inc,
  void *uc_inc_cls)
MHD_FN_PAR_NONNULL_ (1);

/**
 * Create an action that handles an upload as full upload data.
 *
 * @param request the request to create action for
 * @param buff_size how large should the upload buffer be. May allocate memory
 *                  from the large memory pool if necessary. Must not be zero.
 * @param uc the function to call when complete upload
 *           is received (only if fit @a upload_buffer_size)
 * @param uc_cls closure for @a uc
 * @return NULL on error (out of memory. both @a uc is NULL)
 * @ingroup action
 */
#define MHD_action_process_upload_full(request,buff_size,uc,uc_cls) \
        MHD_action_process_upload (request, buff_size, uc, uc_cls, NULL, NULL)

/**
 * Create an action that handles an upload incrementally.
 *
 * @param request the request to create action for
 * @param uc the function to incrementally process the upload data
 * @param uc_cls closure for @a uc
 * @return NULL on error (out of memory. both @a uc is NULL)
 * @ingroup action
 */
#define MHD_action_process_upload_inc(request,uc,uc_cls) \
        MHD_action_process_upload (request, 0, NULL, NULL, uc, uc_cls)

#ifndef MHD_POST_DATA_READER_DEFINED

/**
 * Iterator over key-value pairs where the value maybe made available
 * in increments and/or may not be zero-terminated.  Used for
 * MHD parsing POST data.  To access "raw" data from POST or PUT
 * requests, use #MHD_action_process_upload() instead.
 *
 * @param cls user-specified closure
 * @param name 0-terminated key for the value
 * @param filename name of the uploaded file, NULL if not known
 * @param content_type mime-type of the data, NULL if not known
 * @param encoding the encoding of the data
 * @param data pointer to @a size bytes of data at the
 *             specified @a off offset,
 *             NOT zero-terminated
 * @param off offset of data in the overall value
 * @param size number of bytes in @a data available
 * @return action specifying how to proceed:
 *         #MHD_upload_action_continue() if all is well,
 *         #MHD_upload_action_suspend() to stop reading the upload until
 *         the request is resumed,
 *         #MHD_upload_action_abort_request() to close the socket,
 *         or a response to discard the rest of the upload and transmit
 *         the response
 * @ingroup action
 */
typedef const struct MHD_UploadAction *
(*MHD_PostDataReader) (void *cls,
                       const struct MHD_String *name,
                       const struct MHD_String *filename,
                       const struct MHD_String *content_type,
                       const struct MHD_String *encoding,
                       const void *data,
                       uint_fast64_t off,
                       size_t size);


/**
 * The callback to be called when finished with processing
 * of the postprocessor upload data.
 * @param req the request
 * @param cls the closure
 * @return the action to proceed
 */
typedef const struct MHD_UploadAction *
(*MHD_PostDataFinished) (struct MHD_Request *req,
                         void *cls);

#define MHD_POST_DATA_READER_DEFINED 1
#endif /* ! MHD_POST_DATA_READER_DEFINED */

/**
 * Create an action to parse the POSTed body from the client.
 *
 * At most one action can be created for any request.
 *
 * @param request the request to create action for
 * @param pp_buffer_size how much data should the post processor
 *                       buffer in memory. May allocate memory from
 *                       the shared "large" memory pool if necessary.
 * @param pp_stream_limit values above which length should be // FIXME: Remove? Duplicated with pp_buffer_size
 *   given to @a iter for stream processing // FIXME: iter??
 * @param enc the data encoding to use,
 *            set to #MHD_HTTP_POST_ENCODING_OTHER to detect automatically
 * @param reader function to call for "oversize" values in the stream,
 *               can be NULL
 * @param reader_cls closure for @a reader
 * @param done_cb called once all data has been processed for
 *   the final action; values smaller than @a pp_stream_limit that
 *   fit into @a pp_buffer_size will be available via
 *   #MHD_request_get_values_cb(), #MHD_request_get_values_list() and
 *   #MHD_request_get_post_data_cb(), #MHD_request_get_post_data_list()
 * @param done_cb_cls closure for @a done_cb
 * @return pointer to the action,
 *         NULL if failed (no memory) or if any action has been already
 *         created for the @a request.
 * @sa #MHD_D_OPTION_LARGE_POOL_SIZE()
 * @ingroup action
 */
MHD_EXTERN_ const struct MHD_Action *
MHD_action_post_processor (struct MHD_Request *request,
                           size_t pp_buffer_size,
                           size_t pp_stream_limit, // FIXME: Remove? Duplicated with pp_buffer_size
                           enum MHD_HTTP_PostEncoding enc,
                           MHD_PostDataReader reader,
                           void *reader_cls,
                           MHD_PostDataFinished done_cb,
                           void *done_cb_cls)
MHD_FN_PAR_NONNULL_ (1);


/**
 * Post data element.
 * If any member is not provided/set then pointer to C string is NULL.
 * If any member is set to empty string then pointer to C string not NULL,
 * but the length is zero.
 */
struct MHD_PostData
{
  /**
   * The name of the field
   */
  struct MHD_String name;
  /**
   * The filename if provided (only for "multipart/form-data")
   * If not set or defined then to C string is NULL.
   * If set to empty string then pointer to C string not NULL,
   */
  struct MHD_StringNullable filename;
  /**
   * The Content-Type if provided (only for "multipart/form-data")
   * If not set or defined then to C string is NULL.
   * If set to empty string then pointer to C string not NULL,
   */
  struct MHD_StringNullable content_type;
  /**
   * The Transfer-Encoding if provided (only for "multipart/form-data")
   * If not set or defined then to C string is NULL.
   * If set to empty string then pointer to C string not NULL,
   */
  struct MHD_StringNullable transfer_encoding;
  /**
   * The field data
   * If not set or defined then to C string is NULL.
   * If set to empty string then pointer to C string not NULL,
   */
  struct MHD_StringNullable value;
};

/**
 * Iterator over POST data.
 *
 * The pointers to the strings in @a data are valid until the response
 * is queued. If the data is needed beyond this point, it should be copied.
 *
 * @param cls closure
 * @param data the element of the post data
 * @return #MHD_YES to continue iterating,
 *         #MHD_NO to abort the iteration
 * @ingroup request
 */
typedef enum MHD_Bool
(MHD_FN_PAR_NONNULL_ (2)
 *MHD_PostDataIterator)(void *cls,
                        const struct MHD_PostData *data);

/**
 * Get all of the post data from the request via request.
 *
 * The pointers to the strings in @a elements are valid until the response
 * is queued. If the data is needed beyond this point, it should be copied.
 * @param request the request to get data for
 * @param iterator callback to call on each header;
 *        maybe NULL (then just count headers)
 * @param iterator_cls extra argument to @a iterator
 * @return number of entries iterated over
 * @ingroup request
 */
MHD_EXTERN_ size_t
MHD_request_get_post_data_cb (struct MHD_Request *request,
                              MHD_PostDataIterator iterator,
                              void *iterator_cls)
MHD_FN_PAR_NONNULL_ (1);

/**
 * Get all of the post data from the request.
 *
 * The pointers to the strings in @a elements are valid until the response
 * is queued. If the data is needed beyond this point, it should be copied.
 * @param request the request to get data for
 * @param num_elements the number of elements in @a elements array
 * @param[out] elements the array of @a num_elements to get the data
 * @return the number of elements stored in @a elements,
 *         zero if no data or postprocessor was not used.
 * @ingroup request
 */
MHD_EXTERN_ size_t
MHD_request_get_post_data_list (
  struct MHD_Request *request,
  size_t num_elements,
  struct MHD_PostData elements[MHD_FN_PAR_DYN_ARR_SIZE_ (num_elements)])
MHD_FN_PAR_NONNULL_ (1)
MHD_FN_PAR_NONNULL_ (3) MHD_FN_PAR_OUT_SIZE_ (3,2);

/* ***************** (c) WebSocket support ********** */

/**
 * Enumeration for operations MHD should perform on the underlying socket
 * of the upgrade.  This API is not finalized, and in particular
 * the final set of actions is yet to be decided. This is just an
 * idea for what we might want.
 */
enum MHD_FIXED_ENUM_APP_SET_ MHD_UpgradeOperation
{

  /**
   * Close the socket, the application is done with it.
   */
  MHD_UPGRADE_OPERATION_CLOSE = 0
  ,
  /**
   * Turn on flushing the network buffers after each data piece.
   */
  MHD_UPGRADE_OPERATION_DISABLE_NETWORK_BUFFERING = 1
  ,
  /**
   * Turn on normal data buffering (default).
   */
  MHD_UPGRADE_OPERATION_ENABLE_NETWORK_BUFFERING = 2
  ,

  /* * Sentinel * */
  /**
   * The sentinel value.
   * This value enforces specific underlying integer type for the enum.
   * Do not use.
   */
  MHD_UPGRADE_OPERATION_SENTINEL = 65535
};


/**
 * Handle given to the application to manage special
 * actions relating to MHD responses that "upgrade"
 * the HTTP protocol (i.e. to WebSockets).
 */
struct MHD_UpgradeHandle;

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
MHD_EXTERN_ enum MHD_StatusCode
MHD_upgrade_operation (struct MHD_UpgradeHandle *urh,
                       enum MHD_UpgradeOperation operation)
MHD_FN_PAR_NONNULL_ (1);


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
 * but instead use #MHD_action_upgrade() for special operations
 * on @a sock.
 *
 * Data forwarding to "upgraded" @a sock will be started as soon
 * as this function return.
 *
 * Except when in 'thread-per-connection' mode, implementations
 * of this function should never block (as it will still be called
 * from within the main event loop).
 *
 * @param cls closure, whatever was given to #MHD_action_upgrade().
 * @param request original HTTP request handle,
 *                   giving the function a last chance
 *                   to inspect the original HTTP request
 * @param extra_in_size number of bytes in @a extra_in
 * @param extra_in if we happened to have read bytes after the
 *                 HTTP header already (because the client sent
 *                 more than the HTTP header of the request before
 *                 we sent the upgrade response),
 *                 these are the extra bytes already read from @a sock
 *                 by MHD.  The application should treat these as if
 *                 it had read them from @a sock.
 * @param sock socket to use for bi-directional communication
 *        with the client.  For HTTPS, this may not be a socket
 *        that is directly connected to the client and thus certain
 *        operations (TCP-specific setsockopt(), getsockopt(), etc.)
 *        may not work as expected (as the socket could be from a
 *        socketpair() or a TCP-loopback).  The application is expected
 *        to perform read()/recv() and write()/send() calls on the socket.
 *        The application may also call shutdown(), but must not call
 *        close() directly.
 * @param urh argument for #MHD_upgrade_operation() on this @a response.
 *        Applications must eventually use this callback to (indirectly)
 *        perform the close() action on the @a sock.
 */
typedef void
(*MHD_UpgradeHandler)(void *cls,
                      struct MHD_Request *MHD_RESTRICT request,
                      size_t extra_in_size,
                      const char *extra_in,
                      MHD_Socket sock,
                      struct MHD_UpgradeHandle *MHD_RESTRICT urh);


/**
 * Create a action object that can be used for 101 UPGRADE
 * responses, for example to implement WebSockets.  After sending the
 * response, control over the data stream is given to the callback (which
 * can then, for example, start some bi-directional communication).
 * The callback will ONLY be called after the response header was successfully
 * passed to the OS; if there are communication errors before, the usual MHD
 * connection error handling code will be performed.
 *
 * MHD will automatically set the correct HTTP status
 * code (#MHD_HTTP_STATUS_SWITCHING_PROTOCOLS).
 * Setting correct HTTP headers for the upgrade must be done
 * manually (this way, it is possible to implement most existing
 * WebSocket versions using this API; in fact, this API might be useful
 * for any protocol switch, not just WebSockets).
 *
 * As usual, the response object can be extended with header
 * information and then be used any number of times (as long as the
 * header information is not connection-specific).
 *
 * At most one action can be created for any request.
 *
 * @param request the request to create action for
 * @param upgrade_handler function to call with the "upgraded" socket
 * @param upgrade_handler_cls closure for @a upgrade_handler
 * @param num_headers number of elements in the @a headers array,
 *                    must be zero if @a headers is NULL
 * @param headers the optional pointer to the array of the headers (the strings
 *                are copied and does not need to be valid after return from
 *                this function),
 *                can be NULL if @a num_headers is zero
 * @return NULL on error (i.e. invalid arguments, out of memory)
 * @ingroup action
 */
MHD_EXTERN_ struct MHD_Action *
MHD_action_upgrade (struct MHD_Request *request,
                    MHD_UpgradeHandler upgrade_handler,
                    void *upgrade_handler_cls,
                    size_t num_headers,
                    const struct MHD_NameValueCStr *headers)
MHD_FN_PAR_NONNULL_ (1);


/* ********************** (e) Client auth ********************** */


/**
 * Length of the binary output of the MD5 hash function.
 * @sa #MHD_digest_get_hash_size()
 * @ingroup authentication
 */
#define MHD_MD5_DIGEST_SIZE 16

/**
 * Length of the binary output of the SHA-256 hash function.
 * @sa #MHD_digest_get_hash_size()
 * @ingroup authentication
 */
#define MHD_SHA256_DIGEST_SIZE 32

/**
 * Length of the binary output of the SHA-512/256 hash function.
 * @warning While this value is the same as the #MHD_SHA256_DIGEST_SIZE,
 *          the calculated digests for SHA-256 and SHA-512/256 are different.
 * @sa #MHD_digest_get_hash_size()
 * @ingroup authentication
 */
#define MHD_SHA512_256_DIGEST_SIZE 32

/**
 * Base type of hash calculation.
 * Used as part of #MHD_DigestAuthAlgo values.
 *
 * @warning Not used directly by MHD API.
 */
enum MHD_FIXED_ENUM_MHD_APP_SET_ MHD_DigestBaseAlgo
{
  /**
   * Invalid hash algorithm value
   */
  MHD_DIGEST_BASE_ALGO_INVALID = 0
  ,
  /**
   * MD5 hash algorithm.
   * As specified by RFC1321
   */
  MHD_DIGEST_BASE_ALGO_MD5 = (1 << 0)
  ,
  /**
   * SHA-256 hash algorithm.
   * As specified by FIPS PUB 180-4
   */
  MHD_DIGEST_BASE_ALGO_SHA256 = (1 << 1)
  ,
  /**
   * SHA-512/256 hash algorithm.
   * As specified by FIPS PUB 180-4
   */
  MHD_DIGEST_BASE_ALGO_SHA512_256 = (1 << 2)
};

/**
 * The flag indicating non-session algorithm types,
 * like 'MD5', 'SHA-256' or 'SHA-512-256'.
 */
#define MHD_DIGEST_AUTH_ALGO_NON_SESSION    (1 << 6)

/**
 * The flag indicating session algorithm types,
 * like 'MD5-sess', 'SHA-256-sess' or 'SHA-512-256-sess'.
 */
#define MHD_DIGEST_AUTH_ALGO_SESSION        (1 << 7)

/**
 * Digest algorithm identification
 */
enum MHD_FIXED_ENUM_MHD_APP_SET_ MHD_DigestAuthAlgo
{
  /**
   * Unknown or wrong algorithm type.
   * Used in struct MHD_DigestAuthInfo to indicate client value that
   * cannot by identified.
   */
  MHD_DIGEST_AUTH_ALGO_INVALID = 0
  ,
  /**
   * The 'MD5' algorithm, non-session version.
   */
  MHD_DIGEST_AUTH_ALGO_MD5 =
    MHD_DIGEST_BASE_ALGO_MD5 | MHD_DIGEST_AUTH_ALGO_NON_SESSION
  ,
  /**
   * The 'MD5-sess' algorithm.
   * Not supported by MHD for authentication.
   */
  MHD_DIGEST_AUTH_ALGO_MD5_SESSION =
    MHD_DIGEST_BASE_ALGO_MD5 | MHD_DIGEST_AUTH_ALGO_SESSION
  ,
  /**
   * The 'SHA-256' algorithm, non-session version.
   */
  MHD_DIGEST_AUTH_ALGO_SHA256 =
    MHD_DIGEST_BASE_ALGO_SHA256 | MHD_DIGEST_AUTH_ALGO_NON_SESSION
  ,
  /**
   * The 'SHA-256-sess' algorithm.
   * Not supported by MHD for authentication.
   */
  MHD_DIGEST_AUTH_ALGO_SHA256_SESSION =
    MHD_DIGEST_BASE_ALGO_SHA256 | MHD_DIGEST_AUTH_ALGO_SESSION
  ,
  /**
   * The 'SHA-512-256' (SHA-512/256) algorithm.
   */
  MHD_DIGEST_AUTH_ALGO_SHA512_256 =
    MHD_DIGEST_BASE_ALGO_SHA512_256 | MHD_DIGEST_AUTH_ALGO_NON_SESSION
  ,
  /**
   * The 'SHA-512-256-sess' (SHA-512/256 session) algorithm.
   * Not supported by MHD for authentication.
   */
  MHD_DIGEST_AUTH_ALGO_SHA512_256_SESSION =
    MHD_DIGEST_BASE_ALGO_SHA512_256 | MHD_DIGEST_AUTH_ALGO_SESSION
};


/**
 * Get digest size for specified algorithm.
 *
 * The size of the digest specifies the size of the userhash, userdigest
 * and other parameters which size depends on used hash algorithm.
 * @param algo the algorithm to check
 * @return the size of the digest (either #MHD_MD5_DIGEST_SIZE or
 *         #MHD_SHA256_DIGEST_SIZE/MHD_SHA512_256_DIGEST_SIZE)
 *         or zero if the input value is not supported or not valid
 * @sa #MHD_digest_auth_calc_userdigest()
 * @sa #MHD_digest_auth_calc_userhash(), #MHD_digest_auth_calc_userhash_hex()
 * @ingroup authentication
 */
MHD_EXTERN_ size_t
MHD_digest_get_hash_size (enum MHD_DigestAuthAlgo algo)
MHD_FN_CONST_;

/**
 * Digest algorithm identification, allow multiple selection.
 *
 * #MHD_DigestAuthAlgo always can be casted to #MHD_DigestAuthMultiAlgo, but
 * not vice versa.
 */
enum MHD_FIXED_ENUM_MHD_APP_SET_ MHD_DigestAuthMultiAlgo
{
  /**
   * Unknown or wrong algorithm type.
   */
  MHD_DIGEST_AUTH_MULT_ALGO_INVALID = MHD_DIGEST_AUTH_ALGO_INVALID
  ,
  /**
   * The 'MD5' algorithm, non-session version.
   */
  MHD_DIGEST_AUTH_MULT_ALGO_MD5 = MHD_DIGEST_AUTH_ALGO_MD5
  ,
  /**
   * The 'MD5-sess' algorithm.
   * Not supported by MHD for authentication.
   * Reserved value.
   */
  MHD_DIGEST_AUTH_MULT_ALGO_MD5_SESSION = MHD_DIGEST_AUTH_ALGO_MD5_SESSION
  ,
  /**
   * The 'SHA-256' algorithm, non-session version.
   */
  MHD_DIGEST_AUTH_MULT_ALGO_SHA256 = MHD_DIGEST_AUTH_ALGO_SHA256
  ,
  /**
   * The 'SHA-256-sess' algorithm.
   * Not supported by MHD for authentication.
   * Reserved value.
   */
  MHD_DIGEST_AUTH_MULT_ALGO_SHA256_SESSION =
    MHD_DIGEST_AUTH_ALGO_SHA256_SESSION
  ,
  /**
   * The 'SHA-512-256' (SHA-512/256) algorithm, non-session version.
   */
  MHD_DIGEST_AUTH_MULT_ALGO_SHA512_256 = MHD_DIGEST_AUTH_ALGO_SHA512_256
  ,
  /**
   * The 'SHA-512-256-sess' (SHA-512/256 session) algorithm.
   * Not supported by MHD for authentication.
   * Reserved value.
   */
  MHD_DIGEST_AUTH_MULT_ALGO_SHA512_256_SESSION =
    MHD_DIGEST_AUTH_ALGO_SHA512_256_SESSION
  ,
  /**
   * SHA-256 or SHA-512/256 non-session algorithm, MHD will choose
   * the preferred or the matching one.
   */
  MHD_DIGEST_AUTH_MULT_ALGO_SHA_ANY_NON_SESSION =
    MHD_DIGEST_AUTH_ALGO_SHA256 | MHD_DIGEST_AUTH_ALGO_SHA512_256
  ,
  /**
   * Any non-session algorithm, MHD will choose the preferred or
   * the matching one.
   */
  MHD_DIGEST_AUTH_MULT_ALGO_ANY_NON_SESSION =
    (0x3F) | MHD_DIGEST_AUTH_ALGO_NON_SESSION
  ,
  /**
   * The SHA-256 or SHA-512/256 session algorithm.
   * Not supported by MHD.
   * Reserved value.
   */
  MHD_DIGEST_AUTH_MULT_ALGO_SHA_ANY_SESSION =
    MHD_DIGEST_AUTH_ALGO_SHA256_SESSION
    | MHD_DIGEST_AUTH_ALGO_SHA512_256_SESSION
  ,
  /**
   * Any session algorithm.
   * Not supported by MHD.
   * Reserved value.
   */
  MHD_DIGEST_AUTH_MULT_ALGO_ANY_SESSION =
    (0x3F) | MHD_DIGEST_AUTH_ALGO_SESSION
  ,
  /**
   * The MD5 algorithm, session or non-session.
   * Currently supported as non-session only.
   */
  MHD_DIGEST_AUTH_MULT_ALGO_MD5_ANY =
    MHD_DIGEST_AUTH_MULT_ALGO_MD5 | MHD_DIGEST_AUTH_MULT_ALGO_MD5_SESSION
  ,
  /**
   * The SHA-256 algorithm, session or non-session.
   * Currently supported as non-session only.
   */
  MHD_DIGEST_AUTH_MULT_ALGO_SHA256_ANY =
    MHD_DIGEST_AUTH_MULT_ALGO_SHA256
    | MHD_DIGEST_AUTH_MULT_ALGO_SHA256_SESSION
  ,
  /**
   * The SHA-512/256 algorithm, session or non-session.
   * Currently supported as non-session only.
   */
  MHD_DIGEST_AUTH_MULT_ALGO_SHA512_256_ANY =
    MHD_DIGEST_AUTH_MULT_ALGO_SHA512_256
    | MHD_DIGEST_AUTH_MULT_ALGO_SHA512_256_SESSION
  ,
  /**
   * The SHA-256 or SHA-512/256 algorithm, session or non-session.
   * Currently supported as non-session only.
   */
  MHD_DIGEST_AUTH_MULT_ALGO_SHA_ANY_ANY =
    MHD_DIGEST_AUTH_MULT_ALGO_SHA_ANY_NON_SESSION
    | MHD_DIGEST_AUTH_MULT_ALGO_SHA_ANY_SESSION
  ,
  /**
   * Any algorithm, MHD will choose the preferred or the matching one.
   */
  MHD_DIGEST_AUTH_MULT_ALGO_ANY =
    (0x3F) | MHD_DIGEST_AUTH_ALGO_NON_SESSION | MHD_DIGEST_AUTH_ALGO_SESSION
};


/**
 * Calculate "userhash", return it as binary data.
 *
 * The "userhash" is the hash of the string "username:realm".
 *
 * The "userhash" could be used to avoid sending username in cleartext in Digest
 * Authorization client's header.
 *
 * Userhash is not designed to hide the username in local database or files,
 * as username in cleartext is required for #MHD_digest_auth_check() function
 * to check the response, but it can be used to hide username in HTTP headers.
 *
 * This function could be used when the new username is added to the username
 * database to save the "userhash" alongside with the username (preferably) or
 * when loading list of the usernames to generate the userhash for every loaded
 * username (this will cause delays at the start with the long lists).
 *
 * Once "userhash" is generated it could be used to identify users by clients
 * with "userhash" support.
 * Avoid repetitive usage of this function for the same username/realm
 * combination as it will cause excessive CPU load; save and reuse the result
 * instead.
 *
 * @param algo the algorithm for userhash calculations
 * @param username the username
 * @param realm the realm
 * @param[out] userhash_bin the output buffer for userhash as binary data;
 *                          if this function succeeds, then this buffer has
 *                          #MHD_digest_get_hash_size() bytes of userhash
 *                          upon return
 * @param bin_buf_size the size of the @a userhash_bin buffer, must be
 *                     at least #MHD_digest_get_hash_size() bytes long
 * @return MHD_SC_OK on success,
 *         error code otherwise
 * @sa #MHD_digest_auth_calc_userhash_hex()
 * @ingroup authentication
 */
MHD_EXTERN_ enum MHD_StatusCode
MHD_digest_auth_calc_userhash (enum MHD_DigestAuthAlgo algo,
                               const char *username,
                               const char *realm,
                               size_t bin_buf_size,
                               void *MHD_RESTRICT userhash_bin)
MHD_FN_PURE_ MHD_FN_PAR_NONNULL_ALL_ MHD_FN_PAR_CSTR_ (2)
MHD_FN_PAR_CSTR_ (3) MHD_FN_PAR_OUT_SIZE_ (5,4);


/**
 * Calculate "userhash", return it as hexadecimal string.
 *
 * The "userhash" is the hash of the string "username:realm".
 *
 * The "userhash" could be used to avoid sending username in cleartext in Digest
 * Authorization client's header.
 *
 * Userhash is not designed to hide the username in local database or files,
 * as username in cleartext is required for #MHD_digest_auth_check() function
 * to check the response, but it can be used to hide username in HTTP headers.
 *
 * This function could be used when the new username is added to the username
 * database to save the "userhash" alongside with the username (preferably) or
 * when loading list of the usernames to generate the userhash for every loaded
 * username (this will cause delays at the start with the long lists).
 *
 * Once "userhash" is generated it could be used to identify users by clients
 * with "userhash" support.
 * Avoid repetitive usage of this function for the same username/realm
 * combination as it will cause excessive CPU load; save and reuse the result
 * instead.
 *
 * @param algo the algorithm for userhash calculations
 * @param username the username
 * @param realm the realm
 * @param hex_buf_size the size of the @a userhash_hex buffer, must be
 *                     at least #MHD_digest_get_hash_size()*2+1 chars long
 * @param[out] userhash_hex the output buffer for userhash as hex string;
 *                          if this function succeeds, then this buffer has
 *                          #MHD_digest_get_hash_size()*2 chars long
 *                          userhash zero-terminated string
 * @return MHD_SC_OK on success,
 *         error code otherwise
 * @sa #MHD_digest_auth_calc_userhash()
 * @ingroup authentication
 */
MHD_EXTERN_ enum MHD_StatusCode
MHD_digest_auth_calc_userhash_hex (
  enum MHD_DigestAuthAlgo algo,
  const char *username,
  const char *realm,
  size_t hex_buf_size,
  char userhash_hex[MHD_FN_PAR_DYN_ARR_SIZE_ (hex_buf_size)])
MHD_FN_PURE_ MHD_FN_PAR_NONNULL_ALL_ MHD_FN_PAR_CSTR_ (2)
MHD_FN_PAR_CSTR_ (3) MHD_FN_PAR_OUT_SIZE_ (5,4);


/**
 * The type of username used by client in Digest Authorization header
 *
 * Values are sorted so simplified checks could be used.
 * For example:
 * * (value <= MHD_DIGEST_AUTH_UNAME_TYPE_INVALID) is true if no valid username
 *   is provided by the client
 * * (value >= MHD_DIGEST_AUTH_UNAME_TYPE_USERHASH) is true if username is
 *   provided in any form
 * * (value >= MHD_DIGEST_AUTH_UNAME_TYPE_STANDARD) is true if username is
 *   provided in clear text (no userhash matching is needed)
 */
enum MHD_FIXED_ENUM_MHD_SET_ MHD_DigestAuthUsernameType
{
  /**
   * No username parameter in in Digest Authorization header.
   * This should be treated as an error.
   */
  MHD_DIGEST_AUTH_UNAME_TYPE_MISSING = 0
  ,
  /**
   * The 'username' parameter is used to specify the username.
   */
  MHD_DIGEST_AUTH_UNAME_TYPE_STANDARD = (1 << 2)
  ,
  /**
   * The username is specified by 'username*' parameter with
   * the extended notation (see RFC 5987, section-3.2.1).
   * The only difference between standard and extended types is
   * the way how username value is encoded in the header.
   */
  MHD_DIGEST_AUTH_UNAME_TYPE_EXTENDED = (1 << 3)
  ,
  /**
   * The username provided in form of 'userhash' as
   * specified by RFC 7616, section-3.4.4.
   * @sa #MHD_digest_auth_calc_userhash_hex(), #MHD_digest_auth_calc_userhash()
   */
  MHD_DIGEST_AUTH_UNAME_TYPE_USERHASH = (1 << 1)
  ,
  /**
   * The invalid combination of username parameters are used by client.
   * Either:
   * * both 'username' and 'username*' are used
   * * 'username*' is used with 'userhash=true'
   * * 'username*' used with invalid extended notation
   * * 'username' is not hexadecimal string, while 'userhash' set to 'true'
   */
  MHD_DIGEST_AUTH_UNAME_TYPE_INVALID = (1 << 0)
};

/**
 * The QOP ('quality of protection') types.
 */
enum MHD_FIXED_ENUM_MHD_APP_SET_ MHD_DigestAuthQOP
{
  /**
   * Invalid/unknown QOP.
   * Used in struct MHD_DigestAuthInfo to indicate client value that
   * cannot by identified.
   */
  MHD_DIGEST_AUTH_QOP_INVALID = 0
  ,
  /**
   * No QOP parameter.
   * As described in old RFC 2069 original specification.
   * This mode is not allowed by latest RFCs and should be used only to
   * communicate with clients that do not support more modern modes (with QOP
   * parameter).
   * This mode is less secure than other modes and inefficient.
   */
  MHD_DIGEST_AUTH_QOP_NONE = 1 << 0
  ,
  /**
   * The 'auth' QOP type.
   */
  MHD_DIGEST_AUTH_QOP_AUTH = 1 << 1
  ,
  /**
   * The 'auth-int' QOP type.
   * Not supported by MHD for authentication.
   */
  MHD_DIGEST_AUTH_QOP_AUTH_INT = 1 << 2
};

/**
 * The QOP ('quality of protection') types, multiple selection.
 *
 * #MHD_DigestAuthQOP always can be casted to #MHD_DigestAuthMultiQOP, but
 * not vice versa.
 */
enum MHD_FIXED_ENUM_MHD_APP_SET_ MHD_DigestAuthMultiQOP
{
  /**
   * Invalid/unknown QOP.
   */
  MHD_DIGEST_AUTH_MULT_QOP_INVALID = MHD_DIGEST_AUTH_QOP_INVALID
  ,
  /**
   * No QOP parameter.
   * As described in old RFC 2069 original specification.
   * This mode is not allowed by latest RFCs and should be used only to
   * communicate with clients that do not support more modern modes (with QOP
   * parameter).
   * This mode is less secure than other modes and inefficient.
   */
  MHD_DIGEST_AUTH_MULT_QOP_NONE = MHD_DIGEST_AUTH_QOP_NONE
  ,
  /**
   * The 'auth' QOP type.
   */
  MHD_DIGEST_AUTH_MULT_QOP_AUTH = MHD_DIGEST_AUTH_QOP_AUTH
  ,
  /**
   * The 'auth-int' QOP type.
   * Not supported by MHD.
   * Reserved value.
   */
  MHD_DIGEST_AUTH_MULT_QOP_AUTH_INT = MHD_DIGEST_AUTH_QOP_AUTH_INT
  ,
  /**
   * The 'auth' QOP type OR the old RFC2069 (no QOP) type.
   * In other words: any types except 'auth-int'.
   * RFC2069-compatible mode is allowed, thus this value should be used only
   * when it is really necessary.
   */
  MHD_DIGEST_AUTH_MULT_QOP_ANY_NON_INT =
    MHD_DIGEST_AUTH_QOP_NONE | MHD_DIGEST_AUTH_QOP_AUTH
  ,
  /**
   * Any 'auth' QOP type ('auth' or 'auth-int').
   * Currently supported as 'auth' QOP type only.
   */
  MHD_DIGEST_AUTH_MULT_QOP_AUTH_ANY =
    MHD_DIGEST_AUTH_QOP_AUTH | MHD_DIGEST_AUTH_QOP_AUTH_INT
};

/**
 * The invalid value of 'nc' parameter in client Digest Authorization header.
 */
#define MHD_DIGEST_AUTH_INVALID_NC_VALUE        (0)

/**
 * Information from Digest Authorization client's header.
 *
 * @see #MHD_REQUEST_INFO_DYNAMIC_DAUTH_REQ_INFO
 */
struct MHD_DigestAuthInfo
{
  /**
   * The algorithm as defined by client.
   * Set automatically to MD5 if not specified by client.
   */
  enum MHD_DigestAuthAlgo algo;

  /**
   * The type of username used by client.
   */
  enum MHD_DigestAuthUsernameType uname_type;

  /**
   * The username string.
   * Used only if username type is standard or extended, always NULL otherwise.
   * If extended notation is used, this string is pct-decoded string
   * with charset and language tag removed (i.e. it is original username
   * extracted from the extended notation).
   * When userhash is used by the client, the string pointer is NULL and
   * @a userhash_hex and @a userhash_bin are set.
   */
  struct MHD_StringNullable username;

  /**
   * The userhash string.
   * Valid only if username type is userhash.
   * This is unqoted string without decoding of the hexadecimal
   * digits (as provided by the client).
   * @sa #MHD_digest_auth_calc_userhash_hex()
   */
  struct MHD_StringNullable userhash_hex;

  /**
   * The userhash decoded to binary form.
   * Used only if username type is userhash, always NULL otherwise.
   * When not NULL, this points to binary sequence @a userhash_bin_size bytes
   * long.
   * The valid size should be #MHD_digest_get_hash_size() bytes.
   * @warning This is a binary data, no zero termination.
   * @warning To avoid buffer overruns, always check the size of the data before
   *          use, because @a userhash_bin can point even to zero-sized
   *          data.
   * @sa #MHD_digest_auth_calc_userhash()
   */
  uint8_t *userhash_bin;

  /**
   * The size of the data pointed by @a userhash_bin.
   * Always zero when @a userhash_bin is NULL.
   */
  size_t userhash_bin_size;

  /**
   * The 'opaque' parameter value, as specified by client.
   * If not specified by client then string pointer is NULL.
   */
  struct MHD_StringNullable opaque;

  /**
   * The 'realm' parameter value, as specified by client.
   * If not specified by client then string pointer is NULL.
   */
  struct MHD_StringNullable realm;

  /**
   * The 'qop' parameter value.
   */
  enum MHD_DigestAuthQOP qop;

  /**
   * The length of the 'cnonce' parameter value, including possible
   * backslash-escape characters.
   * 'cnonce' is used in hash calculation, which is CPU-intensive procedure.
   * An application may want to reject too large cnonces to limit the CPU load.
   * A few kilobytes is a reasonable limit, typically cnonce is just 32-160
   * characters long.
   */
  size_t cnonce_len;

  /**
   * The nc parameter value.
   * Can be used by application to limit the number of nonce re-uses. If @a nc
   * is higher than application wants to allow, then "auth required" response
   * with 'stale=true' could be used to force client to retry with the fresh
   * 'nonce'.
   * If not specified by client or does not have hexadecimal digits only, the
   * value is #MHD_DIGEST_AUTH_INVALID_NC_VALUE.
   */
  uint_fast32_t nc;
};


/**
 * Information from Digest Authorization client's header.
 *
 * @see #MHD_REQUEST_INFO_DYNAMIC_DAUTH_USERNAME_INFO
 */
struct MHD_DigestAuthUsernameInfo
{
  /**
   * The algorithm as defined by client.
   * Set automatically to MD5 if not specified by client.
   */
  enum MHD_DigestAuthAlgo algo;

  /**
   * The type of username used by client.
   * The 'invalid' and 'missing' types are not used in this structure,
   * instead NULL is returned for #MHD_REQUEST_INFO_DYNAMIC_DAUTH_USERNAME_INFO.
   */
  enum MHD_DigestAuthUsernameType uname_type;

  /**
   * The username string.
   * Used only if username type is standard or extended, always NULL otherwise.
   * If extended notation is used, this string is pct-decoded string
   * with charset and language tag removed (i.e. it is original username
   * extracted from the extended notation).
   * When userhash is used by the client, this member is NULL and
   * @a userhash_hex and @a userhash_bin are set.
   * The buffer pointed by the @a username becomes invalid when a response
   * for the requested is provided (or request is aborted).
   */
  struct MHD_String username;

  /**
   * The userhash string.
   * Valid only if username type is userhash.
   * This is unqoted string without decoding of the hexadecimal
   * digits (as provided by the client).
   * The buffer pointed by the @a userhash_hex becomes invalid when a response
   * for the requested is provided (or request is aborted).
   * @sa #MHD_digest_auth_calc_userhash_hex()
   */
  struct MHD_String userhash_hex;

  /**
   * The userhash decoded to binary form.
   * Used only if username type is userhash, always NULL otherwise.
   * When not NULL, this points to binary sequence @a userhash_hex_len /2 bytes
   * long.
   * The valid size should be #MHD_digest_get_hash_size() bytes.
   * The buffer pointed by the @a userhash_bin becomes invalid when a response
   * for the requested is provided (or request is aborted).
   * @warning This is a binary data, no zero termination.
   * @warning To avoid buffer overruns, always check the size of the data before
   *          use, because @a userhash_bin can point even to zero-sized
   *          data.
   * @sa #MHD_digest_auth_calc_userhash()
   */
  uint8_t *userhash_bin;
};


/**
 * The result of digest authentication of the client.
 *
 * All error values are zero or negative.
 */
enum MHD_FIXED_ENUM_MHD_SET_ MHD_DigestAuthResult
{
  /**
   * Authentication OK.
   */
  MHD_DAUTH_OK = 1
  ,
  /**
   * General error, like "out of memory".
   */
  MHD_DAUTH_ERROR = 0
  ,
  /**
   * No "Authorization" header or wrong format of the header.
   * Also may be returned if required parameters in client Authorisation header
   * are missing or broken (in invalid format).
   */
  MHD_DAUTH_WRONG_HEADER = -1
  ,
  /**
   * Wrong 'username'.
   */
  MHD_DAUTH_WRONG_USERNAME = -2
  ,
  /**
   * Wrong 'realm'.
   */
  MHD_DAUTH_WRONG_REALM = -3
  ,
  /**
   * Wrong 'URI' (or URI parameters).
   */
  MHD_DAUTH_WRONG_URI = -4
  ,
  /**
   * Wrong 'qop'.
   */
  MHD_DAUTH_WRONG_QOP = -5
  ,
  /**
   * Wrong 'algorithm'.
   */
  MHD_DAUTH_WRONG_ALGO = -6
  ,
  /**
   * Too large (>64 KiB) Authorization parameter value.
   */
  MHD_DAUTH_TOO_LARGE = -15
  ,
  /* The different form of naming is intentionally used for the results below,
   * as they are more important */

  /**
   * The 'nonce' is too old. Suggest the client to retry with the same
   * username and password to get the fresh 'nonce'.
   * The validity of the 'nonce' may be not checked.
   */
  MHD_DAUTH_NONCE_STALE = -17
  ,
  /**
   * The 'nonce' was generated by MHD for other conditions.
   * This value is only returned if #MHD_D_O_DAUTH_NONCE_BIND_TYPE is set
   * to anything other than #MHD_D_OPTION_VALUE_DAUTH_BIND_NONCE_NONE.
   * The interpretation of this code could be different. For example, if
   * #MHD_D_OPTION_VALUE_DAUTH_BIND_NONCE_URI is set and client just used
   * the same 'nonce' for another URI, the code could be handled as
   * #MHD_DAUTH_NONCE_STALE as RFCs allow nonces re-using for other URIs
   * in the same "protection space".
   * However, if only #MHD_D_OPTION_VALUE_DAUTH_BIND_NONCE_CLIENT_IP bit is set
   * and it is know that clients have fixed IP addresses, this return code could
   * be handled like #MHD_DAUTH_NONCE_WRONG.
   */
  MHD_DAUTH_NONCE_OTHER_COND = -18
  ,
  /**
   * The 'nonce' is wrong. May indicate an attack attempt.
   */
  MHD_DAUTH_NONCE_WRONG = -33
  ,
  /**
   * The 'response' is wrong. May indicate an attack attempt.
   */
  MHD_DAUTH_RESPONSE_WRONG = -34
};


/**
 * Authenticates the authorization header sent by the client.
 *
 * If RFC2069 mode is allowed by setting bit #MHD_DIGEST_AUTH_QOP_NONE in
 * @a mqop and the client uses this mode, then server generated nonces are
 * used as one-time nonces because nonce-count is not supported in this old RFC.
 * Communication in this mode is very inefficient, especially if the client
 * requests several resources one-by-one as for every request a new nonce must
 * be generated and client repeats all requests twice (first time to get a new
 * nonce and second time to perform an authorised request).
 *
 * @param request the request
 * @param realm the realm for authorization of the client
 * @param username the username to be authenticated, must be in clear text
 *                 even if userhash is used by the client
 * @param password the password matching the @a username (and the @a realm)
 * @param nonce_timeout the period of seconds since nonce generation, when
 *                      the nonce is recognised as valid and not stale;
 *                      if zero is specified then daemon default value is used.
 * @param max_nc the maximum allowed nc (Nonce Count) value, if client's nc
 *               exceeds the specified value then MHD_DAUTH_NONCE_STALE is
 *               returned;
 *               if zero is specified then daemon default value is used.
 * @param mqop the QOP to use
 * @param malgo digest algorithms allowed to use, fail if algorithm used
 *               by the client is not allowed by this parameter
 * @return #MHD_DAUTH_OK if authenticated,
 *         the error code otherwise
 * @ingroup authentication
 */
MHD_EXTERN_ enum MHD_DigestAuthResult
MHD_digest_auth_check (struct MHD_Request *request,
                       const char *realm,
                       const char *username,
                       const char *password,
                       unsigned int nonce_timeout,
                       uint_fast32_t max_nc,
                       enum MHD_DigestAuthMultiQOP mqop,
                       enum MHD_DigestAuthMultiAlgo malgo)
MHD_FN_PAR_NONNULL_ (1)
MHD_FN_PAR_NONNULL_ (2) MHD_FN_PAR_CSTR_ (2)
MHD_FN_PAR_NONNULL_ (3) MHD_FN_PAR_CSTR_ (3)
MHD_FN_PAR_NONNULL_ (4) MHD_FN_PAR_CSTR_ (4);


/**
 * Calculate userdigest, return it as a binary data.
 *
 * The "userdigest" is the hash of the "username:realm:password" string.
 *
 * The "userdigest" can be used to avoid storing the password in clear text
 * in database/files
 *
 * This function is designed to improve security of stored credentials,
 * the "userdigest" does not improve security of the authentication process.
 *
 * The results can be used to store username & userdigest pairs instead of
 * username & password pairs. To further improve security, application may
 * store username & userhash & userdigest triplets.
 *
 * @param algo the digest algorithm
 * @param username the username
 * @param realm the realm
 * @param password the password
 * @param bin_buf_size the size of the @a userdigest_bin buffer, must be
 *                     at least #MHD_digest_get_hash_size() bytes long
 * @param[out] userdigest_bin the output buffer for userdigest;
 *                            if this function succeeds, then this buffer has
 *                            #MHD_digest_get_hash_size() bytes of
 *                            userdigest upon return
 * @return #MHD_SC_OK on success,
 *         error code otherwise.
 * @sa #MHD_digest_auth_check_digest()
 * @ingroup authentication
 */
MHD_EXTERN_ enum MHD_StatusCode
MHD_digest_auth_calc_userdigest (enum MHD_DigestAuthAlgo algo,
                                 const char *username,
                                 const char *realm,
                                 const char *password,
                                 size_t bin_buf_size,
                                 void *userdigest_bin)
MHD_FN_PURE_ MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_CSTR_ (2)
MHD_FN_PAR_CSTR_ (3)
MHD_FN_PAR_CSTR_ (4)
MHD_FN_PAR_OUT_SIZE_ (6,5);


/**
 * Authenticates the authorization header sent by the client by using
 * hash of "username:realm:password".
 *
 * If RFC2069 mode is allowed by setting bit #MHD_DIGEST_AUTH_QOP_NONE in
 * @a mqop and the client uses this mode, then server generated nonces are
 * used as one-time nonces because nonce-count is not supported in this old RFC.
 * Communication in this mode is very inefficient, especially if the client
 * requests several resources one-by-one as for every request a new nonce must
 * be generated and client repeats all requests twice (first time to get a new
 * nonce and second time to perform an authorised request).
 *
 * @param request the request
 * @param realm the realm for authorization of the client
 * @param username the username to be authenticated, must be in clear text
 *                 even if userhash is used by the client
 * @param userdigest the precalculated binary hash of the string
 *                   "username:realm:password",
 *                   see #MHD_digest_auth_calc_userdigest()
 * @param userdigest_size the size of the @a userdigest in bytes, must match the
 *                        hashing algorithm (see #MHD_MD5_DIGEST_SIZE,
 *                        #MHD_SHA256_DIGEST_SIZE, #MHD_SHA512_256_DIGEST_SIZE,
 *                        #MHD_digest_get_hash_size())
 * @param nonce_timeout the period of seconds since nonce generation, when
 *                      the nonce is recognised as valid and not stale;
 *                      if zero is specified then daemon default value is used.
 * @param max_nc the maximum allowed nc (Nonce Count) value, if client's nc
 *               exceeds the specified value then MHD_DAUTH_NONCE_STALE is
 *               returned;
 *               if zero is specified then daemon default value is used.
 * @param mqop the QOP to use
 * @param malgo digest algorithms allowed to use, fail if algorithm used
 *               by the client is not allowed by this parameter;
 *               more than one base algorithms (MD5, SHA-256, SHA-512/256)
 *               cannot be used at the same time for this function
 *               as @a userdigest must match specified algorithm
 * @return #MHD_DAUTH_OK if authenticated,
 *         the error code otherwise
 * @sa #MHD_digest_auth_calc_userdigest()
 * @ingroup authentication
 */
MHD_EXTERN_ enum MHD_DigestAuthResult
MHD_digest_auth_check_digest (struct MHD_Request *request,
                              const char *realm,
                              const char *username,
                              const void *userdigest,
                              size_t userdigest_size,
                              unsigned int nonce_timeout,
                              uint_fast32_t max_nc,
                              enum MHD_DigestAuthMultiQOP mqop,
                              enum MHD_DigestAuthMultiAlgo malgo)
MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_CSTR_ (2)
MHD_FN_PAR_CSTR_ (3)
MHD_FN_PAR_CSTR_ (4);


/**
 * Create an action to request authentication from the client
 *
 * If @a mqop allows both RFC 2069 (MHD_DIGEST_AUTH_QOP_NONE) and QOP with
 * value, then response is formed like if MHD_DIGEST_AUTH_QOP_NONE bit was
 * not set, because such response should be backward-compatible with RFC 2069.
 *
 * If @a mqop allows only MHD_DIGEST_AUTH_MULT_QOP_NONE, then the response is
 * formed in strict accordance with RFC 2069 (no 'qop', no 'userhash', no
 * 'charset'). For better compatibility with clients, it is recommended (but
 * not required) to set @a domain to NULL in this mode.
 *
 * At most one action can be created for any request.
 *
 * @param request the request
 * @param realm the realm presented to the client
 * @param opaque the string for opaque value, can be NULL, but NULL is
 *               not recommended for better compatibility with clients;
 *               the recommended format is hex or Base64 encoded string
 * @param domain the optional space-separated list of URIs for which the
 *               same authorisation could be used, URIs can be in form
 *               "path-absolute" (the path for the same host with initial slash)
 *               or in form "absolute-URI" (the full path with protocol), in
 *               any case client may assume that URI is in the same "protection
 *               space" if it starts with any of values specified here;
 *               could be NULL (clients typically assume that the same
 *               credentials could be used for any URI on the same host);
 *               this list provides information for the client only and does
 *               not actually restrict anything on the server side
 * @param response the reply to send; should contain the "access denied"
 *                 body;
 *                 note: this function sets the "WWW Authenticate" header and
 *                 the caller should not set this header;
 *                 the response must have #MHD_HTTP_STATUS_FORBIDDEN status
 *                 code, must not have #MHD_R_O_REUSABLE enabled;
 *                 the NULL is tolerated (the result is NULL)
 * @param signal_stale if set to #MHD_YES then indication of stale nonce used in
 *                     the client's request is signalled by adding 'stale=true'
 *                     to the authentication header, this instructs the client
 *                     to retry immediately with the new nonce and the same
 *                     credentials, without asking user for the new password
 * @param mqop the QOP to use
 * @param algo digest algorithm to use; if several algorithms are allowed
 *               then MD5 is preferred (currently, may be changed in next
 *               versions)
 * @param userhash_support if set to non-zero value (#MHD_YES) then support of
 *                         userhash is indicated, allowing client to provide
 *                         hash("username:realm") instead of the username in
 *                         clear text;
 *                         note that clients are allowed to provide the username
 *                         in cleartext even if this parameter set to non-zero;
 *                         when userhash is used, application must be ready to
 *                         identify users by provided userhash value instead of
 *                         username; see #MHD_digest_auth_calc_userhash() and
 *                         #MHD_digest_auth_calc_userhash_hex()
 * @param prefer_utf8 if not set to #MHD_NO, parameter 'charset=UTF-8' is
 *                    added, indicating for the client that UTF-8 encoding for
 *                    the username is preferred
 * @return pointer to the action on success,
 *         NULL on failure
 * @ingroup authentication
 */
MHD_EXTERN_ const struct MHD_Action *
MHD_action_digest_auth_required_response (
  struct MHD_Request *request,
  const char *realm,
  const char *opaque,
  const char *domain,
  struct MHD_Response *response,
  enum MHD_Bool signal_stale,
  enum MHD_DigestAuthMultiQOP mqop,
  enum MHD_DigestAuthMultiAlgo algo,
  enum MHD_Bool userhash_support,
  enum MHD_Bool prefer_utf8)
MHD_FN_PAR_NONNULL_ (1) MHD_FN_PAR_NONNULL_ (2) MHD_FN_PAR_CSTR_ (2)
MHD_FN_PAR_CSTR_ (3) MHD_FN_PAR_CSTR_ (4) MHD_FN_PAR_NONNULL_ (5);


/**
 * Constant to indicate that the nonce of the provided
 * authentication code was wrong.
 * Used as return code by #MHD_digest_auth_check(),
 * #MHD_digest_auth_check_digest()
 * @ingroup authentication
 */
#define MHD_INVALID_NONCE -1


/**
 * Information decoded from Basic Authentication client's header.
 *
 * @see #MHD_REQUEST_INFO_DYNAMIC_BAUTH_REQ_INFO
 */
struct MHD_BasicAuthInfo
{
  /**
   * The username
   */
  struct MHD_String username;

  /**
   * The password, string pointer may be NULL if password is not encoded
   * by the client.
   */
  struct MHD_StringNullable password;
};

/**
 * Send a response to request basic authentication from the client.
 *
 * See RFC 7617, section-2 for details.
 *
 * At most one action can be created for any request.
 *
 * @param connection the MHD connection structure
 * @param realm the realm presented to the client
 * @param prefer_utf8 if not set to #MHD_NO, parameter'charset="UTF-8"' will
 *                    be added, indicating for client that UTF-8 encoding
 *                    is preferred
 * @param response the reply to send; should contain the "access denied"
 *                 body;
 *                 note: this function sets the "WWW Authenticate" header and
 *                 the caller should not set this header;
 *                 the response must have #MHD_HTTP_STATUS_FORBIDDEN status
 *                 code, must not have #MHD_R_O_REUSABLE enabled;
 *                 the NULL is tolerated (the result is NULL)
 * @return pointer to the action on success,
 *         NULL on failure
 * @ingroup authentication
 */
MHD_EXTERN_ const struct MHD_Action *
MHD_action_basic_auth_required_response (
  struct MHD_Connection *connection,
  const char *realm,
  enum MHD_Bool prefer_utf8,
  struct MHD_Response *response);


/* ********************** (f) Introspection ********************** */


/**
 * Types of information about MHD,
 * used by #MHD_lib_get_info_fixed_sz().
 * This information is not changed at run-time.
 */
enum MHD_FIXED_ENUM_APP_SET_ MHD_LibInfoFixed
{
  /* * Basic MHD information * */

  /**
   * Get the MHD version as a number.
   * The result is placed in @a v_uint32 member.
   */
  MHD_LIB_INFO_FIXED_VERSION_NUM = 0
  ,
  /**
   * Get the MHD version as a string.
   * The result is placed in @a v_string member.
   */
  MHD_LIB_INFO_FIXED_VERSION_STR = 1
  ,

  /* * Basic MHD features, buid-time configurable * */
  /* These features should be always available unless the library was
   * not compiled specifically for some embedded project.
   * Exceptions are marked explicitly in the description. */

  /**
   * Get whether messages are supported. If supported then in debug
   * mode messages can be printed to stderr or to external logger.
   * The result is placed in @a v_bool member.
   */
  MHD_LIB_INFO_FIXED_HAS_MESSAGES = 11
  ,
  /**
   * Get whether MHD supports threads.
   * The result is placed in @a v_bool member.
   */
  MHD_LIB_INFO_FIXED_HAS_THREADS = 12
  ,
  /**
   * Get whether MHD was built with asserts enabled.
   * Enabled only on special debug builds.
   * For debug builds the error log is always enabled.
   * The result is placed in @a v_bool member.
   */
  MHD_LIB_INFO_FIXED_HAS_DEBUG = 13
  ,
  /**
   * Get whether automatic parsing of HTTP Cookie header is supported.
   * If disabled, no #MHD_VK_COOKIE will be generated by MHD.
   * The result is placed in @a v_bool member.
   */
  MHD_LIB_INFO_FIXED_HAS_COOKIE_PARSING = 14
  ,
  /**
   * Get whether postprocessor is supported. If supported then
   * #MHD_action_post_processor() can be used.
   * The result is placed in @a v_bool member.
   */
  MHD_LIB_INFO_FIXED_HAS_POSTPROCESSOR = 15
  ,
  /**
   * Get whether HTTP "Upgrade" is supported.
   * If supported then #MHD_action_upgrade() can be used.
   * The result is placed in @a v_bool member.
   */
  MHD_LIB_INFO_FIXED_HAS_UPGRADE = 16
  ,
  /**
   * Get whether HTTP Basic authorization is supported. If supported
   * then functions #MHD_action_basic_auth_required_response ()
   * and #MHD_REQUEST_INFO_DYNAMIC_BAUTH_REQ_INFO can be used.
   * The result is placed in @a v_bool member.
   */
  MHD_LIB_INFO_FIXED_HAS_BASIC_AUTH = 20
  ,
  /**
   * Get whether HTTP Digest authorization is supported. If
   * supported then options #MHD_D_O_RANDOM_ENTROPY,
   * #MHD_D_O_DAUTH_MAP_SIZE and functions
   * #MHD_action_digest_auth_required_response () and
   * #MHD_digest_auth_check() can be used.
   * The result is placed in @a v_bool member.
   */
  MHD_LIB_INFO_FIXED_HAS_DIGEST_AUTH = 21
  ,
  /**
   * Get whether the early version the Digest Authorization (RFC 2069) is
   * supported (digest authorisation without QOP parameter).
   * Currently it is always supported if Digest Auth module is built.
   * The result is placed in @a v_bool member.
   */
  MHD_LIB_INFO_FIXED_HAS_DIGEST_AUTH_RFC2069 = 22
  ,
  /**
   * Get whether the MD5-based hashing algorithms are supported for Digest
   * Authorization and the type of the implementation if supported.
   * Currently it is always supported if Digest Auth module is built
   * unless manually disabled in a custom build.
   * The result is placed in @a v_d_algo member.
   */
  MHD_LIB_INFO_FIXED_TYPE_DIGEST_AUTH_MD5 = 23
  ,
  /**
   * Get whether the SHA-256-based hashing algorithms are supported for Digest
   * Authorization and the type of the implementation if supported.
   * Currently it is always supported if Digest Auth module is built
   * unless manually disabled in a custom build.
   * The result is placed in @a v_d_algo member.
   */
  MHD_LIB_INFO_FIXED_TYPE_DIGEST_AUTH_SHA256 = 24
  ,
  /**
   * Get whether the SHA-512/256-based hashing algorithms are supported
   * Authorization and the type of the implementation if supported.
   * Currently it is always supported if Digest Auth module is built
   * unless manually disabled in a custom build.
   * The result is placed in @a v_d_algo member.
   */
  MHD_LIB_INFO_FIXED_TYPE_DIGEST_AUTH_SHA512_256 = 25
  ,
  /**
   * Get whether QOP with value 'auth-int' (authentication with integrity
   * protection) is supported for Digest Authorization.
   * Currently it is always not supported.
   * The result is placed in @a v_bool member.
   */
  MHD_LIB_INFO_FIXED_HAS_DIGEST_AUTH_AUTH_INT = 28
  ,
  /**
   * Get whether 'session' algorithms (like 'MD5-sess') are supported for Digest
   * Authorization.
   * Currently it is always not supported.
   * The result is placed in @a v_bool member.
   */
  MHD_LIB_INFO_FIXED_HAS_DIGEST_AUTH_ALGO_SESSION = 29
  ,
  /**
   * Get whether 'userhash' is supported for Digest Authorization.
   * Currently it is always supported if Digest Auth module is built.
   * The result is placed in @a v_bool member.
   */
  MHD_LIB_INFO_FIXED_HAS_DIGEST_AUTH_USERHASH = 30
  ,

  /* * Platform-dependent features, some are configurable at build-time * */
  /* These features depends on the platform, third-party libraries and
   * the toolchain.
   * Some of the features can be disabled or selected at build-time. */
  /**
   * Get supported sockets polling function/techniques.
   * The result is placed in @a v_polling member.
   */
  MHD_LIB_INFO_FIXED_TYPE_SOCKETS_POLLING = 50
  ,
  /**
   * Get whether aggregate FD external polling is supported.
   * The result is placed in @a v_polling member.
   */
  MHD_LIB_INFO_FIXED_HAS_AGGREGATE_FD = 51
  ,
  /**
   * Get whether IPv6 is supported on the platform and whether IPv6 without IPv4
   * can be used.
   * The result is placed in @a v_ipv6 member.
   * @note The platform may have disabled IPv6 at run-time, it is not checked
   *       by this information type.
   */
  MHD_LIB_INFO_FIXED_TYPE_IPv6 = 52
  ,
  /**
   * Get whether TCP Fast Open is supported by MHD build.
   * If supported then option #MHD_D_O_TCP_FASTOPEN can be used.
   * The result is placed in @a v_bool member.
   */
  MHD_LIB_INFO_FIXED_HAS_TCP_FASTOPEN = 53
  ,
  /**
   * Get whether MHD support automatic detection of bind port number.
   * @sa #MHD_D_O_BIND_PORT
   * The result is placed in @a v_bool member.
   */
  MHD_LIB_INFO_FIXED_HAS_AUTODETECT_BIND_PORT = 54
  ,
  /**
   * Get whether MHD use system's sendfile() function to send
   * file-FD based responses over non-TLS connections.
   * The result is placed in @a v_bool member.
   */
  MHD_LIB_INFO_FIXED_HAS_SENDFILE = 55
  ,
  /**
   * Get whether MHD supports automatic SIGPIPE suppression.
   * If SIGPIPE suppression is not supported, application must handle
   * SIGPIPE signal by itself.
   * The result is placed in @a v_bool member.
   */
  MHD_LIB_INFO_FIXED_HAS_AUTOSUPPRESS_SIGPIPE = 60
  ,
  /**
   * Get whether MHD sets names on generated threads.
   * The result is placed in @a v_bool member.
   */
  MHD_LIB_INFO_FIXED_HAS_THREAD_NAMES = 61
  ,
  /**
   * Get the type of supported inter-thread communication.
   * The result is placed in @a v_itc member.
   */
  MHD_LIB_INFO_FIXED_TYPE_ITC = 62
  ,
  /**
   * Get whether reading files beyond 2 GiB boundary is supported.
   * If supported then #MHD_response_from_fd() can be used with sizes and
   * offsets larger than 2 GiB. If not supported value of size+offset could be
   * limited to 2 GiB.
   * The result is placed in @a v_bool member.
   */
  MHD_LIB_INFO_FIXED_HAS_LARGE_FILE = 63
  ,

  /* * Platform-dependent features, some set on startup and some are
   *   configurable at build-time * */
  /* These features depends on the platform, third-party libraries availability
   * and configuration. The features can be enabled/disabled during startup
   * of the library depending on conditions.
   * Some of the features can be disabled or selected at build-time. */
  /**
   * Get whether HTTPS is supported and type of TLS backend(s) available if
   * HTTPS is supported.
   * The result is placed in @a v_tls member.
   */
  MHD_LIB_INFO_FIXED_TYPE_TLS = 100
  ,
  /**
  * Get whether password encrypted private key for HTTPS daemon is
  * supported. If supported then option
  * #MHD_D_OPTION_TLS_KEY_CERT can be used with non-NULL @a mem_pass
   * The result is placed in @a v_bool member.
  */
  MHD_LIB_INFO_FIXED_HAS_TLS_KEY_PASSWORD = 102
  ,

  /* * Sentinel * */
  /**
   * The sentinel value.
   * This value enforces specific underlying integer type for the enum.
   * Do not use.
   */
  MHD_LIB_INFO_FIXED_SENTINEL = 65535
};

/**
 * The type of the data for digest algorithm implementations.
 */
enum MHD_FIXED_ENUM_MHD_SET_ MHD_LibInfoFixedDigestAlgoType
{
  /**
   * The algorithm is not implemented or disabled at the build time.
   */
  MHD_LIB_INFO_FIXED_DIGEST_ALGO_TYPE_NOT_AVAILABLE = 0
  ,
  /**
   * The algorithm is implemented by MHD internal code.
   */
  MHD_LIB_INFO_FIXED_DIGEST_ALGO_TYPE_BUILT_IN = 1
  ,
  /**
   * The algorithm is implemented by external code that never fails.
   */
  MHD_LIB_INFO_FIXED_DIGEST_ALGO_TYPE_EXTERNAL_NEVER_FAIL = 2
  ,
  /**
   * The algorithm is implemented by external code that may hypothetically fail.
   */
  MHD_LIB_INFO_FIXED_DIGEST_ALGO_TYPE_EXTERNAL_MAY_FAIL = 3
};

/**
 * The types of the sockets polling functions/techniques supported
 */
struct MHD_LibInfoFixedPollingFunc
{
  /**
   * select() function for sockets polling
   */
  enum MHD_Bool func_select;
  /**
   * poll() function for sockets polling
   */
  enum MHD_Bool func_poll;
  /**
   * epoll technique for sockets polling
   */
  enum MHD_Bool tech_epoll;
};

/**
 * The types of IPv6 supported
 */
enum MHD_FIXED_ENUM_MHD_SET_ MHD_LibInfoFixedIPv6Type
{
  /**
   * IPv6 is not supported by this MHD build
   */
  MHD_LIB_INFO_FIXED_IPV6_TYPE_NONE = 0
  ,
  /**
   * IPv6 is supported only as "dual stack".
   * IPv4 connections can be received by IPv6 listen socket.
   */
  MHD_LIB_INFO_FIXED_IPV6_TYPE_DUAL_ONLY = 1
  ,
  /**
   * IPv6 is supported as IPv6-only or as "dual stack".
   */
  MHD_LIB_INFO_FIXED_IPV6_TYPE_BOTH = 2
};

/**
 * The types of inter-thread communication
 * @note the enum can be extended in future versions with new values
 */
enum MHD_FIXED_ENUM_MHD_SET_ MHD_LibInfoFixedITCType
{
  /**
   * The pair of sockets are used as inter-thread communication.
   * The is the least efficient method of communication.
   */
  MHD_LIB_INFO_FIXED_ITC_TYPE_SOCKETPAIR = 0
  ,
  /**
   * The pipe is used as inter-thread communication.
   */
  MHD_LIB_INFO_FIXED_ITC_TYPE_PIPE = 1
  ,
  /**
   * The EventFD is used as inter-thread communication.
   * This is the most efficient method of communication.
   */
  MHD_LIB_INFO_FIXED_ITC_TYPE_EVENTFD = 2
};


/**
 * The types of the TLS backend supported
 * @note the enum can be extended in future versions with new members
 */
struct MHD_LibInfoFixedTLSType
{
  /**
   * The TLS is supported.
   * Set to #MHD_YES if any other member is #MHD_YES.
   */
  enum MHD_Bool tls_supported;
  /**
   * The TLS is supported by GnuTLS backend.
   */
  enum MHD_Bool tls_gnutls;
};

/**
 * The data provided by #MHD_lib_get_info_fixed_sz()
 */
union MHD_LibInfoFixedData
{
  /**
   * The 32-bit unsigned integer value
   */
  uint_fast32_t v_uint32;
  /**
   * The MHD string value
   */
  struct MHD_String v_string;
  /**
   * The boolean value
   */
  enum MHD_Bool v_bool;
  /**
   * The type of digest algorithm implemetation
   */
  enum MHD_LibInfoFixedDigestAlgoType v_d_algo;
  /**
   * The types of the sockets polling functions/techniques supported
   */
  struct MHD_LibInfoFixedPollingFunc v_polling;
  /**
   * The type of IPv6 supported
   */
  enum MHD_LibInfoFixedIPv6Type v_ipv6;
  /**
   * The type of inter-thread communication
   */
  enum MHD_LibInfoFixedITCType v_itc;
  /**
   * The types of the TLS backend supported
   */
  struct MHD_LibInfoFixedTLSType v_tls;
};

/**
 * Get fixed information about MHD that is not changed at run-time.
 * The returned information can be cached by application as it will be not
 * changed at run-time.
 * The wrapper macro #MHD_lib_get_info_fixed() could be more convenient.
 *
 * @param info_type the type of requested information
 * @param[out] return_data the pointer to union to be set to the required
 *                         information
 * @param return_data_size the size of the memory area pointed
 *                         by @a return_data, in bytes
 * @return #MHD_SC_OK if succeed,
 *         error code otherwise
 * @ingroup specialized
 */
MHD_EXTERN_ enum MHD_StatusCode
MHD_lib_get_info_fixed_sz (enum MHD_LibInfoFixed info_type,
                           union MHD_LibInfoFixedData *return_data,
                           size_t return_data_size)
MHD_FN_PAR_NONNULL_ (2) MHD_FN_PAR_OUT_ (2)
MHD_FN_PURE_;

/**
 * Get fixed information about MHD that is not changed at run-time.
 * The returned information can be cached by application as it will be not
 * changed at run-time.
 *
 * @param info the type of requested information
 * @param[out] data the pointer to union to set to the required information
 * @return #MHD_SC_OK if succeed,
 *         error code otherwise
 * @ingroup specialized
 */
#define MHD_lib_get_info_fixed(info,data) \
        MHD_lib_get_info_fixed_sz ((info),(data),sizeof(*(data)))

/**
 * Types of information about MHD,
 * used by #MHD_lib_get_info_dynamic_sz().
 * This information may vary over time.
 */
enum MHD_FIXED_ENUM_APP_SET_ MHD_LibInfoDynamic
{
  /* * Basic MHD information * */

  /**
   * Get whether MHD was successfully initialised.
   * The result is #MHD_NO when the library has not been yet initialised or
   * when library has been de-initialised.
   * Under normal conditions the result must be always #MHD_YES when requested
   * by application.
   * The result is placed in @a v_bool member.
   */
  MHD_LIB_INFO_DYNAMIC_INITED = 0
  ,

  /* * Sentinel * */
  /**
   * The sentinel value.
   * This value enforces specific underlying integer type for the enum.
   * Do not use.
   */
  MHD_LIB_INFO_DYNAMIC_SENTINEL = 65535
};


/**
 * The data provided by #MHD_lib_get_info_dynamic_sz().
 * The resulting value may vary over time.
 */
union MHD_LibInfoDynamicData
{
  /**
   * The boolean value
   */
  enum MHD_Bool v_bool;

  /**
   * Unused member.
   * Help enforcing future-proof alignment of the union.
   * Do not use.
   */
  void *reserved;
};

/**
 * Get dynamic information about MHD that may be changed at run-time.
 * The wrapper macro #MHD_lib_get_info_dynamic() could be more convenient.
 *
 * @param info_type the type of requested information
 * @param[out] return_data the pointer to union to be set to the required
 *                         information
 * @param return_data_size the size of the memory area pointed
 *                         by @a return_data, in bytes
 * @return #MHD_SC_OK if succeed,
 *         error code otherwise
 * @ingroup specialized
 */
MHD_EXTERN_ enum MHD_StatusCode
MHD_lib_get_info_dynamic_sz (enum MHD_LibInfoDynamic info_type,
                             union MHD_LibInfoDynamicData *return_data,
                             size_t return_data_size)
MHD_FN_PAR_NONNULL_ (2) MHD_FN_PAR_OUT_ (2);

/**
 * Get dynamic information about MHD that may be changed at run-time.
 *
 * @param info the type of requested information
 * @param[out] data the pointer to union to set to the required information
 * @return #MHD_SC_OK if succeed,
 *         error code otherwise
 * @ingroup specialized
 */
#define MHD_lib_get_info_dynamic(info,data) \
        MHD_lib_get_info_fixed_sz ((info),(data),sizeof(*(data)))


/**
 * Values of this enum are used to specify what
 * information about a daemon is desired.
 * This types of information are not changed at after start of the daemon until
 * the daemon is destroyed.
 */
enum MHD_DaemonInfoFixedType
{

  /**
   * Request the file descriptor for the listening socket.
   * The result is placed in @a v_socket member.
   */
  MHD_DAEMON_INFO_FIXED_LISTEN_SOCKET = 1
  ,
  /**
   * Request the file descriptor for the single FD that triggered when
   * any MHD event happens.
   * This FD can be watched as aggregate indicator for all MHD events.
   * The result is placed in @a v_fd member.
   */
  MHD_DAEMON_INFO_FIXED_AGGREAGATE_FD
  ,
  /**
   * Request the port number of daemon's listen socket.
   * No extra arguments should be passed.
   * Note: if port '0' was specified for #MHD_D_OPTION_BIND_PORT(), returned
   * value will be real port number.
   * The result is placed in @a v_port member.
   */
  MHD_DAEMON_INFO_FIXED_BIND_PORT
  ,
  /* * Sentinel * */
  /**
   * The sentinel value.
   * This value enforces specific underlying integer type for the enum.
   * Do not use.
   */
  MHD_DAEMON_INFO_FIXED_SENTINEL = 65535

};


/**
 * Information about an MHD daemon.
 */
union MHD_DaemonInfoFixedData
{

  /**
   * The socket type of data.
   */
  MHD_Socket v_socket;

  /**
   * File descriptor, except sockets
   */
  int v_fd;

  /**
   * Port number
   */
  uint_least16_t v_port;

  /**
   * Unused member.
   * Help enforcing future-proof alignment of the union.
   * Do not use.
   */
  void *reserved;
};


/**
 * Obtain fixed information about the given daemon.
 * This information is not changed at after start of the daemon until
 * the daemon is destroyed.
 * The wrapper macro #MHD_daemon_get_info_fixed() could be more convenient.
 *
 * @param daemon the daemon to get information about
 * @param info_type the type of information requested
 * @param[out] return_value pointer to union where requested information will
 *                          be stored
 * @param return_value_size the size of the memory area pointed
 *                          by @a return_data, in bytes
 * @return #MHD_SC_OK if succeed,
 *         error code otherwise
 * @ingroup specialized
 */
MHD_EXTERN_ enum MHD_StatusCode
MHD_daemon_get_info_fixed_sz (struct MHD_Daemon *daemon,
                              enum MHD_DaemonInfoFixedType info_type,
                              union MHD_DaemonInfoFixedData *return_value,
                              size_t return_value_size)
MHD_FN_PAR_NONNULL_ (1)
MHD_FN_PAR_NONNULL_ (3) MHD_FN_PAR_OUT_ (3)
MHD_FN_PURE_;

/**
 * Obtain fixed information about the given daemon.
 * This types of information are not changed at after start of the daemon until
 * the daemon is destroyed.
 *
 * @param daemon the daemon to get information about
 * @param info_type the type of information requested
 * @param[out] return_value pointer to union where requested information will
 *                          be stored
 * @return #MHD_SC_OK if succeed,
 *         error code otherwise
 * @ingroup specialized
 */
#define MHD_daemon_get_info_fixed(daemon,info_type,return_value) \
        MHD_daemon_get_info_fixed_sz ((daemon), (info_type), (return_value), \
                                      sizeof(*(return_value)))


/**
 * Values of this enum are used to specify what
 * information about a daemon is desired.
 * This types of information may be changed after the start of the daemon.
 */
enum MHD_DaemonInfoDynamicType
{
  /**
   * The the maximum number of microseconds from the current moment until
   * the mandatory call of the daemon data processing function (like
   * #MHD_deamon_process_reg_events(), #MHD_daemon_process_blocking()).
   * If resulting value is zero then daemon data processing function should be
   * called as soon as possible as some data processing is already pending.
   * The data processing function can also be called earlier as well.
   * Available only for daemons stated in #MHD_WM_EXTERNAL_PERIODIC,
   * #MHD_WM_EXTERNAL_EVENT_LOOP_CB_LEVEL, #MHD_WM_EXTERNAL_EVENT_LOOP_CB_EDGE
   * or #MHD_WM_EXTERNAL_SINGLE_FD_WATCH modes.
   * The result is placed in @a v_uint64 member.
   */
  MHD_DAEMON_INFO_DYNAMIC_MAX_TIME_TO_WAIT = 1
  ,
  /**
   * Request the number of current connections handled by the daemon.
   * No extra arguments should be passed.
   * Note: when using MHD without internal threads, this type of request
   * could be used only when MHD is is not processing the connection data
   * in other thread at the same time.
   * The result is placed in @a v_uint member.
   */
  MHD_DAEMON_INFO_DYNAMIC_CURRENT_CONNECTIONS = 20
  ,
  /* * Sentinel * */
  /**
   * The sentinel value.
   * This value enforces specific underlying integer type for the enum.
   * Do not use.
   */
  MHD_DAEMON_INFO_DYNAMIC_SENTINEL = 65535
};


/**
 * Information about an MHD daemon.
 */
union MHD_DaemonInfoDynamicData
{
  /**
   * Unsigned 64 bits integer value.
   */
  uint_fast64_t v_uint64;

  /**
   * Unsigned integer value.
   */
  unsigned int v_uint;

  /**
   * Unused member.
   * Help enforcing future-proof alignment of the union.
   * Do not use.
   */
  void *reserved;
};


/**
 * Obtain dynamic information about the given daemon.
 * This information may be changed after the start of the daemon.
 * The wrapper macro #MHD_daemon_get_info_dynamic() could be more convenient.
 *
 * @param daemon the daemon to get information about
 * @param info_type the type of information requested
 * @param[out] return_value pointer to union where requested information will
 *                          be stored
 * @param return_value_size the size of the memory area pointed
 *                          by @a return_data, in bytes
 * @return #MHD_SC_OK if succeed,
 *         error code otherwise
 * @ingroup specialized
 */
MHD_EXTERN_ enum MHD_StatusCode
MHD_daemon_get_info_dynamic_sz (struct MHD_Daemon *daemon,
                                enum MHD_DaemonInfoDynamicType info_type,
                                union MHD_DaemonInfoDynamicData *return_value,
                                size_t return_value_size)
MHD_FN_PAR_NONNULL_ (1)
MHD_FN_PAR_NONNULL_ (3) MHD_FN_PAR_OUT_ (3);

/**
 * Obtain dynamic information about the given daemon.
 * This types of information may be changed after the start of the daemon.
 *
 * @param daemon the daemon to get information about
 * @param info_type the type of information requested
 * @param[out] return_value pointer to union where requested information will
 *                          be stored
 * @return #MHD_SC_OK if succeed,
 *         error code otherwise
 * @ingroup specialized
 */
#define MHD_daemon_get_info_dynamic(daemon,info_type,return_value) \
        MHD_daemon_get_info_dynamic_sz ((daemon), (info_type), (return_value), \
                                        sizeof(*(return_value)))


/**
 * Select which fixed information about connection is desired.
 * This information is not changed during the lifetime of the connection.
 */
enum MHD_ConnectionInfoFixedType
{
  /**
   * Obtain IP address of the client.
   * The result is placed in @a vs_sa member.
   * @ingroup request
   */
  MHD_CONNECTION_INFO_FIXED_CLIENT_ADDRESS = 1
  ,
  /**
   * Request the file descriptor for the connection socket.
   * The result is placed in @a v_fd member.
   * @ingroup request
   */
  MHD_CONNECTION_INFO_FIXED_CONNECTION_FD = 2
  ,
  /**
   * Get the `struct MHD_Daemon *` responsible for managing this connection.
   * The result is placed in @a v_daemon member.
   * @ingroup request
   */
  MHD_CONNECTION_INFO_FIXED_DAEMON = 20
  ,
  /* * Sentinel * */
  /**
   * The sentinel value.
   * This value enforces specific underlying integer type for the enum.
   * Do not use.
   */
  MHD_CONNECTION_INFO_FIXED_SENTINEL = 65535
};


/**
 * Information about a connection.
 */
union MHD_ConnectionInfoFixedData
{

  /**
   * Socket Address type
   */
  const struct sockaddr *vs_sa;

  /**
   * Socket type
   */
  MHD_Socket v_fd;

  /**
   * Daemon handler type
   */
  struct MHD_Daemon *v_daemon;
};


/**
 * Obtain fixed information about the given connection.
 * This information is not changed for the lifetime of the connection.
 * The wrapper macro #MHD_connection_get_info_fixed() could be more convenient.
 *
 * @param connection the connection to get information about
 * @param info_type the type of information requested
 * @param[out] return_value pointer to union where requested information will
 *                          be stored
 * @param return_value_size the size of the memory area pointed
                            by @a return_data, in bytes
 * @return #MHD_SC_OK if succeed,
 *         error code otherwise
 * @ingroup specialized
 */
MHD_EXTERN_ enum MHD_StatusCode
MHD_connection_get_info_fixed_sz (
  struct MHD_Connection *connection,
  enum MHD_ConnectionInfoFixedType info_type,
  union MHD_ConnectionInfoFixedData *return_value,
  size_t return_value_size)
MHD_FN_PAR_NONNULL_ (1)
MHD_FN_PAR_NONNULL_ (3) MHD_FN_PAR_OUT_ (3)
MHD_FN_PURE_;


/**
 * Obtain fixed information about the given connection.
 * This information is not changed for the lifetime of the connection.
 *
 * @param connection the connection to get information about
 * @param info_type the type of information requested
 * @param[out] return_value pointer to union where requested information will
 *                          be stored
 * @return #MHD_SC_OK if succeed,
 *         error code otherwise
 * @ingroup specialized
 */
#define MHD_connection_get_info_fixed(connection,info_type,return_value) \
        MHD_connection_get_info_fixed_sz ((connection),(info_type),(return_value \
                                                                    ), \
                                          sizeof(*(return_value)))


/**
 * Select which dynamic information about connection is desired.
 * This information may be changed during the lifetime of the connection.
 */
enum MHD_ConnectionInfoDynamicType
{
  /**
   * Get current version of HTTP protocol used for connection.
   * The result is placed in @a v_http_ver member.
   * @ingroup request
   */
  MHD_CONNECTION_INFO_DYNAMIC_HTTP_VER = 1
  ,
  /**
   * Get connection timeout.
   * The result is placed in @a v_uint member.
   * @ingroup request
   */
  MHD_CONNECTION_INFO_DYNAMIC_CONNECTION_TIMEOUT = 10
  ,
  /**
   * Check whether the connection is suspended.
   * The result is placed in @a v_bool member.
   * @ingroup request
   */
  MHD_CONNECTION_INFO_DYNAMIC_CONNECTION_SUSPENDED = 11
  ,
  /**
   * Returns the connection-specific application context data that was
   * (possibly) set during a #MHD_NotifyConnectionCallback or provided via
   * @a connection_cntx parameter of #MHD_daemon_add_connection().
   * The result is placed in @a v_pvoid member.
   */
  MHD_CONNECTION_INFO_DYNAMIC_SOCKET_CONTEXT = 20
  ,
  /**
   * Get current version of TLS transport protocol used for connection
   * The result is placed in @a v_tls_ver member.
   * @ingroup request
   */
  MHD_CONNECTION_INFO_DYNAMIC_TLS_VER = 1
  ,
  /**
   * Get the GnuTLS session handle.
   * The result is placed in @a v_gnutls_session member.
   * @ingroup request
   */
  MHD_CONNECTION_INFO_DYNAMIC_GNUTLS_SESSION = 40
  ,

  /* * Sentinel * */
  /**
   * The sentinel value.
   * This value enforces specific underlying integer type for the enum.
   * Do not use.
   */
  MHD_CONNECTION_INFO_DYNAMIC_SENTINEL = 65535
};


/**
 * The versions of TLS protocol
 */
enum MHD_FIXED_ENUM_MHD_SET_ MHD_TlsVersion
{

  /**
   * No TLS / plain socket connection
   */
  MHD_TLS_VERSION_NO_TLS = 0
  ,
  /**
   * Not supported/failed to negotiate/failed to handshake TLS
   */
  MHD_TLS_VERSION_BROKEN = 1
  ,
  /**
   * TLS version 1.0
   */
  MHD_TLS_VERSION_1_0 = 2
  ,
  /**
   * TLS version 1.1
   */
  MHD_TLS_VERSION_1_1 = 3
  ,
  /**
   * TLS version 1.2
   */
  MHD_TLS_VERSION_1_2 = 4
  ,
  /**
   * TLS version 1.3
   */
  MHD_TLS_VERSION_1_3 = 5
  ,
  /**
   * Some unknown TLS version.
   * The TLS version is supported by TLS backend, but unknown to MHD.
   */
  MHD_TLS_VERSION_UNKNOWN = 1999
};

/**
 * Information about a connection.
 */
union MHD_ConnectionInfoDynamicData
{
  /**
   * The type for HTTP version
   */
  enum MHD_HTTP_ProtocolVersion v_http_ver;

  /**
   * The unsigned integer type
   */
  unsigned int v_uint;

  /**
   * The boolean type
   */
  enum MHD_Bool v_bool;

  /**
   * The pointer to void type
   */
  void *v_pvoid;

  /**
   * The TLS version
   */
  enum MHD_TlsVersion v_tls_ver;

  /* Include <gnutls/gnutls.h> before this header to get a better type safety */
  /**
   * GnuTLS session handle, of type "gnutls_session_t".
   */
#if defined(GNUTLS_VERSION_MAJOR) && GNUTLS_VERSION_MAJOR >= 3
  gnutls_session_t
#else
  void * /* gnutls_session_t */
#endif
  v_gnutls_session;
};

/**
 * Obtain dynamic information about the given connection.
 * This information may be changed during the lifetime of the connection.
 * The wrapper macro #MHD_connection_get_info_dynamic() could be more
 * convenient.
 *
 * @param connection the connection to get information about
 * @param info_type the type of information requested
 * @param[out] return_value pointer to union where requested information will
 *                          be stored
 * @param return_value_size the size of the memory area pointed
                            by @a return_data, in bytes
 * @return #MHD_SC_OK if succeed,
 *         error code otherwise
 * @ingroup specialized
 */
MHD_EXTERN_ enum MHD_StatusCode
MHD_connection_get_info_dynamic_sz (
  struct MHD_Connection *connection,
  enum MHD_ConnectionInfoDynamicType info_type,
  union MHD_ConnectionInfoDynamicData *return_value,
  size_t return_value_size)
MHD_FN_PAR_NONNULL_ (1)
MHD_FN_PAR_NONNULL_ (3) MHD_FN_PAR_OUT_ (3);


/**
 * Obtain dynamic information about the given connection.
 * This information may be changed during the lifetime of the connection.
 *
 * @param connection the connection to get information about
 * @param info_type the type of information requested
 * @param[out] return_value pointer to union where requested information will
 *                          be stored
 * @return #MHD_SC_OK if succeed,
 *         error code otherwise
 * @ingroup specialized
 */
#define MHD_connection_get_info_dynamic(connection,info_type,return_value) \
        MHD_connection_get_info_dynamic_sz ((connection),(info_type),( \
                                              return_value), \
                                            sizeof(*(return_value)))


/**
 * Select which fixed information about stream is desired.
 * This information is not changed during the lifetime of the connection.
 */
enum MHD_FIXED_ENUM_APP_SET_ MHD_StreamInfoFixedType
{
  /**
   * Get the `struct MHD_Connection *` responsible for managing this stream.
   * The result is placed in @a v_connection member.
   * @ingroup request
   */
  MHD_STREAM_INFO_FIXED_CONNECTION = 1
  ,
  /**
   * Get the `struct MHD_Daemon *` responsible for managing connection which
   * is responsible for this stream.
   * The result is placed in @a v_daemon member.
   * @ingroup request
   */
  MHD_STREAM_INFO_FIXED_DAEMON = 2
  ,
  /* * Sentinel * */
  /**
   * The sentinel value.
   * This value enforces specific underlying integer type for the enum.
   * Do not use.
   */
  MHD_STREAM_INFO_FIXED_SENTINEL = 65535
};


/**
 * Fixed information about a stream.
 */
union MHD_StreamInfoFixedData
{
  /**
   * Connection handler type
   */
  struct MHD_Connection *v_connection;
  /**
   * Daemon handler type
   */
  struct MHD_Daemon *v_daemon;
};


/**
 * Obtain fixed information about the given stream.
 * This information is not changed for the lifetime of the stream.
 * The wrapper macro #MHD_stream_get_info_fixed() could be more convenient.
 *
 * @param stream the stream to get information about
 * @param info_type the type of information requested
 * @param[out] return_value pointer to union where requested information will
 *                          be stored
 * @param return_value_size the size of the memory area pointed
 *                          by @a return_data, in bytes
 * @return #MHD_SC_OK if succeed,
 *         error code otherwise
 * @ingroup specialized
 */
MHD_EXTERN_ enum MHD_StatusCode
MHD_stream_get_info_fixed_sz (
  struct MHD_Stream *stream,
  enum MHD_StreamInfoFixedType info_type,
  union MHD_StreamInfoFixedData *return_value,
  size_t return_value_size)
MHD_FN_PAR_NONNULL_ (1)
MHD_FN_PAR_NONNULL_ (3) MHD_FN_PAR_OUT_ (3)
MHD_FN_PURE_;


/**
 * Obtain fixed information about the given stream.
 * This information is not changed for the lifetime of the tream.
 *
 * @param stream the stream to get information about
 * @param info_type the type of information requested
 * @param[out] return_value pointer to union where requested information will
 *                          be stored
 * @return #MHD_SC_OK if succeed,
 *         error code otherwise
 * @ingroup specialized
 */
#define MHD_stream_get_info_fixed(stream,info_type,return_value) \
        MHD_stream_get_info_fixed_sz ((stream),(info_type),(return_value), \
                                      sizeof(*(return_value)))


/**
 * Select which fixed information about stream is desired.
 * This information may be changed during the lifetime of the stream.
 */
enum MHD_FIXED_ENUM_APP_SET_ MHD_StreamInfoDynamicType
{
  /**
   * Get the `struct MHD_Request *` for current request processed by the stream.
   * If no request is being processed, the resulting pointer is NULL.
   * The result is placed in @a v_request member.
   * @ingroup request
   */
  MHD_STREAM_INFO_DYNAMIC_REQUEST = 1
  ,

  /* * Sentinel * */
  /**
   * The sentinel value.
   * This value enforces specific underlying integer type for the enum.
   * Do not use.
   */
  MHD_STREAM_INFO_DYNAMIC_SENTINEL = 65535
};


/**
 * Dynamic information about stream.
 * This information may be changed during the lifetime of the connection.
 */
union MHD_StreamInfoDynamicData
{
  /**
   * The MHD_Request handler type
   */
  struct MHD_Request *v_request;
};

/**
 * Obtain dynamic information about the given stream.
 * This information may be changed during the lifetime of the stream.
 * The wrapper macro #MHD_stream_get_info_dynamic() could be more convenient.
 *
 * @param stream the stream to get information about
 * @param info_type the type of information requested
 * @param[out] return_value pointer to union where requested information will
 *                          be stored
 * @param return_value_size the size of the memory area pointed
                            by @a return_data, in bytes
 * @return #MHD_SC_OK if succeed,
 *         error code otherwise
 * @ingroup specialized
 */
MHD_EXTERN_ enum MHD_StatusCode
MHD_stream_get_info_dynamic_sz (
  struct MHD_Stream *stream,
  enum MHD_StreamInfoDynamicType info_type,
  union MHD_StreamInfoDynamicData *return_value,
  size_t return_value_size)
MHD_FN_PAR_NONNULL_ (1)
MHD_FN_PAR_NONNULL_ (3) MHD_FN_PAR_OUT_ (3);


/**
 * Obtain dynamic information about the given stream.
 * This information may be changed during the lifetime of the stream.
 *
 * @param stream the stream to get information about
 * @param info_type the type of information requested
 * @param[out] return_value pointer to union where requested information will
 *                          be stored
 * @return #MHD_SC_OK if succeed,
 *         error code otherwise
 * @ingroup specialized
 */
#define MHD_stream_get_info_dynamic(stream,info_type,return_value) \
        MHD_stream_get_info_dynamic_sz ((stream),(info_type),(return_value), \
                                        sizeof(*(return_value)))


/**
 * Select which fixed information about request is desired.
 * This information is not changed during the lifetime of the request.
 */
enum MHD_FIXED_ENUM_APP_SET_ MHD_RequestInfoFixedType
{
  /**
   * Return which stream the request is associated with.
   * The result is placed in @a v_stream member.
   */
  MHD_REQUEST_INFO_FIXED_STREAM = 1
  ,
  /**
   * Return which connection is associated with the stream which is associated
   * with the request.
   * The result is placed in @a v_connection member.
   */
  MHD_REQUEST_INFO_FIXED_CONNECTION = 2
  ,
  /**
   * Return MHD daemon to which the request belongs to.
   * The result is placed in @a v_daemon member.
   */
  MHD_REQUEST_INFO_FIXED_DAEMON = 3
  ,
  /**
   * Get the version of HTTP protocol used for the request.
   * The result is placed in @a v_http_ver member.
   * @ingroup request
   */
  MHD_REQUEST_INFO_FIXED_HTTP_VER = 4
  ,
  /**
   * Get the HTTP method used for the request (as a enum).
   * The result is placed in @a v_http_method member.
   * @sa #MHD_REQUEST_INFO_DYNAMIC_HTTP_METHOD_STR
   * @ingroup request
   */
  MHD_REQUEST_INFO_FIXED_HTTP_METHOD = 4
  ,

  /* * Sentinel * */
  /**
   * The sentinel value.
   * This value enforces specific underlying integer type for the enum.
   * Do not use.
   */
  MHD_REQUEST_INFO_FIXED_SENTINEL = 65535
};


/**
 * Fixed information about a request.
 */
union MHD_RequestInfoFixedData
{

  /**
   * The MHD stream handler type.
   */
  struct MHD_Stream *v_stream;

  /**
   * The MHD connection handler type.
   */
  struct MHD_Connection *v_connection;

  /**
   * The MHD daemon handler type.
   */
  struct MHD_Daemon *v_daemon;

  /**
   * The HTTP version type.
   */
  enum MHD_HTTP_ProtocolVersion v_http_ver;

  /**
   * The HTTP method type.
   */
  enum MHD_HTTP_Method v_http_method;
};

/**
 * Obtain fixed information about the given request.
 * This information is not changed for the lifetime of the request.
 * The wrapper macro #MHD_request_get_info_fixed() could be more convenient.
 *
 * @param request the request to get information about
 * @param info_type the type of information requested
 * @param[out] return_value pointer to union where requested information will
 *                          be stored
 * @param return_value_size the size of the memory area pointed
 *                          by @a return_data, in bytes
 * @return #MHD_SC_OK if succeed,
 *         error code otherwise
 * @ingroup specialized
 */
MHD_EXTERN_ enum MHD_StatusCode
MHD_request_get_info_fixed_sz (struct MHD_Request *request,
                               enum MHD_RequestInfoFixedType info_type,
                               union MHD_RequestInfoFixedData *return_value,
                               size_t return_value_size)
MHD_FN_PAR_NONNULL_ (1)
MHD_FN_PAR_NONNULL_ (3) MHD_FN_PAR_OUT_ (3)
MHD_FN_PURE_;


/**
 * Obtain fixed information about the given request.
 * This information is not changed for the lifetime of the request.
 *
 * @param request the request to get information about
 * @param info_type the type of information requested
 * @param[out] return_value pointer to union where requested information will
 *                          be stored
 * @return #MHD_SC_OK if succeed,
 *         error code otherwise
 * @ingroup specialized
 */
#define MHD_request_get_info_fixed(request,info_type,return_value) \
        MHD_request_get_info_fixed_sz ((request), (info_type), (return_value), \
                                       sizeof(*(return_value)))


/**
 * Select which dynamic information about request is desired.
 * This information may be changed during the lifetime of the request.
 * Any returned string pointers are valid only until a response is provided.
 */
enum MHD_FIXED_ENUM_APP_SET_ MHD_RequestInfoDynamicType
{
  /**
   * Get the HTTP method used for the request (as a MHD_String).
   * The result is placed in @a v_str member.
   * The resulting string pointer in valid only until a response is provided.
   * @sa #MHD_REQUEST_INFO_FIXED_HTTP_METHOD
   * @ingroup request
   */
  MHD_REQUEST_INFO_DYNAMIC_HTTP_METHOD_STR = 1
  ,
  /**
   * Get the URI used for the request (as a MHD_String), excluding
   * the parameter part (anything after '?').
   * The result is placed in @a v_str member.
   * The resulting string pointer in valid only until a response is provided.
   * @ingroup request
   */
  MHD_REQUEST_INFO_DYNAMIC_URI = 2
  ,
  /**
   * Get the number of GET parameters (the decoded part of the original
   * URI string after '?')
   * The result is placed in @a v_sizet member.
   * @ingroup request
   */
  MHD_REQUEST_INFO_DYNAMIC_NUMBER_GET_PARAMS = 3
  ,
  /**
   * Get the number of cookies in the request.
   * The result is placed in @a v_sizet member.
   * @ingroup request
   */
  MHD_REQUEST_INFO_DYNAMIC_NUMBER_COOKIES = 4
  ,
  /**
   * Get the number of decoded POST entries in the request.
   * The result is placed in @a v_sizet member.
   * @ingroup request
   */
  MHD_REQUEST_INFO_DYNAMIC_NUMBER_POST_PARAMS = 5
  ,
  /**
   * Get whether the upload content is present in the request.
   * The result is #MHD_YES if any upload content is present, even
   * if the upload content size is zero.
   * The result is placed in @a v_bool member.
   * @ingroup request
   */
  MHD_REQUEST_INFO_DYNAMIC_UPLOAD_PRESENT = 10
  ,
  /**
   * Get the total content upload size.
   * Resulted in zero if no content upload or upload content size is zero,
   * #MHD_SIZE_UNKNOWN if size is not known (chunked upload).
   * The result is placed in @a v_uint64 member.
   * @ingroup request
   */
  MHD_REQUEST_INFO_DYNAMIC_UPLOAD_SIZE_TOTAL = 11
  ,
  /**
   * Get the total size of the content upload already received from the client.
   * This is the total size received, could be not yet fully processed by the
   * application.
   * The result is placed in @a v_uint64 member.
   * @ingroup request
   */
  MHD_REQUEST_INFO_DYNAMIC_UPLOAD_SIZE_RECIEVED = 12
  ,
  /**
   * Get the total size of the content upload left to be received from
   * the client.
   * Resulted in #MHD_SIZE_UNKNOWN if total size is not known (chunked upload).
   * The result is placed in @a v_uint64 member.
   * @ingroup request
   */
  MHD_REQUEST_INFO_DYNAMIC_UPLOAD_SIZE_TO_RECIEVE = 13
  ,
  /**
   * Get the total size of the content upload already processed (upload callback
   * called and completed (if any)).
   * If the value is requested from #MHD_UploadCallback, then result does NOT
   * include the current data being processed by the callback.
   * The result is placed in @a v_uint64 member.
   * @ingroup request
   */
  MHD_REQUEST_INFO_DYNAMIC_UPLOAD_SIZE_PROCESSED = 14
  ,
  /**
   * Get the total size of the content upload left to be processed.
   * The resulting value includes the size of the data not yet received from
   * the client.
   * If the value is requested from #MHD_UploadCallback, then result includes
   * the current data being processed by the callback.
   * Resulted in #MHD_SIZE_UNKNOWN if total size is not known (chunked upload).
   * The result is placed in @a v_uint64 member.
   * @ingroup request
   */
  MHD_REQUEST_INFO_DYNAMIC_UPLOAD_SIZE_TO_PROCESS = 15
  ,
  /**
   * Return length of the client's HTTP request header.
   * This is a total raw size of the header (after TLS decipher if any)
   * The result is placed in @a v_sizet member.
   * @ingroup request
   */
  MHD_REQUEST_INFO_DYNAMIC_HEADER_SIZE = 21
  ,
  /**
   * Returns the request-specific pointer to a `void *`. The pointer obtainable
   * by this pointer is the same as provided for #MHD_EarlyUriLogCallback and
   * #MHD_RequestTerminationCallback.
   * By using provided pointer application may get or set the pointer to
   * any data specific for the particular request.
   * The result is placed in @a v_ppvoid member.
   * @ingroup request
   */
  MHD_REQUEST_INFO_DYNAMIC_APP_CONTEXT = 31
  ,
  /**
   * Returns pointer to information about username in client's digest auth
   * request.
   * The resulting pointer is NULL if no digest auth header is set by
   * the client, the format of the digest auth header is broken, no
   * username is provided or the format of the username parameter is broken.
   * Pointers in the returned structure (if any) are valid until response
   * is provided for the request.
   * The result is placed in @a v_dauth_username member.
   */
  MHD_REQUEST_INFO_DYNAMIC_DAUTH_USERNAME_INFO = 41
  ,
  /**
   * Returns pointer to information about digest auth in client request.
   * The resulting pointer is NULL if no digest auth header is set by
   * the client or the format of the digest auth header is broken.
   * Pointers in the returned structure (if any) are valid until response
   * is provided for the request.
   * The result is placed in @a v_dauth_info member.
   */
  MHD_REQUEST_INFO_DYNAMIC_DAUTH_REQ_INFO = 42
  ,
  /**
   * Returns pointer to information about basic auth in client request.
   * The resulting pointer is NULL if no basic auth header is set by
   * the client or the format of the basic auth header is broken.
   * Pointers in the returned structure (if any) are valid until response
   * is provided for the request.
   * The result is placed in @a v_bauth_info member.
   */
  MHD_REQUEST_INFO_DYNAMIC_BAUTH_REQ_INFO = 51
  ,
  /* * Sentinel * */
  /**
   * The sentinel value.
   * This value enforces specific underlying integer type for the enum.
   * Do not use.
   */
  MHD_REQUEST_INFO_DYNAMIC_SENTINEL = 65535
};


/**
 * Dynamic information about a request.
 */
union MHD_RequestInfoDynamicData
{

  /**
   * The MHD String type
   */
  struct MHD_String v_str;
  /**
   * The size_t type
   */
  size_t v_sizet;
  /**
   * The boolean type
   */
  enum MHD_Bool v_bool;
  /**
   * The unsigned 64 bits integer
   */
  uint_fast64_t v_uint64;
  /**
   * The pointer to pointer to the data.
   */
  void **v_ppvoid;

  /**
   * The information about client provided username for digest auth
   */
  struct MHD_DigestAuthUsernameInfo *v_dauth_username;

  /**
   * The information about client's digest auth
   */
  struct MHD_DigestAuthInfo *v_dauth_info;

  /**
   * The information about client's basic auth
   */
  struct MHD_BasicAuthInfo *v_bauth_info;
};


/**
 * Obtain dynamic information about the given request.
 * This information may be changed during the lifetime of the request.
 * The wrapper macro #MHD_request_get_info_dynamic() could be more convenient.
 *
 * @param request the request to get information about
 * @param info_type the type of information requested
 * @param[out] return_value pointer to union where requested information will
 *                          be stored
 * @param return_value_size the size of the memory area pointed
 *                          by @a return_data, in bytes
 * @return #MHD_SC_OK if succeed,
 *         error code otherwise
 * @ingroup specialized
 */
MHD_EXTERN_ enum MHD_StatusCode
MHD_request_get_info_dynamic_sz (struct MHD_Request *request,
                                 enum MHD_RequestInfoDynamicType info_type,
                                 union MHD_RequestInfoDynamicData *return_value,
                                 size_t return_value_size)
MHD_FN_PAR_NONNULL_ (1)
MHD_FN_PAR_NONNULL_ (3) MHD_FN_PAR_OUT_ (3)
MHD_FN_PURE_;


/**
 * Obtain dynamic information about the given request.
 * This information may be changed during the lifetime of the request.
 *
 * @param request the request to get information about
 * @param info_type the type of information requested
 * @param[out] return_value pointer to union where requested information will
 *                          be stored
 * @return #MHD_SC_OK if succeed,
 *         error code otherwise
 * @ingroup specialized
 */
#define MHD_request_get_info_dynamic(request,info_type,return_value) \
        MHD_request_get_info_dynamic_sz ((request), (info_type), (return_value), \
                                         sizeof(*(return_value)))

/**
 * Callback for serious error condition. The default action is to print
 * an error message and `abort()`.
 * The callback should not return.
 * Some parameters could be empty strings (the strings with zero-termination at
 * zero position) if MHD built without log messages (only for embedded
 * projects).
 *
 * @param cls user specified value
 * @param file where the error occurred, could be empty
 * @param func the name of the function, where the error occurred, may be empty
 * @param line where the error occurred
 * @param message the error details, could be empty
 * @ingroup logging
 */
typedef void
(*MHD_PanicCallback) (void *cls,
                      const char *file,
                      const char *func,
                      unsigned int line,
                      const char *message);


/**
 * Sets the global error handler to a different implementation.
 * The @a cb will only be called in the case of typically fatal, serious
 * internal consistency issues.
 * These issues should only arise in the case of serious memory corruption or
 * similar problems with the architecture.
 * The @a cb should not return.
 *
 * The default implementation that is used if no panic function is set
 * simply prints an error message and calls `abort()`.  Alternative
 * implementations might call `exit()` or other similar functions.
 *
 * @param cb new error handler, NULL to reset to default handler
 * @param cls passed to @a cb
 * @ingroup logging
 */
MHD_EXTERN_ void
MHD_lib_set_panic_func (MHD_PanicCallback cb,
                        void *cls);

#define MHD_lib_set_panic_func_default() \
        MHD_lib_set_panic_func (MHD_STATIC_CAST_ (MHD_PanicCallback,NULL),NULL)
MHD_C_DECLRATIONS_FINISH_HERE_

#endif /* ! MICROHTTPD2_H */
