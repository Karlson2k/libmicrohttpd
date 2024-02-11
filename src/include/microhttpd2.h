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

/**
 * Just includes the NEW definitions for the NG-API.
 * Note that we do not indicate which of the OLD APIs
 * simply need to be kept vs. deprecated.
 *
 *
 * The goal is to provide a basis for discussion!
 * Little of this is implemented yet.
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
 *      per request. Match on method + URL (longest-prefix /foo/bar/* /foo/ /foo /fo, etc).
 *      "GET /foo/$ARG/$BAR/match"
 *    struct MHD_Dispatcher;
 *
 *    struct MHD_Dispatcher *
 *    MHD_dispatcher_create (...);
 *    enum {no_url, no_method, found}
 *    MHD_dispatcher_dispatch (dispatcher, url, method, *result);
 *    MHD_RequestCallback
 *    MHD_dispatcher_get_callback (struct MHD_Dispatcher *dispatcher);
 *    struct MHD_dispatcher_destroy (*dispatcher);
 *
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
 *
 * NEW-EG:
 * - avoid fixed types, like uint32_t. They may not exist on some
 *   platforms. Instead use uint_fast32_t.
 *   It is also better for future-proof.
 * - check portability for embedded platforms. Some of them support
 *   64 bits, but 'int' could be just 16 bits resulting of silently
 *   dropping enum values higher than 65535.
 *   => in general, more functions, fewer enums for setup
 *
 * - Avoid returning pointers to internal members. It is not thread-safe and
 * even in single thread the value could change over the time. Prefer pointers to
 * app-allocated memory with the size, like MHD_daemon_get_static_info(enum
 * MHD_enum_name info_type, void *buf, size_t buf_size).
 *   => Except in cases where zero-copy matters.
 *
 * - Use separate app calls/functions for data the will not change for the
 * lifetime of the object and dynamic data. The only difference should be the
 * name. Like MHD_daemon_get_static_info(enum MHD_enum_name info_type, void *buf,
 * size_t buf_size) MHD_daemon_get_dynamic_info(enum MHD_enum_name info_type,
 * void *buf, size_t buf_size) Examples of static data: listen socket, number of
 * workers, daemon flags.  Examples of dynamic data: number of connections,
 * quiesce status.  It should give a clear idea whether the data could be changed
 * over the time (could be not obvious for some data) and thus may change the
 * approach how to use the data in app.  The same for: library, daemon,
 * connection, request. Not sure that dynamic data makes sense for the library.
 *
 * - Use clear separation between connection and request. Do not mix the kind
 * data in the callbacks.  Currently we are mixing things in
 * MHD_AccessHandlerCallback and MHD_RequestCompletedCallback. Instead of
 * pointers to struct MHD_Connection we should use pointers to (new) struct
 * MHD_Request.  Probably some other functions are mixing the things as well, to
 * be re-checked.
 *
 * - Define default response code in response object. There are a very little
 * chance that response body designed for 404 or 403 codes will be used with
 * 200 code. However, the responses body for 307 and 308 could be the same. So:
 * * add default response code in response object. Use zero for default 200.
 * * When app sending the response use zero for response's default code or
 *   use specific code to override response's default value.
 *
 * - Make responses unmodifiable after first use. It is not thread-safe.
 *   MHD-generated headers (Date, Connection/Keep-Alive) are again
 *   part of the *request* and do not count as part of the "response" here.
 *
 * - Remove "footers" from responses. With unmodifiable responses everything should be "headers".
 *   Add footers to *requests* instead.
 *
 * - Add API for adding request-specific response headers and footers. To
 * simplify the things it should just copy the strings (to avoid dealing with
 * complicated deinit of possible dynamic strings).  After this change it should
 * be possible to simplify DAuth handling as response could be reused (currently
 * 403 responses are modified for each reply).
 *
 * - Control response behaviour mainly by response flags, not by additional
 * headers (like MHD_RF_FORCE_CLOSE instead of "Connection: close").
 * It is easier for both: app and MHD.
 *
 * - Move response codes from MHD_HTTP_xxx namespace to MHD_HTTP_CODE_xxx
 *   namespace. It already may clash with other HTTP values.
 *
 * - plus other things that was discussed already, like avoiding extra calls
 *   for body-less requests. I assume it should be resolved with fundamental
 *   re-design of request/response cycle handling.
 *
 * - Internals: carefully check where locking is really required. Probably
 *   separate locks. Check out-of-thread value reading. Currently code assumes
 *   atomic reading of values used in other threads, which mostly true on x86,
 *   but not OK on other arches. Probably use read/write locking to minimize
 *   the threads interference.
 *
 * - figure out how to do portable variant of cork/uncork
 *
 * NEW-CG:
 * - Postprocessor is unusable night-mare when doing "stream processing"
 *   for tiny values where the application basically has to copy together
 *   the stream back into a single compact heap value, just making the
 *   parsing highly more complicated (see examples in Challenger)
 *
 * - non-stream processing variant for request bodies, give apps a
 *   way to request the full body in one buffer; give apps a way
 *   to request a 'large new allocation' for such buffers; give apps
 *   a way to specify a global quota for large allocations to ensure
 *   memory usage has a hard bound
 *
 * - remove request data from memory pool when response is queued
 *   (IF no callbacks and thus data cannot be used anymore, or IF
 *    application permits explictly per daemon) to get more space
 *   for building response;
 *
 * - Fix TCP FIN graceful closure issue for upgraded
 *   connections (API implications?)
 *
 * TODO:
 * - varargs in upgrade is still there and ugly (and not even used!)
 * - migrate event loop apis (get fdset, timeout, MHD_run(), etc.)
 *
 * FIXME: Add to public API internal helpers, like Base64 decoder?
 * Keep smaller API for now. Do not export.
 */
#ifndef MICROHTTPD2_H
#define MICROHTTPD2_H


#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/* While we generally would like users to use a configure-driven
   build process which detects which headers are present and
   hence works on any platform, we use "standard" includes here
   to build out-of-the-box for beginning users on common systems.

   If generic headers don't work on your platform, include headers
   which define 'va_list', 'size_t', 'ssize_t', 'intptr_t',
   'uint16_t', 'uint32_t', 'uint64_t', 'off_t', 'struct sockaddr',
   'socklen_t', 'fd_set' and "#define MHD_PLATFORM_H" before
   including "microhttpd.h". Then the following "standard"
   includes won't be used (which might be a good idea, especially
   on platforms where they do not exist).
   */
#ifndef MHD_PLATFORM_H
#include <stdarg.h>
#include <stdint.h>
#include <sys/types.h>
#if defined(_WIN32) && ! defined(__CYGWIN__)
#include <ws2tcpip.h>
#if defined(_MSC_FULL_VER) && ! defined(_SSIZE_T_DEFINED)
#define _SSIZE_T_DEFINED
typedef intptr_t ssize_t;
#endif /* !_SSIZE_T_DEFINED */
#else
#include <unistd.h>
#include <sys/time.h>
#include <sys/socket.h>
#endif
#endif

#if defined(__CYGWIN__) && ! defined(_SYS_TYPES_FD_SET)
/* Do not define __USE_W32_SOCKETS under Cygwin! */
#error Cygwin with winsock fd_set is not supported
#endif

/**
 * Current version of the library.
 * 0x01093001 = 1.9.30-1.
 */
#define MHD_VERSION 0x02000000

// FIXME: doxy edited
/**
 * Representation of 'bool' in the public API as stdbool.h may not
 * always be available and presence of 'bool' keyword may depend on
 * used C version.
 * It is always safe to cast 'MHD_Bool' variable to 'bool' and vice versa.
 * Note: it may be NOT safe to cast pointers 'MHD_Bool*' to 'bool*' and
 *       vice versa.
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
 * String with length data.
 */
struct MHD_String
{
  // FIXME: edited
  /**
   * Number of characters in @e buf, not counting 0-termination.
   */
  size_t len;

  /**
   * 0-terminated C-string.
   */
  const char *buf;
};


/**
 * Constant used to indicate unknown size (use when
 * creating a response).
 */
#ifdef UINT_FAST64_MAX
#  define MHD_SIZE_UNKNOWN UINT_FAST64_MAX
#else
#  define MHD_SIZE_UNKNOWN ((uint_fast64_t) -1LL)
#endif

#ifdef SIZE_MAX
#define MHD_CONTENT_READER_END_OF_STREAM SIZE_MAX
#define MHD_CONTENT_READER_END_WITH_ERROR (SIZE_MAX - 1)
#else
#define MHD_CONTENT_READER_END_OF_STREAM ((size_t) -1LL)
#define MHD_CONTENT_READER_END_WITH_ERROR ((size_t) -2LL)
#endif

#ifndef _MHD_EXTERN
#if defined(_WIN32) && defined(MHD_W32LIB)
#define _MHD_EXTERN extern
#elif defined(_WIN32) && defined(MHD_W32DLL)
/* Define MHD_W32DLL when using MHD as W32 .DLL to speed up linker a little */
#define _MHD_EXTERN extern __declspec(dllimport)
#else
#define _MHD_EXTERN extern
#endif
#endif

#ifndef MHD_SOCKET_DEFINED
/**
 * MHD_socket is type for socket FDs
 */
#if ! defined(_WIN32) || defined(_SYS_TYPES_FD_SET)
#define MHD_POSIX_SOCKETS 1
typedef int MHD_socket;
#define MHD_INVALID_SOCKET (-1)
#else /* !defined(_WIN32) || defined(_SYS_TYPES_FD_SET) */
#define MHD_WINSOCK_SOCKETS 1
#include <winsock2.h>
typedef SOCKET MHD_socket;
#define MHD_INVALID_SOCKET (INVALID_SOCKET)
#endif /* !defined(_WIN32) || defined(_SYS_TYPES_FD_SET) */
#define MHD_SOCKET_DEFINED 1
#endif /* MHD_SOCKET_DEFINED */

// TODO: move compiler macros to separate header

/**
 * Define MHD_NO_DEPRECATION before including "microhttpd.h" to disable deprecation messages
 */
#ifdef MHD_NO_DEPRECATION
#define _MHD_DEPR_MACRO(msg)
#define _MHD_NO_DEPR_IN_MACRO 1
#define _MHD_DEPR_IN_MACRO(msg)
#define _MHD_NO_DEPR_FUNC 1
#define _MHD_DEPR_FUNC(msg)
#endif /* MHD_NO_DEPRECATION */

#ifndef _MHD_DEPR_MACRO
#if defined(_MSC_FULL_VER) && _MSC_VER + 0 >= 1500
/* VS 2008 or later */
/* Stringify macros */
#define _MHD_INSTRMACRO(a) #a
#define _MHD_STRMACRO(a) _MHD_INSTRMACRO (a)
/* deprecation message */
#define _MHD_DEPR_MACRO(msg) __pragma(message (__FILE__ "(" _MHD_STRMACRO ( \
  __LINE__) "): warning: " msg))
#define _MHD_DEPR_IN_MACRO(msg) _MHD_DEPR_MACRO (msg)
#elif defined(__clang__) || defined(__GNUC_PATCHLEVEL__)
/* clang or GCC since 3.0 */
#define _MHD_GCC_PRAG(x) _Pragma(#x)
#if (defined(__clang__) && (__clang_major__ + 0 >= 5 ||     \
                            (! defined(__apple_build_version__) && \
  (__clang_major__ + 0  > 3 || (__clang_major__ + 0 == 3 && __clang_minor__ >= \
                                3))))) || \
  __GNUC__ + 0 > 4 || (__GNUC__ + 0 == 4 && __GNUC_MINOR__ + 0 >= 8)
/* clang >= 3.3 (or XCode's clang >= 5.0) or
   GCC >= 4.8 */
#define _MHD_DEPR_MACRO(msg) _MHD_GCC_PRAG (GCC warning msg)
#define _MHD_DEPR_IN_MACRO(msg) _MHD_DEPR_MACRO (msg)
#else /* older clang or GCC */
/* clang < 3.3, XCode's clang < 5.0, 3.0 <= GCC < 4.8 */
#define _MHD_DEPR_MACRO(msg) _MHD_GCC_PRAG (message msg)
#if (defined(__clang__) && (__clang_major__ + 0  > 2 || (__clang_major__ + 0 == \
                                                         2 && __clang_minor__ >= \
                                                         9)))                                            /* FIXME: clang >= 2.9, earlier versions not tested */
/* clang handles inline pragmas better than GCC */
#define _MHD_DEPR_IN_MACRO(msg) _MHD_DEPR_MACRO (msg)
#endif /* clang >= 2.9 */
#endif  /* older clang or GCC */
/* #elif defined(SOMEMACRO) */ /* add compiler-specific macros here if required */
#endif /* clang || GCC >= 3.0 */
#endif /* !_MHD_DEPR_MACRO */

#ifndef _MHD_DEPR_MACRO
#define _MHD_DEPR_MACRO(msg)
#endif /* !_MHD_DEPR_MACRO */

#ifndef _MHD_DEPR_IN_MACRO
#define _MHD_NO_DEPR_IN_MACRO 1
#define _MHD_DEPR_IN_MACRO(msg)
#endif /* !_MHD_DEPR_IN_MACRO */

#ifndef _MHD_DEPR_FUNC
#if defined(_MSC_FULL_VER) && _MSC_VER + 0 >= 1400
/* VS 2005 or later */
#define _MHD_DEPR_FUNC(msg) __declspec(deprecated (msg))
#elif defined(_MSC_FULL_VER) && _MSC_VER + 0 >= 1310
/* VS .NET 2003 deprecation do not support custom messages */
#define _MHD_DEPR_FUNC(msg) __declspec(deprecated)
#elif (__GNUC__ + 0 >= 5) || (defined(__clang__) && \
  (__clang_major__ + 0 > 2 || (__clang_major__ + 0 == 2 && __clang_minor__ >= \
                               9)))                                             /* FIXME: earlier versions not tested */
/* GCC >= 5.0 or clang >= 2.9 */
#define _MHD_DEPR_FUNC(msg) __attribute__((deprecated (msg)))
#elif defined(__clang__) || __GNUC__ + 0 > 3 || (__GNUC__ + 0 == 3 && \
                                                 __GNUC_MINOR__ + 0 >= 1)
/* 3.1 <= GCC < 5.0 or clang < 2.9 */
/* old GCC-style deprecation do not support custom messages */
#define _MHD_DEPR_FUNC(msg) __attribute__((__deprecated__))
/* #elif defined(SOMEMACRO) */ /* add compiler-specific macros here if required */
#endif /* clang < 2.9 || GCC >= 3.1 */
#endif /* !_MHD_DEPR_FUNC */

#ifndef _MHD_DEPR_FUNC
#define _MHD_NO_DEPR_FUNC 1
#define _MHD_DEPR_FUNC(msg)
#endif /* !_MHD_DEPR_FUNC */


/* Define MHD_FUNC_PARAM_NONNULL_ attribute */

/**
 * Macro to indicate that certain parameters must be
 * non-null.  Todo: port to non-gcc platforms.
 */
#if defined(__CYGWIN__) || defined(_WIN32) || defined(MHD_W32LIB) || \
  defined(__clang__) || ! defined(__GNUC__)
// FIXME: vararg macros still not universally supported
// FIXME: discuss long list of attributes
#define MHD_FUNC_PARAM_NONNULL_(...) /* empty */
#else
#define MHD_FUNC_PARAM_NONNULL_(...) __THROW __nonnull ((__VA_ARGS__))
#endif

// TODO: document
#if ! defined(MHD_NO_FUNC_ATTRIBUTES)
#  if defined(__has_attribute)

// TODO: document
#    if __has_attribute (const) && ! defined(MHD_FUNC_CONST_)
/**
 * MHD_FUNC_CONST_ functions always return the same value for this same
 * input value, even if any memory pointed by parameter is changed or
 * any global value changed. The functions do not change any global values.
 * In general, such functions must not dereference any pointers provided
 * as a parameter and must not access any global variables that can be
 * changed over the time.
 * Typical examples:
 *   int square(int x);
 *   int sum(int a, int b);
 */
#      define MHD_FUNC_CONST_ __attribute__ ((const))
#    endif /* const && !MHD_FUNC_CONST_ */

// TODO: document
#    if __has_attribute (pure) && ! defined(MHD_FUNC_PURE_)
/**
 * MHD_FUNC_PURE_ functions always return the same value for this same input
 * if volatile memory content is not changed.
 * In general, such functions must must not access any global variables that
 * can be changed over the time.
 * Typical examples:
 *   size_t strlen(const char *str);
 *   int memcmpconst void *ptr1, const void *ptr2, size_t _Size);
 */
#      define MHD_FUNC_PURE_ __attribute__ ((pure))
#    endif /* pure && !MHD_FUNC_PURE_ */

// TODO: document
#    if __has_attribute (warn_unused_result) && \
  ! defined(MHD_FUNC_MUST_CHECK_RESULT_)
/**
 * MHD_FUNC_MUST_CHECK_RESULT_ indicates that caller must check the value
 * returned by the function.
 */
#      define MHD_FUNC_MUST_CHECK_RESULT_ __attribute__ ((warn_unused_result))
#    endif /* warn_unused_result && !MHD_FUNC_MUST_CHECK_RESULT_ */

#    if __has_attribute (nonnull) && \
  ! defined(MHD_FUNC_PARAM_NONNULL_)
/**
 * MHD_FUNC_PARAM_NONNULL_ indicates function parameter number @a param_num
 * must never be NULL.
 */
#      define MHD_FUNC_PARAM_NONNULL_(param_num) \
          __attribute__ ((nonnull (param_num)))
#    endif /* nonnull && !MHD_FUNC_PARAM_NONNULL_ */

#    if __has_attribute (nonnull) && \
  ! defined(MHD_FUNC_PARAM_NONNULL_ALL_)
/**
 * MHD_FUNC_PARAM_NONNULL_ALL_ indicates all function parameters must
 * never be NULL.
 */
#      define MHD_FUNC_PARAM_NONNULL_ALL_ __attribute__ ((nonnull))
#    endif /* nonnull && !MHD_FUNC_PARAM_NONNULL_ALL_ */

#    if __has_attribute (access)

#      if ! defined(MHD_FUNC_PARAM_IN_)
/**
 * MHD_FUNC_PARAM_IN_ indicates function parameter points to data
 * that must not be modified by the function
 */
#        define MHD_FUNC_PARAM_IN_(param_num) \
           __attribute__ ((access(read_only,pram_num)))
#      endif /* !MHD_FUNC_PARAM_IN_ */

#      if ! defined(MHD_FUNC_PARAM_IN_SIZE_)
/**
 * MHD_FUNC_PARAM_IN_SIZE_ indicates function parameter points to data
 * which size is specified by @a size_num parameter and that must not be
 * modified by the function
 */
#        define MHD_FUNC_PARAM_IN_SIZE_(param_num,size_num) \
           __attribute__ ((access(read_only,pram_num,size_num)))
#      endif /* !MHD_FUNC_PARAM_IN_SIZE_ */

#      if ! defined(MHD_FUNC_PARAM_OUT_)
/**
 * MHD_FUNC_PARAM_OUT_ indicates function parameter points to data
 * that could be written by the function, but not read.
 */
#        define MHD_FUNC_PARAM_OUT_(param_num) \
           __attribute__ ((access(write_only,pram_num)))
#      endif /* !MHD_FUNC_PARAM_OUT_ */

#      if ! defined(MHD_FUNC_PARAM_OUT_SIZE_)
/**
 * MHD_FUNC_PARAM_OUT_SIZE_ indicates function parameter points to data
 * which size is specified by @a size_num parameter and that could be
 * written by the function, but not read.
 */
#        define MHD_FUNC_PARAM_OUT_SIZE_(param_num,size_num) \
           __attribute__ ((access(write_only,pram_num,size_num)))
#      endif /* !MHD_FUNC_PARAM_OUT_SIZE_ */

#      if ! defined(MHD_FUNC_PARAM_INOUT_)
/**
 * MHD_FUNC_PARAM_INOUT_ indicates function parameter points to data
 * that could be both read and written by the function.
 */
#        define MHD_FUNC_PARAM_INOUT_(param_num) \
           __attribute__ ((access(read_write,pram_num)))
#      endif /* !MHD_FUNC_PARAM_INOUT_ */

#      if ! defined(MHD_FUNC_PARAM_INOUT_SIZE_)
/**
 * MHD_FUNC_PARAM_INOUT_SIZE_ indicates function parameter points to data
 * which size is specified by @a size_num parameter and that could be
 * both read and written by the function.
 */
#        define MHD_FUNC_PARAM_INOUT_SIZE_(param_num,size_num) \
           __attribute__ ((access(read_write,pram_num,size_num)))
#      endif /* !MHD_FUNC_PARAM_INOUT_SIZE_ */

#    endif /* access */

#    if __has_attribute (returns_nonnull) && \
  ! defined(MHD_FUNC_RETURNS_NONNULL_)
/**
 * MHD_FUNC_RETURNS_NONNULL_ indicates that function never returns NULL.
 */
#      define MHD_FUNC_RETURNS_NONNULL_ __attribute__ ((returns_nonnull))
#    endif /* returns_nonnull && !MHD_FUNC_RETURNS_NONNULL_ */

#    if __has_attribute (access) && \
  ! defined(MHD_FUNC_PARAM_IN_)
/**
 * MHD_FUNC_PARAM_IN_ indicates function parameter points to data
 * that must not be modified by the function
 */
#      define MHD_FUNC_PARAM_IN_(param_num) \
         __attribute__ ((access(read_only,pram_num)))
#    endif /* returns_nonnull && !MHD_FUNC_RETURNS_NONNULL_ */

#  endif /* __has_attribute */
#endif /* ! MHD_NO_FUNC_ATTRIBUTES */

#ifndef MHD_C99_
#  if __STDC_VERSION__ >= 199901L
// FIXME: does not work with VLA on C11 on some compilers at least
// FIXME: whitelist supported compilers
// Probably problematic for typedefs for callbacks
#    define MHD_C99_(x) x
#  endif /* __STDC_VERSION__ >= 199901L */
#endif /* MHD_C99_ */


#ifndef MHD_FUNC_CONST_
#  define MHD_FUNC_CONST_ /* empty */
#endif /* ! MHD_FUNC_CONST_ */
#ifndef MHD_FUNC_PURE_
#  define MHD_FUNC_PURE_ /* empty */
#endif /* ! MHD_FUNC_PURE_ */
#ifndef MHD_FUNC_MUST_CHECK_RESULT_
#  define MHD_FUNC_MUST_CHECK_RESULT_ /* empty */
#endif /* ! MHD_FUNC_MUST_CHECK_RESULT_ */
#ifndef MHD_FUNC_PARAM_NONNULL_
#  define MHD_FUNC_PARAM_NONNULL_(ignored) /* empty */
#endif /* ! MHD_FUNC_PARAM_NONNULL_ */
#ifndef MHD_FUNC_PARAM_NONNULL_ALL_
#  define MHD_FUNC_PARAM_NONNULL_ALL_ /* empty */
#endif /* ! MHD_FUNC_PARAM_NONNULL_ALL_ */
#if ! defined(MHD_FUNC_PARAM_IN_)
#  define MHD_FUNC_PARAM_IN_(param_num) /* empty */
#endif /* !MHD_FUNC_PARAM_IN_ */
#if ! defined(MHD_FUNC_PARAM_IN_SIZE_)
#  define MHD_FUNC_PARAM_IN_SIZE_(param_num,size_num) /* empty */
#endif /* !MHD_FUNC_PARAM_IN_SIZE_ */
#if ! defined(MHD_FUNC_PARAM_OUT_)
#  define MHD_FUNC_PARAM_OUT_(param_num) /* empty */
#endif /* !MHD_FUNC_PARAM_OUT_ */
#if ! defined(MHD_FUNC_PARAM_OUT_SIZE_)
#  define MHD_FUNC_PARAM_OUT_SIZE_(param_num,size_num) /* empty */
#endif /* !MHD_FUNC_PARAM_OUT_SIZE_ */
#if ! defined(MHD_FUNC_PARAM_INOUT_)
#  define MHD_FUNC_PARAM_INOUT_(param_num) /* empty */
#endif /* !MHD_FUNC_PARAM_INOUT_ */
#if ! defined(MHD_FUNC_PARAM_INOUT_SIZE_)
#  define MHD_FUNC_PARAM_INOUT_SIZE_(param_num,size_num) /* empty */
#endif /* !MHD_FUNC_PARAM_INOUT_SIZE_ */
#ifndef MHD_FUNC_RETURNS_NONNULL_
#  define MHD_FUNC_RETURNS_NONNULL_ /* empty */
#endif /* ! MHD_FUNC_RETURNS_NONNULL_ */

#ifndef MHD_C99_
#  define MHD_C99_(ignored) /* empty */
#endif /* MHD_C99_ */

/* ********** (a) Core HTTP Processing ************ */


/**
 * @brief Handle for a daemon that listens for requests.
 *
 * Manages the listen socket, event loop, optional threads and server
 * settings.
 */
struct MHD_Daemon;


/**
 * @brief Handle/identifier of a network connection abstraction.
 *
 * A single network (i.e. TCP) connection can be used for
 * a single (in HTTP/1.1) data stream.
 *
 * @ingroup connection
 */
struct MHD_Connection;


/**
 * @brief Handle/identifier of a data stream over network
 * connection.
 *
 * A data stream may be used for multiple requests, which
 * in HTTP/1.1 must be processed sequentially.
 *
 * @ingroup connection
 */
struct MHD_Stream;

/**
 * @brief Handle representing an HTTP request.
 *
 * With HTTP/1.1, multiple requests can be run over the same
 * stream.  However, MHD will only show one request per data
 * stream to the client at any given time.
 *
 * Replaces `struct MHD_Connection`, renamed to better reflect
 * what this object truly represents to the application using
 * MHD.
 *
 * @ingroup request
 */
struct MHD_Request;


/**
 * Actions are returned by the application to drive the request
 * handling of MHD.
 */
struct MHD_Action;


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
 */
enum MHD_StatusCode
{

  /* 00000-level status codes indicate return values
     the application must act on. */

  /**
   * Successful operation (not used for logging).
   */
  MHD_SC_OK = 0,

  /**
   * We were asked to return a timeout, but, there is no timeout.
   * FIXME: explain better? Remove?
   */
  MHD_SC_NO_TIMEOUT = 1,


  /* 10000-level status codes indicate intermediate
     results of some kind. */

  /**
   * Informational event, MHD started.
   */
  MHD_SC_DAEMON_STARTED = 10000,

  /**
   * Informational event, we accepted a connection.
   */
  MHD_SC_CONNECTION_ACCEPTED = 10001,

  /**
   * Informational event, thread processing connection terminates.
   */
  MHD_SC_THREAD_TERMINATING = 10002,

  /**
   * Informational event, state machine status for a connection.
   */
  MHD_SC_STATE_MACHINE_STATUS_REPORT = 10003,

  /**
   * accept() returned transient error.
   */
  MHD_SC_ACCEPT_FAILED_EAGAIN = 10004,


  /* 20000-level status codes indicate success of some kind. */

  /**
   * MHD is closing a connection after the client closed it
   * (perfectly normal end).
   */
  MHD_SC_CONNECTION_CLOSED = 20000,

  /**
   * MHD is closing a connection because the application
   * logic to generate the response data completed.
   */
  MHD_SC_APPLICATION_DATA_GENERATION_FINISHED = 20001,


  /* 30000-level status codes indicate transient failures
     that might go away if the client tries again. */


  /**
   * Resource limit in terms of number of parallel connections
   * hit.
   */
  MHD_SC_LIMIT_CONNECTIONS_REACHED = 30000,

  /**
   * We failed to allocate memory for poll() syscall.
   * (May be transient.)
   */
  MHD_SC_POLL_MALLOC_FAILURE = 30001,

  /**
   * The operation failed because the respective
   * daemon is already too deep inside of the shutdown
   * activity.
   */
  MHD_SC_DAEMON_ALREADY_SHUTDOWN = 30002,

  /**
   * We failed to start a thread.
   */
  MHD_SC_THREAD_LAUNCH_FAILURE = 30003,

  /**
   * The operation failed because we either have no
   * listen socket or were already quiesced.
   */
  MHD_SC_DAEMON_ALREADY_QUIESCED = 30004,

  /**
   * The operation failed because client disconnected
   * faster than we could accept().
   */
  MHD_SC_ACCEPT_FAST_DISCONNECT = 30005,

  /**
   * Operating resource limits hit on accept().
   */
  MHD_SC_ACCEPT_SYSTEM_LIMIT_REACHED = 30006,

  /**
   * Connection was refused by accept policy callback.
   */
  MHD_SC_ACCEPT_POLICY_REJECTED = 30007,

  /**
   * We failed to allocate memory for the connection.
   * (May be transient.)
   */
  MHD_SC_CONNECTION_MALLOC_FAILURE = 30008,

  /**
   * We failed to allocate memory for the connection's memory pool.
   * (May be transient.)
   */
  MHD_SC_POOL_MALLOC_FAILURE = 30009,

  /**
   * We failed to forward data from a Web socket to the
   * application to the remote side due to the socket
   * being closed prematurely. (May be transient.)
   */
  MHD_SC_UPGRADE_FORWARD_INCOMPLETE = 30010,

  /**
   * We failed to allocate memory for generating the response from our
   * memory pool.  Likely the request header was too large to leave
   * enough room.
   */
  MHD_SC_CONNECTION_POOL_MALLOC_FAILURE = 30011,


  /* 40000-level errors are caused by the HTTP client
     (or the network) */

  /**
   * MHD is closing a connection because parsing the
   * request failed.
   */
  MHD_SC_CONNECTION_PARSE_FAIL_CLOSED = 40000,

  /**
   * MHD is closing a connection because it was reset.
   */
  MHD_SC_CONNECTION_RESET_CLOSED = 40001,

  /**
   * MHD is closing a connection because reading the
   * request failed.
   */
  MHD_SC_CONNECTION_READ_FAIL_CLOSED = 40002,

  /**
   * MHD is closing a connection because writing the response failed.
   */
  MHD_SC_CONNECTION_WRITE_FAIL_CLOSED = 40003,

  /**
   * MHD is returning an error because the header provided
   * by the client is too big.
   */
  MHD_SC_CLIENT_HEADER_TOO_BIG = 40004,

  /**
   * An HTTP/1.1 request was sent without the "Host:" header.
   */
  MHD_SC_HOST_HEADER_MISSING = 40005,

  /**
   * The given content length was not a number.
   */
  MHD_SC_CONTENT_LENGTH_MALFORMED = 40006,

  /**
   * The given uploaded, chunked-encoded body was malformed.
   */
  MHD_SC_CHUNKED_ENCODING_MALFORMED = 40007,


  /* 50000-level errors are because of an error internal
     to the MHD logic, possibly including our interaction
     with the operating system (but not the application) */

  /**
   * This build of MHD does not support TLS, but the application
   * requested TLS.
   */
  MHD_SC_TLS_DISABLED = 50000,

  /**
   * The application attempted to setup TLS parameters before
   * enabling TLS.
   */
  MHD_SC_TLS_BACKEND_UNINITIALIZED = 50003,

  /**
   * The selected TLS backend does not yet support this operation.
   */
  MHD_SC_TLS_BACKEND_OPERATION_UNSUPPORTED = 50004,

  /**
   * Failed to setup ITC channel.
   */
  MHD_SC_ITC_INITIALIZATION_FAILED = 50005,

  /**
   * File descriptor for ITC channel too large.
   */
  MHD_SC_ITC_DESCRIPTOR_TOO_LARGE = 50006,

  /**
   * The specified value for the NC length is way too large
   * for this platform (integer overflow on `size_t`).
   */
  MHD_SC_DIGEST_AUTH_NC_LENGTH_TOO_BIG = 50007,

  /**
   * We failed to allocate memory for the specified nonce
   * counter array.  The option was not set.
   */
  MHD_SC_DIGEST_AUTH_NC_ALLOCATION_FAILURE = 50008,

  /**
   * This build of the library does not support
   * digest authentication.
   */
  MHD_SC_DIGEST_AUTH_NOT_SUPPORTED_BY_BUILD = 50009,

  /**
   * IPv6 requested but not supported by this build.
   */
  MHD_SC_IPV6_NOT_SUPPORTED_BY_BUILD = 50010,

  /// FIXME: Similar to 60xxx???
  /**
   * We failed to open the listen socket. Maybe the build
   * supports IPv6, but your kernel does not?
   */
  MHD_SC_FAILED_TO_OPEN_LISTEN_SOCKET = 50011,

  /**
   * Specified address family is not supported by this build.
   */
  MHD_SC_AF_NOT_SUPPORTED_BY_BUILD = 50012,

  /**
   * Failed to enable listen address reuse.
   */
  MHD_SC_LISTEN_ADDRESS_REUSE_ENABLE_FAILED = 50013,

  /**
   * Enabling listen address reuse is not supported by this platform.
   */
  MHD_SC_LISTEN_ADDRESS_REUSE_ENABLE_NOT_SUPPORTED = 50014,

  /**
   * Failed to disable listen address reuse.
   */
  MHD_SC_LISTEN_ADDRESS_REUSE_DISABLE_FAILED = 50015,

  /**
   * Disabling listen address reuse is not supported by this platform.
   */
  MHD_SC_LISTEN_ADDRESS_REUSE_DISABLE_NOT_SUPPORTED = 50016,

  /**
   * We failed to explicitly enable or disable dual stack for
   * the IPv6 listen socket.  The socket will be used in whatever
   * the default is the OS gives us.
   */
  MHD_SC_LISTEN_DUAL_STACK_CONFIGURATION_FAILED = 50017,

  /**
   * On this platform, MHD does not support explicitly configuring
   * dual stack behavior.
   */
  MHD_SC_LISTEN_DUAL_STACK_CONFIGURATION_NOT_SUPPORTED = 50018,

  /**
   * Failed to enable TCP FAST OPEN option.
   */
  MHD_SC_FAST_OPEN_FAILURE = 50020,

  /**
   * Failed to start listening on listen socket.
   */
  MHD_SC_LISTEN_FAILURE = 50021,

  /**
   * Failed to obtain our listen port via introspection.
   */
  MHD_SC_LISTEN_PORT_INTROSPECTION_FAILURE = 50022,

  /**
   * Failed to obtain our listen port via introspection
   * due to unsupported address family being used.
   */
  MHD_SC_LISTEN_PORT_INTROSPECTION_UNKNOWN_AF = 50023,

  /**
   * We failed to set the listen socket to non-blocking.
   */
  MHD_SC_LISTEN_SOCKET_NONBLOCKING_FAILURE = 50024,

  /**
   * Listen socket value is too large (for use with select()).
   */
  MHD_SC_LISTEN_SOCKET_TOO_LARGE = 50025,

  /**
   * We failed to allocate memory for the thread pool.
   */
  MHD_SC_THREAD_POOL_MALLOC_FAILURE = 50026,

  /**
   * We failed to allocate mutex for thread pool worker.
   */
  MHD_SC_THREAD_POOL_CREATE_MUTEX_FAILURE = 50027,

  /**
   * There was an attempt to upgrade a connection on
   * a daemon where upgrades are disallowed.
   */
  MHD_SC_UPGRADE_ON_DAEMON_WITH_UPGRADE_DISALLOWED = 50028,

  /**
   * Failed to signal via ITC channel.
   */
  MHD_SC_ITC_USE_FAILED = 50029,

  /**
   * We failed to initialize the main thread for listening.
   */
  MHD_SC_THREAD_MAIN_LAUNCH_FAILURE = 50030,

  /**
   * We failed to initialize the threads for the worker pool.
   */
  MHD_SC_THREAD_POOL_LAUNCH_FAILURE = 50031,

  /**
   * We failed to add a socket to the epoll() set.
   */
  MHD_SC_EPOLL_CTL_ADD_FAILED = 50032,

  /**
   * We failed to create control socket for the epoll().
   */
  MHD_SC_EPOLL_CTL_CREATE_FAILED = 50034,

  /**
   * We failed to configure control socket for the epoll()
   * to be non-inheritable.
   */
  MHD_SC_EPOLL_CTL_CONFIGURE_NOINHERIT_FAILED = 50035,

  /**
   * We failed to build the FD set because a socket was
   * outside of the permitted range.
   */
  MHD_SC_SOCKET_OUTSIDE_OF_FDSET_RANGE = 50036,

  /**
   * This daemon was not configured with options that
   * would allow us to build an FD set for select().
   */
  MHD_SC_CONFIGURATION_MISMATCH_FOR_GET_FDSET = 50037,

  /**
   * This daemon was not configured with options that
   * would allow us to obtain a meaningful timeout.
   */
  MHD_SC_CONFIGURATION_MISMATCH_FOR_GET_TIMEOUT = 50038,

  /**
   * This daemon was not configured with options that
   * would allow us to run with select() data.
   */
  MHD_SC_CONFIGURATION_MISMATCH_FOR_RUN_SELECT = 50039,

  /**
   * This daemon was not configured to run with an
   * external event loop.
   */
  MHD_SC_CONFIGURATION_MISMATCH_FOR_RUN_EXTERNAL = 50040,

  /**
   * Encountered an unexpected event loop style
   * (should never happen).
   */
  MHD_SC_CONFIGURATION_UNEXPECTED_ELS = 50041,

  /**
   * Encountered an unexpected error from select()
   * (should never happen).
   */
  MHD_SC_UNEXPECTED_SELECT_ERROR = 50042,

  /**
   * poll() is not supported.
   */
  MHD_SC_POLL_NOT_SUPPORTED = 50043,

  /**
   * Encountered an unexpected error from poll()
   * (should never happen).
   */
  MHD_SC_UNEXPECTED_POLL_ERROR = 50044,

  /**
   * We failed to configure accepted socket
   * to not use a signal pipe.
   */
  MHD_SC_ACCEPT_CONFIGURE_NOSIGPIPE_FAILED = 50045,

  /**
   * Encountered an unexpected error from epoll_wait()
   * (should never happen).
   */
  MHD_SC_UNEXPECTED_EPOLL_WAIT_ERROR = 50046,

  /**
   * epoll file descriptor is invalid (strange)
   */
  MHD_SC_EPOLL_FD_INVALID = 50047,

  /**
   * We failed to configure accepted socket
   * to be non-inheritable.
   */
  MHD_SC_ACCEPT_CONFIGURE_NOINHERIT_FAILED = 50048,

  /**
   * We failed to configure accepted socket
   * to be non-blocking.
   */
  MHD_SC_ACCEPT_CONFIGURE_NONBLOCKING_FAILED = 50049,

  /**
   * accept() returned non-transient error.
   */
  MHD_SC_ACCEPT_FAILED_UNEXPECTEDLY = 50050,

  /**
   * Operating resource limits hit on accept() while
   * zero connections are active. Oopsie.
   */
  MHD_SC_ACCEPT_SYSTEM_LIMIT_REACHED_INSTANTLY = 50051,

  /**
   * Failed to add IP address to per-IP counter for
   * some reason.
   */
  MHD_SC_IP_COUNTER_FAILURE = 50052,

  /**
   * Application violated our API by calling shutdown
   * while having an upgrade connection still open.
   */
  MHD_SC_SHUTDOWN_WITH_OPEN_UPGRADED_CONNECTION = 50053,

  /**
   * Due to an unexpected internal error with the
   * state machine, we closed the connection.
   */
  MHD_SC_STATEMACHINE_FAILURE_CONNECTION_CLOSED = 50054,

  /**
   * Failed to allocate memory in connection's pool
   * to parse the cookie header.
   */
  MHD_SC_COOKIE_POOL_ALLOCATION_FAILURE = 50055,

  /**
   * MHD failed to build the response header.
   */
  MHD_SC_FAILED_RESPONSE_HEADER_GENERATION = 50056,

  /**
   * The feature is not supported by this MHD build (either
   * disabled by configure parameters or build platform
   * did not support it, because headers are missing or
   * so kernel does not have such feature).
   * The feature will not be enabled if the same MHD binary
   * will be run on another kernel, computer or system
   * configuration.
   */
  MHD_SC_FEATURE_DISABLED = 500057,

  /**
   * The feature is not supported by this platform, while
   * supported by MHD build.
   * The feature can be enabled by changing the kernel or
   * running on another computer or with other system
   * configuration.
   */
  MHD_SC_FEATURE_NOT_AVAILABLE = 500058,


  /* 60000-level errors are because the application
     logic did something wrong or generated an error. */

  /**
   * MHD does not support the requested combination of
   * EPOLL with thread-per-connection mode.
   */
  MHD_SC_SYSCALL_THREAD_COMBINATION_INVALID = 60000,

  /**
   * MHD does not support quiescing if ITC was disabled
   * and threads are used.
   */
  MHD_SC_SYSCALL_QUIESCE_REQUIRES_ITC = 60001,

  // FIXME: similar to 50xxx???
  /**
   * We failed to bind the listen socket.
   */
  MHD_SC_LISTEN_SOCKET_BIND_FAILED = 60002,

  /**
   * The application requested an unsupported TLS backend to be used.
   */
  MHD_SC_TLS_BACKEND_UNSUPPORTED = 60003,

  /**
   * The application requested a TLS cipher suite which is not
   * supported by the selected backend.
   */
  MHD_SC_TLS_CIPHERS_INVALID = 60004,

  /**
   * MHD is closing a connection because the application
   * logic to generate the response data failed.
   */
  MHD_SC_APPLICATION_DATA_GENERATION_FAILURE_CLOSED = 60005,

  /**
   * MHD is closing a connection because the application
   * callback told it to do so.
   */
  MHD_SC_APPLICATION_CALLBACK_FAILURE_CLOSED = 60006,

  /**
   * Application only partially processed upload and did
   * not suspend connection. This may result in a hung
   * connection.
   */
  MHD_SC_APPLICATION_HUNG_CONNECTION = 60007,

  /**
   * Application only partially processed upload and did
   * not suspend connection and the read buffer was maxxed
   * out, so MHD closed the connection.
   */
  MHD_SC_APPLICATION_HUNG_CONNECTION_CLOSED = 60008,

  /**
   * Application called function too late, for example because
   * MHD already changed state.
   */
  MHD_SC_TOO_LATE = 60009,

  /**
   * Attempted to set an option that conflicts with another option
   * already set.
   */
  MHD_SC_OPTIONS_CONFLICT = 60010


};


// FIXME: maybe not needed? Too large possibly?
enum MHD_Bool
MHD_status_code_is_fatal(enum MHD_StatusCode code)
MHD_FUNC_CONST_;


// FIXME: struct MHD_String
const char *
MHD_status_code_to_string (enum MHD_StatusCode code)
MHD_FUNC_CONST_ MHD_FUNC_RETURNS_NONNULL_;

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
 *
 * @defgroup methods HTTP methods
 * HTTP methods (as strings).
 * See: http://www.iana.org/assignments/http-methods/http-methods.xml
 * Registry Version 2015-05-19
 * @{
 */
enum MHD_HTTP_Method
{

  /**
   * Method did not match any of the methods given below.
   */
  MHD_HTTP_METHOD_OTHER = 0,

  /* Main HTTP methods. */

  /**
   * "GET"
   * Safe.     Idempotent.     RFC9110, Section 9.3.1.
   */
  MHD_HTTP_METHOD_GET = 1,

  /**
   * "HEAD"
   * Safe.     Idempotent.     RFC9110, Section 9.3.2.
   */
  MHD_HTTP_METHOD_HEAD = 2,

  /**
   * "POST"
   * Not safe. Not idempotent. RFC9110, Section 9.3.3.
   */
  MHD_HTTP_METHOD_POST = 3,

  /**
   * "PUT"
   * Not safe. Idempotent.     RFC9110, Section 9.3.4.
   */
  MHD_HTTP_METHOD_PUT = 4,

  /**
   * "DELETE"
   * Not safe. Idempotent.     RFC9110, Section 9.3.5.
   */
  MHD_HTTP_METHOD_DELETE = 5,

  /**
   * "CONNECT"
   * Not safe. Not idempotent. RFC9110, Section 9.3.6.
   */
  MHD_HTTP_METHOD_CONNECT = 6,

  /**
   * "OPTIONS"
   * Safe.     Idempotent.     RFC9110, Section 9.3.7.
   */
  MHD_HTTP_METHOD_OPTIONS = 7,

  /**
   * "TRACE"
   * Safe.     Idempotent.     RFC9110, Section 9.3.8.
   */
  MHD_HTTP_METHOD_TRACE = 8,

  /**
   * "*"
   * Not safe. Not idempotent. RFC9110, Section 18.2.
   */
  MHD_HTTP_METHOD_ASTERISK = 9
};

// FIXME: added
// FIXME: return 'const char *'?
_MHD_EXTERN const struct MHD_String
MHD_get_http_method_string(enum MHD_HTTP_Method method)
MHD_FUNC_CONST_;

/**
 * @defgroup methods HTTP methods
 * HTTP methods (as strings).
 * See: https://www.iana.org/assignments/http-methods/http-methods.xml
 * Registry export date: 2023-10-02
 * @{
 */

// FIXME: added
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
/* Not safe. Not idempotent. RFC9110, Section 18.2. */
#define MHD_HTTP_METHOD_STR_ASTERISK       "*"

/** @} */ /* end of group methods */


/**
 * @defgroup postenc HTTP POST encodings
 * See also: http://www.w3.org/TR/html4/interact/forms.html#h-17.13.4
 * @{
 */

enum MHD_HTTP_PostEncoding
{
  /**
   * No post encoding / broken data / unknown encoding
   */
  MHD_HTTP_POST_ENCODING_OTHER = 0,

  /**
   * "application/x-www-form-urlencoded"
   * See https://html.spec.whatwg.org/multipage/form-control-infrastructure.html#url-encoded-form-data
   * See https://url.spec.whatwg.org/#application/x-www-form-urlencoded
   * See https://datatracker.ietf.org/doc/html/rfc3986#section-2
   */
  MHD_HTTP_POST_ENCODING_FORM_URLENCODED = 1,

  /**
   * "multipart/form-data"
   * See https://html.spec.whatwg.org/multipage/form-control-infrastructure.html#url-encoded-form-data
   * See https://www.rfc-editor.org/rfc/rfc7578.html
   */
  MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA = 2,

  /**
   * "text/plain"
   * Introduced by HTML5
   * See https://html.spec.whatwg.org/multipage/form-control-infrastructure.html#plain-text-form-data
   * @warning Format is ambiguous. Do not use unless there is a very strong reason.
   */
  MHD_HTTP_POST_ENCODING_TEXT_PLAIN = 3
};


/** @} */ /* end of group postenc */


/**
 * @defgroup headers HTTP headers
 * The standard headers found in HTTP requests and responses.
 * See: https://www.iana.org/assignments/http-fields/http-fields.xhtml
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

/** @} */ /* end of group headers */

/* Forward declaration */
struct MHD_Action;

/**
 * A client has requested the given url using the given method
 * (#MHD_HTTP_METHOD_GET, #MHD_HTTP_METHOD_PUT,
 * #MHD_HTTP_METHOD_DELETE, #MHD_HTTP_METHOD_POST, etc).
 *
 * @param cls argument given together with the function
 *        pointer when the handler was registered with MHD
 * @param path the requested uri (without arguments after "?")
 * @param method the HTTP method used (#MHD_HTTP_METHOD_GET,
 *        #MHD_HTTP_METHOD_PUT, etc.)
 * @param upload_size the size of the message upload content payload,
 *                    #MHD_SIZE_UNKNOWN for chunked uploads (if the
 *                    final chunk has not been processed yet)
 * @return action how to proceed, NULL
 *         if the request must be closed due to a serious
 *         error while handling the request (implies closure
 *         of underling data stream, for HTTP/1.1 it means
 *         socket closure).
 */
typedef const struct MHD_Action *
(MHD_FUNC_PARAM_NONNULL_ (2) MHD_FUNC_PARAM_NONNULL_ (3)
 *MHD_RequestCallback) (void *cls,
                        struct MHD_Request *request,
                        const struct MHD_String *path,
                        enum MHD_Method method,
                        uint_fast64_t upload_size);


// FIXME: add port? It is used by most of the application.
/**
 * Create (but do not yet start) an MHD daemon.
 * Usually, you will want to set various options before
 * starting the daemon with #MHD_daemon_start().
 *
 * @param cb function to be called for incoming requests
 * @param cb_cls closure for @a cb
 * @return NULL on error
 */
_MHD_EXTERN struct MHD_Daemon *
MHD_daemon_create (MHD_RequestCallback cb,
                   void *cb_cls)
MHD_FUNC_PARAM_NONNULL_(1);


/**
 * Start a webserver.
 *
 * @param[in,out] daemon daemon to start; you can no longer set
 *        options on this daemon after this call!
 * @return #MHD_SC_OK on success
 * @ingroup event
 */
_MHD_EXTERN enum MHD_StatusCode
MHD_daemon_start (struct MHD_Daemon *daemon)
MHD_FUNC_PARAM_NONNULL_ (1);


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
 * @param[in,out] daemon daemon to stop accepting new connections for
 * @return old listen socket on success, #MHD_INVALID_SOCKET if
 *         the daemon was already not listening anymore, or
 *         was never started, or has not listen socket.
 * @ingroup specialized
 */
_MHD_EXTERN MHD_socket
MHD_daemon_quiesce (struct MHD_Daemon *daemon)
MHD_FUNC_PARAM_NONNULL_ALL_;


/**
 * Shutdown and destroy an HTTP daemon.
 *
 * @param[in] daemon daemon to stop
 * @ingroup event
 */
_MHD_EXTERN void
MHD_daemon_destroy (struct MHD_Daemon *daemon)
MHD_FUNC_PARAM_NONNULL_ALL_;


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
 * Logging will not work if MHD was compiled with "--disable-logging".
 * (The function will still be exported, but the @a logger will never
 * be invoked.)
 *
 * @param[in,out] daemon which instance to setup logging for
 * @param logger function to invoke
 * @param logger_cls closure for @a logger
 * @return #MHD_SC_FEATURE_DISABLED
 */
_MHD_EXTERN enum MHD_StatusCode
MHD_daemon_set_logger (struct MHD_Daemon *daemon,
                       MHD_LoggingCallback logger,
                       void *logger_cls)
MHD_FUNC_PARAM_NONNULL_ (1);


/**
 * Convenience macro used to disable logging.
 *
 * @param daemon which instance to disable logging for
 */
#define MHD_daemon_disable_logging(daemon) \
  MHD_daemon_set_logger ((daemon), \
                         NULL,   \
                         NULL)
// TODO: Sort values and assign numbers
enum MHD_DeamonOptionBool
{
  // FIXME: edited names, shortened
  /**
   * Suppresses use of "Date:" header.
   * According to RFC should be used only if the system has no RTC.
   */
  MHD_DAEMON_OB_SUPPRESS_DATE_HEADER = 1,

  /**
   * Disable use of inter-thread communication channel.
   * #MHD_daemon_disable_itc() can be used with
   * #MHD_daemon_thread_internal() to perform some additional
   * optimizations (in particular, not creating a pipe for IPC
   * signaling).  If it is used, certain functions like
   * #MHD_daemon_quiesce() or #MHD_daemon_add_connection() or
   * #MHD_action_suspend() cannot be used anymore.
   * #MHD_daemon_disable_itc() is not beneficial on platforms where
   * select()/poll()/other signal shutdown() of a listen socket.
   *
   * You should only use this function if you are sure you do
   * satisfy all of its requirements and need a generally minor
   * boost in performance.
   */
  MHD_DAEMON_OB_SUPPRESS_ITC = 2,

  /**
   * Enable `turbo`.  Disables certain calls to `shutdown()`,
   * enables aggressive non-blocking optimistic reads and
   * other potentially unsafe optimizations.
   * Most effects only happen with #MHD_USE_EPOLL.
   */
  MHD_DAEMON_OB_TURBO = 3,

  /**
   * You need to set this option if you want to disable use of HTTP "Upgrade".
   * "Upgrade" may require usage of additional internal resources,
   * which we can avoid providing if they will not be used.
   *
   * You should only use this function if you are sure you do
   * satisfy all of its requirements and need a generally minor
   * boost in performance.
   */
  MHD_DAEMON_OB_DISALLOW_UPGRADE,

  /**
   * Disable #MHD_action_suspend() functionality.
   *
   * You should only use this function if you are sure you do
   * satisfy all of its requirements and need a generally minor
   * boost in performance.
   */
  MHD_DAEMON_OB_DISALLOW_SUSPEND_RESUME,

  /**
   * If present true, allow reusing address:port socket (by using
   * SO_REUSEPORT on most platform, or platform-specific ways).  If
   * present and set to false, disallow reusing address:port socket
   * (does nothing on most platform, but uses SO_EXCLUSIVEADDRUSE on
   * Windows).
   * Ineffective in conjunction with #MHD_daemon_listen_socket().
   */
  MHD_DAEMON_OB_LISTEN_ALLOW_ADDRESS_REUSE,

  /**
   * Use SHOUTcast.  This will cause *all* responses to begin
   * with the SHOUTcast "ICY" line instead of "HTTP".
   */
  MHD_DAEMON_OB_ENABLE_SHOUTCAST,

  // FIXME: Added
  /**
   * Disable converting plus ('+') character to space in GET
   * parameters (URI part after '?').
   */
  MHD_DAEMON_OB_DISABLE_PLUS_SPACE
};


/**
 * Set boolean MHD option.
 *
 * @param[in,out] daemon which instance to set boolean @a option for
 * @param option option to modify
 * @param value new value for the option
 * @return #MHD_SC_OK on on success,
 *         #MHD_SC_TOO_LATE if this option was set after the daemon was started and it cannot be set anymore
 *         #MHD_SC_FEATURE_DISABLED if this option is not implemented in this version of the library,
 *         #MHD_SC_FEATURE_NOT_AVAILABLE if this options is not supported on this system
 *         #MHD_SC_OPTIONS_CONFLICT
 */
_MHD_EXTERN enum MHD_StatusCode
MHD_daemon_set_option_bool (struct MHD_Daemon *daemon,
                            enum MHD_DaemonOptionBool option,
                            enum MHD_Bool value)
MHD_FUNC_PARAM_NONNULL_ALL_ MHD_FUNC_MUST_CHECK_RESULT_;

/**
 * Possible levels of enforcement for TCP_FASTOPEN.
 */
enum MHD_FastOpenOption
{
  /**
   * Disable use of TCP_FASTOPEN.
   */
  MHD_FOM_DISABLE = -1,

  /**
   * Enable TCP_FASTOPEN where supported.
   * On GNU/Linux it works with a kernel >= 3.6.
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
 * @return #MHD_SC_OK on on success,
 *         #MHD_SC_TOO_LATE if this option was set after the daemon was started and it cannot be set anymore
 *         #MHD_SC_FEATURE_DISABLED,
 *         #MHD_SC_FEATURE_NOT_AVAILABLE,
 *         #MHD_SC_OPTIONS_CONFLICT
 */
_MHD_EXTERN enum MHD_StatusCode
MHD_daemon_set_option_tcp_fastopen (struct MHD_Daemon *daemon,
                                    enum MHD_FastOpenOption option,
                                    unsigned int queue_length)
MHD_FUNC_PARAM_NONNULL_ALL_ MHD_FUNC_MUST_CHECK_RESULT_;


/**
 * Address family to be used by MHD.
 */
enum MHD_AddressFamily
{
  /**
   * Option not given, do not listen at all
   * (unless listen socket or address specified by
   * other means).
   */
  MHD_AF_NONE = 0,

  /**
   * Pick "best" available method automatically.
   */
  MHD_AF_AUTO = 1,

  /**
   * Use IPv4.
   */
  MHD_AF_INET4 = 2,

  /**
   * Use IPv6.
   */
  MHD_AF_INET6 = 3,

  /**
   * Use dual stack.
   */
  MHD_AF_DUAL = 4
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
 * @param[in,out] daemon which instance to configure the TCP port for
 * @param af address family to use
 * @param port port to use, 0 to bind to a random (free) port
 * @return #MHD_SC_OK on on success,
 *         #MHD_SC_TOO_LATE if this option was set after the daemon was started and it cannot be set anymore
 *         #MHD_SC_FEATURE_DISABLED,
 *         #MHD_SC_FEATURE_NOT_AVAILABLE,
 *         #MHD_SC_OPTIONS_CONFLICT
 */
_MHD_EXTERN enum MHD_StatusCode
MHD_daemon_bind_port (struct MHD_Daemon *daemon,
                      enum MHD_AddressFamily af,
                      uint16_t port)
MHD_FUNC_PARAM_NONNULL_ALL_ MHD_FUNC_MUST_CHECK_RESULT_;


/**
 * Bind to the given socket address.
 * Ineffective in conjunction with #MHD_daemon_listen_socket().
 *
 * @param[in,out] daemon which instance to configure the binding address for
 * @param sa address to bind to; can be IPv4 (AF_INET), IPv6 (AF_INET6)
 *        or even a UNIX domain socket (AF_UNIX)
 * @param sa_len number of bytes in @a sa
 * @return #MHD_SC_OK on on success,
 *         #MHD_SC_TOO_LATE if this option was set after the daemon was started and it cannot be set anymore
 *         #MHD_SC_FEATURE_DISABLED,
 *         #MHD_SC_FEATURE_NOT_AVAILABLE,
 *         #MHD_SC_OPTIONS_CONFLICT
 */
_MHD_EXTERN enum MHD_StatusCode
MHD_daemon_bind_socket_address (struct MHD_Daemon *daemon,
                                const struct sockaddr *sa,
                                size_t sa_len)
MHD_FUNC_PARAM_NONNULL_ALL_ MHD_FUNC_MUST_CHECK_RESULT_;

// TODO: Sort values and assign numbers
enum MHD_DeamonOptionUInt
{
  /**
   * Use the given backlog for the listen() call.
   * Ineffective in conjunction with #MHD_daemon_listen_socket()
   */
  MHD_DAEMON_OPTION_UINT_LISTEN_BACKLOG,
  /**
   * Maximum number of (concurrent) network connections served
   * by daemon
   */
  MHD_DAEMON_OPTION_UINT_GLOBAL_CONNECTION_LIMIT,
  /**
   * Limit on the number of (concurrent) network connections
   * made to the server from the same IP address.
   * Can be used to prevent one IP from taking over all of
   * the allowed connections. If the same IP tries to establish
   * more than the specified number of connections, they will
   * be immediately rejected.
   */
  MHD_DAEMON_OPTION_UINT_IP_CONNECTION_LIMIT,

  /**
   * After how many seconds of inactivity should a
   * connection automatically be timed out?
   * Use zero for no timeout, which is also the (unsafe!) default.
   */
  MHD_DAEMON_OPTION_UINT_DEFAULT_TIMEOUT,

  /**
   * The number of worker threads.
   * Only useful if the selected threading mode
   * is #MHD_TM_WORKER_THREADS.
   * Zero number is silently ignored.
   */
  MHD_DAEMON_OPTION_UINT_NUM_WORKERS

};

// ADD - Discussed
/**
 * Set unsigned integer MHD option.
 *
 * @param[in,out] daemon which instance to set uint @a option for
 * @param option option to modify
 * @param value new value for the option
 * @return #MHD_SC_OK on on success,
 *         #MHD_SC_TOO_LATE if this option was set after the daemon was started and it cannot be set anymore
 *         #MHD_SC_FEATURE_DISABLED if this option is not implemented in this version of the library,
 *         #MHD_SC_FEATURE_NOT_AVAILABLE if this options is not supported on this system
 *         #MHD_SC_OPTIONS_CONFLICT
 */
_MHD_EXTERN enum MHD_StatusCode
MHD_daemon_set_option_uint (struct MHD_Daemon *daemon,
                            enum MHD_DeamonOptionUInt option,
                            unsigned int value)
MHD_FUNC_PARAM_NONNULL_ (1);

// FIXME: Alternative or additional implementation.

struct MHD_DaemonOptioniUIntEntry
{
  /**
   * The option to update the @a value
   */
  enum MHD_DeamonOptionUInt option;
  /**
   * The value to update for the @a option
   */
  unsigned int value;
};

/**
 * Set unsigned integer MHD options.
 *
 * @param[in,out] daemon which instance to set uint @a option for
 * @param num_entries the number of entries in the @a opt_val array
 *                    and in @a results (if not NULL)
 * @param[in] opt_val the array with options and values to modify
 * @param[out] results the results for the applying the options,
 *                     can be NULL,
 *                     if not NULL must have @a num_entries entries
 * @return #MHD_YES if all options have applied successfully
 *         #MHD_NO if at least single option failed (for more
 *         details check @a results)
 */
_MHD_EXTERN enum MHD_Bool
MHD_daemon_set_option_uint (
  struct MHD_Daemon *daemon,
  size_t num_entries,
  struct MHD_DaemonOptioniUIntEntry opt_val[MHD_C99_ (static num_entries)],
  enum MHD_StatusCode *results)
MHD_FUNC_PARAM_NONNULL_ (1) MHD_FUNC_PARAM_NONNULL_ (3);


/**
 * Accept connections from the given socket.  Socket
 * must be a TCP or UNIX domain (stream) socket.
 *
 * Unless MHD_INVALID_SOCKET is given, this disables
 * other listen options.
 *
 * @param daemon daemon to set listen socket for
 * @param listen_socket listen socket to use,
 *        MHD_INVALID_SOCKET value will cause this call to be
 *        ignored (other binding options may still be effective)
 * @return #MHD_SC_OK on on success,
 *         #MHD_SC_TOO_LATE if this option was set after the daemon was started and it cannot be set anymore
 *         #MHD_SC_FEATURE_DISABLED if this option is not implemented in this version of the library,
 *         #MHD_SC_FEATURE_NOT_AVAILABLE if this options is not supported on this system
 *         #MHD_SC_OPTIONS_CONFLICT
 */
_MHD_EXTERN enum MHD_StatusCode // FIXME - corrected
MHD_daemon_listen_socket (struct MHD_Daemon *daemon,
                          MHD_socket listen_socket)
MHD_FUNC_PARAM_NONNULL_ (1);


/**
 * Event loop internal syscalls supported by MHD.
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
 * @return #MHD_SC_OK on on success,
 *         #MHD_SC_TOO_LATE if this option was set after the daemon was started and it cannot be set anymore
 *         #MHD_SC_FEATURE_DISABLED if this option is not implemented in this version of the library,
 *         #MHD_SC_FEATURE_NOT_AVAILABLE if this options is not supported on this system
 *         #MHD_SC_OPTIONS_CONFLICT
 */
_MHD_EXTERN enum MHD_StatusCode // FIXME - corrected
MHD_daemon_event_loop (struct MHD_Daemon *daemon,
                       enum MHD_EventLoopSyscall els)
MHD_FUNC_PARAM_NONNULL_ (1);


/**
 * Protocol strictness enforced by MHD on clients.
 * All levels have different parsing settings for the headers.
 */
enum MHD_ProtocolStrictLevel
{
// FIXME: updated

  /* * Basic levels * */
  /**
   * Sane level of protocol enforcement for production use.
   * A balance between extra security and broader compatibility,
   * as allowed by RFCs for HTTP servers.
   */
  MHD_PSL_DEFAULT = 0,

  /**
   * Be strict about the protocol (as opposed to as tolerant as
   * possible), within the limits set by RFCs for HTTP servers.
   * This level (and more strict) forbids use of bare LF as
   * CRLF. It also rejects requests with both "Transfer-Encoding:"
   * and "Content-Length:".
   * It is suitable for public servers.
   */
  MHD_PSL_STRICT = 1,

  /**
   * Be particularly permissive about the protocol, within
   * the limits set by RFCs for HTTP servers.
   */
  MHD_PSL_PERMISSIVE = -1,

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
  MHD_PSL_VERY_STRICT = 2,

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
  MHD_PSL_EXTRA_STRICT = 3,

  /**
   * More relaxed protocol interpretation, violating RFCs'
   * "SHOULD" type of requirements for HTTP servers.
   * For cookies parsing this (and more permissive) level
   * allows whitespaces in cookie values.
   * This level can be used in isolated environments.
   */
  MHD_PSL_VERY_PERMISSIVE = -2,

  /**
   * The most flexible protocol interpretation, beyond
   * RFCs' "MUST" type of requirements for HTTP server.
   * The level allow HTTP/1.1 requests without "Host:" header.
   * For cookies parsing this level adds allowance of
   * whitespaces before and after '=' character.
   * This level is not recommended unless it is absolutely
   * necessary to communicate with some client(s) with
   * badly broken HTTP implementation.
   */
  MHD_PSL_EXTRA_PERMISSIVE = -3,
};

// FIXME: Added
/**
 * The way Strict Level is enforced.
 * MHD can be compiled with limited set of strictness levels.
 * These values instructs MHD how to apply the request level.
 */
enum MHD_UseStictLevel
{
  /**
   * Use requested level if available or the nearest stricter
   * level.
   * Fail if only more permissive levels available.
   */
  MHD_USL_THIS_OR_STRICTER = 0,
  /**
   * Use requested level only.
   * Fail if this level is not available.
   */
  MHD_USL_PRECISE = 1,
  /**
   * Use requested level if available or the nearest level (stricter
   * or more permissive).
   */
  MHD_USL_NEAREST = -1
};

/**
 * Set how strictly MHD will enforce the HTTP protocol.
 *
 * @param[in,out] daemon daemon to configure strictness for
 * @param sl the level of strictness
 * @param how the way how to use the requested level
 * @return #MHD_SC_OK on on success,
 *         #MHD_SC_TOO_LATE if this option was set after the daemon was started and it cannot be set anymore
 *         #MHD_SC_FEATURE_DISABLED if this option is not implemented in this version of the library,
 */
_MHD_EXTERN enum MHD_StatusCode // FIXME - corrected
MHD_daemon_protocol_strict_level (struct MHD_Daemon *daemon,
                                  enum MHD_ProtocolStrictLevel sl,
                                  enum MHD_UseStictLevel how)
MHD_FUNC_PARAM_NONNULL_ (1);

// FIXME: do we want to keep it as generic API?
// FIXME: other TLS backends will not support it.
// + TLS ciphers
// + 'application name' for lookup
// of TLS cipher option in configuration file.
// ciphers which ciphers should be used by TLS, default is
//    "NORMAL"
_MHD_EXTERN enum MHD_StatusCode
MHD_daemon_set_option_string (struct MHD_Daemon *daemon,
                              enum foo,
                              const char *value)
MHD_FUNC_PARAM_NONNULL_ (1);

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
                                         const char *pass)
MHD_FUNC_PARAM_NONNULL_ (1) MHD_FUNC_PARAM_NONNULL_ (2)
MHD_FUNC_PARAM_NONNULL_ (3);


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
                             const char *dh)
MHD_FUNC_PARAM_NONNULL_ (1);

/**
 * Memory pointer for the certificate (ca.pem) to be used by the
 * HTTPS daemon for client authentication.
 *
 * @param daemon daemon to configure tls for
 * @param mem_trust memory pointer to the certificate
 * @return #MHD_SC_OK upon success; TODO: define failure modes
 */
_MHD_EXTERN enum MHD_StatusCode
MHD_daemon_tls_mem_trust (struct MHD_Daemon *daemon,
                          const char *mem_trust)
MHD_FUNC_PARAM_NONNULL_ (1);


/* ********************** (d) TLS support ********************** */

/**
 * The TLS backend choice
 */
enum MHD_TlsBackend
{
  /**
   * Use best available TLS backend.
   * Currently this is equivalent to GnuTLS (if TLS is enabled
   * for MHD build).
   */
  MHD_TLS_BACKEND_ANY = 0,
  /**
   * Use GnuTLS as TLS backend.
   */
  MHD_TLS_BACKEND_GNUTLS = 1
};

// FIXME: should we enforce the order of settings applied?
// Is it required to first enable TLS before using any
// TLS-specific settings?
/**
 * Enable and configure TLS.
 *
 * @param daemon which instance should be configured
 * @param tls_backend which TLS backend should be used,
 *    currently only "gnutls" is supported.  You can
 *    also specify NULL for best-available (which is the default).
 * @return status code, #MHD_SC_OK upon success
 *     #MHD_TLS_BACKEND_UNSUPPORTED if the @a backend is unknown
 *     #MHD_TLS_DISABLED if this build of MHD does not support TLS
 *     #MHD_TLS_CIPHERS_INVALID if the given @a ciphers are not supported
 *     by this backend
 */
_MHD_EXTERN enum MHD_StatusCode
MHD_daemon_set_tls_backend (struct MHD_Daemon *daemon,
                            enum MHD_TlsBackend backend);

MHD_FUNC_PARAM_NONNULL_ (1);


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

enum MHD_StatusCode
MHD_connection_set_psk (struct MHD_ServerCredentialsContext *mscc,
                        size_t psk_size,
                        const /*void? */ char psk[MHD_C99_ (psk_size)]);

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
(*MHD_PskServerCredentialsCallback)(void *cls,
                                    const struct MHD_Connection *connection,
                                    const struct MHD_String *username,
                                    struct MHD_ServerCredentialsContext *mscc);


/**
 * Configure PSK to use for the TLS key exchange.
 *
 * @param daemon daemon to configure tls for
 * @param psk_cb function to call to obtain pre-shared key
 * @param psk_cb_cls closure for @a psk_cb
 * @return #MHD_SC_OK upon success; TODO: define failure modes
 */
_MHD_EXTERN enum MHD_StatusCode
MHD_daemon_set_tls_psk_callback (struct MHD_Daemon *daemon,
                                 MHD_PskServerCredentialsCallback psk_cb,
                                 void *psk_cb_cls)
MHD_FUNC_PARAM_NONNULL_ (1);


/**
 * Configure daemon credentials type for GnuTLS.
 *
 * @param gnutls_credentials must be a value of
 *   type `gnutls_credentials_type_t`
 * @return #MHD_SC_OK upon success; TODO: define failure modes
 *
 * FIXME: find a way to do this better that is TLS backend independent!
 * => replace by exposing TLS library low-level details via
 *    introspection, see below
 */
_MHD_EXTERN enum MHD_StatusCode
MHD_daemon_gnutls_credentials (struct MHD_Daemon *daemon,
                               int gnutls_credentials)
MHD_FUNC_PARAM_NONNULL_ (1);


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
 * @return #MHD_SC_OK on success
 *
 * FIXME: find a way to do this better that is TLS backend independent!
 * => replace by exposing TLS library low-level details via
 *    introspection, see below
 */
_MHD_EXTERN enum MHD_StatusCode
MHD_daemon_gnutls_key_and_cert_from_callback (struct MHD_Daemon *daemon,
                                              void *cb)
MHD_FUNC_PARAM_NONNULL_ (1);

// Callback invoked between full initialization of MHD
// during MHD_daemon_start() and actual event loop
// starting to accept incoming connections. So at this
// point, the listen socket (and if applicable TLS context)
// will be available for introspection.
typedef void
(*MHD_DaemonReadyCallback)(void *cls);


_MHD_EXTERN enum MHD_StatusCode
MHD_daemon_set_daemon_ready_callback (struct MHD_Daemon *daemon,
                                      MHD_DaemonReadyCallback cb,
                                      void *cb)
MHD_FUNC_PARAM_NONNULL_ (1);


/**
 * Allow or deny a client to connect.
 *
 * @param cls closure
 * @param addrlen length of @a addr
 * @param addr address information from the client
 * @see #MHD_daemon_accept_policy()
 * @return #MHD_YES if connection is allowed, #MHD_NO if not
 */
typedef enum MHD_Bool
(*MHD_AcceptPolicyCallback)(void *cls,
                            size_t addr_len,
                            const struct sockaddr *addr);


/**
 * Set a policy callback that accepts/rejects connections
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
                          void *apc_cls)
MHD_FUNC_PARAM_NONNULL_ (1);


/**
 * Function called by MHD to allow the application to log
 * the @a full_uri of a @a request.
 * This is the only moment when unmodified URI is provided.
 * After this callback MHD parses the URI and modifies it
 * by extracting GET parameters in-place.
 *
 * @param cls client-defined closure
 * @param[in,out] request the HTTP request handle (headers are
 *         not yet available)
 * @param uri the full URI from the HTTP request including parameters (after '?')
 */
typedef void
(MHD_FUNC_PARAM_NONNULL_ (2) MHD_FUNC_PARAM_NONNULL_ (3)
 *MHD_EarlyUriLogCallback)(void *cls,
                           struct MHD_Request *request,
                           const struct MHD_String *full_uri);


/**
 * Register a callback to be called first for every request
 * (before any parsing of the header).  Makes it easy to
 * log the full URL.
 *
 * @param daemon daemon for which to set the logger
 * @param cb function to call
 * @param cb_cls closure for @a cb
 */
_MHD_EXTERN enum MHD_StatusCode
MHD_daemon_set_early_uri_logger (struct MHD_Daemon *daemon,
                                 MHD_EarlyUriLogCallback cb,
                                 void *cb_cls)
MHD_FUNC_PARAM_NONNULL_ (1);


/**
 * The `enum MHD_ConnectionNotificationCode` specifies types
 * of connection notifications.
 * @ingroup request
 */
enum MHD_ConnectionNotificationCode
{

  /**
   * A new connection has been started.
   * @ingroup request
   */
  MHD_CONNECTION_NOTIFY_STARTED = 0,

  /**
   * A connection is closed.
   * @ingroup request
   */
  MHD_CONNECTION_NOTIFY_CLOSED = 1

};


/**
 * Signature of the callback used by MHD to notify the
 * application about started/stopped network connections
 *
 * @param cls client-defined closure
 * @param connection connection handle
 * @param toe reason for connection notification
 * @see #MHD_daemon_set_notify_connection()
 * @ingroup request
 */
typedef void
(MHD_FUNC_PARAM_NONNULL_ (2)
 *MHD_NotifyConnectionCallback) (void *cls,
                                 struct MHD_Connection *connection,
                                 enum MHD_ConnectionNotificationCode toe);


/**
 * Register a function that should be called whenever a connection is
 * started or closed.
 *
 * @param daemon daemon to set callback for
 * @param ncc function to call to check the policy
 * @param ncc_cls closure for @a apc
 */
_MHD_EXTERN enum MHD_StatusCode
MHD_daemon_set_notify_connection (struct MHD_Daemon *daemon,
                                  MHD_NotifyConnectionCallback ncc,
                                  void *ncc_cls)
MHD_FUNC_PARAM_NONNULL_ (1);


// FIXME: Added
/**
 * The `enum MHD_ConnectionNotificationCode` specifies types
 * of connection notifications.
 * @ingroup request
 */
enum MHD_StreamNotificationCode
{
  // FIXME: more codes, like "server started", "closed with error"&
  /**
   * A new connection has been started.
   * @ingroup request
   */
  MHD_STREAM_NOTIFY_STARTED = 0,

  /**
   * A connection is closed.
   * @ingroup request
   */
  MHD_STREAM_NOTIFY_CLOSED = 1

};

// FIXME: Added
/**
 * Signature of the callback used by MHD to notify the
 * application about started/stopped data stream
 * For HTTP/1.1 it is the same like network connection
 * with 1:1 match.
 *
 * @param cls client-defined closure
 * @param stream the stream handle
 * @param toe reason for connection notification
 * @see #MHD_OPTION_NOTIFY_CONNECTION
 * @ingroup request
 */
typedef void
(MHD_FUNC_PARAM_NONNULL_ (2)
 *MHD_NotifyStreamCallback) (void *cls,
                             struct MHD_Stream *stream,
                             enum MHD_ConnectionNotificationCode toe);


// FIXME: Added
/**
 * Register a function that should be called whenever a stream is
 * started or closed.
 *
 * @param daemon daemon to set callback for
 * @param nsc function to call to check the policy
 * @param nsc_cls closure for @a apc
 */
_MHD_EXTERN enum MHD_StatusCode
MHD_daemon_set_notify_stream (struct MHD_Daemon *daemon,
                              MHD_NotifyStreamCallback nsc,
                              void *nsc_cls)
MHD_FUNC_PARAM_NONNULL_ (1);

// TODO: Sort and assign values
enum MHD_DaemonOptionSizet
{
  /**
   * Maximum memory size per connection.
   * Default is 32 kb (#MHD_POOL_SIZE_DEFAULT).
   * Values above 128k are unlikely to result in much performance benefit,
   * as half of the memory will be typically used for IO, and TCP buffers
   * are unlikely to support window sizes above 64k on most systems.
   * The size should be large enough to fit all request headers (together
   * with internal parsing information).
   */
  MHD_DAEMON_OPTION_SIZET_CONN_MEM_LIMIT,
  // FIXME: remove this option completely and manage it in MHD?
  // Users do not have clear understanding of what is it and why is it needed/
  /**
   * The step in which read buffer is incremented when needed.
   * If initial half size of the connection's memory region is not enough
   * for message header and initial part of the request context/body then
   * buffer is increased by this size.
   */
  MHD_DAEMON_OPTION_SIZET_CONN_INCR_SIZE,
  /**
   * Desired size of the stack for threads created by MHD.
   * Use 0 for system default, which is also MHD default.
   * Only useful if the selected threading mode
   * is not #MHD_TM_EXTERNAL_EVENT_LOOP.
   */
  MHD_DAEMON_OPTION_SIZET_STACK_SIZE,

};
// FIXME:
_MHD_EXTERN void
MHD_daemon_option_set_sizet (struct MHD_Daemon *daemon,
                             enum MHD_DaemonOptionSizet option,
                             size_t value)
MHD_FUNC_PARAM_NONNULL_ (1);

/* ******************* Event loop ************************ */


/**
 * Which threading mode should be used by MHD?
 */
enum MHD_ThreadingMode
{
  // FIXME: Updated
  /**
   * The daemon has no internal threads.
   * The application periodically calls #MHD_process_data(), MHD checks
   * all sockets internally automatically.
   * This is the default.
   */
  MHD_TM_EXTERNAL_PERIODIC = 0,
  /**
   * Use an external event loop.
   * Application used one of MHD APIs to watch sockets status.
   */
  MHD_TM_EXTERNAL_EVENT_LOOP = 1,
// FIXME: updated
  /**
   * Run with one or more worker threads.
   * If #MHD_DAEMON_OPTION_UINT_NUM_WORKERS is not specified
   * then daemon starts with single worker thread that process
   * all connections.
   * If #MHD_DAEMON_OPTION_UINT_NUM_WORKERS used with value more
   * than one, then that number of worker threads and distributed
   * processing of requests among the workers.
   *
   * If this mode is specified, #MHD_daemon_run() and
   * #MHD_daemon_run_from_select() cannot be used.
   */
  MHD_TM_WORKER_THREADS = 2,

  // FIXME: could be unavailable for HTTP/2 and /3. Streams must be
  // multiplexed. Multiplexing from several threads looks overcomplicated.
  /**
   * MHD should create its own thread for listening and furthermore create
   * another thread per request. Threads may be re-used on the same
   * connection.  Use this if handling requests is CPU-intensive or blocking,
   * your application is thread-safe and you have plenty of memory (per
   * request).
   */
  MHD_TM_THREAD_PER_REQUEST = 3

};

/* FUTURE:
   (with eventually option "number of masters")
   MHD_TM_WORKER_THREADS_WITH_MASTER_LISTENER = 3 */


/**
 * Specify threading mode to use.
 *
 * @param[in,out] daemon daemon to configure
 * @param tm mode to use
 */
_MHD_EXTERN enum MHD_StatusCode
MHD_daemon_set_threading_mode (struct MHD_Daemon *daemon,
                               enum MHD_ThreadingMode tm)
MHD_FUNC_PARAM_NONNULL_ (1);


// edge vs. level triggers? howto unify? => application returns type?
// thread safety?
// existing cascaded epoll FD approach, how to keep?
// -> introspection API to return the FD
// -> if app does NOT set MHD_set_external_event_loop()
//    we presumably use 'internal' implementation(s),
//    if internal e-pool implementation configured...

enum MHD_EventType // bitmask
{
  MHD_ET_LISTEN = 1,// want to accept
  MHD_ET_READ = 2,  // want to read
  MHD_ET_WRITE = 4, // want to write
  MHD_ET_EXCEPT = 8 // care about remote close / interruption
};

enum MHD_TriggerLevel
{
  MHD_TL_EDGE, // epoll in edge trigger mode
  MHD_TL_LEVEL // epoll in level trigger mode
};

// implemented within MHD!
typedef void
(*MHD_EventCallback) (void *cls,
                      enum MHD_EventType et,
                      enum MHD_TriggerLevel tl);


#ifdef EXAMPLE_APP_CODE

struct MHD_ApplicationRegistrationContext *
// NULL
app_ereg_cb_select (void *cls,
                    enum MHD_EventType et,
                    int fd,
                    MHD_EventCallback cb,
                    void *cb_cls)
{
  assert (fd < FD_SETSIZE);
  max_fd = MAX (fd, max_fd);
  events[fd].cb = cb;
  events[fd].cb_cls = cb_cls;
  if (1 == 1 & et)
    FD_SET (fd, &reads);
  if (2 == 2 & et)
    FD_SET (fd, &writes);
  if (4 == 4 & et)
    FD_SET (fd, &excepts);
  return &events[fd];
}


void
app_unreg (ptr)
{
  ptr->cb = NULL;
  // whichever applicable...
  int fd = ptr - events;
  FD_CLR (fd, &reads);
  FD_CLR (fd, &writes);
  FD_CLR (fd, &excepts);
  if (fd == max_fd)
    while ( (max_fd > 0) &&
            (NULL == events[--max_fd].cb) )
      ;
}


loop_do ()
{
  d = MHD_daemon_create (...);
  MHD_set_external_event_loop (d,
                               &app_reg,
                               &app_unreg);
  MHD_daemon_go (d); // => calls app_reg on listen socket
  while (1)
  {
    rs = reads; // copy!
    ws = writes; // copy!
    es = excepts; // copy!
    // + add application FDs here (if not in global reads/writes/excepts)
    // once per iteration (also runs edge-based events)
    new_timeout = MHD_run_jobs_and_get_timeout (d);
    select (max_fd, &rs, &ws, &es, new_timeout);
    for (bits_set)
    {
      events[bit].cb (events[bit].cb_cls,
                      LISTEN / READ / WRITE / EXCEPT,
                      MHD_TL_LEVEL);
    }
  }
}
#endif


uint64_t
MHD_external_event_loop_get_timeout (struct MHD_Daemon *d);


struct MHD_ApplicationRegistrationContext; // opaque to MHD, app must define per socket/event

// implemented usually by application,
typedef struct MHD_ApplicationRegistrationContext * // NULL on error, e.g. fd too large / out of memory => log + close connection
(*MHD_EventRegistrationUpdateCallback)(
  void *cls,
  struct MHD_ApplicationRegistrationContext *old, // null if no previous reg for fd exists
  enum MHD_EventType et,                          // use NONE to unregister
  int fd,
  MHD_EventCallback cb,
  void *cb_cls);

// NEW style:
void
MHD_set_external_event_loop (struct MHD_Daemon *daemon,
                             MHD_EventRegistrationUpdateCallback cb,
                             void *cb_cls);


// FIXME: Alternative style

struct MHD_WatchedFD
{
  /**
   * The watched socket
   */
  MHD_socket fd;

  /**
   * Indicates that socket should be watched for incoming data
   * (when set by #MHD_get_watched_fds())
   * / socket has incoming data ready to read (when used for
   * #MHD_process_watched_fds())
   */
  enum MHD_bool recv_ready;

  /**
   * Indicates that socket should be watched for availability for sending
   * (when set by #MHD_get_watched_fds())
   * / socket has ability to send data (when used for
   * #MHD_process_watched_fds())
   */
  enum MHD_bool send_ready;

  /**
   * Indicates that socket should be watched for disconnect, out-of-band
   * data available or high priority data available (when set by
   * #MHD_get_watched_fds())
   * / socket has been disconnected, has out-of-band data available or
   * has high priority data available (when used for
   * #MHD_process_watched_fds()). This status must not include "remote
   * peer shut down writing" status.
   * Note: #MHD_get_watched_fds() always set it as exceptions must be
   * always watched.
   */
  enum MHD_bool exception;
};

/**
 * Get the full list of the sockets that must be watched by application.
 *
 * The application may use this function each time to get a full list of
 * the sockets for watch or may use #MHD_get_watched_fds_update() to
 * get the incremental updates.
 *
 * @param daemon the daemon to get the list
 * @param num_elements the number of elements in @a fds list
 * @param[out] fds the arrays of @a num_elements of sockets to be watched
 *                 by application,
 *                 could be NULL to get the required number of elements
 * @param[out] max_wait the pointer to value set to maximum wait time
 *                      for the network events, set only if @fds is not NULL
 * @return number of elements set in @a fds, never larger than
 *         @a num_elements (if @a fds in not NULL);
 *         the required number elements in @a fds (if @a fds is NULL)
 */
_MHD_EXTERN unsigned int
MHD_get_watched_fds (struct MHD_Daemon *daemon,
                     unsigned int num_elements,
                     struct MHD_WatchedFD *fds,
                     uint_fast64_t *max_wait) // FIXME: never return "no timeout"
MHD_FUNC_PARAM_NONNULL_ (1) MHD_FUNC_PARAM_NONNULL_ (4);


enum MHD_WatchedFdAction
{
  /**
   * New watched FD, to be added to the list
   */
  MHD_WFA_ADD,

  /**
   * Update watching interest in already watched FD
   */
  MHD_WFA_UPDATE,

  /**
   * Delete FD from watching list
   */
  MHD_WFA_REMOVE
};

struct MHD_WatchedFdUpdate
{
  /**
   * The required action: add/update/delete
   */
  enum MHD_WatchedFdAction action;

  /**
   * The watched FD to add, update or delete.
   */
  struct MHD_WatchedFD watched_fd;
};

/**
 * Get the update of the listt of the sockets that must be watched
 * by application.
 * This function provides an update to the list of watched sockets
 * since the last call of #MHD_get_watched_fds() or
 * #MHD_get_watched_fds_update() with non-NULL @a fds.
 * If this function is called before #MHD_get_watched_fds() then it
 * returns full list of sockets to watch with action #MHD_WFA_ADD.
 *
 * @param daemon the daemon to get the list
 * @param num_elements the number of elements in @a fds list
 * @param[out] fds the arrays of @a num_elements to update the list
 *                 of watched sockets,
 *                 could be NULL to get the required number of elements
 * @param[out] max_wait the pointer to value set to maximum wait time
 *                      for the network events, set only if @fds is not NULL
 * @return number of elements set in @a fds, never larger than
 *         @a num_elements (if @a fds in not NULL);
 *         the required number elements in @a fds (if @a fds is NULL)
 */
_MHD_EXTERN unsigned int
MHD_get_watched_fds_update (struct MHD_Daemon *daemon,
                            unsigned int num_elements,
                            struct MHD_WatchedFdUpdate *fds,
                            uint_fast64_t *max_wait)
MHD_FUNC_PARAM_NONNULL_ (1);


/**
 * Perform round of sockets processing, including receiving, sending,
 * data processing, sockets closing and other things.
 * @param daemon the daemon to process
 * @param num_elements the number of elements in the @a fds array
 * @param fds the array of watched sockets, must be complete list of
 *            all watched sockets if @a type is #MHD_TL_LEVEL or
 *            just partial list otherwise
 * @param type the type of the trigger used to watch sockets
 * @return #MHD_SC_OK on success,
 *         otherwise error code TODO: complete list of error codes
 */
_MHD_EXTERN enum MHD_StatusCode // FIXME: bool? void?
MHD_process_watched_fds (
  struct MHD_Daemon *daemon,
  unsigned int num_elements,
  struct MHD_WatchedFD fds[MHD_C99_ (static num_elements)],
  enum MHD_TriggerLevel type)
MHD_FUNC_PARAM_NONNULL_ (1) MHD_FUNC_PARAM_NONNULL_ (2);

/**
 * Obtain the `select()` sets for this daemon.  Daemon's FDs will be
 * added to fd_sets. To get only daemon FDs in fd_sets, call FD_ZERO
 * for each fd_set before calling this function. FD_SETSIZE is assumed
 * to be platform's default.
 *
 * Passing custom FD_SETSIZE as @a fd_setsize allow usage of
 * larger/smaller than platform's default fd_sets.
 *
 * This function should only be called in when MHD is configured to
 * use external select with 'select()' or with 'epoll'.  In the latter
 * case, it will only add the single 'epoll()' file descriptor used by
 * MHD to the sets.  It's necessary to use #MHD_get_timeout() in
 * combination with this function.
 *
 * This function must be called only for daemon started without
 * #MHD_USE_INTERNAL_POLLING_THREAD flag.
 *
 * @param[in,out] daemon daemon to get sets from
 * @param[in,out] read_fd_set read set; our FDs are added, existing bits set are unchanged
 * @param[in,out] write_fd_set write set; our FDs are added, existing bits set are unchanged
 * @param[in,out] except_fd_set except set; our FDs are added, existing bits set are unchanged
 * @param[in,out] max_fd increased to largest FD added (if larger
 *                than existing value); can be NULL
 * @param[out] timeout set to the timeout (in milliseconds), -1LL indicates "forever"
 * @param fd_setsize value of FD_SETSIZE (needed if application set custom values that do not match compile-time MHD)
 * @return #MHD_SC_OK on success, otherwise error code (specify which ones...); #MHD_SC_NOT_IMPLEMENTED ...
 * @ingroup event
 */
// @deprecated, new CB approach!
_MHD_EXTERN enum MHD_StatusCode
MHD_daemon_get_fdset2 (struct MHD_Daemon *daemon,
                       fd_set *read_fd_set,
                       fd_set *write_fd_set,
                       fd_set *except_fd_set,
                       MHD_socket *max_fd,
                       int64_fast_t *timeout,
                       unsigned int fd_setsize)
MHD_FUNC_PARAM_NONNULL_ (1,2,3,4,6);


/**
 * Obtain the `select()` sets for this daemon.  Daemon's FDs will be
 * added to fd_sets. To get only daemon FDs in fd_sets, call FD_ZERO
 * for each fd_set before calling this function. Size of fd_set is
 * determined by current value of FD_SETSIZE.  It's necessary to use
 * #MHD_get_timeout() in combination with this function.
 *
 * This function could be called only for daemon started
 * without #MHD_USE_INTERNAL_POLLING_THREAD flag.
 *
 * @param daemon daemon to get sets from
 * @param read_fd_set read set
 * @param write_fd_set write set
 * @param except_fd_set except set
 * @param max_fd increased to largest FD added (if larger
 *               than existing value); can be NULL
 * @return #MHD_YES on success, #MHD_NO if this
 *         daemon was not started with the right
 *         options for this call or any FD didn't
 *         fit fd_set.
 * @ingroup event
 */
// @deprecated, new CB approach!
#define MHD_daemon_get_fdset(daemon,read_fd_set,write_fd_set,except_fd_set, \
                             max_fd) \
  MHD_get_fdset2 ((daemon),(read_fd_set),(write_fd_set),(except_fd_set), \
                  (max_fd),FD_SETSIZE)

/**
 * Run webserver operations. This method should be called by clients
 * in combination with #MHD_get_fdset and #MHD_get_timeout() if the
 * client-controlled select method is used.
 *
 * You can use this function instead of #MHD_run if you called
 * `select()` on the result from #MHD_get_fdset.  File descriptors in
 * the sets that are not controlled by MHD will be ignored.  Calling
 * this function instead of #MHD_run is more efficient as MHD will not
 * have to call `select()` again to determine which operations are
 * ready.
 *
 * This function cannot be used with daemon started with
 * #MHD_USE_INTERNAL_POLLING_THREAD flag.
 *
 * @param[in,out] daemon daemon to run select loop for
 * @param read_fd_set read set
 * @param write_fd_set write set
 * @param except_fd_set except set
 * @return #MHD_SC_OK on success, #MHD_SC_NOT_IMPLEMENTED ...
 * @ingroup event
 */
// @deprecated, new CB approach!
_MHD_EXTERN enum MHD_StatusCode
MHD_daemon_run_from_select (struct MHD_Daemon *daemon,
                            const fd_set *read_fd_set,
                            const fd_set *write_fd_set,
                            const fd_set *except_fd_set)
MHD_FUNC_PARAM_NONNULL_ (1,2,3,4);


/**
 * Obtain timeout value for polling function for this daemon.
 * This function set value to amount of milliseconds for which polling
 * function (`select()` or `poll()`) should at most block, not the
 * timeout value set for connections.
 * It is important to always use this function, even if connection
 * timeout is not set, as in some cases MHD may already have more
 * data to process on next turn (data pending in TLS buffers,
 * connections are already ready with epoll etc.) and returned timeout
 * will be zero.
 *
 * @param[in,out] daemon daemon to query for timeout
 * @param[out] timeout set to the timeout (in milliseconds)
 * @return #MHD_SC_OK on success, #MHD_SC_NO_TIMEOUT if timeouts are
 *        not used (or no connections exist that would
 *        necessitate the use of a timeout right now), otherwise
 *        an error code
 * @ingroup event
 */
// @deprecated, new CB approach / use for inspiration
_MHD_EXTERN enum MHD_StatusCode
MHD_daemon_get_timeout (struct MHD_Daemon *daemon,
                        uint64_fast_t *timeout)
MHD_FUNC_PARAM_NONNULL_ (1) MHD_FUNC_PARAM_NONNULL_ (2);


/**
 * Run websever operation with possible blocking.
 *
 * This function does the following: waits for any network event not more than
 * specified number of milliseconds, processes all incoming and outgoing data,
 * processes new connections, processes any timed-out connection, and does
 * other things required to run webserver.
 * Once all connections are processed, function returns.
 *
 * This function is useful for quick and simple (lazy) webserver implementation
 * if application needs to run a single thread only and does not have any other
 * network activity.
 *
 * FIXME: document use of this function for epoll(), too!
 *
 * This function calls MHD_get_timeout() internally and use returned value as
 * maximum wait time if it less than value of @a millisec parameter.
 *
 * It is expected that the "external" socket polling function is not used in
 * conjunction with this function unless the @a millisec is set to zero.
 *
 * @param daemon the daemon to run
 * @param millisec the maximum time in milliseconds to wait for network and
 *                 other events. Note: there is no guarantee that function
 *                 blocks for the specified amount of time. The real processing
 *                 time can be shorter (if some data or connection timeout
 *                 comes earlier) or longer (if data processing requires more
 *                 time, especially in user callbacks).
 *                 If set to '0' then function does not block and processes
 *                 only already available data (if any).
 *                 If set to '-1' then function waits for events
 *                 indefinitely (blocks until next network activity or
 *                 connection timeout).
 * @return #MHD_YES on success, #MHD_NO if this
 *         daemon was not started with the right
 *         options for this call or some serious
 *         unrecoverable error occurs.
 * @note Available since #MHD_VERSION 0x00097206
 * @ingroup event
 */
// @deprecated, new CB approach!
_MHD_EXTERN enum MHD_Result
MHD_daemon_run_wait (struct MHD_Daemon *daemon,
                     int32_t millisec);


/**
 * Run webserver operations (without blocking unless in client
 * callbacks).  This method should be called by clients in combination
 * with #MHD_get_fdset if the client-controlled select method is used
 * and #MHD_get_timeout().
 *
 * FIXME: document use of this function for epoll(), too!
 *
 * This function is a convenience method, which is useful if the
 * fd_sets from #MHD_get_fdset were not directly passed to `select()`;
 * with this function, MHD will internally do the appropriate `select()`
 * call itself again.  While it is always safe to call #MHD_run (if
 * #MHD_USE_INTERNAL_POLLING_THREAD is not set), you should call
 * #MHD_run_from_select if performance is important (as it saves an
 * expensive call to `select()`).
 *
 * @param[in,out] daemon daemon to run
 * @return #MHD_SC_OK on success
 * @ingroup event
 */
#define MHD_daemon_run(d) \
  MHD_daemon_run_wait (d, 0);


// FIXME: support external poll???
// FIXME: remove, use universal solution
struct pollfd;

// num_fds: in,out: in: fds length, out: number desired (if larger than in), number initialized (if smaller or equal to in)
// @deprecated, new CB approach!
_MHD_EXTERN enum MHD_StatusCode
MHD_daemon_get_poll_set (struct MHD_Daemon *daemon,
                         unsigned int *num_fds,
                         struct pollfd *fds);


// @deprecated, new CB approach!
_MHD_EXTERN enum MHD_StatusCode
MHD_daemon_run_from_poll (struct MHD_Daemon *daemon,
                          unsigned int num_fds,
                          const struct pollfd fds[MHD_C99_ (static num_fds)]);


/**
 * Add another client connection to the set of connections managed by
 * MHD.  This API is usually not needed (since MHD will accept inbound
 * connections on the server socket).  Use this API in special cases,
 * for example if your HTTP server is behind NAT and needs to connect
 * out to the HTTP client, or if you are building a proxy.
 *
 * If you use this API in conjunction with a internal select or a
 * thread pool, you must set the option #MHD_USE_ITC to ensure that
 * the freshly added connection is immediately processed by MHD.
 *
 * The given client socket will be managed (and closed!) by MHD after
 * this call and must no longer be used directly by the application
 * afterwards.
 *
 * @param daemon daemon that manages the connection
 * @param client_socket socket to manage (MHD will expect
 *        to receive an HTTP request from this socket next).
 * @param addr IP address of the client
 * @param addrlen number of bytes in @a addr
 * @param connection_cls meta data the application wants to
 *          associate with the new connection object
 * @return #MHD_SC_OK on success
 *         FIXME: add detailed list of codes
 * @ingroup specialized
 */
_MHD_EXTERN enum MHD_StatusCode
MHD_daemon_add_connection (struct MHD_Daemon *daemon,
                           MHD_socket client_socket,
                           const struct sockaddr *addr,
                           socklen_t addrlen,
                           void *connection_cls)
MHD_FUNC_PARAM_NONNULL_ (1);


/* ********************* connection options ************** */


/**
 * Set custom timeout for the given connection.
 * Specified as the number of seconds.  Use zero for no timeout.
 * Calling this function will reset its timeout timer.
 *
 * @param[in,out] connection connection to configure timeout for
 * @param timeout_s new timeout in seconds
 */
_MHD_EXTERN enum MHD_StatusCode
MHD_connection_set_timeout (struct MHD_Connection *connection,
                            unsigned int timeout_s)
MHD_FUNC_PARAM_NONNULL_ (1);


/* **************** Request handling functions ***************** */


// FIXME: Updated
/**
 * The `enum MHD_ValueKind` specifies the source of
 * the key-value pairs in the HTTP protocol.
 */
enum MHD_ValueKind
{

  /**
   * HTTP header.
   */
  MHD_VK_HEADER = 1,

  /**
   * Cookies.  Note that the original HTTP header containing
   * the cookie(s) will still be available and intact.
   */
  MHD_VK_COOKIE = 2,

  // FIXME: swappaed values
  /**
   * GET (URI) arguments.
   */
  MHD_VK_GET_ARGUMENT = 4,

  /**
   * POST data.
   * FIXME: Correct description
   * This is available only if a content encoding
   * supported by MHD is used, and only if the posted content
   * fits within the available memory pool.
   * Note that in that case, the upload data given to
   * the #MHD_AccessHandlerCallback will be empty (since it has
   * already been processed).
   */
  MHD_VK_POSTDATA = 8,

  /**
   * HTTP footer (only for HTTP 1.1 chunked encodings).
   */
  MHD_VK_FOOTER = 16,

  // FIXME: combined values
  /**
   * Header and footer values
   */
  MHD_VK_HEADER_FOOTER = MHD_VK_HEADER | MHD_VK_FOOTER,

  /**
   * Values from get arguments or post data
   */
  MHD_VK_GET_POST = MHD_VK_POSTDATA | MHD_VK_GET_ARGUMENT
                    // FIXME: Add chunk extension? Another API for extension?
};


/**
 * Iterator over key-value pairs.  This iterator can be used to
 * iterate over all of the cookies, headers, or POST-data fields of a
 * request, and also to iterate over the headers that have been added
 * to a response.
 *
 * @param cls closure
 * @param kind kind of the header we are looking at
 * @param key key for the value, can be an empty string
 * @param value corresponding value, can be NULL
 * @return #MHD_YES to continue iterating,
 *         #MHD_NO to abort the iteration
 * @ingroup request
 */
typedef enum MHD_Bool
(MHD_FUNC_PARAM_NONNULL_ (3)
 *MHD_KeyValueIterator)(void *cls,
                        enum MHD_ValueKind kind,
                        const struct MHD_String *key,
                        const struct MHD_String *value);


/**
 * Get all of the headers from the request via callback.
 *
 * @param[in,out] request request to get values from
 * @param kind types of values to iterate over, can be a bitmask
 * @param iterator callback to call on each header;
 *        maybe NULL (then just count headers)
 * @param iterator_cls extra argument to @a iterator
 * @return number of entries iterated over
 * @ingroup request
 */
_MHD_EXTERN unsigned int
MHD_request_get_values_cb (struct MHD_Request *request,
                           enum MHD_ValueKind kind,
                           MHD_KeyValueIterator iterator,
                           void *iterator_cls)
MHD_FUNC_PARAM_NONNULL_ (1);

// FIXME: added - to discuss
/**
 * Get all of the headers from the request.
 *
 * @param[in] request request to get values from
 * @param kind the types of values to iterate over, can be a bitmask
 * @param num_elements the number of elements in @a keys and @a values arrays
 * @param[out] keys the array of @a num_elements strings to be filled with
 *                  the keys data; if @a request has more elements than
 *                  @a num_elements than first @a num_elements are stored,
 *                  the parameter can be NULL
 * @param[out] values the array of @a num_elements strings to be filled with
 *                    the values data if @a request has more elements than
 *                    @a num_elements than first @a num_elements are stored,
 *                    the parameter can be NULL
 * @return the number of keys (and values) available (if @a keys is NULL),
 *         the number of elements stored in @a key (and in @a values), the
 *         number cannot be larger then @a num_elements
 */
_MHD_EXTERN unsigned int
MHD_request_get_values_list (struct MHD_Request *request,
                             enum MHD_ValueKind kind,
                             unsigned int num_elements,
                             struct MHD_String *keys,
                             struct MHD_String *values)
MHD_FUNC_PARAM_NONNULL_ (1);


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
                          const char *key)
MHD_FUNC_PARAM_NONNULL_ (1);


// FIXME: gana? table for RFC 7541...
enum MHD_StaticTableKey;

/**
 * Get last occurence of a particular header value under
 * the given @a skt.
 *
 * @param[in,out] request request to get values from
 * @param kind what kind of value are we looking for
 * @param skt the header to look for based on RFC 7541 Appendix A.
 * @return NULL if no such item was found
 * @ingroup request
 */
_MHD_EXTERN const char *
MHD_request_lookup_value_by_static_header (struct MHD_Request *request,
                                           enum MHD_ValueKind kind,
                                           enum MHD_StaticTableKey skt)
MHD_FUNC_PARAM_NONNULL_ (1);


/**
 * @defgroup httpcode HTTP response codes.
 * These are the status codes defined for HTTP responses.
 * @{
 */
/* See http://www.iana.org/assignments/http-status-codes/http-status-codes.xhtml */
// Use GANA!
// FIXME: Discuss GANA. It will be always behind the official specs.
enum MHD_HTTP_StatusCode
{
  MHD_HTTP_STATUS_CONTINUE = 100,
  MHD_HTTP_STATUS_SWITCHING_PROTOCOLS = 101,
  MHD_HTTP_STATUS_PROCESSING = 102,

  MHD_HTTP_STATUS_OK = 200,
  MHD_HTTP_STATUS_CREATED = 201,
  MHD_HTTP_STATUS_ACCEPTED = 202,
  MHD_HTTP_STATUS_NON_AUTHORITATIVE_INFORMATION = 203,
  MHD_HTTP_STATUS_NO_CONTENT = 204,
  MHD_HTTP_STATUS_RESET_CONTENT = 205,
  MHD_HTTP_STATUS_PARTIAL_CONTENT = 206,
  MHD_HTTP_STATUS_MULTI_STATUS = 207,
  MHD_HTTP_STATUS_ALREADY_REPORTED = 208,

  MHD_HTTP_STATUS_IM_USED = 226,

  MHD_HTTP_STATUS_MULTIPLE_CHOICES = 300,
  MHD_HTTP_STATUS_MOVED_PERMANENTLY = 301,
  MHD_HTTP_STATUS_FOUND = 302,
  MHD_HTTP_STATUS_SEE_OTHER = 303,
  MHD_HTTP_STATUS_NOT_MODIFIED = 304,
  MHD_HTTP_STATUS_USE_PROXY = 305,
  MHD_HTTP_STATUS_SWITCH_PROXY = 306, /* IANA: unused */
  MHD_HTTP_STATUS_TEMPORARY_REDIRECT = 307,
  MHD_HTTP_STATUS_PERMANENT_REDIRECT = 308,

  MHD_HTTP_STATUS_BAD_REQUEST = 400,
  MHD_HTTP_STATUS_UNAUTHORIZED = 401,
  MHD_HTTP_STATUS_PAYMENT_REQUIRED = 402,
  MHD_HTTP_STATUS_FORBIDDEN = 403,
  MHD_HTTP_STATUS_NOT_FOUND = 404,
  MHD_HTTP_STATUS_METHOD_NOT_ALLOWED = 405,
  MHD_HTTP_STATUS_NOT_ACCEPTABLE = 406,
  MHD_HTTP_STATUS_PROXY_AUTHENTICATION_REQUIRED = 407,
  MHD_HTTP_STATUS_REQUEST_TIMEOUT = 408,
  MHD_HTTP_STATUS_CONFLICT = 409,
  MHD_HTTP_STATUS_GONE = 410,
  MHD_HTTP_STATUS_LENGTH_REQUIRED = 411,
  MHD_HTTP_STATUS_PRECONDITION_FAILED = 412,
  MHD_HTTP_STATUS_PAYLOAD_TOO_LARGE = 413,
  MHD_HTTP_STATUS_URI_TOO_LONG = 414,
  MHD_HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE = 415,
  MHD_HTTP_STATUS_RANGE_NOT_SATISFIABLE = 416,
  MHD_HTTP_STATUS_EXPECTATION_FAILED = 417,

  MHD_HTTP_STATUS_MISDIRECTED_REQUEST = 421,
  MHD_HTTP_STATUS_UNPROCESSABLE_ENTITY = 422,
  MHD_HTTP_STATUS_LOCKED = 423,
  MHD_HTTP_STATUS_FAILED_DEPENDENCY = 424,
  MHD_HTTP_STATUS_UNORDERED_COLLECTION = 425, /* IANA: unused */
  MHD_HTTP_STATUS_UPGRADE_REQUIRED = 426,

  MHD_HTTP_STATUS_PRECONDITION_REQUIRED = 428,
  MHD_HTTP_STATUS_TOO_MANY_REQUESTS = 429,
  MHD_HTTP_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE = 431,

  MHD_HTTP_STATUS_NO_RESPONSE = 444, /* IANA: unused */

  MHD_HTTP_STATUS_RETRY_WITH = 449, /* IANA: unused */
  MHD_HTTP_STATUS_BLOCKED_BY_WINDOWS_PARENTAL_CONTROLS = 450,  /* IANA: unused */
  MHD_HTTP_STATUS_UNAVAILABLE_FOR_LEGAL_REASONS = 451,

  MHD_HTTP_STATUS_INTERNAL_SERVER_ERROR = 500,
  MHD_HTTP_STATUS_NOT_IMPLEMENTED = 501,
  MHD_HTTP_STATUS_BAD_GATEWAY = 502,
  MHD_HTTP_STATUS_SERVICE_UNAVAILABLE = 503,
  MHD_HTTP_STATUS_GATEWAY_TIMEOUT = 504,
  MHD_HTTP_STATUS_HTTP_VERSION_NOT_SUPPORTED = 505,
  MHD_HTTP_STATUS_VARIANT_ALSO_NEGOTIATES = 506,
  MHD_HTTP_STATUS_INSUFFICIENT_STORAGE = 507,
  MHD_HTTP_STATUS_LOOP_DETECTED = 508,
  MHD_HTTP_STATUS_BANDWIDTH_LIMIT_EXCEEDED = 509,  /* IANA: unused */
  MHD_HTTP_STATUS_NOT_EXTENDED = 510,
  MHD_HTTP_STATUS_NETWORK_AUTHENTICATION_REQUIRED = 511

};


/**
 * Returns the string reason phrase for a response code.
 *
 * If we don't have a string for a status code, we give the first
 * message in that status code class.
 */
_MHD_EXTERN const char *
MHD_status_code_to_string (enum MHD_HTTP_StatusCode code);

/** @} */ /* end of group httpcode */


/**
 * @defgroup versions HTTP versions
 * These strings should be used to match against the first line of the
 * HTTP header.
 * @{
 */
// Again: GANA?
// FIXME: Discuss GANA. It will be always behind the official specs.
enum MHD_HTTP_ProtocolVersion
{
  MHD_HTTP_VERSION_INVALID = 0,
  MHD_HTTP_VERSION_1_0 = 1,
  MHD_HTTP_VERSION_1_1 = 2,
  MHD_HTTP_VERSION_2_0 = 3,
  MHD_HTTP_VERSION_3_0 = 4,
  MHD_HTTP_VERSION_FUTURE = 99
};

// FIXME: remove completely, usable only for HTTP/1.x
_MHD_EXTERN const char *
MHD_protocol_version_to_string (enum MHD_HTTP_ProtocolVersion pv);

// Reminder:
// #define MHD_HTTP_VERSION_1_0 "HTTP/1.0"
// #define MHD_HTTP_VERSION_1_1 "HTTP/1.1"
// #define MHD_HTTP_VERSION_2 "HTTP/2"
// #define MHD_HTTP_VERSION_3 "HTTP/3"

/** @} */ /* end of group versions */


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
_MHD_EXTERN const struct MHD_Action *
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
 * @param[in,out] request the request to resume
 */
_MHD_EXTERN void
MHD_request_resume (struct MHD_Request *request)
MHD_FUNC_PARAM_NONNULL_ALL_;


/* **************** Response manipulation functions ***************** */


/**
 * Data transmitted in response to an HTTP request.
 * Usually the final action taken in response to
 * receiving a request.
 */
struct MHD_Response;


/**
 * Converts a @a response to an action.  If @a destroy_after_use
 * is set, the reference to the @a response is consumed
 * by the conversion. If @a consume is #MHD_NO, then
 * the @a response can be converted to actions in the future.
 * However, the @a response is frozen by this step and
 * must no longer be modified (i.e. by setting headers).
 *
 * @param[in] response response to convert, not NULL
 */
_MHD_EXTERN const struct MHD_Action *
MHD_action_from_response (struct MHD_Response *response)
MHD_FUNC_PARAM_NONNULL_ (1);

#ifndef FIXME_FUN
struct MHD_Action
{
  enum type;
  // depending on type:
  union
  {
    struct
    {
      struct MHD_Response *response;
    } from_response;
  } details;
};
struct MHD_Response
{
  struct MHD_Action my_action = {
    .type = from_response;
    .details.from_response = &self;
  };
};
#endif


/**
 * Flags for special handling of responses.
 */
// FIXME: this should not be a bit map...
enum MHD_ResponseOption
{
  /**
   * Default: no special flags.
   * @note Available since #MHD_VERSION 0x00093701
   */
  MHD_RF_NONE = 0,

  /**
   * Only respond in conservative (dumb) HTTP/1.0-compatible mode.
   * Response still use HTTP/1.1 version in header, but always close
   * the connection after sending the response and do not use chunked
   * encoding for the response.
   * You can also set the #MHD_RF_HTTP_1_0_SERVER flag to force
   * HTTP/1.0 version in the response.
   * Responses are still compatible with HTTP/1.1.
   * This option can be used to communicate with some broken client, which
   * does not implement HTTP/1.1 features, but advertises HTTP/1.1 support.
   * @note Available since #MHD_VERSION 0x00097308
   */
  // FIXME: no more bit mask!
  MHD_RF_HTTP_1_0_COMPATIBLE_STRICT = 1 << 0,

  /**
   * The same as #MHD_RF_HTTP_1_0_COMPATIBLE_STRICT
   * @note Available since #MHD_VERSION 0x00093701
   */
  MHD_RF_HTTP_VERSION_1_0_ONLY = 1 << 0,

  /**
   * Only respond in HTTP 1.0-mode.
   * Contrary to the #MHD_RF_HTTP_1_0_COMPATIBLE_STRICT flag, the response's
   * HTTP version will always be set to 1.0 and keep-alive connections
   * will be used if explicitly requested by the client.
   * The "Connection:" header will be added for both "close" and "keep-alive"
   * connections.
   * Chunked encoding will not be used for the response.
   * Due to backward compatibility, responses still can be used with
   * HTTP/1.1 clients.
   * This option can be used to emulate HTTP/1.0 server (for response part
   * only as chunked encoding in requests (if any) is processed by MHD).
   * @note Available since #MHD_VERSION 0x00097308
   */
  MHD_RF_HTTP_1_0_SERVER = 1 << 1,
  /**
   * The same as #MHD_RF_HTTP_1_0_SERVER
   * @note Available since #MHD_VERSION 0x00096000
   */
  MHD_RF_HTTP_VERSION_1_0_RESPONSE = 1 << 1,

  /**
   * Disable sanity check preventing clients from manually
   * setting the HTTP content length option.
   * Allow to set several "Content-Length" headers. These headers will
   * be used even with replies without body.
   * @note Available since #MHD_VERSION 0x00096702
   */
  MHD_RF_INSANITY_HEADER_CONTENT_LENGTH = 1 << 2,

  /**
   * Enable sending of "Connection: keep-alive" header even for
   * HTTP/1.1 clients when "Keep-Alive" connection is used.
   * Disabled by default for HTTP/1.1 clients as per RFC.
   * @note Available since #MHD_VERSION 0x00097310
   */
  MHD_RF_SEND_KEEP_ALIVE_HEADER = 1 << 3,

  /**
   * Enable special processing of the response as body-less (with undefined
   * body size). No automatic "Content-Length" or "Transfer-Encoding: chunked"
   * headers are added when the response is used with #MHD_HTTP_NOT_MODIFIED
   * code or to respond to HEAD request.
   * The flag also allow to set arbitrary "Content-Length" by
   * MHD_add_response_header() function.
   * This flag value can be used only with responses created without body
   * (zero-size body).
   * Responses with this flag enabled cannot be used in situations where
   * reply body must be sent to the client.
   * This flag is primarily intended to be used when automatic "Content-Length"
   * header is undesirable in response to HEAD requests.
   * @note Available since #MHD_VERSION 0x00097701
   */
  MHD_RF_HEAD_ONLY_RESPONSE = 1 << 4,

  // action_from_response does not decrement RC...
  MHD_RF_REUSABLE = 1 << 5
} _MHD_FIXED_FLAGS_ENUM;


_MHD_EXTERN enum MHD_StatusCode
MHD_response_set_option_bool (struct MHD_Response *response,
                              enum MHD_ResponseOption ro,
                              enum MHD_Bool value)
MHD_FUNC_PARAM_NONNULL_ALL_;


/**
 * Only respond in conservative HTTP 1.0-mode.  In
 * particular, do not (automatically) sent "Connection" headers and
 * always close the connection after generating the response.
 *
 * @param request the request for which we force HTTP 1.0 to be used
 */
_MHD_EXTERN void
MHD_response_option_v10_only (struct MHD_Response *response)
MHD_FUNC_PARAM_NONNULL_ (1);


/**
 * The `enum MHD_RequestTerminationCode` specifies reasons
 * why a request has been terminated (or completed).
 * @ingroup request
 */
enum MHD_RequestTerminationCode
{

  /**
   * We finished sending the response.
   * @ingroup request
   */
  MHD_REQUEST_TERMINATED_COMPLETED_OK = 0,

  /**
   * Error handling the connection (resources
   * exhausted, other side closed connection,
   * application error accepting request, etc.)
   * @ingroup request
   */
  MHD_REQUEST_TERMINATED_WITH_ERROR = 1,

  /**
   * No activity on the connection for the number
   * of seconds specified using
   * #MHD_OPTION_CONNECTION_TIMEOUT.
   * @ingroup request
   */
  MHD_REQUEST_TERMINATED_TIMEOUT_REACHED = 2,

  /**
   * We had to close the session since MHD was being
   * shut down.
   * @ingroup request
   */
  MHD_REQUEST_TERMINATED_DAEMON_SHUTDOWN = 3,

  /**
   * We tried to read additional data, but the other side closed the
   * connection.  This error is similar to
   * #MHD_REQUEST_TERMINATED_WITH_ERROR, but specific to the case where
   * the connection died because the other side did not send expected
   * data.
   * @ingroup request
   */
  MHD_REQUEST_TERMINATED_READ_ERROR = 4,

  /**
   * The client terminated the connection by closing the socket
   * for writing (TCP half-closed); MHD aborted sending the
   * response according to RFC 2616, section 8.1.4.
   * @ingroup request
   */
  MHD_REQUEST_TERMINATED_CLIENT_ABORT = 5

};


/**
 * Signature of the callback used by MHD to notify the application
 * about completed requests.
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
 * @param[in,out] response which response to set the callback for
 * @param termination_cb function to call
 * @param termination_cb_cls closure for @e termination_cb
 */
_MHD_EXTERN enum MHD_StatusCode
MHD_response_set_option_termination_callback (
  struct MHD_Response *response,
  MHD_RequestTerminationCallback termination_cb,
  void *termination_cb_cls)
MHD_FUNC_PARAM_NONNULL_ (1);


/**
 * Callback used by libmicrohttpd in order to obtain content.  The
 * callback is to copy at most @a max bytes of content into @a buf.  The
 * total number of bytes that has been placed into @a buf should be
 * returned.
 *
 * Note that returning zero will cause libmicrohttpd to try again.
 * Thus, returning zero should only be used in conjunction
 * with MHD_suspend_connection() to avoid busy waiting.
 *
 * @param cls extra argument to the callback
 * @param pos position in the datastream to access;
 *        note that if a `struct MHD_Response` object is re-used,
 *        it is possible for the same content reader to
 *        be queried multiple times for the same data;
 *        however, if a `struct MHD_Response` is not re-used,
 *        libmicrohttpd guarantees that "pos" will be
 *        the sum of all non-negative return values
 *        obtained from the content reader so far.
 * @param[out] buf where to copy the data
 * @param max maximum number of bytes to copy to @a buf (size of @a buf)
 * @return number of bytes written to @a buf;
 *  0 is legal unless we are running in internal select mode (since
 *    this would cause busy-waiting); 0 in external select mode
 *    will cause this function to be called again once the external
 *    select calls MHD again;
 *  #MHD_CONTENT_READER_END_OF_STREAM (-1) for the regular
 *    end of transmission (with chunked encoding, MHD will then
 *    terminate the chunk and send any HTTP footers that might be
 *    present; without chunked encoding and given an unknown
 *    response size, MHD will simply close the connection; note
 *    that while returning #MHD_CONTENT_READER_END_OF_STREAM is not technically
 *    legal if a response size was specified, MHD accepts this
 *    and treats it just as #MHD_CONTENT_READER_END_WITH_ERROR;
 *  #MHD_CONTENT_READER_END_WITH_ERROR (-2) to indicate a server
 *    error generating the response; this will cause MHD to simply
 *    close the connection immediately.  If a response size was
 *    given or if chunked encoding is in use, this will indicate
 *    an error to the client.  Note, however, that if the client
 *    does not know a response size and chunked encoding is not in
 *    use, then clients will not be able to tell the difference between
 *    #MHD_CONTENT_READER_END_WITH_ERROR and #MHD_CONTENT_READER_END_OF_STREAM.
 *    This is not a limitation of MHD but rather of the HTTP protocol.
 */
typedef ssize_t
(*MHD_ContentReaderCallback) (void *cls,
                              uint64_t pos,
                              void *buf,
                              size_t max);


/**
 * This method is called by libmicrohttpd if we are done with a
 * content reader.  It should be used to free resources associated
 * with the content reader.
 *
 * @param[in] cls closure
 * @ingroup response
 */
typedef void
(*MHD_ContentReaderFreeCallback) (void *cls);


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
                          size_t buffer_size,
                          const char buffer[MHD_C99_ (static buffer_size)],
                          enum MHD_ResponseMemoryMode mode);


/**
 * Create a response object with empty (zero size) body.
 *
 * The response object can be extended with header information and then be used
 * any number of times.
 */
#define MHD_response_from_empty(sc) \
  MHD_response_from_buffer (sc, \
                            0, \
                            NULL,  \
                            MHD_RESPMEM_PERSISTENT)


/**
 * Create a response object with an array of memory buffers
 * used as the response body.
 *
 * The response object can be extended with header information and then
 * be used any number of times.
 *
 * If response object is used to answer HEAD request then the body
 * of the response is not used, while all headers (including automatic
 * headers) are used.
 *
 * @param iov_count the number of elements in @a iov
 * @param iov the array for response data buffers, an internal copy of this
 *        will be made
 * @param free_cb the callback to clean up any data associated with @a iov when
 *        the response is destroyed.
 * @param free_cb_cls the argument passed to @a free_cb
 * @return NULL on error (i.e. invalid arguments, out of memory)
 * @note Available since #MHD_VERSION 0x00097204
 * @ingroup response
 */
_MHD_EXTERN struct MHD_Response *
MHD_response_from_iovec (
  enum MHD_HTTP_StatusCode sc,
  unsigned int iov_count,
  const struct MHD_IoVec iov[MHD_C99_ (iov_count)],
  MHD_ContentReaderFreeCallback free_cb,
  void *free_cb_cls);


/**
 * Create a response object with the content of provided buffer used as
 * the response body.
 *
 * The response object can be extended with header information and then
 * be used any number of times.
 *
 * If response object is used to answer HEAD request then the body
 * of the response is not used, while all headers (including automatic
 * headers) are used.
 *
 * @param size size of the data portion of the response
 * @param buffer size bytes containing the response's data portion
 * @param crfc function to call to cleanup, if set to NULL then callback
 *             is not called
 * @param crfc_cls an argument for @a crfc
 * @return NULL on error (i.e. invalid arguments, out of memory)
 * @note 'const' qualifier is used for @a buffer since #MHD_VERSION 0x00097701
 * @ingroup response
 */
_MHD_EXTERN struct MHD_Response *
MHD_response_from_buffer_with_free_callback (
  enum MHD_HTTP_StatusCode sc,
  size_t size,
  const char buffer[MHD_C99_ (static size)],
  MHD_ContentReaderFreeCallback crfc,
  void *crfc_cls);


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
 * @param fd file descriptor referring to a read-end of a pipe with the
 *        data; will be closed when response is destroyed;
 *        fd should be in 'blocking' mode
 * @return NULL on error (i.e. invalid arguments, out of memory)
 * @ingroup response
 */
_MHD_EXTERN struct MHD_Response *
MHD_response_from_pipe (enum MHD_HTTP_StatusCode sc,
                        int fd);


/**
 * Explicitly decrease reference counter of a response object.  If the
 * counter hits zero, destroys a response object and associated
 * resources.  Usually, this is implicitly done by converting a
 * response to an action and returning the action to MHD.
 *
 * @param[in] response response to decrement RC of
 * @ingroup response
 */
_MHD_EXTERN void
MHD_response_queue_for_destroy (struct MHD_Response *response)
MHD_FUNC_PARAM_NONNULL_ (1);


_MHD_EXTERN struct MHD_Response *
MHD_response_incref (struct MHD_Response *response)
MHD_FUNC_PARAM_NONNULL_ (1);


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
_MHD_EXTERN enum MHD_StatusCode
MHD_response_add_header (struct MHD_Response *response,
                         const char *header,
                         const char *content)
MHD_FUNC_PARAM_NONNULL_ (1,2,3);


_MHD_EXTERN enum MHD_StatusCode
MHD_response_add_static_header (struct MHD_Response *response,
                                enum MHD_StaticTableKey stk,
                                const char *content)
MHD_FUNC_PARAM_NONNULL_ (1,3);


/**
 * Delete a header (or footer) line from the response.
 *
 * @param[in,out] response response to remove a header from
 * @param header the header to delete
 * @param content value to delete
 * @return #MHD_NO on error (no such header known)
 * @ingroup response
 */
_MHD_EXTERN enum MHD_StatusCode
MHD_response_del_header (struct MHD_Response *response,
                         const char *header,
                         const char *content)
MHD_FUNC_PARAM_NONNULL_ (1,2,3);


/**
 * Get all of the headers that were added to a response.
 *
 * @param response response to query
 * @param iterator callback to call on each header;
 *        maybe NULL (then just count headers)
 * @param iterator_cls extra argument to @a iterator
 * @return number of entries iterated over
 * @ingroup response
 */
_MHD_EXTERN unsigned int
MHD_response_get_headers (const struct MHD_Response *response,
                          MHD_KeyValueIterator iterator,
                          void *iterator_cls)
MHD_FUNC_PARAM_NONNULL_ (1);


/**
 * Get a particular header from the response.  Valid as
 * long as the response is valid and the header is not
 * explicitly deleted from the response.
 *
 * @param response response to query
 * @param key which header to get
 * @return NULL if header does not exist
 * @ingroup response
 */
_MHD_EXTERN const struct MHD_String *
MHD_response_get_header (const struct MHD_Response *response,
                         const char *key)
MHD_FUNC_PARAM_NONNULL_ (1,2);


/**
 * Add a tailer line to the response for this request.
 * Usually called within a MHD_ContentReaderCallback.
 *
 * @param response response to add a footer to
 * @param footer the footer to add
 * @param content value to add
 * @return #MHD_NO on error (i.e. invalid footer or content format),
 *         or out of memory
 * @ingroup response
 */
_MHD_EXTERN enum MHD_Bool
MHD_request_set_response_trailer (
  struct MHD_Request *request,
  const char *footer,
  const char *content)
MHD_FUNC_PARAM_NONNULL_ (1,2,3);


/* ************ (b) Upload and PostProcessor functions ********************** */


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
 * @param[in,out] request the request for which a
 *  value should be set
 * @param kind kind of the value
 * @param key key for the value
 * @param value the value itself
 * @return #MHD_NO if the operation could not be
 *         performed due to insufficient memory;
 *         #MHD_YES on success
 * @ingroup request
 *
 * FIXME: remove, instead fox PostProcessor API to allow application to provide value!
 */
_MHD_EXTERN enum MHD_Bool
MHD_request_set_value (struct MHD_Request *request,
                       enum MHD_ValueKind kind,
                       const char *key,
                       const char *value)
MHD_FUNC_PARAM_NONNULL_ (1,3,4);


/**
 * Action telling MHD to continue processing the upload.
 *
 * @return action operation, never NULL
 */
_MHD_EXTERN const struct MHD_Action *
MHD_action_continue (void);


/**
 * Action telling MHD to close the connection hard
 * (kind-of breaking HTTP specification).
 *
 * FIXME: Note: equvalent to returning MHD_NO before!
 *
 * @return action operation, always NULL ? :-)
 */
#define MHD_action_close_connection() \
  ((const struct MHD_Action *) NULL)


/**
 * Function to process data uploaded by a client.
 *
 * @param cls argument given together with the function
 *        pointer when the handler was registered with MHD
 * @param path the requested uri (without arguments after "?")
 * @param method the HTTP method used (#MHD_HTTP_METHOD_GET,
 *        #MHD_HTTP_METHOD_PUT, etc.)
 * @param content_total_size the size of the message content payload,
 *                           #MHD_SIZE_UNKNOWN for chunked uploads
 *                           when the final chunk has not been
 *                           processed yet.
 * @param uploaded_content_size the size of already uploaded
 *                              content in @a content_data
 * @param[in] content_data the uploaded content data,
 *                         may be modified in .....
 *                         must not be freed
 *                         NULL if no content has been
 *                         processed yet,
 *                          not NULL if any content has been
 *                          processed even if content is
 *                          zero size
 * @param content_processed_size the size of previously provided and
 *                               processes content data
 * @return action specifying how to proceed, often
 *         #MHD_action_continue() if all is well,
 *         #MHD_action_suspend() to stop reading the upload until
 *              the request is resumed,
 *         NULL to close the socket, or a response
 *         to discard the rest of the upload and return the data given
 */
typedef const struct MHD_Action *
(MHD_FUNC_PARAM_NONNULL_ (2) MHD_FUNC_PARAM_NONNULL_ (3)
 *MHD_UploadCallback) (void *upload_cls,
                       struct MHD_Request *request,
                       size_t content_data_size,
                       void *content_data);


/**
 * Create an action that handles an upload.
 *
 * @param uc function to call with uploaded data
 * @param uc_cls closure for @a uc
 * @param upload_buffer_size how large should the
 *        upload buffer be. Use 0 for stream processing using
 *        the normal memory pool. May allocate memory from
 *        the large memory pool if necessary and non-zero is given.
 * @param call_when_full only call @a uc when the buffer is full
 *        (or the upload is complete); otherwise call as soon
 *        as data is available
 * @return NULL on error (out of memory)
 * @ingroup action
 */
_MHD_EXTERN const struct MHD_Action *
MHD_action_process_upload (
  // ?? ugly, how to avoid alloc otherwise??
  struct MHD_Request *request,
  size_t upload_buffer_size,
  bool call_when_full,
  MHD_UploadCallback uc,
  void *uc_cls)
MHD_FUNC_PARAM_NONNULL_ (1);


/**
 * Iterator over key-value pairs where the value maybe made available
 * in increments and/or may not be zero-terminated.  Used for
 * MHD parsing POST data.  To access "raw" data from POST or PUT
 * requests, use #MHD_action_process_upload() instead.
 *
 * @param cls user-specified closure
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
typedef const struct MHD_Action *
(*MHD_PostDataIterator) (void *cls,
                         const struct MHD_String *key,
                         const struct MHD_String *filename,
                         const struct MHD_String *content_type,
                         const struct MHD_String *transfer_encoding,
                         const struct MHD_String *data,
                         uint64_t off,
                         size_t size);


typedef const struct MHD_Action *
(*MHD_PostDataFinished) (void *cls);


/**
 * @param pp_buffer_size how much data should the post processor
 *   buffer in memory
 * @param pp_stream_limit values above which length should be
 *   given to @a iter for stream processing
 * @param iter function to call for "oversize" values in the stream,
 *             can be NULL
 * @param iter_cls closure for @a iter
 * @param done_cb called once all data has been processed for
 *   the final action; values smaller than @a pp_stream_limit that
 *   fit into @a pp_buffer_size will be available via
 *   MHD_request_get_post_processor_value()
 */
_MHD_EXTERN struct MHD_Action *
MHD_action_post_processor (struct MHD_Request *req,
                           size_t pp_buffer_size,
                           size_t pp_stream_limit,
                           MHD_PostDataIterator iter,
                           void *iter_cls,
                           MHD_PostDataFinished done_cb,
                           void *done_cb_cls)
MHD_FUNC_PARAM_NONNULL_ (2);


// @a kind can be filename, content_type, transfer_encoding or (raw) data
// NULL if key not found or PP not used.
_MHD_EXTERN const struct MHD_String *
MHD_request_get_post_processor_value (struct MHD_Request *req,
                                      enum MHD_ValueKind kind,
                                      const char *key)
MHD_FUNC_PARAM_NONNULL_ (2);


/* ***************** (c) WebSocket support ********** */

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
 * FIXME: this API still uses the untyped, ugly varargs.
 * Should we not modernize this one as well?
 *
 * @param urh the handle identifying the connection to perform
 *            the upgrade @a action on.
 * @param operation which operation should be performed
 * @param ... arguments to the action (depends on the action)
 * @return #MHD_NO on error, #MHD_YES on success
 */
_MHD_EXTERN struct MHD_Action *// ???
MHD_upgrade_operation (struct MHD_UpgradeResponseHandle *urh,
                       enum MHD_UpgradeOperation operation,
                       ...)
MHD_FUNC_PARAM_NONNULL_ (1);


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
 * @param req_cls last value left in `req_cls` of the `MHD_AccessHandlerCallback`
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
                      void *req_cls,
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
                          void *upgrade_handler_cls)
MHD_FUNC_PARAM_NONNULL_ (1);


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
 * @note Available since #MHD_VERSION 0x00097701
 * @ingroup authentication
 */
#define MHD_SHA512_256_DIGEST_SIZE 32

/**
 * Base type of hash calculation.
 * Used as part of #MHD_DigestAuthAlgo3 values.
 *
 * @warning Not used directly by MHD API.
 * @note Available since #MHD_VERSION 0x00097701
 */
enum MHD_DigestBaseAlgo
{
  /**
   * Invalid hash algorithm value
   */
  MHD_DIGEST_BASE_ALGO_INVALID = 0,

  /**
   * MD5 hash algorithm.
   * As specified by RFC1321
   */
  MHD_DIGEST_BASE_ALGO_MD5 = (1 << 0),

  /**
   * SHA-256 hash algorithm.
   * As specified by FIPS PUB 180-4
   */
  MHD_DIGEST_BASE_ALGO_SHA256 = (1 << 1),

  /**
   * SHA-512/256 hash algorithm.
   * As specified by FIPS PUB 180-4
   */
  MHD_DIGEST_BASE_ALGO_SHA512_256 = (1 << 2)
} _MHD_FIXED_FLAGS_ENUM;

/**
 * The flag indicating non-session algorithm types,
 * like 'MD5', 'SHA-256' or 'SHA-512-256'.
 * @note Available since #MHD_VERSION 0x00097701
 */
#define MHD_DIGEST_AUTH_ALGO3_NON_SESSION    (1 << 6)

/**
 * The flag indicating session algorithm types,
 * like 'MD5-sess', 'SHA-256-sess' or 'SHA-512-256-sess'.
 * @note Available since #MHD_VERSION 0x00097701
 */
#define MHD_DIGEST_AUTH_ALGO3_SESSION        (1 << 7)

/**
 * Digest algorithm identification
 * @warning Do not be confused with #MHD_DigestAuthAlgorithm,
 *          which uses other values!
 * @note Available since #MHD_VERSION 0x00097701
 */
enum MHD_DigestAuthAlgo3
{
  /**
   * Unknown or wrong algorithm type.
   * Used in struct MHD_DigestAuthInfo to indicate client value that
   * cannot by identified.
   */
  MHD_DIGEST_AUTH_ALGO3_INVALID = 0,

  /**
   * The 'MD5' algorithm, non-session version.
   */
  MHD_DIGEST_AUTH_ALGO3_MD5 =
    MHD_DIGEST_BASE_ALGO_MD5 | MHD_DIGEST_AUTH_ALGO3_NON_SESSION,

  /**
   * The 'MD5-sess' algorithm.
   * Not supported by MHD for authentication.
   */
  MHD_DIGEST_AUTH_ALGO3_MD5_SESSION =
    MHD_DIGEST_BASE_ALGO_MD5 | MHD_DIGEST_AUTH_ALGO3_SESSION,

  /**
   * The 'SHA-256' algorithm, non-session version.
   */
  MHD_DIGEST_AUTH_ALGO3_SHA256 =
    MHD_DIGEST_BASE_ALGO_SHA256 | MHD_DIGEST_AUTH_ALGO3_NON_SESSION,

  /**
   * The 'SHA-256-sess' algorithm.
   * Not supported by MHD for authentication.
   */
  MHD_DIGEST_AUTH_ALGO3_SHA256_SESSION =
    MHD_DIGEST_BASE_ALGO_SHA256 | MHD_DIGEST_AUTH_ALGO3_SESSION,

  /**
   * The 'SHA-512-256' (SHA-512/256) algorithm.
   */
  MHD_DIGEST_AUTH_ALGO3_SHA512_256 =
    MHD_DIGEST_BASE_ALGO_SHA512_256 | MHD_DIGEST_AUTH_ALGO3_NON_SESSION,

  /**
   * The 'SHA-512-256-sess' (SHA-512/256 session) algorithm.
   * Not supported by MHD for authentication.
   */
  MHD_DIGEST_AUTH_ALGO3_SHA512_256_SESSION =
    MHD_DIGEST_BASE_ALGO_SHA512_256 | MHD_DIGEST_AUTH_ALGO3_SESSION
};


/**
 * Get digest size for specified algorithm.
 *
 * The size of the digest specifies the size of the userhash, userdigest
 * and other parameters which size depends on used hash algorithm.
 * @param algo3 the algorithm to check
 * @return the size of the digest (either #MHD_MD5_DIGEST_SIZE or
 *         #MHD_SHA256_DIGEST_SIZE/MHD_SHA512_256_DIGEST_SIZE)
 *         or zero if the input value is not supported or not valid
 * @sa #MHD_digest_auth_calc_userdigest()
 * @sa #MHD_digest_auth_calc_userhash(), #MHD_digest_auth_calc_userhash_hex()
 * @note Available since #MHD_VERSION 0x00097701
 * @ingroup authentication
 */
_MHD_EXTERN size_t
MHD_digest_get_hash_size (enum MHD_DigestAuthAlgo3 algo3);

/**
 * Digest algorithm identification, allow multiple selection.
 *
 * #MHD_DigestAuthAlgo3 always can be casted to #MHD_DigestAuthMultiAlgo3, but
 * not vice versa.
 *
 * @note Available since #MHD_VERSION 0x00097701
 */
enum MHD_DigestAuthMultiAlgo3
{
  /**
   * Unknown or wrong algorithm type.
   */
  MHD_DIGEST_AUTH_MULT_ALGO3_INVALID = MHD_DIGEST_AUTH_ALGO3_INVALID,

  /**
   * The 'MD5' algorithm, non-session version.
   */
  MHD_DIGEST_AUTH_MULT_ALGO3_MD5 = MHD_DIGEST_AUTH_ALGO3_MD5,

  /**
   * The 'MD5-sess' algorithm.
   * Not supported by MHD for authentication.
   * Reserved value.
   */
  MHD_DIGEST_AUTH_MULT_ALGO3_MD5_SESSION = MHD_DIGEST_AUTH_ALGO3_MD5_SESSION,

  /**
   * The 'SHA-256' algorithm, non-session version.
   */
  MHD_DIGEST_AUTH_MULT_ALGO3_SHA256 = MHD_DIGEST_AUTH_ALGO3_SHA256,

  /**
   * The 'SHA-256-sess' algorithm.
   * Not supported by MHD for authentication.
   * Reserved value.
   */
  MHD_DIGEST_AUTH_MULT_ALGO3_SHA256_SESSION =
    MHD_DIGEST_AUTH_ALGO3_SHA256_SESSION,

  /**
   * The 'SHA-512-256' (SHA-512/256) algorithm, non-session version.
   */
  MHD_DIGEST_AUTH_MULT_ALGO3_SHA512_256 = MHD_DIGEST_AUTH_ALGO3_SHA512_256,

  /**
   * The 'SHA-512-256-sess' (SHA-512/256 session) algorithm.
   * Not supported by MHD for authentication.
   * Reserved value.
   */
  MHD_DIGEST_AUTH_MULT_ALGO3_SHA512_256_SESSION =
    MHD_DIGEST_AUTH_ALGO3_SHA512_256_SESSION,

  /**
   * SHA-256 or SHA-512/256 non-session algorithm, MHD will choose
   * the preferred or the matching one.
   */
  MHD_DIGEST_AUTH_MULT_ALGO3_SHA_ANY_NON_SESSION =
    MHD_DIGEST_AUTH_ALGO3_SHA256 | MHD_DIGEST_AUTH_ALGO3_SHA512_256,

  /**
   * Any non-session algorithm, MHD will choose the preferred or
   * the matching one.
   */
  MHD_DIGEST_AUTH_MULT_ALGO3_ANY_NON_SESSION =
    (0x3F) | MHD_DIGEST_AUTH_ALGO3_NON_SESSION,

  /**
   * The SHA-256 or SHA-512/256 session algorithm.
   * Not supported by MHD.
   * Reserved value.
   */
  MHD_DIGEST_AUTH_MULT_ALGO3_SHA_ANY_SESSION =
    MHD_DIGEST_AUTH_ALGO3_SHA256_SESSION
    | MHD_DIGEST_AUTH_ALGO3_SHA512_256_SESSION,

  /**
   * Any session algorithm.
   * Not supported by MHD.
   * Reserved value.
   */
  MHD_DIGEST_AUTH_MULT_ALGO3_ANY_SESSION =
    (0x3F) | MHD_DIGEST_AUTH_ALGO3_SESSION,

  /**
   * The MD5 algorithm, session or non-session.
   * Currently supported as non-session only.
   */
  MHD_DIGEST_AUTH_MULT_ALGO3_MD5_ANY =
    MHD_DIGEST_AUTH_MULT_ALGO3_MD5 | MHD_DIGEST_AUTH_MULT_ALGO3_MD5_SESSION,

  /**
   * The SHA-256 algorithm, session or non-session.
   * Currently supported as non-session only.
   */
  MHD_DIGEST_AUTH_MULT_ALGO3_SHA256_ANY =
    MHD_DIGEST_AUTH_MULT_ALGO3_SHA256
    | MHD_DIGEST_AUTH_MULT_ALGO3_SHA256_SESSION,

  /**
   * The SHA-512/256 algorithm, session or non-session.
   * Currently supported as non-session only.
   */
  MHD_DIGEST_AUTH_MULT_ALGO3_SHA512_256_ANY =
    MHD_DIGEST_AUTH_MULT_ALGO3_SHA512_256
    | MHD_DIGEST_AUTH_MULT_ALGO3_SHA512_256_SESSION,

  /**
   * The SHA-256 or SHA-512/256 algorithm, session or non-session.
   * Currently supported as non-session only.
   */
  MHD_DIGEST_AUTH_MULT_ALGO3_SHA_ANY_ANY =
    MHD_DIGEST_AUTH_MULT_ALGO3_SHA_ANY_NON_SESSION
    | MHD_DIGEST_AUTH_MULT_ALGO3_SHA_ANY_SESSION,

  /**
   * Any algorithm, MHD will choose the preferred or the matching one.
   */
  MHD_DIGEST_AUTH_MULT_ALGO3_ANY =
    (0x3F) | MHD_DIGEST_AUTH_ALGO3_NON_SESSION | MHD_DIGEST_AUTH_ALGO3_SESSION
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
 * as username in cleartext is required for #MHD_digest_auth_check3() function
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
 * combination as it will cause excessive CPU load; save and re-use the result
 * instead.
 *
 * @param algo3 the algorithm for userhash calculations
 * @param username the username
 * @param realm the realm
 * @param[out] userhash_bin the output buffer for userhash as binary data;
 *                          if this function succeeds, then this buffer has
 *                          #MHD_digest_get_hash_size(algo3) bytes of userhash
 *                          upon return
 * @param bin_buf_size the size of the @a userhash_bin buffer, must be
 *                     at least #MHD_digest_get_hash_size(algo3) bytes long
 * @return MHD_YES on success,
 *         MHD_NO if @a bin_buf_size is too small or if @a algo3 algorithm is
 *         not supported (or external error has occurred,
 *         see #MHD_FEATURE_EXTERN_HASH)
 * @sa #MHD_digest_auth_calc_userhash_hex()
 * @note Available since #MHD_VERSION 0x00097701
 * @ingroup authentication
 */
_MHD_EXTERN enum MHD_Result
MHD_digest_auth_calc_userhash (enum MHD_DigestAuthAlgo3 algo3,
                               const char *username,
                               const char *realm,
                               void *userhash_bin,
                               size_t bin_buf_size);


/**
 * Calculate "userhash", return it as hexadecimal string.
 *
 * The "userhash" is the hash of the string "username:realm".
 *
 * The "userhash" could be used to avoid sending username in cleartext in Digest
 * Authorization client's header.
 *
 * Userhash is not designed to hide the username in local database or files,
 * as username in cleartext is required for #MHD_digest_auth_check3() function
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
 * combination as it will cause excessive CPU load; save and re-use the result
 * instead.
 *
 * @param algo3 the algorithm for userhash calculations
 * @param username the username
 * @param realm the realm
 * @param[out] userhash_hex the output buffer for userhash as hex string;
 *                          if this function succeeds, then this buffer has
 *                          #MHD_digest_get_hash_size(algo3)*2 chars long
 *                          userhash zero-terminated string
 * @param bin_buf_size the size of the @a userhash_bin buffer, must be
 *                     at least #MHD_digest_get_hash_size(algo3)*2+1 chars long
 * @return MHD_YES on success,
 *         MHD_NO if @a bin_buf_size is too small or if @a algo3 algorithm is
 *         not supported (or external error has occurred,
 *         see #MHD_FEATURE_EXTERN_HASH).
 * @sa #MHD_digest_auth_calc_userhash()
 * @note Available since #MHD_VERSION 0x00097701
 * @ingroup authentication
 */
_MHD_EXTERN enum MHD_Result
MHD_digest_auth_calc_userhash_hex (enum MHD_DigestAuthAlgo3 algo3,
                                   const char *username,
                                   const char *realm,
                                   char *userhash_hex,
                                   size_t hex_buf_size);


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
 *
 * @note Available since #MHD_VERSION 0x00097701
 */
enum MHD_DigestAuthUsernameType
{
  /**
   * No username parameter in in Digest Authorization header.
   * This should be treated as an error.
   */
  MHD_DIGEST_AUTH_UNAME_TYPE_MISSING = 0,

  /**
   * The 'username' parameter is used to specify the username.
   */
  MHD_DIGEST_AUTH_UNAME_TYPE_STANDARD = (1 << 2),

  /**
   * The username is specified by 'username*' parameter with
   * the extended notation (see RFC 5987 #section-3.2.1).
   * The only difference between standard and extended types is
   * the way how username value is encoded in the header.
   */
  MHD_DIGEST_AUTH_UNAME_TYPE_EXTENDED = (1 << 3),

  /**
   * The username provided in form of 'userhash' as
   * specified by RFC 7616 #section-3.4.4.
   * @sa #MHD_digest_auth_calc_userhash_hex(), #MHD_digest_auth_calc_userhash()
   */
  MHD_DIGEST_AUTH_UNAME_TYPE_USERHASH = (1 << 1),

  /**
   * The invalid combination of username parameters are used by client.
   * Either:
   * * both 'username' and 'username*' are used
   * * 'username*' is used with 'userhash=true'
   * * 'username*' used with invalid extended notation
   * * 'username' is not hexadecimal string, while 'userhash' set to 'true'
   */
  MHD_DIGEST_AUTH_UNAME_TYPE_INVALID = (1 << 0)
} _MHD_FIXED_ENUM;

/**
 * The QOP ('quality of protection') types.
 * @note Available since #MHD_VERSION 0x00097701
 */
enum MHD_DigestAuthQOP
{
  /**
   * Invalid/unknown QOP.
   * Used in struct MHD_DigestAuthInfo to indicate client value that
   * cannot by identified.
   */
  MHD_DIGEST_AUTH_QOP_INVALID = 0,

  /**
   * No QOP parameter.
   * As described in old RFC 2069 original specification.
   * This mode is not allowed by latest RFCs and should be used only to
   * communicate with clients that do not support more modern modes (with QOP
   * parameter).
   * This mode is less secure than other modes and inefficient.
   */
  MHD_DIGEST_AUTH_QOP_NONE = 1 << 0,

  /**
   * The 'auth' QOP type.
   */
  MHD_DIGEST_AUTH_QOP_AUTH = 1 << 1,

  /**
   * The 'auth-int' QOP type.
   * Not supported by MHD for authentication.
   */
  MHD_DIGEST_AUTH_QOP_AUTH_INT = 1 << 2
} _MHD_FIXED_FLAGS_ENUM;

/**
 * The QOP ('quality of protection') types, multiple selection.
 *
 * #MHD_DigestAuthQOP always can be casted to #MHD_DigestAuthMultiQOP, but
 * not vice versa.
 *
 * @note Available since #MHD_VERSION 0x00097701
 */
enum MHD_DigestAuthMultiQOP
{
  /**
   * Invalid/unknown QOP.
   */
  MHD_DIGEST_AUTH_MULT_QOP_INVALID = MHD_DIGEST_AUTH_QOP_INVALID,

  /**
   * No QOP parameter.
   * As described in old RFC 2069 original specification.
   * This mode is not allowed by latest RFCs and should be used only to
   * communicate with clients that do not support more modern modes (with QOP
   * parameter).
   * This mode is less secure than other modes and inefficient.
   */
  MHD_DIGEST_AUTH_MULT_QOP_NONE = MHD_DIGEST_AUTH_QOP_NONE,

  /**
   * The 'auth' QOP type.
   */
  MHD_DIGEST_AUTH_MULT_QOP_AUTH = MHD_DIGEST_AUTH_QOP_AUTH,

  /**
   * The 'auth-int' QOP type.
   * Not supported by MHD.
   * Reserved value.
   */
  MHD_DIGEST_AUTH_MULT_QOP_AUTH_INT = MHD_DIGEST_AUTH_QOP_AUTH_INT,

  /**
   * The 'auth' QOP type OR the old RFC2069 (no QOP) type.
   * In other words: any types except 'auth-int'.
   * RFC2069-compatible mode is allowed, thus this value should be used only
   * when it is really necessary.
   */
  MHD_DIGEST_AUTH_MULT_QOP_ANY_NON_INT =
    MHD_DIGEST_AUTH_QOP_NONE | MHD_DIGEST_AUTH_QOP_AUTH,

  /**
   * Any 'auth' QOP type ('auth' or 'auth-int').
   * Currently supported as 'auth' QOP type only.
   */
  MHD_DIGEST_AUTH_MULT_QOP_AUTH_ANY =
    MHD_DIGEST_AUTH_QOP_AUTH | MHD_DIGEST_AUTH_QOP_AUTH_INT
} _MHD_FIXED_ENUM;

/**
 * The invalid value of 'nc' parameter in client Digest Authorization header.
 * @note Available since #MHD_VERSION 0x00097701
 */
#define MHD_DIGEST_AUTH_INVALID_NC_VALUE        (0)

/**
 * Information from Digest Authorization client's header.
 *
 * All buffers pointed by any struct members are freed when #MHD_free() is
 * called for pointer to this structure.
 *
 * Application may modify buffers as needed until #MHD_free() is called for
 * pointer to this structure
 * @note Available since #MHD_VERSION 0x00097701
 */
struct MHD_DigestAuthInfo
{
  /**
   * The algorithm as defined by client.
   * Set automatically to MD5 if not specified by client.
   * @warning Do not be confused with #MHD_DigestAuthAlgorithm,
   *          which uses other values!
   */
  enum MHD_DigestAuthAlgo3 algo3;

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
   * When userhash is used by the client, this member is NULL and
   * @a userhash_hex and @a userhash_bin are set.
   * The buffer pointed by the @a username becomes invalid when the pointer
   * to the structure is freed by #MHD_free().
   */
  char *username;

  /**
   * The length of the @a username.
   * When the @a username is NULL, this member is always zero.
   */
  size_t username_len;

  /**
   * The userhash string.
   * Valid only if username type is userhash.
   * This is unqoted string without decoding of the hexadecimal
   * digits (as provided by the client).
   * The buffer pointed by the @a userhash_hex becomes invalid when the pointer
   * to the structure is freed by #MHD_free().
   * @sa #MHD_digest_auth_calc_userhash_hex()
   */
  char *userhash_hex;

  /**
   * The length of the @a userhash_hex in characters.
   * The valid size should be #MHD_digest_get_hash_size(algo3) * 2 characters.
   * When the @a userhash_hex is NULL, this member is always zero.
   */
  size_t userhash_hex_len;

  /**
   * The userhash decoded to binary form.
   * Used only if username type is userhash, always NULL otherwise.
   * When not NULL, this points to binary sequence @a userhash_hex_len /2 bytes
   * long.
   * The valid size should be #MHD_digest_get_hash_size(algo3) bytes.
   * The buffer pointed by the @a userhash_bin becomes invalid when the pointer
   * to the structure is freed by #MHD_free().
   * @warning This is a binary data, no zero termination.
   * @warning To avoid buffer overruns, always check the size of the data before
   *          use, because @a userhash_bin can point even to zero-sized
   *          data.
   * @sa #MHD_digest_auth_calc_userhash()
   */
  uint8_t *userhash_bin;

  /**
   * The 'opaque' parameter value, as specified by client.
   * NULL if not specified by client.
   * The buffer pointed by the @a opaque becomes invalid when the pointer
   * to the structure is freed by #MHD_free().
   */
  char *opaque;

  /**
   * The length of the @a opaque.
   * When the @a opaque is NULL, this member is always zero.
   */
  size_t opaque_len;

  /**
   * The 'realm' parameter value, as specified by client.
   * NULL if not specified by client.
   * The buffer pointed by the @a realm becomes invalid when the pointer
   * to the structure is freed by #MHD_free().
   */
  char *realm;

  /**
   * The length of the @a realm.
   * When the @a realm is NULL, this member is always zero.
   */
  size_t realm_len;

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
  uint32_t nc;
};


/**
 * Get information about Digest Authorization client's header.
 *
 * @param connection The MHD connection structure
 * @return NULL if no valid Digest Authorization header is used in the request;
 *         a pointer to the structure with information if the valid request
 *         header found, free using #MHD_free().
 * @sa #MHD_digest_auth_get_username3()
 * @note Available since #MHD_VERSION 0x00097701
 * @ingroup authentication
 */
_MHD_EXTERN struct MHD_DigestAuthInfo *
MHD_digest_auth_get_request_info3 (struct MHD_Connection *connection);


/**
 * Information from Digest Authorization client's header.
 *
 * All buffers pointed by any struct members are freed when #MHD_free() is
 * called for pointer to this structure.
 *
 * Application may modify buffers as needed until #MHD_free() is called for
 * pointer to this structure
 * @note Available since #MHD_VERSION 0x00097701
 */
struct MHD_DigestAuthUsernameInfo
{
  /**
   * The algorithm as defined by client.
   * Set automatically to MD5 if not specified by client.
   * @warning Do not be confused with #MHD_DigestAuthAlgorithm,
   *          which uses other values!
   */
  enum MHD_DigestAuthAlgo3 algo3;

  /**
   * The type of username used by client.
   * The 'invalid' and 'missing' types are not used in this structure,
   * instead NULL is returned by #MHD_digest_auth_get_username3().
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
   * The buffer pointed by the @a username becomes invalid when the pointer
   * to the structure is freed by #MHD_free().
   */
  char *username;

  /**
   * The length of the @a username.
   * When the @a username is NULL, this member is always zero.
   */
  size_t username_len;

  /**
   * The userhash string.
   * Valid only if username type is userhash.
   * This is unqoted string without decoding of the hexadecimal
   * digits (as provided by the client).
   * The buffer pointed by the @a userhash_hex becomes invalid when the pointer
   * to the structure is freed by #MHD_free().
   * @sa #MHD_digest_auth_calc_userhash_hex()
   */
  char *userhash_hex;

  /**
   * The length of the @a userhash_hex in characters.
   * The valid size should be #MHD_digest_get_hash_size(algo3) * 2 characters.
   * When the @a userhash_hex is NULL, this member is always zero.
   */
  size_t userhash_hex_len;

  /**
   * The userhash decoded to binary form.
   * Used only if username type is userhash, always NULL otherwise.
   * When not NULL, this points to binary sequence @a userhash_hex_len /2 bytes
   * long.
   * The valid size should be #MHD_digest_get_hash_size(algo3) bytes.
   * The buffer pointed by the @a userhash_bin becomes invalid when the pointer
   * to the structure is freed by #MHD_free().
   * @warning This is a binary data, no zero termination.
   * @warning To avoid buffer overruns, always check the size of the data before
   *          use, because @a userhash_bin can point even to zero-sized
   *          data.
   * @sa #MHD_digest_auth_calc_userhash()
   */
  uint8_t *userhash_bin;
};


/**
 * Get the username from Digest Authorization client's header.
 *
 * @param connection The MHD connection structure
 * @return NULL if no valid Digest Authorization header is used in the request,
 *         or no username parameter is present in the header, or username is
 *         provided incorrectly by client (see description for
 *         #MHD_DIGEST_AUTH_UNAME_TYPE_INVALID);
 *         a pointer structure with information if the valid request header
 *         found, free using #MHD_free().
 * @sa #MHD_digest_auth_get_request_info3() provides more complete information
 * @note Available since #MHD_VERSION 0x00097701
 * @ingroup authentication
 */
_MHD_EXTERN struct MHD_DigestAuthUsernameInfo *
MHD_digest_auth_get_username3 (struct MHD_Connection *connection);


/**
 * The result of digest authentication of the client.
 *
 * All error values are zero or negative.
 *
 * @note Available since #MHD_VERSION 0x00097701
 */
enum MHD_DigestAuthResult
{
  /**
   * Authentication OK.
   */
  MHD_DAUTH_OK = 1,

  /**
   * General error, like "out of memory".
   */
  MHD_DAUTH_ERROR = 0,

  /**
   * No "Authorization" header or wrong format of the header.
   * Also may be returned if required parameters in client Authorisation header
   * are missing or broken (in invalid format).
   */
  MHD_DAUTH_WRONG_HEADER = -1,

  /**
   * Wrong 'username'.
   */
  MHD_DAUTH_WRONG_USERNAME = -2,

  /**
   * Wrong 'realm'.
   */
  MHD_DAUTH_WRONG_REALM = -3,

  /**
   * Wrong 'URI' (or URI parameters).
   */
  MHD_DAUTH_WRONG_URI = -4,

  /**
   * Wrong 'qop'.
   */
  MHD_DAUTH_WRONG_QOP = -5,

  /**
   * Wrong 'algorithm'.
   */
  MHD_DAUTH_WRONG_ALGO = -6,

  /**
   * Too large (>64 KiB) Authorization parameter value.
   */
  MHD_DAUTH_TOO_LARGE = -15,

  /* The different form of naming is intentionally used for the results below,
   * as they are more important */

  /**
   * The 'nonce' is too old. Suggest the client to retry with the same
   * username and password to get the fresh 'nonce'.
   * The validity of the 'nonce' may be not checked.
   */
  MHD_DAUTH_NONCE_STALE = -17,

  /**
   * The 'nonce' was generated by MHD for other conditions.
   * This value is only returned if #MHD_OPTION_DIGEST_AUTH_NONCE_BIND_TYPE
   * is set to anything other than #MHD_DAUTH_BIND_NONCE_NONE.
   * The interpretation of this code could be different. For example, if
   * #MHD_DAUTH_BIND_NONCE_URI is set and client just used the same 'nonce' for
   * another URI, the code could be handled as #MHD_DAUTH_NONCE_STALE as
   * RFCs allow nonces re-using for other URIs in the same "protection
   * space". However, if only #MHD_DAUTH_BIND_NONCE_CLIENT_IP bit is set and
   * it is know that clients have fixed IP addresses, this return code could
   * be handled like #MHD_DAUTH_NONCE_WRONG.
   */
  MHD_DAUTH_NONCE_OTHER_COND = -18,

  /**
   * The 'nonce' is wrong. May indicate an attack attempt.
   */
  MHD_DAUTH_NONCE_WRONG = -33,

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
 * @param connection the MHD connection structure
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
 * @param malgo3 digest algorithms allowed to use, fail if algorithm used
 *               by the client is not allowed by this parameter
 * @return #MHD_DAUTH_OK if authenticated,
 *         the error code otherwise
 * @note Available since #MHD_VERSION 0x00097708
 * @ingroup authentication
 */
_MHD_EXTERN enum MHD_DigestAuthResult
MHD_digest_auth_check3 (struct MHD_Connection *connection,
                        const char *realm,
                        const char *username,
                        const char *password,
                        unsigned int nonce_timeout,
                        uint32_t max_nc,
                        enum MHD_DigestAuthMultiQOP mqop,
                        enum MHD_DigestAuthMultiAlgo3 malgo3);


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
 * @param algo3 the digest algorithm
 * @param username the username
 * @param realm the realm
 * @param password the password
 * @param[out] userdigest_bin the output buffer for userdigest;
 *                            if this function succeeds, then this buffer has
 *                            #MHD_digest_get_hash_size(algo3) bytes of
 *                            userdigest upon return
 * @param userdigest_bin the size of the @a userdigest_bin buffer, must be
 *                       at least #MHD_digest_get_hash_size(algo3) bytes long
 * @return MHD_YES on success,
 *         MHD_NO if @a userdigest_bin is too small or if @a algo3 algorithm is
 *         not supported (or external error has occurred,
 *         see #MHD_FEATURE_EXTERN_HASH).
 * @sa #MHD_digest_auth_check_digest3()
 * @note Available since #MHD_VERSION 0x00097701
 * @ingroup authentication
 */
_MHD_EXTERN enum MHD_Result
MHD_digest_auth_calc_userdigest (enum MHD_DigestAuthAlgo3 algo3,
                                 const char *username,
                                 const char *realm,
                                 const char *password,
                                 void *userdigest_bin,
                                 size_t bin_buf_size);


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
 * @param connection the MHD connection structure
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
 * @param malgo3 digest algorithms allowed to use, fail if algorithm used
 *               by the client is not allowed by this parameter;
 *               more than one base algorithms (MD5, SHA-256, SHA-512/256)
 *               cannot be used at the same time for this function
 *               as @a userdigest must match specified algorithm
 * @return #MHD_DAUTH_OK if authenticated,
 *         the error code otherwise
 * @sa #MHD_digest_auth_calc_userdigest()
 * @note Available since #MHD_VERSION 0x00097701
 * @ingroup authentication
 */
_MHD_EXTERN enum MHD_DigestAuthResult
MHD_digest_auth_check_digest3 (struct MHD_Connection *connection,
                               const char *realm,
                               const char *username,
                               const void *userdigest,
                               size_t userdigest_size,
                               unsigned int nonce_timeout,
                               uint32_t max_nc,
                               enum MHD_DigestAuthMultiQOP mqop,
                               enum MHD_DigestAuthMultiAlgo3 malgo3);


/**
 * Queues a response to request authentication from the client
 *
 * This function modifies provided @a response. The @a response must not be
 * reused and should be destroyed (by #MHD_destroy_response()) after call of
 * this function.
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
 * @param connection the MHD connection structure
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
 *                 the NULL is tolerated
 * @param signal_stale if set to #MHD_YES then indication of stale nonce used in
 *                     the client's request is signalled by adding 'stale=true'
 *                     to the authentication header, this instructs the client
 *                     to retry immediately with the new nonce and the same
 *                     credentials, without asking user for the new password
 * @param mqop the QOP to use
 * @param malgo3 digest algorithm to use; if several algorithms are allowed
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
 * @return #MHD_YES on success, #MHD_NO otherwise
 * @note Available since #MHD_VERSION 0x00097701
 * @ingroup authentication
 */
_MHD_EXTERN enum MHD_Result
MHD_queue_auth_required_response3 (struct MHD_Connection *connection,
                                   const char *realm,
                                   const char *opaque,
                                   const char *domain,
                                   struct MHD_Response *response,
                                   int signal_stale,
                                   enum MHD_DigestAuthMultiQOP mqop,
                                   enum MHD_DigestAuthMultiAlgo3 algo,
                                   int userhash_support,
                                   int prefer_utf8);


/**
 * Constant to indicate that the nonce of the provided
 * authentication code was wrong.
 * Used as return code by #MHD_digest_auth_check(), #MHD_digest_auth_check2(),
 * #MHD_digest_auth_check_digest(), #MHD_digest_auth_check_digest2().
 * @ingroup authentication
 */
#define MHD_INVALID_NONCE -1


/**
 * Get the username from the authorization header sent by the client
 *
 * This function supports username in standard and extended notations.
 * "userhash" is not supported by this function.
 *
 * @param connection The MHD connection structure
 * @return NULL if no username could be found, username provided as
 *         "userhash", extended notation broken or memory allocation error
 *         occurs;
 *         a pointer to the username if found, free using #MHD_free().
 * @warning Returned value must be freed by #MHD_free().
 * @sa #MHD_digest_auth_get_username3()
 * @ingroup authentication
 */
_MHD_EXTERN char *
MHD_digest_auth_get_username (struct MHD_Connection *connection);


/**
 * Which digest algorithm should MHD use for HTTP digest authentication?
 * Used as parameter for #MHD_digest_auth_check2(),
 * #MHD_digest_auth_check_digest2(), #MHD_queue_auth_fail_response2().
 */
enum MHD_DigestAuthAlgorithm
{

  /**
   * MHD should pick (currently defaults to MD5).
   */
  MHD_DIGEST_ALG_AUTO = 0,

  /**
   * Force use of MD5.
   */
  MHD_DIGEST_ALG_MD5,

  /**
   * Force use of SHA-256.
   */
  MHD_DIGEST_ALG_SHA256

} _MHD_FIXED_ENUM;


/**
 * Authenticates the authorization header sent by the client.
 *
 * @param connection The MHD connection structure
 * @param realm The realm presented to the client
 * @param username The username needs to be authenticated
 * @param password The password used in the authentication
 * @param nonce_timeout The amount of time for a nonce to be
 *      invalid in seconds
 * @param algo digest algorithms allowed for verification
 * @return #MHD_YES if authenticated, #MHD_NO if not,
 *         #MHD_INVALID_NONCE if nonce is invalid or stale
 * @note Available since #MHD_VERSION 0x00096200
 * @deprecated use MHD_digest_auth_check3()
 * @ingroup authentication
 */
_MHD_EXTERN int
MHD_digest_auth_check2 (struct MHD_Connection *connection,
                        const char *realm,
                        const char *username,
                        const char *password,
                        unsigned int nonce_timeout,
                        enum MHD_DigestAuthAlgorithm algo);


/**
 * Authenticates the authorization header sent by the client.
 * Uses #MHD_DIGEST_ALG_MD5 (for now, for backwards-compatibility).
 * Note that this MAY change to #MHD_DIGEST_ALG_AUTO in the future.
 * If you want to be sure you get MD5, use #MHD_digest_auth_check2()
 * and specify MD5 explicitly.
 *
 * @param connection The MHD connection structure
 * @param realm The realm presented to the client
 * @param username The username needs to be authenticated
 * @param password The password used in the authentication
 * @param nonce_timeout The amount of time for a nonce to be
 *      invalid in seconds
 * @return #MHD_YES if authenticated, #MHD_NO if not,
 *         #MHD_INVALID_NONCE if nonce is invalid or stale
 * @deprecated use MHD_digest_auth_check3()
 * @ingroup authentication
 */
_MHD_EXTERN int
MHD_digest_auth_check (struct MHD_Connection *connection,
                       const char *realm,
                       const char *username,
                       const char *password,
                       unsigned int nonce_timeout);


/**
 * Authenticates the authorization header sent by the client.
 *
 * @param connection The MHD connection structure
 * @param realm The realm presented to the client
 * @param username The username needs to be authenticated
 * @param digest An `unsigned char *' pointer to the binary MD5 sum
 *      for the precalculated hash value "username:realm:password"
 *      of @a digest_size bytes
 * @param digest_size number of bytes in @a digest (size must match @a algo!)
 * @param nonce_timeout The amount of time for a nonce to be
 *      invalid in seconds
 * @param algo digest algorithms allowed for verification
 * @return #MHD_YES if authenticated, #MHD_NO if not,
 *         #MHD_INVALID_NONCE if nonce is invalid or stale
 * @note Available since #MHD_VERSION 0x00096200
 * @deprecated use MHD_digest_auth_check_digest3()
 * @ingroup authentication
 */
_MHD_EXTERN int
MHD_digest_auth_check_digest2 (struct MHD_Connection *connection,
                               const char *realm,
                               const char *username,
                               const uint8_t *digest,
                               size_t digest_size,
                               unsigned int nonce_timeout,
                               enum MHD_DigestAuthAlgorithm algo);


/**
 * Authenticates the authorization header sent by the client
 * Uses #MHD_DIGEST_ALG_MD5 (required, as @a digest is of fixed
 * size).
 *
 * @param connection The MHD connection structure
 * @param realm The realm presented to the client
 * @param username The username needs to be authenticated
 * @param digest An `unsigned char *' pointer to the binary hash
 *    for the precalculated hash value "username:realm:password";
 *    length must be #MHD_MD5_DIGEST_SIZE bytes
 * @param nonce_timeout The amount of time for a nonce to be
 *      invalid in seconds
 * @return #MHD_YES if authenticated, #MHD_NO if not,
 *         #MHD_INVALID_NONCE if nonce is invalid or stale
 * @note Available since #MHD_VERSION 0x00096000
 * @deprecated use #MHD_digest_auth_check_digest3()
 * @ingroup authentication
 */
_MHD_EXTERN int
MHD_digest_auth_check_digest (struct MHD_Connection *connection,
                              const char *realm,
                              const char *username,
                              const uint8_t digest[MHD_MD5_DIGEST_SIZE],
                              unsigned int nonce_timeout);


/**
 * Queues a response to request authentication from the client
 *
 * This function modifies provided @a response. The @a response must not be
 * reused and should be destroyed after call of this function.
 *
 * @param connection The MHD connection structure
 * @param realm the realm presented to the client
 * @param opaque string to user for opaque value
 * @param response reply to send; should contain the "access denied"
 *        body; note that this function will set the "WWW Authenticate"
 *        header and that the caller should not do this; the NULL is tolerated
 * @param signal_stale #MHD_YES if the nonce is stale to add
 *        'stale=true' to the authentication header
 * @param algo digest algorithm to use
 * @return #MHD_YES on success, #MHD_NO otherwise
 * @note Available since #MHD_VERSION 0x00096200
 * @deprecated use MHD_queue_auth_required_response3()
 * @ingroup authentication
 */
_MHD_EXTERN enum MHD_Result
MHD_queue_auth_fail_response2 (struct MHD_Connection *connection,
                               const char *realm,
                               const char *opaque,
                               struct MHD_Response *response,
                               int signal_stale,
                               enum MHD_DigestAuthAlgorithm algo);


/**
 * Queues a response to request authentication from the client.
 * For now uses MD5 (for backwards-compatibility). Still, if you
 * need to be sure, use #MHD_queue_auth_fail_response2().
 *
 * This function modifies provided @a response. The @a response must not be
 * reused and should be destroyed after call of this function.
 *
 * @param connection The MHD connection structure
 * @param realm the realm presented to the client
 * @param opaque string to user for opaque value
 * @param response reply to send; should contain the "access denied"
 *        body; note that this function will set the "WWW Authenticate"
 *        header and that the caller should not do this; the NULL is tolerated
 * @param signal_stale #MHD_YES if the nonce is stale to add
 *        'stale=true' to the authentication header
 * @return #MHD_YES on success, #MHD_NO otherwise
 * @deprecated use MHD_queue_auth_required_response3()
 * @ingroup authentication
 */
_MHD_EXTERN enum MHD_Result
MHD_queue_auth_fail_response (struct MHD_Connection *connection,
                              const char *realm,
                              const char *opaque,
                              struct MHD_Response *response,
                              int signal_stale);


/**
 * Information decoded from Basic Authentication client's header.
 *
 * The username and the password are technically allowed to have binary zeros,
 * username_len and password_len could be used to detect such situations.
 *
 * The buffers pointed by username and password members are freed
 * when #MHD_free() is called for pointer to this structure.
 *
 * Application may modify buffers as needed until #MHD_free() is called for
 * pointer to this structure
 */
struct MHD_BasicAuthInfo
{
  /**
   * The username, cannot be NULL.
   * The buffer pointed by the @a username becomes invalid when the pointer
   * to the structure is freed by #MHD_free().
   */
  char *username;

  /**
   * The length of the @a username, not including zero-termination
   */
  size_t username_len;

  /**
   * The password, may be NULL if password is not encoded by the client.
   * The buffer pointed by the @a password becomes invalid when the pointer
   * to the structure is freed by #MHD_free().
   */
  char *password;

  /**
   * The length of the @a password, not including zero-termination;
   * when the @a password is NULL, the length is always zero.
   */
  size_t password_len;
};

/**
 * Get the username and password from the Basic Authorisation header
 * sent by the client
 *
 * @param connection the MHD connection structure
 * @return NULL if no valid Basic Authentication header is present in
 *         current request, or
 *         pointer to structure with username and password, which must be
 *         freed by #MHD_free().
 * @note Available since #MHD_VERSION 0x00097701
 * @ingroup authentication
 */
_MHD_EXTERN struct MHD_BasicAuthInfo *
MHD_basic_auth_get_username_password3 (struct MHD_Connection *connection);

/**
 * Queues a response to request basic authentication from the client.
 *
 * The given response object is expected to include the payload for
 * the response; the "WWW-Authenticate" header will be added and the
 * response queued with the 'UNAUTHORIZED' status code.
 *
 * See RFC 7617#section-2 for details.
 *
 * The @a response is modified by this function. The modified response object
 * can be used to respond subsequent requests by #MHD_queue_response()
 * function with status code #MHD_HTTP_UNAUTHORIZED and must not be used again
 * with MHD_queue_basic_auth_required_response3() function. The response could
 * be destroyed right after call of this function.
 *
 * @param connection the MHD connection structure
 * @param realm the realm presented to the client
 * @param prefer_utf8 if not set to #MHD_NO, parameter'charset="UTF-8"' will
 *                    be added, indicating for client that UTF-8 encoding
 *                    is preferred
 * @param response the response object to modify and queue; the NULL
 *                 is tolerated
 * @return #MHD_YES on success, #MHD_NO otherwise
 * @note Available since #MHD_VERSION 0x00097704
 * @ingroup authentication
 */
_MHD_EXTERN enum MHD_Result
MHD_queue_basic_auth_required_response3 (struct MHD_Connection *connection,
                                         const char *realm,
                                         int prefer_utf8,
                                         struct MHD_Response *response);

/**
 * Get the username and password from the basic authorization header sent by the client
 *
 * @param connection The MHD connection structure
 * @param[out] password a pointer for the password, free using #MHD_free().
 * @return NULL if no username could be found, a pointer
 *      to the username if found, free using #MHD_free().
 * @deprecated use #MHD_basic_auth_get_username_password3()
 * @ingroup authentication
 */
_MHD_EXTERN char *
MHD_basic_auth_get_username_password (struct MHD_Connection *connection,
                                      char **password);


/**
 * Queues a response to request basic authentication from the client
 * The given response object is expected to include the payload for
 * the response; the "WWW-Authenticate" header will be added and the
 * response queued with the 'UNAUTHORIZED' status code.
 *
 * @param connection The MHD connection structure
 * @param realm the realm presented to the client
 * @param response response object to modify and queue; the NULL is tolerated
 * @return #MHD_YES on success, #MHD_NO otherwise
 * @deprecated use MHD_queue_basic_auth_required_response3()
 * @ingroup authentication
 */
_MHD_EXTERN enum MHD_Result
MHD_queue_basic_auth_fail_response (struct MHD_Connection *connection,
                                    const char *realm,
                                    struct MHD_Response *response);


/**
 * Set random values to be used by the Digest Auth module.  Note that
 * the application must ensure that @a buf remains allocated and
 * unmodified while the daemon is running.
 *
 * @param daemon daemon to configure
 * @param buf_size number of bytes in @a buf
 * @param buf entropy buffer
 */
_MHD_EXTERN void
MHD_daemon_digest_auth_random (struct MHD_Daemon *daemon,
                               size_t buf_size,
                               const void *buf)
MHD_FUNC_PARAM_NONNULL_ (1,3);


/**
 * Length of the internal array holding the map of the nonce and
 * the nonce counter.
 *
 * @param daemon daemon to configure
 * @param nc_length desired array length
 */
_MHD_EXTERN enum MHD_StatusCode
MHD_daemon_digest_auth_nc_length (struct MHD_Daemon *daemon,
                                  size_t nc_length)
MHD_FUNC_PARAM_NONNULL_ (1);


/* ********************** (f) Introspection ********************** */


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
   * first accepted.  Note that this is NOT the same as the "req_cls"
   * argument of the #MHD_AccessHandlerCallback.  The "req_cls" is
   * fresh for each HTTP request, while the "socket_context" is fresh
   * for each socket.
   */
  MHD_CONNECTION_INFORMATION_SOCKET_CONTEXT,

  /**
   * Get connection timeout
   * @ingroup request
   */
  MHD_CONNECTION_INFORMATION_CONNECTION_TIMEOUT,

  /**
   * Check whether the connection is suspended.
   * @ingroup request
   */
  MHD_CONNECTION_INFORMATION_CONNECTION_SUSPENDED


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
  const struct sockaddr *client_addr;

  /**
   * Which daemon manages this connection (useful in case there are many
   * daemons running).
   */
  struct MHD_Daemon *daemon;

  /**
   * Pointer to connection-specific client context.  Points to the
   * same address as the "socket_context" of the
   * #MHD_NotifyConnectionCallback.
   */
  void **socket_context;

  /**
   * Is this connection right now suspended?
   */
  enum MHD_Bool suspended;
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
                                   union MHD_ConnectionInformation *return_value
                                   ,
                                   size_t return_value_size)
MHD_FUNC_PARAM_NONNULL_ (1,3);


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
  MHD_connection_get_information_sz ((connection),(info_type),(return_value), \
                                     sizeof(union MHD_ConnectionInformation))


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
   * Pointer to client context.  Will also be given to
   * the application in a #MHD_RequestTerminationCallback.
   */
  void **request_context;

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
   * Returns the client-specific pointer to a `void *` that
   * is specific to this request.
   */
  MHD_REQUEST_INFORMATION_CLIENT_CONTEXT,

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
                                size_t return_value_size)
MHD_FUNC_PARAM_NONNULL_ (1,3);


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
  MHD_request_get_information_sz ((request), (info_type), (return_value), \
                                  sizeof(union MHD_RequestInformation))


/**
 * Values of this enum are used to specify what
 * information about a daemon is desired.
 */
enum MHD_DaemonInformationType
{

  /**
   * Request the file descriptor for the listening socket.
   * No extra arguments should be passed.
   */
  MHD_DAEMON_INFORMATION_LISTEN_SOCKET,

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
   * Socket, returned for #MHD_DAEMON_INFORMATION_LISTEN_SOCKET.
   */
  MHD_socket listen_socket;

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
                               size_t return_value_size)
MHD_FUNC_PARAM_NONNULL_ (1,3);

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
  MHD_daemon_get_information_sz ((daemon), (info_type), (return_value), \
                                 sizeof(union MHD_DaemonInformation));


/**
 * Callback for serious error condition. The default action is to print
 * an error message and `abort()`.
 *
 * @param cls user specified value
 * @param file where the error occurred
 * @param line where the error occurred
 * @param reason error detail, may be NULL
 * @ingroup logging
 */
typedef void
(*MHD_PanicCallback) (void *cls,
                      const char *file,
                      unsigned int line,
                      const char *reason);


/**
 * Sets the global error handler to a different implementation.  @a cb
 * will only be called in the case of typically fatal, serious
 * internal consistency issues.  These issues should only arise in the
 * case of serious memory corruption or similar problems with the
 * architecture.  While @a cb is allowed to return and MHD will then
 * try to continue, this is never safe.
 *
 * The default implementation that is used if no panic function is set
 * simply prints an error message and calls `abort()`.  Alternative
 * implementations might call `exit()` or other similar functions.
 *
 * @param cb new error handler
 * @param cls passed to @a cb
 * @ingroup logging
 */
_MHD_EXTERN void
MHD_set_panic_func (MHD_PanicCallback cb,
                    void *cls);


/**
 * Process escape sequences ('%HH') Updates val in place; the
 * result should be UTF-8 encoded and cannot be larger than the input.
 * The result must also still be 0-terminated.
 *
 * @param val value to unescape (modified in the process)
 * @return length of the resulting val (`strlen(val)` may be
 *  shorter afterwards due to elimination of escape sequences)
 */
_MHD_EXTERN size_t
MHD_http_unescape (char *val)
MHD_FUNC_PARAM_NONNULL_ (1);


/**
 * Types of information about MHD features,
 * used by #MHD_is_feature_supported().
 */
enum MHD_Feature
{
  /**
   * Get whether messages are supported. If supported then in debug
   * mode messages can be printed to stderr or to external logger.
   */
  MHD_FEATURE_MESSAGES = 1,

  /**
   * Get whether HTTPS is supported.  If supported then flag
   * #MHD_USE_TLS and options #MHD_OPTION_HTTPS_MEM_KEY,
   * #MHD_OPTION_HTTPS_MEM_CERT, #MHD_OPTION_HTTPS_MEM_TRUST,
   * #MHD_OPTION_HTTPS_MEM_DHPARAMS, #MHD_OPTION_HTTPS_CRED_TYPE,
   * #MHD_OPTION_HTTPS_PRIORITIES can be used.
   */
  MHD_FEATURE_TLS = 2,

  /**
   * Get whether option #MHD_OPTION_HTTPS_CERT_CALLBACK is
   * supported.
   */
  MHD_FEATURE_HTTPS_CERT_CALLBACK = 3,

  /**
   * Get whether IPv6 is supported. If supported then flag
   * #MHD_USE_IPv6 can be used.
   */
  MHD_FEATURE_IPv6 = 4,

  /**
   * Get whether IPv6 without IPv4 is supported. If not supported
   * then IPv4 is always enabled in IPv6 sockets and
   * flag #MHD_USE_DUAL_STACK if always used when #MHD_USE_IPv6 is
   * specified.
   */
  MHD_FEATURE_IPv6_ONLY = 5,

  /**
   * Get whether `poll()` is supported. If supported then flag
   * #MHD_USE_POLL can be used.
   */
  MHD_FEATURE_POLL = 6,

  /**
   * Get whether `epoll()` is supported. If supported then Flags
   * #MHD_USE_EPOLL and
   * #MHD_USE_EPOLL_INTERNAL_THREAD can be used.
   */
  MHD_FEATURE_EPOLL = 7,

  /**
   * Get whether shutdown on listen socket to signal other
   * threads is supported. If not supported flag
   * #MHD_USE_ITC is automatically forced.
   */
  MHD_FEATURE_SHUTDOWN_LISTEN_SOCKET = 8,

  /**
   * Get whether socketpair is used internally instead of pipe to
   * signal other threads.
   */
  MHD_FEATURE_SOCKETPAIR = 9,

  /**
   * Get whether TCP Fast Open is supported. If supported then
   * flag #MHD_USE_TCP_FASTOPEN and option
   * #MHD_OPTION_TCP_FASTOPEN_QUEUE_SIZE can be used.
   */
  MHD_FEATURE_TCP_FASTOPEN = 10,

  /**
   * Get whether HTTP Basic authorization is supported. If supported
   * then functions #MHD_basic_auth_get_username_password and
   * #MHD_queue_basic_auth_fail_response can be used.
   */
  MHD_FEATURE_BASIC_AUTH = 11,

  /**
   * Get whether HTTP Digest authorization is supported. If
   * supported then options #MHD_OPTION_DIGEST_AUTH_RANDOM,
   * #MHD_OPTION_NONCE_NC_SIZE and
   * #MHD_digest_auth_check() can be used.
   */
  MHD_FEATURE_DIGEST_AUTH = 12,

  /**
   * Get whether postprocessor is supported. If supported then
   * functions #MHD_create_post_processor(), #MHD_post_process() and
   * #MHD_destroy_post_processor() can
   * be used.
   */
  MHD_FEATURE_POSTPROCESSOR = 13,

  /**
  * Get whether password encrypted private key for HTTPS daemon is
  * supported. If supported then option
  * ::MHD_OPTION_HTTPS_KEY_PASSWORD can be used.
  */
  MHD_FEATURE_HTTPS_KEY_PASSWORD = 14,

  /**
   * Get whether reading files beyond 2 GiB boundary is supported.
   * If supported then #MHD_create_response_from_fd(),
   * #MHD_create_response_from_fd64 #MHD_create_response_from_fd_at_offset()
   * and #MHD_create_response_from_fd_at_offset64() can be used with sizes and
   * offsets larger than 2 GiB. If not supported value of size+offset is
   * limited to 2 GiB.
   */
  MHD_FEATURE_LARGE_FILE = 15,

  /**
   * Get whether MHD set names on generated threads.
   */
  MHD_FEATURE_THREAD_NAMES = 16,

  /**
   * Get whether HTTP "Upgrade" is supported.
   * If supported then #MHD_ALLOW_UPGRADE, #MHD_upgrade_action() and
   * #MHD_create_response_for_upgrade() can be used.
   */
  MHD_FEATURE_UPGRADE = 17,

  /**
   * Get whether it's safe to use same FD for multiple calls of
   * #MHD_create_response_from_fd() and whether it's safe to use single
   * response generated by #MHD_create_response_from_fd() with multiple
   * connections at same time.
   * If #MHD_is_feature_supported() return #MHD_NO for this feature then
   * usage of responses with same file FD in multiple parallel threads may
   * results in incorrect data sent to remote client.
   * It's always safe to use same file FD in multiple responses if MHD
   * is run in any single thread mode.
   */
  MHD_FEATURE_RESPONSES_SHARED_FD = 18,

  /**
   * Get whether MHD support automatic detection of bind port number.
   * @sa #MHD_DAEMON_INFO_BIND_PORT
   */
  MHD_FEATURE_AUTODETECT_BIND_PORT = 19,

  /**
   * Get whether MHD support SIGPIPE suppression.
   * If SIGPIPE suppression is not supported, application must handle
   * SIGPIPE signal by itself.
   */
  MHD_FEATURE_AUTOSUPPRESS_SIGPIPE = 20,

  /**
   * Get whether MHD use system's sendfile() function to send
   * file-FD based responses over non-TLS connections.
   * @note Since v0.9.56
   */
  MHD_FEATURE_SENDFILE = 21
};


/**
 * Get information about supported MHD features.
 * Indicate that MHD was compiled with or without support for
 * particular feature. Some features require additional support
 * by kernel. Kernel support is not checked by this function.
 *
 * @param feature type of requested information
 * @return #MHD_YES if feature is supported by MHD, #MHD_NO if
 * feature is not supported or feature is unknown.
 * @ingroup specialized
 */
_MHD_EXTERN enum MHD_Bool
MHD_is_feature_supported (enum MHD_Feature feature);


/**
 * What is this request waiting for?
 */
enum MHD_RequestEventLoopInfo
{
  /**
   * We are waiting to be able to read.
   */
  MHD_EVENT_LOOP_INFO_READ = 0,

  /**
   * We are waiting to be able to write.
   */
  MHD_EVENT_LOOP_INFO_WRITE = 1,

  /**
   * We are waiting for the application to provide data.
   */
  MHD_EVENT_LOOP_INFO_BLOCK = 2,

  /**
   * We are finished and are awaiting cleanup.
   */
  MHD_EVENT_LOOP_INFO_CLEANUP = 3
};


#endif
