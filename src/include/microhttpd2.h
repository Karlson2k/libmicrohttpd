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
 *   MHD_request_get_info_fixed()
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
 */
#ifndef MICROHTTPD2_H
#define MICROHTTPD2_H

// TODO: finish daemon options with recutils
// TODO: finish response options with recutils


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
// TODO: review the list of includes, reduce it
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
#define MHD_VERSION 0x02000001

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
  MHD_NO = 0
  ,
  /**
   * MHD-internal return code for "YES".  All non-zero values
   * will be interpreted as "YES", but MHD will only ever
   * return #MHD_YES or #MHD_NO.
   */
  MHD_YES = 1
};


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

#ifndef __cplusplus
#  define MHD_STATIC_CAST_(type,value) \
   ((type)(value))
#else
#  define MHD_STATIC_CAST_(type,value) \
   (static_cast<type>(value))
#endif

/**
 * Constant used to indicate unknown size (use when
 * creating a response).
 */
#ifdef UINT64_MAX
#  define MHD_SIZE_UNKNOWN UINT64_MAX
#else
#  define MHD_SIZE_UNKNOWN MHD_STATIC_CAST_(uint_fast64_t,0xffffffffffffffffU)
#endif


/**
 * Constant used to indicate unlimited wait time.
 */
#ifdef UINT64_MAX
#  define MHD_WAIT_INDEFINITELY UINT64_MAX
#else
#  define MHD_WAIT_INDEFINITELY MHD_STATIC_CAST_(uint_fast64_t,0xffffffffffffffffU)
#endif


/**
 * Constant used to indicate that options array is limited by zero-termination
 */
#define MHD_OPTIONS_ARRAY_MAX_SIZE \
  MHD_STATIC_CAST_(size_t,~ MHD_STATIC_CAST_(size_t, 0))


#ifndef MHD_EXTERN_
#  if !defined(_WIN32)
#    define MHD_EXTERN_ extern
#  else /* defined(_WIN32) */
#    if !defined(MHD_W32LIB)
#      define MHD_EXTERN_ extern
#    else /* defined(_WIN32) && efined(MHD_W32LIB) */
  /* Define MHD_W32DLL when using MHD as W32 .DLL to speed up linker a little */
#      define MHD_EXTERN_ extern __declspec(dllimport)
#    endif
#  endif
#endif

#ifndef MHD_SOCKET_DEFINED
/**
 * MHD_socket is type for socket FDs
 */
#  if ! defined(_WIN32) || defined(_SYS_TYPES_FD_SET)
#    define MHD_POSIX_SOCKETS 1
     typedef int MHD_socket;
#    define MHD_INVALID_SOCKET (-1)
#  else /* !defined(_WIN32) || defined(_SYS_TYPES_FD_SET) */
#    define MHD_WINSOCK_SOCKETS 1
#    include <winsock2.h>
     typedef SOCKET MHD_socket;
#    define MHD_INVALID_SOCKET (INVALID_SOCKET)
#  endif /* !defined(_WIN32) || defined(_SYS_TYPES_FD_SET) */
#  define MHD_SOCKET_DEFINED 1
#endif /* MHD_SOCKET_DEFINED */


/* Compiler macros for internal needs */

/* Stringify macro parameter literally */
#define MHD_MACRO_STR__(x) #x
/* Stringify macro parameter after expansion */
#define MHD_MACRO_STR_(x) MHD_MACRO_STR__(x)

/* Concatenate macro parameters literally */
#define MHD_MACRO_CAT__(a,b) a ## b
/* Concatenate macro parameters after expansion */
#define MHD_MACRO_CAT_(a,b) MHD_MACRO_CAT__(a,b)

#ifdef __GNUC__
#  define MHD_GNUC_MINV(major,minor)    \
     ((__GNUC__ > (major)) ||           \
      ((__GNUC__ == (major)) && (__GNUC_MINOR__ >= (minor+0))))
#else  /* ! __GNUC__ */
#  define MHD_GNUC_MINV(major,minor) (0)
#endif /* ! __GNUC__ */

#ifdef __clang__
#  define MHD_CLANG_MINV(major,minor)    \
     ((__clang_major__ > (major)) ||           \
      ((__clang_major__ == (major)) && (__clang_minor__ >= (minor+0))))
#else  /* ! __GNUC__ */
#  define MHD_CLANG_MINV(major,minor) (0)
#endif /* ! __GNUC__ */

#if defined(_MSC_FULL_VER)
#  define MHD_MSC_MINV(version) (_MSC_VER >= (version+0))
#  if defined(_MSC_FULL_VER) \
      && (!defined(__STDC__) || defined(_MSC_EXTENSIONS))
     /* Visual C with extensions */
#    define MHD_HAS_MSC_EXTENSION 1
#  endif
#else  /* ! _MSC_FULL_VER */
#  define MHD_MSC_MINV(version) (0)
#endif /* ! _MSC_FULL_VER */

#if defined(__STDC_VERSION__) && !defined(__cplusplus)
#  define MHD_C_MINV(version)   (__STDC_VERSION__ >= (version))
#else
#  define MHD_C_MINV(version)   (0)
#endif

#define MHD_C_MINV_99     MHD_C_MINV(199901)


#ifndef __cplusplus
#  define MHD_CXX_MINV(version) (0)
#elif !defined(_MSC_FULL_VER) || !defined(_MSVC_LANG)
#  define MHD_CXX_MINV(version) ((__cplusplus+0) >= version)
#else
#  define MHD_CXX_MINV(version) \
  ((__cplusplus+0) >= version) || ((_MSVC_LANG+0) >= version)
#endif

/* Use compound literals? */
#if !defined(MHD_NO_COMPOUND_LITERALS)
#  if !defined(MHD_USE_COMPOUND_LITERALS)
#    if MHD_C_MINV_99
#      define MHD_USE_COMPOUND_LITERALS   1
#    elif MHD_GNUC_MINV(3,0) && !defined(__STRICT_ANSI__)
       /* This may warn in "pedantic" compilation mode */
#      define MHD_USE_COMPOUND_LITERALS   1
       /* Compound literals are an extension */
#      define MHD_USE_COMPOUND_LITERALS_EXT     1
#    elif defined(MHD_HAS_MSC_EXTENSION) && MHD_MSC_MINV(1800) \
          && !defined(__cplusplus)
#      define MHD_USE_COMPOUND_LITERALS   1
      /* Compound literals are an extension */
#      define MHD_USE_COMPOUND_LITERALS_EXT     1
#    else
       /* Compound literals are not supported */
#      define MHD_NO_COMPOUND_LITERALS    1
#    endif
#  endif /* !MHD_USE_COMPOUND_LITERALS */
#elif defined(MHD_USE_COMPOUND_LITERALS)
#error MHD_USE_COMPOUND_LITERALS and MHD_NO_COMPOUND_LITERALS are both defined
#endif /* MHD_NO_COMPOUND_LITERALS */

/* Use compound literals array as function parameter? */
#if defined(MHD_USE_COMPOUND_LITERALS)
#  if !defined(MHD_NO_COMP_LIT_FUNC_PARAMS)
#    if !defined(MHD_USE_COMP_LIT_FUNC_PARAMS)
#      if !defined(__cplusplus)
         /* Compound literals are lvalues and their addresses can be taken */
#        define MHD_USE_COMP_LIT_FUNC_PARAMS    1
#      elif defined(__llvm__)
         /* clang and LLVM-based compilers treat compound literals as lvalue */
#        define MHD_USE_COMP_LIT_FUNC_PARAMS    1
#      else
         /* Compound literals array cannot be used as function parameter */
#        define MHD_NO_COMP_LIT_FUNC_PARAMS     1
#      endif
#    endif
#  elif defined(MHD_USE_COMP_LIT_FUNC_PARAMS)
#error MHD_USE_COMP_LIT_FUNC_PARAMS and MHD_USE_COMP_LIT_FUNC_PARAMS are both \
  defined
#  endif
#else  /* ! MHD_USE_COMPOUND_LITERALS */
#  ifndef MHD_NO_COMP_LIT_FUNC_PARAMS
     /* Compound literals array cannot be used as function parameter */
#    define MHD_NO_COMP_LIT_FUNC_PARAMS 1
#  endif
#  ifdef MHD_USE_COMP_LIT_FUNC_PARAMS
#    undef MHD_USE_COMP_LIT_FUNC_PARAMS
#  endif
#endif /* ! MHD_USE_COMPOUND_LITERALS */

/* Use designated initializers? */
#if !defined(MHD_NO_DESIGNATED_INIT)
#  if !defined(MHD_USE_DESIGNATED_INIT)
#    if MHD_C_MINV_99
#      define MHD_USE_DESIGNATED_INIT   1
#    elif defined(__cplusplus) && defined(__cpp_designated_initializers)
#      define MHD_USE_DESIGNATED_INIT   1
#    elif (MHD_GNUC_MINV(3,0) && !defined(__STRICT_ANSI__) \
           && !defined(__cplusplus)) \
          || (defined(__GNUG__) && MHD_GNUC_MINV(4,7))
       /* This may warn in "pedantic" compilation mode */
#      define MHD_USE_DESIGNATED_INIT   1
       /* Designated initializers are an extension */
#      define MHD_USE_DESIGNATED_INIT_EXT       1
#    elif defined(MHD_HAS_MSC_EXTENSION) && MHD_MSC_MINV(1800)
#      define MHD_USE_DESIGNATED_INIT   1
       /* Designated initializers are an extension */
#      define MHD_USE_DESIGNATED_INIT_EXT       1
#    else
       /* Designated initializers are not supported */
#      define MHD_NO_DESIGNATED_INIT    1
#    endif
#  endif /* !MHD_USE_DESIGNATED_INIT */
#elif defined(MHD_USE_DESIGNATED_INIT)
#error MHD_USE_DESIGNATED_INIT and MHD_NO_DESIGNATED_INIT are both defined
#endif /* MHD_NO_DESIGNATED_INIT */

/* Use nested designated initializers? */
#if defined(MHD_USE_DESIGNATED_INIT) && !defined(__cplusplus)
#  ifdef MHD_NO_DESIG_NEST_INIT
#    undef MHD_NO_DESIG_NEST_INIT
#  endif
#  ifndef MHD_USE_DESIG_NEST_INIT
#    define MHD_USE_DESIG_NEST_INIT     1
#  endif
#else  /* ! MHD_USE_DESIGNATED_INIT || __cplusplus */
#  ifdef MHD_USE_DESIG_NEST_INIT
#    undef MHD_USE_DESIG_NEST_INIT
#  endif
#  ifndef MHD_NO_DESIG_NEST_INIT
     /* Designated nested initializers are not supported */
#    define MHD_NO_DESIG_NEST_INIT      1
#  endif
#endif /* ! MHD_USE_DESIGNATED_INIT || __cplusplus */

/* Use C++ initializer lists? */
#if !defined(MHD_NO_CPP_INIT_LIST)
#  if !defined(MHD_USE_CPP_INIT_LIST)
#    if defined(__cplusplus) && defined(__cpp_initializer_lists)
#      define MHD_USE_CPP_INIT_LIST     1
#    else
#      define MHD_NO_CPP_INIT_LIST      1
#    endif
#  endif
#elif defined(MHD_USE_CPP_INIT_LIST)
#error MHD_USE_CPP_INIT_LIST and MHD_NO_CPP_INIT_LIST are both defined
#endif

/* Use variadic arguments macros? */
#if !defined(MHD_NO_VARARG_MACROS)
#  if !defined(MHD_USE_VARARG_MACROS)
#    if MHD_C_MINV_99
#      define MHD_USE_VARARG_MACROS   1
#    elif MHD_CXX_MINV(201103)
#      define MHD_USE_VARARG_MACROS   1
#    elif MHD_GNUC_MINV(3,0) && !defined(__STRICT_ANSI__)
       /* This may warn in "pedantic" compilation mode */
#      define MHD_USE_VARARG_MACROS   1
       /* Variable arguments macros are an extension */
#      define MHD_USE_VARARG_MACROS_EXT 1
#    elif defined(MHD_HAS_MSC_EXTENSION) && MHD_MSC_MINV(1400)
#      define MHD_USE_VARARG_MACROS   1
       /* Variable arguments macros are an extension */
#      define MHD_USE_VARARG_MACROS_EXT 1
#    else
       /* Variable arguments macros are not supported */
#      define MHD_NO_VARARG_MACROS    1
#    endif
#  endif /* !MHD_USE_VARARG_MACROS */
#elif defined(MHD_USE_VARARG_MACROS)
#error MHD_USE_VARARG_MACROS and MHD_NO_VARARG_MACROS are both defined
#endif /* MHD_NO_VARARG_MACROS */


/* Use variable-length arrays? */
#if !defined(MHD_NO_VLA)
#  if !defined(MHD_USE_VLA)
#    if MHD_C_MINV_99 && (!defined(__STDC_NO_VLA__) || __STDC_NO_VLA__+0 != 0)
#      if defined(__GNUC__) || defined(__clang__)
#        define MHD_USE_VLA     1
#      elif defined(_MSC_VER)
#        define MHD_NO_VLA      1
#      else
         /* Assume 'not supported' */
#        define MHD_NO_VLA      1
#      endif
#    else
#      define MHD_NO_VLA        1
#    endif
#  endif
#elif defined(MHD_USE_VLA)
#error MHD_USE_VLA and MHD_NO_VLA are both defined
#endif /* MHD_NO_VARARG_MACROS */

#if !defined(MHD_INLINE)
#  if defined(inline)
     /* Assume that proper value of 'inline' was already defined */
#    define MHD_INLINE inline
#  elif MHD_C_MINV_99
     /* C99 (and later) supports 'inline' */
#    define MHD_INLINE inline
#  elif defined(__cplusplus)
     /* C++ always supports 'inline' */
#    define MHD_INLINE inline
#  elif MHD_GNUC_MINV(3,0) && !defined(__STRICT_ANSI__)
#    define MHD_INLINE __inline__
#  elif defined(MHD_HAS_MSC_EXTENSION) && MHD_MSC_MINV(1400)
#    define MHD_INLINE __inline
#  else
#    define MHD_INLINE /* empty */
#  endif
#endif /* MHD_INLINE */


#if !defined(MHD_NO__PRAGMA)
#  if MHD_GNUC_MINV(4,6) && !defined(__clang__)
     /* '_Pragma()' support was added in GCC 3.0.0
      * 'pragma push/pop' support was added in GCC 4.6.0 */
#    define MHD_WARN_PUSH_ _Pragma("GCC diagnostic push")
#    define MHD_WARN_POP_  _Pragma("GCC diagnostic pop")
#    define MHD_WARN_INGORE_(warn) \
       _Pragma(MHD_MACRO_STR_(GCC diagnostic ignored MHD_MACRO_STR__(warn)))
#    ifdef MHD_USE_VARARG_MACROS_EXT
#      define MHD_NOWARN_VARIADIC_MACROS_ \
         MHD_WARN_PUSH_ MHD_WARN_INGORE_(-Wvariadic-macros)
#      define MHD_RESTORE_WARN_VARIADIC_MACROS_ MHD_WARN_POP_
#    endif
#    ifdef MHD_USE_COMPOUND_LITERALS_EXT
#      define MHD_NOWARN_COMPOUND_LITERALS_     __extension__
#      define MHD_RESTORE_WARN_COMPOUND_LITERALS_       /* empty */
#    endif
#    define MHD_NOWARN_UNUSED_FUNC_ \
        MHD_WARN_PUSH_  MHD_WARN_INGORE_(-Wunused-function)
#    define MHD_RESTORE_WARN_UNUSED_FUNC_ MHD_WARN_POP_
#  elif MHD_CLANG_MINV(3,1)
#    define MHD_WARN_PUSH_ _Pragma("clang diagnostic push")
#    define MHD_WARN_POP_  _Pragma("clang diagnostic pop")
#    define MHD_WARN_INGORE_(warn) \
       _Pragma(MHD_MACRO_STR_(clang diagnostic ignored MHD_MACRO_STR__(warn)))
#    ifdef MHD_USE_VARARG_MACROS_EXT
#      define MHD_NOWARN_VARIADIC_MACROS_ \
         MHD_WARN_PUSH_ \
         MHD_WARN_INGORE_(-Wvariadic-macros) \
         MHD_WARN_INGORE_(-Wc++98-compat-pedantic)
#      define MHD_RESTORE_WARN_VARIADIC_MACROS_ MHD_WARN_POP_
#    else  /* ! MHD_USE_VARARG_MACROS_EXT */
#      define MHD_NOWARN_VARIADIC_MACROS_ \
         MHD_WARN_PUSH_  MHD_WARN_INGORE_(-Wc++98-compat-pedantic)
#      define MHD_RESTORE_WARN_VARIADIC_MACROS_ MHD_WARN_POP_
#    endif
#    ifdef MHD_USE_CPP_INIT_LIST
#      define MHD_NOWARN_CPP_INIT_LIST_ \
         MHD_WARN_PUSH_  MHD_WARN_INGORE_(-Wc++98-compat)
#      define MHD_RESTORE_WARN_CPP_INIT_LIST_ MHD_WARN_POP_
#    endif
#    ifdef MHD_USE_COMPOUND_LITERALS_EXT
#      define MHD_NOWARN_COMPOUND_LITERALS_ \
         MHD_WARN_PUSH_  MHD_WARN_INGORE_(-Wc99-extensions)
#      define MHD_RESTORE_WARN_COMPOUND_LITERALS_ MHD_WARN_POP_
#    endif
#    define MHD_NOWARN_UNUSED_FUNC_ \
        MHD_WARN_PUSH_  MHD_WARN_INGORE_(-Wunused-function)
#    define MHD_RESTORE_WARN_UNUSED_FUNC_ MHD_WARN_POP_
#  elif MHD_MSC_MINV(1500)
#    define MHD_WARN_PUSH_ __pragma(warning(push))
#    define MHD_WARN_POP_  __pragma(warning(pop))
#    define MHD_WARN_INGORE_(warn)      __pragma(warning(disable:warn))
#    define MHD_NOWARN_UNUSED_FUNC_ \
        MHD_WARN_PUSH_  MHD_WARN_INGORE_(4514)
#    define MHD_RESTORE_WARN_UNUSED_FUNC_ MHD_WARN_POP_
#  endif
#endif /*!  MHD_NO__PRAGMA */

#ifndef MHD_WARN_PUSH_
#  define MHD_WARN_PUSH_        /* empty */
#endif
#ifndef MHD_WARN_POP_
#  define MHD_WARN_POP_         /* empty */
#endif
#ifndef MHD_WARN_INGORE_
#  define MHD_WARN_INGORE_(ignored)     /* empty */
#endif
#ifndef MHD_NOWARN_VARIADIC_MACROS_
#  define MHD_NOWARN_VARIADIC_MACROS_   /* empty */
#endif
#ifndef MHD_RESTORE_WARN_VARIADIC_MACROS_
#  define MHD_RESTORE_WARN_VARIADIC_MACROS_     /* empty */
#endif
#ifndef MHD_NOWARN_CPP_INIT_LIST_
#  define MHD_NOWARN_CPP_INIT_LIST_     /* empty */
#endif
#ifndef MHD_RESTORE_WARN_CPP_INIT_LIST_
#  define MHD_RESTORE_WARN_CPP_INIT_LIST_       /* empty */
#endif
#ifndef MHD_NOWARN_COMPOUND_LITERALS_
#  define MHD_NOWARN_COMPOUND_LITERALS_ /* empty */
#endif
#ifndef MHD_RESTORE_WARN_COMPOUND_LITERALS_
#  define MHD_RESTORE_WARN_COMPOUND_LITERALS_   /* empty */
#endif
#ifndef MHD_NOWARN_UNUSED_FUNC_
#  define MHD_NOWARN_UNUSED_FUNC_       /* empty */
#endif
#ifndef MHD_RESTORE_WARN_UNUSED_FUNC_
#  define MHD_RESTORE_WARN_UNUSED_FUNC_ /* empty */
#endif

/**
 * Define MHD_NO_DEPRECATION before including "microhttpd2.h" to disable deprecation messages
 */
#ifdef MHD_NO_DEPRECATION
#  define MHD_DEPR_MACRO_(msg)
#  define MHD_NO_DEPR_IN_MACRO_ 1
#  define MHD_DEPR_IN_MACRO_(msg)
#  define MHD_NO_DEPR_FUNC_ 1
#  define MHD_DEPR_FUNC_(msg)
#endif /* MHD_NO_DEPRECATION */

#ifndef MHD_DEPR_MACRO_
#  if MHD_GNUC_MINV(4,8) && ! deifned(__clang__) /* GCC >= 4.8 */
/* Print warning when the macro is processed (if not excluded from processing).
 * To be used outside other macros */
#    define MHD_DEPR_MACRO_(msg) _Pragma(MHD_MACRO_STR_(GCC warning msg))
/* Print warning message when another macro which includes this macro is used */
#    define MHD_DEPR_IN_MACRO_(msg) MHD_DEPR_MACRO_(msg)
#  elif (MHD_CLANG_MINV(3,3) && !defined(__apple_build_version__)) \
      || MHD_CLANG_MINV(5,0)
/* clang >= 3.3 (or XCode's clang >= 5.0) */
/* Print warning when the macro is processed (if not excluded from processing).
 * To be used outside other macros */
#    define MHD_DEPR_MACRO_(msg) _Pragma (MHD_MACRO_STR_(clang warning msg))
/* Print warning message when another macro which includes this macro is used */
#    define MHD_DEPR_IN_MACRO_(msg) MHD_DEPR_MACRO_ (msg)
#  elif MHD_MSC_MINV(1500)
/* Print warning when the macro is processed (if not excluded from processing).
 * To be used outside other macros */
#    define MHD_DEPR_MACRO_(msg) \
      __pragma(message (__FILE__ "(" MHD_MACRO_STR_ ( __LINE__) ") : " \
                        "warning MHDWARN01 : " msg))
/* Print warning message when another macro which includes this macro is used */
#    define MHD_DEPR_IN_MACRO_(msg) MHD_DEPR_MACRO_ (msg)
#  elif MHD_GNUC_MINV(3,0) /* 3.0 <= GCC < 4.8 */
/* Print warning when the macro is processed (if not excluded from processing).
 * To be used outside other macros */
#    define MHD_DEPR_MACRO_(msg) _Pragma (MHD_MACRO_STR_(message msg))
#  elif MHD_CLANG_MINV(2,9)
/* Print warning when the macro is processed (if not excluded from processing).
 * To be used outside other macros */
#    define MHD_DEPR_MACRO_(msg) _Pragma (MHD_MACRO_STR_(message msg))
/* Print warning message when another macro which includes this macro is used */
#    define MHD_DEPR_IN_MACRO_(msg) MHD_DEPR_MACRO_ (msg)
/* #  elif defined(SOMEMACRO) */ /* add compiler-specific macros here if required */
#  endif
#endif /* !MHD_DEPR_MACRO_ */

#ifndef MHD_DEPR_FUNC_
#  if MHD_GNUC_MINV(5,0) || MHD_CLANG_MINV(2,9)
  /* GCC >= 5.0 or clang >= 2.9 */
#    define MHD_DEPR_FUNC_(msg) __attribute__((deprecated (msg)))
#  elif  MHD_GNUC_MINV(3,1) || defined(__clang__)
  /* 3.1 <= GCC < 5.0 or clang < 2.9 */
#    define MHD_DEPR_FUNC_(msg) __attribute__((__deprecated__))
#  elif MHD_MSC_MINV(1400)
  /* VS 2005 or later */
#    define MHD_DEPR_FUNC_(msg) __declspec(deprecated (msg))
#  elif MHD_MSC_MINV(1310)
#    define MHD_DEPR_FUNC_(msg) __declspec(deprecated)
/* #  elif defined(SOMEMACRO) */ /* add compiler-specific macros here if required */
#  endif
#endif /* ! MHD_DEPR_FUNC_ */

#ifndef MHD_DEPR_MACRO_
#  define MHD_DEPR_MACRO_(msg)
#endif /* !MHD_DEPR_MACRO_ */

#ifndef MHD_DEPR_IN_MACRO_
#  define MHD_NO_DEPR_IN_MACRO_ 1
#  define MHD_DEPR_IN_MACRO_(msg)
#endif /* !MHD_DEPR_IN_MACRO_ */

#ifndef MHD_DEPR_FUNC_
#  define MHD_NO_DEPR_FUNC_ 1
#  define MHD_DEPR_FUNC_(msg)
#endif /* !MHD_DEPR_FUNC_ */

#ifdef __has_attribute
#  if __has_attribute (enum_extensibility)
     /* Enum will not be extended */
#    define MHD_FIXED_ENUM_ __attribute__((enum_extensibility (closed)))
#  endif /* enum_extensibility */
#  if __has_attribute (flag_enum)
     /* Enum is a bitmap */
#    define MHD_FLAGS_ENUM_ __attribute__((flag_enum))
#  endif /* flag_enum */
#endif /* __has_attribute */

#ifndef MHD_FIXED_ENUM_
#  define MHD_FIXED_ENUM_       /* empty */
#endif /* MHD_FIXED_ENUM_ */
#ifndef MHD_FLAGS_ENUM_
#  define MHD_FLAGS_ENUM_       /* empty */
#endif /* MHD_FLAGS_ENUM_ */

#ifndef MHD_FIXED_FLAGS_ENUM_
#  define MHD_FIXED_FLAGS_ENUM_ MHD_FIXED_ENUM_ MHD_FLAGS_ENUM_
#endif

#ifndef MHD_FIXED_ENUM_APP_SET_
/* The enum is set by an application to the fixed list of values */
#  define MHD_FIXED_ENUM_APP_SET_ MHD_FIXED_ENUM_
#endif

#ifndef MHD_FLAGS_ENUM_APP_SET_
/* The enum is set by an application, it is a bitmap */
#  define MHD_FLAGS_ENUM_APP_SET_ MHD_FLAGS_ENUM_
#endif

#ifndef MHD_FIXED_FLAGS_ENUM_APP_SET_
/* The enum is set by an application to the fixed bitmap values */
#  define MHD_FIXED_FLAGS_ENUM_APP_SET_ MHD_FIXED_FLAGS_ENUM_
#endif

#ifndef MHD_FIXED_ENUM_MHD_SET_
/* The enum is set by MHD to the fixed list of values */
#  define MHD_FIXED_ENUM_MHD_SET_ /* enum can be extended in next MHD versions */
#endif

#ifndef MHD_FLAGS_ENUM_MHD_SET_
/* The enum is set by MHD, it is a bitmap */
#  define MHD_FLAGS_ENUM_MHD_SET_ MHD_FLAGS_ENUM_
#endif

#ifndef MHD_FIXED_FLAGS_ENUM_MHD_SET_
/* The enum is set by MHD to the fixed bitmap values */
#  define MHD_FIXED_FLAGS_ENUM_MHD_SET_ MHD_FLAGS_ENUM_ /* enum can be extended in next MHD versions */
#endif

#ifndef MHD_FIXED_ENUM_MHD_APP_SET_
/* The enum is set by both MHD and app to the fixed list of values */
#  define MHD_FIXED_ENUM_MHD_APP_SET_ /* enum can be extended in next MHD versions */
#endif

#ifndef MHD_FLAGS_ENUM_MHD_APP_SET_
/* The enum is set by both MHD and app, it is a bitmap */
#  define MHD_FLAGS_ENUM_MHD_APP_SET_ MHD_FLAGS_ENUM_
#endif

#ifndef MHD_FIXED_FLAGS_ENUM_MHD_APP_SET_
/* The enum is set by both MHD and app to the fixed bitmap values */
#  define MHD_FIXED_FLAGS_ENUM_MHD_APP_SET_ MHD_FLAGS_ENUM_ /* enum can be extended in next MHD versions */
#endif


/* Define MHD_NO_FUNC_ATTRIBUTES to avoid having function attributes */
#if ! defined(MHD_NO_FUNC_ATTRIBUTES)
#  if defined(__has_attribute)

 /* Override detected value of MHD_FN_PURE_ by defining it before including
  * the header */
#    if __has_attribute (pure) && ! defined(MHD_FN_PURE_)
/**
 * MHD_FN_PURE_ functions always return the same value for this same input
 * if volatile memory content is not changed.
 * In general, such functions must must not access any global variables that
 * can be changed over the time.
 * Typical examples:
 *   size_t strlen(const char *str);
 *   int memcmpconst void *ptr1, const void *ptr2, size_t _Size);
 */
#      define MHD_FN_PURE_ __attribute__ ((pure))
#    endif /* pure && !MHD_FN_PURE_ */

/* Override detected value of MHD_FN_CONST_ by defining it before including
 * the header */
 */
#    if ! defined(MHD_FN_CONST_)
#      if __has_attribute (const)
/**
 * MHD_FN_CONST_ functions always return the same value for this same
 * input value, even if any memory pointed by parameter is changed or
 * any global value changed. The functions do not change any global values.
 * In general, such functions must not dereference any pointers provided
 * as a parameter and must not access any global variables that can be
 * changed over the time.
 * Typical examples:
 *   int square(int x);
 *   int sum(int a, int b);
 */
#        define MHD_FN_CONST_ __attribute__ ((const))
#      elif defined(MHD_FN_PURE_) /* && ! __has_attribute (const) */
#        define MHD_FN_CONST_ MHD_FN_PURE_
#      endif
#    endif /* const && !MHD_FN_CONST_ */

 /* Override detected value of MHD_FN_MUST_CHECK_RESULT_ by defining it before
  * including the header */
#    if __has_attribute (warn_unused_result) && \
  ! defined(MHD_FN_MUST_CHECK_RESULT_)
/**
 * MHD_FN_MUST_CHECK_RESULT_ indicates that caller must check the value
 * returned by the function.
 */
#      define MHD_FN_MUST_CHECK_RESULT_ __attribute__ ((warn_unused_result))
#    endif /* warn_unused_result && !MHD_FN_MUST_CHECK_RESULT_ */

 /* Override detected value of MHD_FN_PAR_NONNULL_ by defining it before
  * including the header */
#    if __has_attribute (nonnull) && \
  ! defined(MHD_FN_PAR_NONNULL_)
/**
 * MHD_FN_PAR_NONNULL_ indicates function parameter number @a param_num
 * must never be NULL.
 */
#      define MHD_FN_PAR_NONNULL_(param_num) \
  __attribute__ ((nonnull (param_num)))
#    endif /* nonnull && !MHD_FN_PAR_NONNULL_ */

 /* Override detected value of MHD_FN_PAR_NONNULL_ALL_ by defining it before
  * including the header */
#    if __has_attribute (nonnull) && \
  ! defined(MHD_FN_PAR_NONNULL_ALL_)
/**
 * MHD_FN_PAR_NONNULL_ALL_ indicates all function parameters must
 * never be NULL.
 */
#      define MHD_FN_PAR_NONNULL_ALL_ __attribute__ ((nonnull))
#    endif /* nonnull && !MHD_FN_PAR_NONNULL_ALL_ */

#    if __has_attribute (access)

 /* Override detected value of MHD_FN_PAR_IN_ by defining it before
  * including the header */
#      if ! defined(MHD_FN_PAR_IN_)
/**
 * MHD_FN_PAR_IN_ indicates function parameter points to data
 * that must not be modified by the function
 */
#        define MHD_FN_PAR_IN_(param_num) \
  __attribute__ ((access (read_only,pram_num)))
#      endif /* !MHD_FN_PAR_IN_ */

 /* Override detected value of MHD_FN_PAR_IN_SIZE_ by defining it before
  * including the header */
#      if ! defined(MHD_FN_PAR_IN_SIZE_)
/**
 * MHD_FN_PAR_IN_SIZE_ indicates function parameter points to data
 * which size is specified by @a size_num parameter and that must not be
 * modified by the function
 */
#        define MHD_FN_PAR_IN_SIZE_(param_num,size_num) \
  __attribute__ ((access (read_only,pram_num,size_num)))
#      endif /* !MHD_FN_PAR_IN_SIZE_ */

 /* Override detected value of MHD_FN_PAR_OUT_ by defining it before
  * including the header */
#      if ! defined(MHD_FN_PAR_OUT_)
/**
 * MHD_FN_PAR_OUT_ indicates function parameter points to data
 * that could be written by the function, but not read.
 */
#        define MHD_FN_PAR_OUT_(param_num) \
  __attribute__ ((access (write_only,pram_num)))
#      endif /* !MHD_FN_PAR_OUT_ */

 /* Override detected value of MHD_FN_PAR_OUT_SIZE_ by defining it before
  * including the header */
#      if ! defined(MHD_FN_PAR_OUT_SIZE_)
/**
 * MHD_FN_PAR_OUT_SIZE_ indicates function parameter points to data
 * which size is specified by @a size_num parameter and that could be
 * written by the function, but not read.
 */
#        define MHD_FN_PAR_OUT_SIZE_(param_num,size_num) \
  __attribute__ ((access (write_only,pram_num,size_num)))
#      endif /* !MHD_FN_PAR_OUT_SIZE_ */

 /* Override detected value of MHD_FN_PAR_INOUT_ by defining it before
  * including the header */
#      if ! defined(MHD_FN_PAR_INOUT_)
/**
 * MHD_FN_PAR_INOUT_ indicates function parameter points to data
 * that could be both read and written by the function.
 */
#        define MHD_FN_PAR_INOUT_(param_num) \
  __attribute__ ((access (read_write,pram_num)))
#      endif /* !MHD_FN_PAR_INOUT_ */

 /* Override detected value of MHD_FN_PAR_INOUT_SIZE_ by defining it before
  * including the header */
#      if ! defined(MHD_FN_PAR_INOUT_SIZE_)
/**
 * MHD_FN_PAR_INOUT_SIZE_ indicates function parameter points to data
 * which size is specified by @a size_num parameter and that could be
 * both read and written by the function.
 */
#        define MHD_FN_PAR_INOUT_SIZE_(param_num,size_num) \
  __attribute__ ((access (read_write,pram_num,size_num)))
#      endif /* !MHD_FN_PAR_INOUT_SIZE_ */

#    endif /* access */

 /* Override detected value of MHD_FN_PAR_FD_READ_ by defining it before
  * including the header */
#    if __has_attribute (fd_arg_read) && \
  ! defined(MHD_FN_PAR_FD_READ_)
/**
 * MHD_FN_PAR_IN_ indicates function parameter is file descriptor that
 * must be in open state and available for reading
 */
#      define MHD_FN_PAR_FD_READ_(param_num) \
  __attribute__ ((fd_arg_read (param_num)))
#    endif /* fd_arg_read && !MHD_FN_PAR_FD_READ_ */

 /* Override detected value of MHD_FN_PAR_CSTR_ by defining it before
  * including the header */
#    if __has_attribute (null_terminated_string_arg) && \
  ! defined(MHD_FN_PAR_CSTR_)
/**
 * MHD_FN_PAR_IN_ indicates function parameter is file descriptor that
 * must be in open state and available for reading
 */
#      define MHD_FN_PAR_CSTR_(param_num) \
  __attribute__ ((null_terminated_string_arg (param_num)))
#    endif /* null_terminated_string_arg && !MHD_FN_PAR_CSTR_ */

 /* Override detected value of MHD_FN_RETURNS_NONNULL_ by defining it before
  * including the header */
#    if __has_attribute (returns_nonnull) && \
  ! defined(MHD_FN_RETURNS_NONNULL_)
/**
 * MHD_FN_RETURNS_NONNULL_ indicates that function never returns NULL.
 */
#      define MHD_FN_RETURNS_NONNULL_ __attribute__ ((returns_nonnull))
#    endif /* returns_nonnull && !MHD_FN_RETURNS_NONNULL_ */

 /* Override detected value of MHD_FN_WARN_UNUSED_RESULT_ by defining it before
  * including the header */
#    if __has_attribute (warn_unused_result) && \
  ! defined(MHD_FN_WARN_UNUSED_RESULT_)
/**
 * MHD_FN_WARN_UNUSED_RESULT_ that function return value should not be ignored
 */
#      define MHD_FN_WARN_UNUSED_RESULT_ \
  __attribute__ ((warn_unused_result))
#    endif /* warn_unused_result && !MHD_FN_WARN_UNUSED_RESULT_ */

#  endif /* __has_attribute */
#endif /* ! MHD_NO_FUNC_ATTRIBUTES */

 /* Override detected value of MHD_FN_PAR_DYN_ARR_SIZE_() by defining it
  * before including the header */
#ifndef MHD_FN_PAR_DYN_ARR_SIZE_
#  if MHD_C_MINV_99
#    if MHD_USE_VLA
#      define MHD_FN_PAR_DYN_ARR_SIZE_(size)  static size
#    else
#      define MHD_FN_PAR_DYN_ARR_SIZE_(size)  1
#    endif
#  else  /* ! MHD_C_MINV_99 */
#    define MHD_FN_PAR_DYN_ARR_SIZE_(size)    1
#  endif /* ! MHD_C_MINV_99 */
#endif /* MHD_FN_PAR_DYN_ARR_SIZE_ */

 /* Override detected value of MHD_FN_PAR_FIX_ARR_SIZE_() by defining it
  * before including the header */
#ifndef MHD_FN_PAR_FIX_ARR_SIZE_
#  if MHD_C_MINV_99
     /* The size must be constant expression */
#    define MHD_FN_PAR_FIX_ARR_SIZE_(size)    static size
#  else
     /* The size must be constant expression */
#    define MHD_FN_PAR_FIX_ARR_SIZE_(size)    size
#  endif /* MHD_C_MINV_99 */
#endif /* MHD_FN_PAR_FIX_ARR_SIZE_ */


#ifndef MHD_FN_CONST_
#  define MHD_FN_CONST_       /* empty */
#endif /* ! MHD_FN_CONST_ */
#ifndef MHD_FN_PURE_
#  define MHD_FN_PURE_        /* empty */
#endif /* ! MHD_FN_PURE_ */
#ifndef MHD_FN_MUST_CHECK_RESULT_
#  define MHD_FN_MUST_CHECK_RESULT_   /* empty */
#endif /* ! MHD_FN_MUST_CHECK_RESULT_ */
#ifndef MHD_FN_PAR_NONNULL_
#  define MHD_FN_PAR_NONNULL_(param_num)    /* empty */
#endif /* ! MHD_FN_PAR_NONNULL_ */
#ifndef MHD_FN_PAR_NONNULL_ALL_
#  define MHD_FN_PAR_NONNULL_ALL_   /* empty */
#endif /* ! MHD_FN_PAR_NONNULL_ALL_ */
#ifndef MHD_FN_PAR_IN_
#  define MHD_FN_PAR_IN_(param_num) /* empty */
#endif /* !MHD_FN_PAR_IN_ */
#ifndef MHD_FN_PAR_IN_SIZE_
#  define MHD_FN_PAR_IN_SIZE_(param_num,size_num)   /* empty */
#endif /* !MHD_FN_PAR_IN_SIZE_ */
#ifndef MHD_FN_PAR_OUT_
#  define MHD_FN_PAR_OUT_(param_num)        /* empty */
#endif /* !MHD_FN_PAR_OUT_ */
#ifndef MHD_FN_PAR_OUT_SIZE_
#  define MHD_FN_PAR_OUT_SIZE_(param_num,size_num)  /* empty */
#endif /* !MHD_FN_PAR_OUT_SIZE_ */
#ifndef MHD_FN_PAR_INOUT_
#  define MHD_FN_PAR_INOUT_(param_num)      /* empty */
#endif /* !MHD_FN_PAR_INOUT_ */
#ifndef MHD_FN_PAR_INOUT_SIZE_
#  define MHD_FN_PAR_INOUT_SIZE_(param_num,size_num)        /* empty */
#endif /* !MHD_FN_PAR_INOUT_SIZE_ */
#ifndef MHD_FN_PAR_FD_READ_
#  define MHD_FN_PAR_FD_READ_(param_num)        /* empty */
#endif /* !MHD_FN_PAR_FD_READ_ */
#ifndef MHD_FN_PAR_CSTR_
#  define MHD_FN_PAR_CSTR_(param_num)   /* empty */
#endif /* ! MHD_FN_PAR_CSTR_ */
#ifndef MHD_FN_RETURNS_NONNULL_
#  define MHD_FN_RETURNS_NONNULL_       /* empty */
#endif /* ! MHD_FN_RETURNS_NONNULL_ */
#ifndef MHD_FN_WARN_UNUSED_RESULT_
#  define MHD_FN_WARN_UNUSED_RESULT_    /* empty */
#endif /* ! MHD_FN_WARN_UNUSED_RESULT_ */

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
 * Replaces `struct MHD_Connection` in the API prior to version 2.0.0,
 * renamed to better reflect what this object truly represents to
 * the application using MHD.
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
  /**
   * We were asked to return a timeout, but, there is no timeout.
   */
  MHD_SC_NO_TIMEOUT = 1
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
   * We failed to allocate memory for poll() syscall.
   * (May be transient.)
   */
  MHD_SC_POLL_MALLOC_FAILURE = 30001
  ,
  /**
   * The operation failed because the respective
   * daemon is already too deep inside of the shutdown
   * activity.
   */
  MHD_SC_DAEMON_ALREADY_SHUTDOWN = 30002
  ,
  /**
   * We failed to start a thread.
   */
  MHD_SC_THREAD_LAUNCH_FAILURE = 30003
  ,
  /**
   * The operation failed because we either have no
   * listen socket or were already quiesced.
   */
  MHD_SC_DAEMON_ALREADY_QUIESCED = 30004
  ,
  /**
   * The operation failed because client disconnected
   * faster than we could accept().
   */
  MHD_SC_ACCEPT_FAST_DISCONNECT = 30005
  ,
  /**
   * Operating resource limits hit on accept().
   */
  MHD_SC_ACCEPT_SYSTEM_LIMIT_REACHED = 30006
  ,
  /**
   * Connection was refused by accept policy callback.
   */
  MHD_SC_ACCEPT_POLICY_REJECTED = 30007
  ,
  /**
   * We failed to allocate memory for the connection.
   * (May be transient.)
   */
  MHD_SC_CONNECTION_MALLOC_FAILURE = 30008
  ,
  /**
   * We failed to allocate memory for the connection's memory pool.
   * (May be transient.)
   */
  MHD_SC_POOL_MALLOC_FAILURE = 30009
  ,
  /**
   * We failed to forward data from a Web socket to the
   * application to the remote side due to the socket
   * being closed prematurely. (May be transient.)
   */
  MHD_SC_UPGRADE_FORWARD_INCOMPLETE = 30010
  ,
  /**
   * We failed to allocate memory for generating the response from our
   * memory pool.  Likely the request header was too large to leave
   * enough room.
   */
  MHD_SC_CONNECTION_POOL_MALLOC_FAILURE = 30011
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
   * MHD is closing a connection because reading the
   * request failed.
   */
  MHD_SC_CONNECTION_READ_FAIL_CLOSED = 40002
  ,
  /**
   * MHD is closing a connection because writing the response failed.
   */
  MHD_SC_CONNECTION_WRITE_FAIL_CLOSED = 40003
  ,
  /**
   * MHD is returning an error because the header provided
   * by the client is too big.
   */
  MHD_SC_CLIENT_HEADER_TOO_BIG = 40004
  ,
  /**
   * An HTTP/1.1 request was sent without the "Host:" header.
   */
  MHD_SC_HOST_HEADER_MISSING = 40005
  ,
  /**
   * The given content length was not a number.
   */
  MHD_SC_CONTENT_LENGTH_MALFORMED = 40006
  ,
  /**
   * The given uploaded, chunked-encoded body was malformed.
   */
  MHD_SC_CHUNKED_ENCODING_MALFORMED = 40007
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
   * File descriptor for ITC channel too large.
   */
  MHD_SC_ITC_DESCRIPTOR_TOO_LARGE = 50006
  ,
  /**
   * The specified value for the NC length is way too large
   * for this platform (integer overflow on `size_t`).
   */
  MHD_SC_DIGEST_AUTH_NC_LENGTH_TOO_BIG = 50007
  ,
  /**
   * We failed to allocate memory for the specified nonce
   * counter array.  The option was not set.
   */
  MHD_SC_DIGEST_AUTH_NC_ALLOCATION_FAILURE = 50008
  ,
  /**
   * This build of the library does not support
   * digest authentication.
   */
  MHD_SC_DIGEST_AUTH_NOT_SUPPORTED_BY_BUILD = 50009
  ,
  /**
   * IPv6 requested but not supported by this build.
   */
  MHD_SC_IPV6_NOT_SUPPORTED_BY_BUILD = 50010
  ,
  /**
   * We failed to open the listen socket. Maybe the build
   * supports IPv6, but your kernel does not?
   */
  MHD_SC_FAILED_TO_OPEN_LISTEN_SOCKET = 50011
  ,
  /**
   * Specified address family is not supported by this build.
   */
  MHD_SC_AF_NOT_SUPPORTED_BY_BUILD = 50012
  ,
  /**
   * Failed to enable listen address reuse.
   */
  MHD_SC_LISTEN_ADDRESS_REUSE_ENABLE_FAILED = 50013
  ,
  /**
   * Enabling listen address reuse is not supported by this platform.
   */
  MHD_SC_LISTEN_ADDRESS_REUSE_ENABLE_NOT_SUPPORTED = 50014
  ,
  /**
   * Failed to disable listen address reuse.
   */
  MHD_SC_LISTEN_ADDRESS_REUSE_DISABLE_FAILED = 50015
  ,
  /**
   * Disabling listen address reuse is not supported by this platform.
   */
  MHD_SC_LISTEN_ADDRESS_REUSE_DISABLE_NOT_SUPPORTED = 50016
  ,
  /**
   * We failed to explicitly enable or disable dual stack for
   * the IPv6 listen socket.  The socket will be used in whatever
   * the default is the OS gives us.
   */
  MHD_SC_LISTEN_DUAL_STACK_CONFIGURATION_FAILED = 50017
  ,
  /**
   * On this platform, MHD does not support explicitly configuring
   * dual stack behavior.
   */
  MHD_SC_LISTEN_DUAL_STACK_CONFIGURATION_NOT_SUPPORTED = 50018
  ,
  /**
   * Failed to enable TCP FAST OPEN option.
   */
  MHD_SC_FAST_OPEN_FAILURE = 50020
  ,
  /**
   * Failed to start listening on listen socket.
   */
  MHD_SC_LISTEN_FAILURE = 50021
  ,
  /**
   * Failed to obtain our listen port via introspection.
   */
  MHD_SC_LISTEN_PORT_INTROSPECTION_FAILURE = 50022
  ,
  /**
   * Failed to obtain our listen port via introspection
   * due to unsupported address family being used.
   */
  MHD_SC_LISTEN_PORT_INTROSPECTION_UNKNOWN_AF = 50023
  ,
  /**
   * We failed to set the listen socket to non-blocking.
   */
  MHD_SC_LISTEN_SOCKET_NONBLOCKING_FAILURE = 50024
  ,
  /**
   * Listen socket value is too large (for use with select()).
   */
  MHD_SC_LISTEN_SOCKET_TOO_LARGE = 50025
  ,
  /**
   * We failed to allocate memory for the thread pool.
   */
  MHD_SC_THREAD_POOL_MALLOC_FAILURE = 50026
  ,
  /**
   * We failed to allocate mutex for thread pool worker.
   */
  MHD_SC_THREAD_POOL_CREATE_MUTEX_FAILURE = 50027
  ,
  /**
   * There was an attempt to upgrade a connection on
   * a daemon where upgrades are disallowed.
   */
  MHD_SC_UPGRADE_ON_DAEMON_WITH_UPGRADE_DISALLOWED = 50028
  ,
  /**
   * Failed to signal via ITC channel.
   */
  MHD_SC_ITC_USE_FAILED = 50029
  ,
  /**
   * We failed to initialize the main thread for listening.
   */
  MHD_SC_THREAD_MAIN_LAUNCH_FAILURE = 50030
  ,
  /**
   * We failed to initialize the threads for the worker pool.
   */
  MHD_SC_THREAD_POOL_LAUNCH_FAILURE = 50031
  ,
  /**
   * We failed to add a socket to the epoll() set.
   */
  MHD_SC_EPOLL_CTL_ADD_FAILED = 50032
  ,
  /**
   * We failed to create control socket for the epoll().
   */
  MHD_SC_EPOLL_CTL_CREATE_FAILED = 50034
  ,
  /**
   * We failed to configure control socket for the epoll()
   * to be non-inheritable.
   */
  MHD_SC_EPOLL_CTL_CONFIGURE_NOINHERIT_FAILED = 50035
  ,
  /**
   * We failed to build the FD set because a socket was
   * outside of the permitted range.
   */
  MHD_SC_SOCKET_OUTSIDE_OF_FDSET_RANGE = 50036
  ,
  /**
   * This daemon was not configured with options that
   * would allow us to build an FD set for select().
   */
  MHD_SC_CONFIGURATION_MISMATCH_FOR_GET_FDSET = 50037
  ,
  /**
   * This daemon was not configured with options that
   * would allow us to obtain a meaningful timeout.
   */
  MHD_SC_CONFIGURATION_MISMATCH_FOR_GET_TIMEOUT = 50038
  ,
  /**
   * This daemon was not configured with options that
   * would allow us to run with select() data.
   */
  MHD_SC_CONFIGURATION_MISMATCH_FOR_RUN_SELECT = 50039
  ,
  /**
   * This daemon was not configured to run with an
   * external event loop.
   */
  MHD_SC_CONFIGURATION_MISMATCH_FOR_RUN_EXTERNAL = 50040
  ,
  /**
   * Encountered an unexpected event loop style
   * (should never happen).
   */
  MHD_SC_CONFIGURATION_UNEXPECTED_ELS = 50041
  ,
  /**
   * Encountered an unexpected error from select()
   * (should never happen).
   */
  MHD_SC_UNEXPECTED_SELECT_ERROR = 50042
  ,
  /**
   * poll() is not supported.
   */
  MHD_SC_POLL_NOT_SUPPORTED = 50043
  ,
  /**
   * Encountered an unexpected error from poll()
   * (should never happen).
   */
  MHD_SC_UNEXPECTED_POLL_ERROR = 50044
  ,
  /**
   * We failed to configure accepted socket
   * to not use a signal pipe.
   */
  MHD_SC_ACCEPT_CONFIGURE_NOSIGPIPE_FAILED = 50045
  ,
  /**
   * Encountered an unexpected error from epoll_wait()
   * (should never happen).
   */
  MHD_SC_UNEXPECTED_EPOLL_WAIT_ERROR = 50046
  ,
  /**
   * epoll file descriptor is invalid (strange)
   */
  MHD_SC_EPOLL_FD_INVALID = 50047
  ,
  /**
   * We failed to configure accepted socket
   * to be non-inheritable.
   */
  MHD_SC_ACCEPT_CONFIGURE_NOINHERIT_FAILED = 50048
  ,
  /**
   * We failed to configure accepted socket
   * to be non-blocking.
   */
  MHD_SC_ACCEPT_CONFIGURE_NONBLOCKING_FAILED = 50049
  ,
  /**
   * accept() returned non-transient error.
   */
  MHD_SC_ACCEPT_FAILED_UNEXPECTEDLY = 50050
  ,
  /**
   * Operating resource limits hit on accept() while
   * zero connections are active. Oopsie.
   */
  MHD_SC_ACCEPT_SYSTEM_LIMIT_REACHED_INSTANTLY = 50051
  ,
  /**
   * Failed to add IP address to per-IP counter for
   * some reason.
   */
  MHD_SC_IP_COUNTER_FAILURE = 50052
  ,
  /**
   * Application violated our API by calling shutdown
   * while having an upgrade connection still open.
   */
  MHD_SC_SHUTDOWN_WITH_OPEN_UPGRADED_CONNECTION = 50053
  ,
  /**
   * Due to an unexpected internal error with the
   * state machine, we closed the connection.
   */
  MHD_SC_STATEMACHINE_FAILURE_CONNECTION_CLOSED = 50054
  ,
  /**
   * Failed to allocate memory in connection's pool
   * to parse the cookie header.
   */
  MHD_SC_COOKIE_POOL_ALLOCATION_FAILURE = 50055
  ,
  /**
   * MHD failed to build the response header.
   */
  MHD_SC_FAILED_RESPONSE_HEADER_GENERATION = 50056
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
  MHD_SC_FEATURE_DISABLED = 500057
  ,
  /**
   * The feature is not supported by this platform, while
   * supported by MHD build.
   * The feature can be enabled by changing the kernel or
   * running on another computer or with other system
   * configuration.
   */
  MHD_SC_FEATURE_NOT_AVAILABLE = 500058
  ,

  /* 60000-level errors are because the application
     logic did something wrong or generated an error. */

  /**
   * MHD does not support the requested combination of
   * EPOLL with thread-per-connection mode.
   */
  MHD_SC_SYSCALL_THREAD_COMBINATION_INVALID = 60000
  ,
  /**
   * MHD does not support quiescing if ITC was disabled
   * and threads are used.
   */
  MHD_SC_SYSCALL_QUIESCE_REQUIRES_ITC = 60001
  ,
  /**
   * We failed to bind the listen socket.
   */
  MHD_SC_LISTEN_SOCKET_BIND_FAILED = 60002
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
  MHD_SC_APPLICATION_CALLBACK_FAILURE_CLOSED = 60006
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


};

/**
 * Get text description for the MHD error code.
 *
 * This function works for @b MHD error codes, not for @b HTTP status codes.
 * @param code the MHD code to get description for
 * @return the pointer to the text description,
 *         NULL if MHD code in not known.
 */
MHD_EXTERN_ const struct MHD_String *
MHD_status_code_to_string (enum MHD_StatusCode code)
MHD_FN_PURE_;

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
enum MHD_FIXED_ENUM_ MHD_HTTP_Method
{

  /**
   * Method did not match any of the methods given below.
   */
  MHD_HTTP_METHOD_OTHER = 0
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

/**
 * Get text version of the method name.
 * @param method the method to get the text version
 * @return the pointer to the text version,
 *         NULL if method is MHD_HTTP_METHOD_OTHER
 *         or not known.
 */
MHD_EXTERN_ const struct MHD_String *
MHD_http_method_to_string (enum MHD_HTTP_Method method)
MHD_FN_PURE_;

/**
 * @defgroup methods HTTP methods
 * HTTP methods (as strings).
 * See: https://www.iana.org/assignments/http-methods/http-methods.xml
 * Registry export date: 2023-10-02
 * @{
 */

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
   * See https://html.spec.whatwg.org/multipage/form-control-infrastructure.html#url-encoded-form-data
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

/**
 * A client has requested the given url using the given method
 * (#MHD_HTTP_METHOD_GET, #MHD_HTTP_METHOD_PUT,
 * #MHD_HTTP_METHOD_DELETE, #MHD_HTTP_METHOD_POST, etc).
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
 *         if the request must be closed due to a serious
 *         error while handling the request (implies closure
 *         of underling data stream, for HTTP/1.1 it means
 *         socket closure).
 */
typedef const struct MHD_Action *
(MHD_FN_PAR_NONNULL_ (2) MHD_FN_PAR_NONNULL_ (3)
 *MHD_RequestCallback)(void *cls,
                       struct MHD_Request *request,
                       const struct MHD_String *path,
                       enum MHD_Method method,
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
MHD_FN_PAR_NONNULL_ (1) MHD_FN_PAR_IN_(1);


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
 * @ingroup event
 */
MHD_EXTERN_ enum MHD_StatusCode
MHD_daemon_start (struct MHD_Daemon *daemon)
MHD_FN_PAR_NONNULL_ (1);


/**
 * Stop accepting connections from the listening socket.  Allows
 * clients to continue processing, but stops accepting new
 * connections.  Note that the caller is responsible for closing the
 * returned socket; however, if MHD is run using threads (anything but
 * external select mode), it must not be closed until AFTER
 * #MHD_stop_daemon has been called (as it is theoretically possible
 * that an existing thread is still using it).
 *
 * @param[in,out] daemon the daemon to stop accepting new connections for
 * @return the old listen socket on success, #MHD_INVALID_SOCKET if
 *         the daemon was already not listening anymore, or
 *         was never started, or has no listen socket.
 * @ingroup specialized
 */
MHD_EXTERN_ MHD_socket
MHD_daemon_quiesce (struct MHD_Daemon *daemon)
MHD_FN_PAR_NONNULL_ALL_ MHD_FN_PAR_INOUT_(1);


/**
 * Shutdown and destroy an HTTP daemon.
 *
 * @param[in] daemon daemon to stop
 * @ingroup event
 */
MHD_EXTERN_ void
MHD_daemon_destroy (struct MHD_Daemon *daemon)
MHD_FN_PAR_NONNULL_ALL_;

/* ******************* External event loop ************************ */

/**
 * The network status of the socket.
 * When set by MHD (by #MHD_get_watched_fds(), #MHD_get_watched_fds_update() and
 * similar) it indicates a request to watch for specific socket state:
 * readiness for receiving the data, readiness for sending the data and/or
 * exception state of the socket.
 * When set by application (and provided for #MHD_process_watched_fds() and
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
   * for #MHD_SocketRegistrationUpdateCallback().
   */
  MHD_FD_STATE_NONE = 0
  ,
  /* ** Three bit-flags ** */

  /**
   * Indicates that socket should be watched for incoming data
   * (when set by #MHD_get_watched_fds())
   * / socket has incoming data ready to read (when used for
   * #MHD_process_watched_fds())
   */
  MHD_FD_STATE_RECV = 1 << 0,
  /**
   * Indicates that socket should be watched for availability for sending
   * (when set by #MHD_get_watched_fds())
   * / socket has ability to send data (when used for
   * #MHD_process_watched_fds())
   */
  MHD_FD_STATE_SEND = 1 << 1,
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
  MHD_FD_STATE_EXCEPT = 1 << 2,

  /* The rest of the list is a bit-wise combination of three main
   * states. Application may use three main states directly as
   * a bit-mask instead of using of following values
   */

  /**
   * Combination of #MHD_FD_STATE_RECV and #MHD_FD_STATE_SEND states.
   */
  MHD_FD_STATE_RECV_SEND = MHD_FD_STATE_RECV | MHD_FD_STATE_SEND,
  /**
   * Combination of #MHD_FD_STATE_RECV and #MHD_FD_STATE_EXCEPT states.
   */
  MHD_FD_STATE_RECV_EXCEPT = MHD_FD_STATE_RECV | MHD_FD_STATE_EXCEPT,
  /**
   * Combination of #MHD_FD_STATE_RECV and #MHD_FD_STATE_EXCEPT states.
   */
  MHD_FD_STATE_SEND_EXCEPT = MHD_FD_STATE_RECV | MHD_FD_STATE_EXCEPT,
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


/* Changes:
 * + status update callback replaced with function
 * + status update accepts array of updates
 */

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
 * @return NULL if error (to connection will be closed),
 *         or the new socket context
 * @ingroup event
 */
typedef MHD_APP_SOCKET_CNTX_TYPE *
(MHD_FN_PAR_NONNULL_(5)
 *MHD_SocketRegistrationUpdateCallback)(
  void *cls,
  MHD_socket fd,
  enum MHD_FdState watch_for,
  MHD_APP_SOCKET_CNTX_TYPE *app_cntx_old,
  struct MHD_EventUpdateContext *ecb_cntx);


/**
 * Update the sockets state.
 * Must be called for every socket that got state updated.
 * For #MHD_TM_EXTERNAL_EVENT_LOOP_CB_LEVEL mode should be called for each
 * socket.
 * Available only for daemons stated in #MHD_TM_EXTERNAL_EVENT_LOOP_CB_LEVEL or
 * #MHD_TM_EXTERNAL_EVENT_LOOP_CB_EDGE modes.
 * @param daemon the daemon handle
 * @param ecb_cntx the context handle provided
 *                 for #MHD_SocketRegistrationUpdateCallback
 * @param fd_current_state the current state of the socket
 */
MHD_EXTERN_ void
MHD_daemon_event_update (
  struct MHD_Daemon *daemon,
  struct MHD_EventUpdateContext *ecb_cntx,
  enum MHD_FdState fd_current_state)
MHD_FN_PAR_NONNULL_(1) MHD_FN_PAR_NONNULL_(2);


/**
 * Perform sockets registration, process registered network events.
 *
 * This function first processes all registered (by MHD_daemon_event_update())
 * network events (if any) and then calls #MHD_SocketRegistrationUpdateCallback
 * callback for every socket that needs to be added/updated/removed.
 *
 * Available only for daemons stated in #MHD_TM_EXTERNAL_EVENT_LOOP_CB_LEVEL or
 * #MHD_TM_EXTERNAL_EVENT_LOOP_CB_EDGE modes.
 *
 * @param daemon the daemon handle
 * @param[out] next_max_wait the optional pointer to receive the next maximum
 *                           wait time in microseconds to be used for sockets
 *                           polling function, can be NULL
 * @return MHD_SC_OK on success,
 *         error code otherwise
 */
MHD_EXTERN_ enum MHD_StatusCode
MHD_deamon_process_reg_events(struct MHD_Daemon *daemon,
                              uint_fast64_t *next_max_wait)
MHD_FN_PAR_NONNULL_(1);

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
   */
  MHD_WM_EXTERNAL_PERIODIC = 0
  ,
  /**
   * Work mode with an external event loop with level triggers.
   * Application uses #MHD_SocketRegistrationUpdateCallback, level triggered
   * sockets polling (like select() or poll()) and #MHD_daemon_event_update().
   */
  MHD_WM_EXTERNAL_EVENT_LOOP_CB_LEVEL = 8
  ,
  /**
   * Work mode with an external event loop with edge triggers.
   * Application uses #MHD_SocketRegistrationUpdateCallback, edge triggered
   * sockets polling (like epoll with EPOLLET) and #MHD_daemon_event_update().
   */
  MHD_WM_EXTERNAL_EVENT_LOOP_CB_EDGE = 9
  ,
  /**
   * Work mode with no internal threads and aggregate watch FD.
   * Application uses #MHD_DAEMON_INFO_FIXED_AGGREAGATE_FD to get single FD
   * that gets triggered by any MHD event.
   * This FD can be watched as an aggregate indicator for all MHD events.
   * This mode is available only on selected platforms (currently
   * GNU/Linux only), see #MHD_LIB_INFO_FIXED_HAS_AGGREGATE_FD.
   * When the FD is triggered, #MHD_daemon_process_nonblocking() should
   * be called.
   */
  MHD_WM_EXTERNAL_SINGLE_FD_WATCH = 16
  ,
  /**
   * Work mode with one or more worker threads.
   * If #MHD_DAEMON_OPTION_UINT_NUM_WORKERS is not specified
   * then daemon starts with single worker thread that process
   * all connections.
   * If #MHD_DAEMON_OPTION_UINT_NUM_WORKERS used with value more
   * than one, then that number of worker threads and distributed
   * processing of requests among the workers.
   */
  MHD_WM_WORKER_THREADS = 24
  ,
  /**
   * Work mode with one internal thread for listening and additional threads
   * per every connection.  Use this if handling requests is CPU-intensive or
   * blocking, your application is thread-safe and you have plenty of
   * memory (per connection).
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
}

/**
 * MHD work mode parameters
 */
union MHD_WorkModeParam
{
  /**
   * Work mode parameters for #MHD_WM_EXTERNAL_EVENT_LOOP_CB_LEVEL and
   * #MHD_WM_EXTERNAL_EVENT_LOOP_CB_EDGE modes
   */
  MHD_SocketRegistrationUpdateCallback v_external_event_loop_cb;
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
 * Parameter for #MHD_DAEMON_OPTION_WORK_MODE().
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
 * Create parameter for #MHD_DAEMON_OPTION_WORK_MODE() for work mode with
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
 * Create parameter for #MHD_DAEMON_OPTION_WORK_MODE() for work mode with
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
 * Create parameter for #MHD_DAEMON_OPTION_WORK_MODE() for work mode with
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
 * Create parameter for #MHD_DAEMON_OPTION_WORK_MODE() for work mode with
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
 * Create parameter for #MHD_DAEMON_OPTION_WORK_MODE() for work mode with
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
 * Create parameter for #MHD_DAEMON_OPTION_WORK_MODE() for work mode with
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
 * Create parameter for #MHD_DAEMON_OPTION_WORK_MODE() for work mode with
 * no internal threads.
 * The application periodically calls #MHD_daemon_process_blocking(), where
 * MHD internally checks all sockets automatically.
 * This is the default mode.
 * @return the object of struct MHD_WorkModeWithParam with requested values
 */
static MHD_INLINE struct MHD_WorkModeWithParam
MHD_WM_OPTION_EXTERNAL_PERIODIC(void)
{
  struct MHD_WorkModeWithParam wm_val;

  wm_val.mode = MHD_WM_EXTERNAL_PERIODIC;

  return wm_val;
}

/**
 * Create parameter for #MHD_DAEMON_OPTION_WORK_MODE() for work mode with
 * an external event loop with level triggers.
 * Application uses #MHD_SocketRegistrationUpdateCallback, level triggered
 * sockets polling (like select() or poll()) and #MHD_daemon_event_update().
 * @param cb_val the callback for sockets registration
 * @param cb_cls_val the closure for the @a cv_val callback
 * @return the object of struct MHD_WorkModeWithParam with requested values
 */
static MHD_INLINE struct MHD_WorkModeWithParam
MHD_WM_OPTION_EXTERNAL_EVENT_LOOP_CB_LEVEL(
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
 * Create parameter for #MHD_DAEMON_OPTION_WORK_MODE() for work mode with
 * an external event loop with edge triggers.
 * Application uses #MHD_SocketRegistrationUpdateCallback, edge triggered
 * sockets polling (like epoll with EPOLLET) and #MHD_daemon_event_update().
 * @param cb_val the callback for sockets registration
 * @param cb_cls_val the closure for the @a cv_val callback
 * @return the object of struct MHD_WorkModeWithParam with requested values
 */
static MHD_INLINE struct MHD_WorkModeWithParam
MHD_WM_OPTION_EXTERNAL_EVENT_LOOP_CB_EDGE(
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
 * Create parameter for #MHD_DAEMON_OPTION_WORK_MODE() for work mode with
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
MHD_WM_OPTION_EXTERNAL_SINGLE_FD_WATCH(void)
{
  struct MHD_WorkModeWithParam wm_val;

  wm_val.mode = MHD_WM_EXTERNAL_SINGLE_FD_WATCH;

  return wm_val;
}

/**
 * Create parameter for #MHD_DAEMON_OPTION_WORK_MODE() for work mode with
 * one or more worker threads.
 * If number of threads is one, then daemon starts with single worker thread
 * that handles all connections.
 * If number of threads is larger than one, then that number of worker threads,
 * and handling of connection is distributed among the workers.
 * @param num_workers the number of worker threads, zero is treated as one
 * @return the object of struct MHD_WorkModeWithParam with requested values
 */
static MHD_INLINE struct MHD_WorkModeWithParam
MHD_WM_OPTION_WORKER_THREADS(unsigned int num_workers)
{
  struct MHD_WorkModeWithParam wm_val;

  wm_val.mode = MHD_WM_EXTERNAL_EVENT_LOOP_CB_EDGE;
  wm_val.params.num_worker_threads = num_workers;

  return wm_val;
}

/**
 * Create parameter for #MHD_DAEMON_OPTION_WORK_MODE() for work mode with
 * one internal thread for listening and additional threads per every
 * connection.  Use this if handling requests is CPU-intensive or blocking,
 * your application is thread-safe and you have plenty of memory (per
 * connection).
 * @return the object of struct MHD_WorkModeWithParam with requested values
 */
static MHD_INLINE struct MHD_WorkModeWithParam
MHD_WM_OPTION_THREAD_PER_CONNECTION(void)
{
  struct MHD_WorkModeWithParam wm_val;

  wm_val.mode = MHD_WM_THREAD_PER_CONNECTION;

  return wm_val;
}

MHD_RESTORE_WARN_UNUSED_FUNC_
#endif /* !MHD_USE_COMPOUND_LITERALS || !MHD_USE_DESIG_NEST_INIT */


/**
 * Specify threading mode to use.
 *
 * @param[in,out] daemon daemon to configure
 * @param tm mode to use
 */
MHD_EXTERN_ enum MHD_StatusCode
MHD_daemon_set_threading_mode (struct MHD_Daemon *daemon,
                               enum MHD_ThreadingMode tm)
MHD_FN_PAR_NONNULL_ (1);

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
(MHD_FN_PAR_NONNULL_(3)
 MHD_FN_PAR_CSTR_(3)
 *MHD_LoggingCallback)(void *cls,
                       enum MHD_StatusCode sc,
                       const char *fm,
                       va_list ap);

// FIXME: convert
/**
 * Convenience macro used to disable logging.
 *
 * @param daemon which instance to disable logging for
 */
#define MHD_daemon_disable_logging(daemon) \
  MHD_daemon_set_logger ((daemon), \
                         MHD_STATIC_CAST_(MHD_LoggingCallback,NULL),   \
                         NULL)

/**
 * Parameter for listen socket binding type
 */
enum MHD_FIXED_ENUM_APP_SET_ MHD_DaemonOptionBindType
{
  /**
   * The listen socket bind to the networks address without sharing the address.
   * Default.
   */
  MHD_DAEMON_OPTION_BIND_TYPE_NOT_SHARED = 0
  ,
  /**
   * The listen socket bind to the networks address with sharing the address.
   * Several sockets can bind to the same address.
   */
  MHD_DAEMON_OPTION_BIND_TYPE_SHARED = 1
  ,
  /**
   * The list socket bind to the networks address in explicit exclusive mode.
   * Ignored on platforms without support for the explicit exclusive socket use.
   */
  MHD_DAEMON_OPTION_BIND_TYPE_EXCLUSIVE = 2
};


enum MHD_FIXED_ENUM_APP_SET_ MHD_DaemonOption
{
  /**
   * Not a real option.
   * Should not be used directly.
   * This value indicates the end of the list of the options.
   */
  MHD_D_O_END = 0
  ,
  /**
   * Suppresses use of "Date:" header.
   * According to RFC should be used only if the system has no RTC.
   * The "Date:" is not suppressed (the header is enabled) by default.
   */
  MHD_D_O_BOOL_SUPPRESS_DATE_HEADER = 100
  ,
  /**
   * Enable `turbo`.  Disables certain calls to `shutdown()`,
   * enables aggressive non-blocking optimistic reads and
   * other potentially unsafe optimisations.
   * Most effects only happen with internal threads with epoll.
   * The 'turbo' mode is not enabled (mode is disabled) by default.
   */
  MHD_D_O_BOOL_TURBO = 102
  ,
  /**
   * Disable some internal thread safety.
   * Indicates that MHD daemon will be used by application in single-threaded
   * mode only.  When this flag is set then application must call any MHD
   * function only within a single thread.
   * This flag turns off some internal thread-safety and allows MHD making
   * some of the internal optimisations suitable only for single-threaded
   * environment.
   * Not compatible with any internal threads mode.
   * Thread safety is not disabled (safety is enabled) by default.
   */
  MHD_D_O_DISABLE_THREAD_SAFETY = 103
  ,
  /**
   * You need to set this option if you want to disable use of HTTP "Upgrade".
   * "Upgrade" may require usage of additional internal resources,
   * which we can avoid providing if they will not be used.
   *
   * You should only use this function if you do not use "Upgrade" functionality
   * and need a generally minor boost in performance.
   * The "Upgrade" is not disallowed ("upgrade" is allowed) by default.
   */
  MHD_D_O_BOOL_DISALLOW_UPGRADE = 104
  ,
  /**
   * Disable #MHD_action_suspend() functionality.
   *
   * You should only use this function if you do not use suspend functionality
   * and need a generally minor boost in performance.
   * The suspend is not disallowed (suspend is allowed) by default.
   */
  MHD_D_O_BOOL_DISALLOW_SUSPEND_RESUME
  ,
  /**
   * Use SHOUTcast.  This will cause *all* responses to begin
   * with the SHOUTcast "ICY" line instead of "HTTP".
   */
  MHD_D_O_BOOL_ENABLE_SHOUTCAST
  ,
  /**
   * Disable converting plus ('+') character to space in GET
   * parameters (URI part after '?').
   * TODO: Add explanation, RFCs, HTML
   */
  MHD_D_O_BOOL_DISABLE_GET_PARAM_PLUS_AS_SPACE,

  /**
   * Bind to the given socket address.
   */
  MHD_D_O_SA
  ,
  /**
   * If present true, allow reusing address:port socket (by using
   * SO_REUSEPORT on most platform, or platform-specific ways).  If
   * present and set to false, disallow reusing address:port socket
   * (does nothing on most platform, but uses SO_EXCLUSIVEADDRUSE on
   * Windows).
   * Ineffective in conjunction with #MHD_daemon_listen_socket().
   */
  MHD_D_O_BOOL_LISTEN_ALLOW_ADDRESS_REUSE
};

// FIXME: transform everything to option

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
   * Also causes #MHD_daemon_start() to fail if setting
   * the option fails later.
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
   * Use IPv4.
   */
  MHD_AF_INET4 = 2
  ,
  /**
   * Use IPv6.
   */
  MHD_AF_INET6 = 3
  ,
  /**
   * Use dual stack.
   */
  MHD_AF_DUAL = 4
};


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
MHD_EXTERN_ enum MHD_StatusCode
MHD_daemon_bind_socket_address (struct MHD_Daemon *daemon,
                                const struct sockaddr *sa,
                                size_t sa_len)
MHD_FN_PAR_NONNULL_ALL_ MHD_FN_MUST_CHECK_RESULT_;

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
MHD_EXTERN_ enum MHD_StatusCode
MHD_daemon_set_option_uint (struct MHD_Daemon *daemon,
                            enum MHD_DeamonOptionUInt option,
                            unsigned int value)
MHD_FN_PAR_NONNULL_ (1);

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
  // TODO: union
};

#if 0
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
MHD_EXTERN_ enum MHD_StatusCode // First failed // TODO: Document that rest may be used
MHD_daemon_set_option_uint (
  struct MHD_Daemon *daemon,
  size_t num_entries,
  struct MHD_DaemonOptioniUIntEntry opt_val[MHD_C99_ (static num_entries)])
MHD_FN_PAR_NONNULL_ (1) MHD_FN_PAR_NONNULL_ (3);
#endif
// TODO: combine all types of options into single list with union
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
MHD_EXTERN_ enum MHD_StatusCode
MHD_daemon_listen_socket (struct MHD_Daemon *daemon,
                          MHD_socket listen_socket)
MHD_FN_PAR_NONNULL_ (1);

/**
 * Sockets polling internal syscalls used by MHD.
 */
enum MHD_FIXED_ENUM_APP_SET_ MHD_SockPollSyscall
{
  /**
   * Automatic selection of best-available method. This is also the
   * default.
   */
  MHD_ELS_AUTO = 0
  ,
  /**
   * Use select().
   */
  MHD_ELS_SELECT = 1
  ,
  /**
   * Use poll().
   */
  MHD_ELS_POLL = 2
  ,
  /**
   * Use epoll.
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
MHD_EXTERN_ enum MHD_StatusCode
MHD_daemon_event_loop (struct MHD_Daemon *daemon,
                       enum MHD_EventLoopSyscall els)
MHD_FN_PAR_NONNULL_ (1);


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
  MHD_PSL_VERY_PERMISSIVE = -2,

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
MHD_EXTERN_ enum MHD_StatusCode
MHD_daemon_protocol_strict_level (struct MHD_Daemon *daemon,
                                  enum MHD_ProtocolStrictLevel sl,
                                  enum MHD_UseStictLevel how)
MHD_FN_PAR_NONNULL_ (1);

MHD_EXTERN_ enum MHD_StatusCode
MHD_daemon_set_option_string (struct MHD_Daemon *daemon,
                              enum foo,
                              const char *value)
MHD_FN_PAR_NONNULL_ (1);

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
 * @return #MHD_SC_OK upon success;
 */
MHD_EXTERN_ enum MHD_StatusCode
MHD_daemon_tls_key_and_cert_from_memory (struct MHD_Daemon *daemon,
                                         const char *mem_key,
                                         const char *mem_cert,
                                         const char *pass)
MHD_FN_PAR_NONNULL_ (1) MHD_FN_PAR_NONNULL_ (2)
MHD_FN_PAR_NONNULL_ (3);


/**
 * Configure DH parameters (dh.pem) to use for the TLS key
 * exchange.
 *
 * @param daemon daemon to configure tls for
 * @param dh parameters to use
 * @return #MHD_SC_OK upon success; TODO: define failure modes
 */
MHD_EXTERN_ enum MHD_StatusCode
MHD_daemon_tls_mem_dhparams (struct MHD_Daemon *daemon,
                             const char *dh)
MHD_FN_PAR_NONNULL_ (1);

/**
 * Memory pointer for the certificate (ca.pem) to be used by the
 * HTTPS daemon for client authentication.
 *
 * @param daemon daemon to configure tls for
 * @param mem_trust memory pointer to the certificate
 * @return #MHD_SC_OK upon success; TODO: define failure modes
 */
MHD_EXTERN_ enum MHD_StatusCode
MHD_daemon_tls_mem_trust (struct MHD_Daemon *daemon,
                          const char *mem_trust)
MHD_FN_PAR_NONNULL_ (1);


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
 * Values for #MHD_OPTION_DIGEST_AUTH_NONCE_BIND_TYPE.
 *
 * These values can limit the scope of validity of MHD-generated nonces.
 * Values can be combined with bitwise OR.
 * Any value, except #MHD_DAUTH_BIND_NONCE_NONE, enforce function
 * #MHD_digest_auth_check() (and similar functions) to check nonce by
 * re-generating it again with the same parameters, which is CPU-intensive
 * operation.
 */
enum MHD_FIXED_FLAGS_ENUM_APP_SET_ MHD_DaemonOptionValueDAuthBindNonce
{
  /**
   * Generated nonces are valid for any request from any client until expired.
   * This is default and recommended value.
   * #MHD_digest_auth_check3() (and similar functions) would check only whether
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
  MHD_DAEMON_OPTION_VALUE_DAUTH_BIND_NONCE_NONE = 0,

  /**
   * Generated nonces are valid only for the same realm.
   */
  MHD_DAEMON_OPTION_VALUE_DAUTH_BIND_NONCE_REALM = 1 << 0,

  /**
   * Generated nonces are valid only for the same URI (excluding parameters
   * after '?' in URI) and request method (GET, POST etc).
   * Not recommended unless "protection space" is limited to a single URI as
   * RFC 7616 allows clients to re-use server-generated nonces for any URI
   * in the same "protection space" which by default consists of all server
   * URIs.
   * Before #MHD_VERSION 0x00097701 this was default (and only supported)
   * nonce bind type.
   */
  MHD_DAEMON_OPTION_VALUE_DAUTH_BIND_NONCE_URI = 1 << 1,

  /**
   * Generated nonces are valid only for the same URI including URI parameters
   * and request method (GET, POST etc).
   * This value implies #MHD_DAUTH_BIND_NONCE_URI.
   * Not recommended for that same reasons as #MHD_DAUTH_BIND_NONCE_URI.
   */
  MHD_DAEMON_OPTION_VALUE_DAUTH_BIND_NONCE_URI_PARAMS = 1 << 2,

  /**
   * Generated nonces are valid only for the single client's IP.
   * While it looks like security improvement, in practice the same client may
   * jump from one IP to another (mobile or Wi-Fi handover, DHCP re-assignment,
   * Multi-NAT, different proxy chain and other reasons), while IP address
   * spoofing could be used relatively easily.
   */
  MHD_DAEMON_OPTION_VALUE_DAUTH_BIND_NONCE_CLIENT_IP = 1 << 3
};

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
MHD_EXTERN_ enum MHD_StatusCode
MHD_daemon_set_tls_backend (struct MHD_Daemon *daemon,
                            enum MHD_TlsBackend backend)
MHD_FN_PAR_NONNULL_ (1);


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
MHD_EXTERN_ enum MHD_StatusCode
MHD_daemon_set_tls_psk_callback (struct MHD_Daemon *daemon,
                                 MHD_PskServerCredentialsCallback psk_cb,
                                 void *psk_cb_cls)
MHD_FN_PAR_NONNULL_ (1);



// Callback invoked between full initialization of MHD
// during MHD_daemon_start() and actual event loop
// starting to accept incoming connections. So at this
// point, the listen socket (and if applicable TLS context)
// will be available for introspection.
typedef void
(*MHD_DaemonReadyCallback)(void *cls);


MHD_EXTERN_ enum MHD_StatusCode
MHD_daemon_set_daemon_ready_callback (struct MHD_Daemon *daemon,
                                      MHD_DaemonReadyCallback cb,
                                      void *cb)
MHD_FN_PAR_NONNULL_ (1);


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
MHD_EXTERN_ void
MHD_daemon_accept_policy (struct MHD_Daemon *daemon,
                          MHD_AcceptPolicyCallback apc,
                          void *apc_cls)
MHD_FN_PAR_NONNULL_ (1);


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
(MHD_FN_PAR_NONNULL_ (2) MHD_FN_PAR_NONNULL_ (3)
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
MHD_EXTERN_ enum MHD_StatusCode
MHD_daemon_set_early_uri_logger (struct MHD_Daemon *daemon,
                                 MHD_EarlyUriLogCallback cb,
                                 void *cb_cls)
MHD_FN_PAR_NONNULL_ (1);


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
 * @see #MHD_daemon_set_notify_connection()
 * @ingroup request
 */
typedef void
(MHD_FN_PAR_NONNULL_ (2)
 *MHD_NotifyConnectionCallback)(void *cls,
                                struct MHD_ConnectionNotificationData *data);


/**
 * Register a function that should be called whenever a connection is
 * started or closed.
 *
 * @param daemon daemon to set callback for
 * @param ncc function to call to check the policy
 * @param ncc_cls closure for @a apc
 */
MHD_EXTERN_ enum MHD_StatusCode
MHD_daemon_set_notify_connection (struct MHD_Daemon *daemon,
                                  MHD_NotifyConnectionCallback ncc,
                                  void *ncc_cls)
MHD_FN_PAR_NONNULL_ (1);


/**
 * The type of stream notifications.
 * @ingroup request
 */
enum MHD_FIXED_ENUM_MHD_SET_ MHD_StreamNotificationCode
{
  /**
   * A new connection has been started.
   * @ingroup request
   */
  MHD_STREAM_NOTIFY_STARTED = 0
  ,
  /**
   * A connection is closed.
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
 * @see #MHD_OPTION_NOTIFY_CONNECTION
 * @ingroup request
 */
typedef void
(MHD_FN_PAR_NONNULL_ (2)
 *MHD_NotifyStreamCallback)(
   void *cls,
   const struct MHD_StreamNotificationData *data);


/**
 * Register a function that should be called whenever a stream is
 * started or closed.
 *
 * @param daemon daemon to set callback for
 * @param nsc function to call to check the policy
 * @param nsc_cls closure for @a apc
 */
MHD_EXTERN_ enum MHD_StatusCode
MHD_daemon_set_notify_stream (struct MHD_Daemon *daemon,
                              MHD_NotifyStreamCallback nsc,
                              void *nsc_cls)
MHD_FN_PAR_NONNULL_ (1);

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
  /**
   * Desired size of the stack for threads created by MHD.
   * Use 0 for system default, which is also MHD default.
   * Only useful if the selected threading mode
   * is not #MHD_TM_EXTERNAL_EVENT_LOOP.
   */
  MHD_DAEMON_OPTION_SIZET_STACK_SIZE,

};
MHD_EXTERN_ void
MHD_daemon_option_set_sizet (struct MHD_Daemon *daemon,
                             enum MHD_DaemonOptionSizet option,
                             size_t value)
MHD_FN_PAR_NONNULL_ (1);

/**
 * Set random values to be used by the Digest Auth module.  Note that
 * the application must ensure that @a buf remains allocated and
 * unmodified while the daemon is running.
 *
 * @param daemon daemon to configure
 * @param buf_size number of bytes in @a buf
 * @param buf entropy buffer
 */
MHD_EXTERN_ void
MHD_daemon_digest_auth_random (struct MHD_Daemon *daemon,
                               size_t buf_size,
                               const void *buf)
MHD_FN_PAR_NONNULL_ (1) MHD_FN_PAR_NONNULL_ (3);

/**
 * Length of the internal array holding the map of the nonce and
 * the nonce counter.
 *
 * @param daemon daemon to configure
 * @param nc_length desired array length
 */
MHD_EXTERN_ enum MHD_StatusCode
MHD_daemon_set_digest_auth_nc_length (struct MHD_Daemon *daemon,
                                      size_t nc_length)
MHD_FN_PAR_NONNULL_ (1);

// FIXME: end of transform everything to option

union MHD_DaemonOptionValue
{
  enum MHD_Bool v_bool;
  unsigned int v_uint;
  size_t v_sizet;
  struct MHD_DaemonOptionValueSA v_sa;
  enum MHD_DaemonOptionAddrReuse v_addr_reuse;
};

struct MHD_DaemonOptionAndValue
{
  /**
   * The daemon configuration option
   */
  enum MHD_DaemonOption opt;
  /**
   * The value for the @a opt option
   */
  union MHD_DaemonOptionValue val;
};


#if defined(MHD_USE_COMPOUND_LITERALS) && defined(MHD_USE_DESIG_NEST_INIT)
/*  */ // TODO: no generic form
#  define MHD_D_OPTION_BOOL_SET_(option,bool_val)  \
  MHD_NOWARN_COMPOUND_LITERALS_                  \
  (const struct MHD_DaemonOptionAndValue)        \
  {                                              \
    .opt = (option),                             \
    .val.v_bool = (bool_val)                     \
  }                                              \
  MHD_RESTORE_WARN_COMPOUND_LITERALS_

/**
 * Bind to the given socket address.
 * Ineffective in conjunction with #MHD_daemon_listen_socket().
 *
 * @param sa address to bind to; can be IPv4 (AF_INET), IPv6 (AF_INET6)
 *        or even a UNIX domain socket (AF_UNIX)
 * @param sa_len number of bytes in @a sa
 * @return the object of struct MHD_DaemonOptionAndValue with requested values
 */
#  define MHD_D_OPTION_SOCK_ADDR(sa_len_val,sa_val)       \
  MHD_NOWARN_COMPOUND_LITERALS_                         \
  (const struct MHD_DaemonOptionAndValue)               \
  {                                                     \
    .opt = (MHD_D_O_SA),                                \
    .val.v_sa.sa_len = (sa_len_val),                    \
    .val.v_sa.sa = (sa_val)                             \
  }                                                     \
  MHD_RESTORE_WARN_COMPOUND_LITERALS_

/**
 * Terminate the list of the options
 * @return the terminating object of struct MHD_DaemonOptionAndValue
 */
#  define MHD_D_OPTION_TERMINATE()                 \
  MHD_NOWARN_COMPOUND_LITERALS_                  \
  (const struct MHD_DaemonOptionAndValue)        \
  {                                              \
    .opt = (MHD_D_O_END)                         \
  }                                              \
  MHD_RESTORE_WARN_COMPOUND_LITERALS_

#else  /* !MHD_USE_COMPOUND_LITERALS || !MHD_USE_DESIG_NEST_INIT */
MHD_NOWARN_UNUSED_FUNC_

/* Do not use directly */
static MHD_INLINE struct MHD_DaemonOptionAndValue
MHD_D_OPTION_BOOL_SET_(enum MHD_DaemonOption option,
                  enum MHD_Bool bool_val)
{
  struct MHD_DaemonOptionAndValue opt_val;

  opt_val.opt = option;
  opt_val.val.v_bool = bool_val;

  return opt_val;
}

/**
 * Bind to the given socket address.
 * Ineffective in conjunction with #MHD_daemon_listen_socket().
 *
 * @param sa_len_val the number of bytes in @a sa
 * @param sa_val the address to bind to; can be IPv4 (AF_INET), IPv6 (AF_INET6)
 *        or even a UNIX domain socket (AF_UNIX)
 * @return the object of struct MHD_DaemonOptionAndValue with requested values
 */
static MHD_INLINE struct MHD_DaemonOptionAndValue
MHD_D_OPTION_SOCK_ADDR(size_t sa_len_val,
                     const struct sockaddr *sa_val)
{
  struct MHD_DaemonOptionAndValue opt_val;

  opt_val.opt = MHD_D_O_SA;
  opt_val.val.v_sa.sa_len = sa_len_val;
  opt_val.val.v_sa.sa = sa_val;

  return opt_val;
}

/**
 * Terminate the list of the options
 * @return the terminating object of struct MHD_DaemonOptionAndValue
 */
static MHD_INLINE struct MHD_DaemonOptionAndValue
MHD_D_OPTION_TERMINATE(void)
{
  struct MHD_DaemonOptionAndValue opt_val;

  opt_val.opt = MHD_D_O_END;

  return opt_val;
}

MHD_RESTORE_WARN_UNUSED_FUNC_
#endif /* !MHD_USE_COMPOUND_LITERALS || !MHD_USE_DESIG_NEST_INIT */



/**
 * Suppresses use of "Date:" header.
 * According to RFC should be used only if the system has no RTC.
 * @param bool_val the value of the parameter
 * @return the object of struct MHD_DaemonOptionAndValue with requested values
 */
#define MHD_D_OPTION_SUPPRESS_DATE_HEADER(bool_val) \
  MHD_D_OPTION_BOOL_SET_(MHD_D_O_BOOL_SUPPRESS_DATE_HEADER,(bool_val))

/**
 * Disable #MHD_action_suspend() functionality.
 *
 * You should only use this function if you are sure you do
 * satisfy all of its requirements and need a generally minor
 * boost in performance.
 * @param bool_val the value of the parameter
 * @return the object of struct MHD_DaemonOptionAndValue with requested values
 */
#define MHD_D_OPTION_DISALLOW_SUSPEND_RESUME(bool_val) \
  MHD_D_OPTION_BOOL_SET_(MHD_D_O_BOOL_DISALLOW_SUSPEND_RESUME,(bool_val))


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
 *                        use MHD_OPTIONS_ARRAY_MAX_SIZE if options processing
 *                        must stop only at zero-termination option
 * @return ::MHD_SC_OK on success,
 *         error code otherwise
 */
MHD_EXTERN_ enum MHD_StatusCode
MHD_daemon_options_set(struct MHD_Daemon *daemon,
                       const struct MHD_DaemonOptionAndValue *options,
                       size_t options_max_num)
MHD_FN_PAR_NONNULL_ALL_;


/**
 * Set the requested single option for the daemon.
 *
 * @param daemon the daemon to set the option
 * @param[in] options the pointer to the option
 * @return ::MHD_SC_OK on success,
 *         error code otherwise
 */
#define MHD_daemon_option_set(daemon, option_ptr) \
  MHD_daemon_options_set(daemon, options_ptr, 1)


#ifdef MHD_USE_VARARG_MACROS
MHD_NOWARN_VARIADIC_MACROS_
#  if defined(MHD_USE_COMPOUND_LITERALS) && defined(MHD_USE_COMP_LIT_FUNC_PARAMS)
/**
 * Set the requested options for the daemon.
 *
 * If any option fail other options may be or may be not applied.
 *
 * It should be used with helpers that creates required options, for example:
 *
 * MHD_DAEMON_OPTIONS_SET(d, MHD_D_OPTION_SUPPRESS_DATE_HEADER(MHD_YES),
 *                        MHD_D_OPTION_SOCK_ADDR(sa_len, sa))
 *
 * @param daemon the daemon to set the options
 * @param ... the list of the options, each option must be created
 *            by helpers MHD_DAEMON_OPTION_NameOfOption(option_value)
 * @return ::MHD_SC_OK on success,
 *         error code otherwise
 */
#    define MHD_DAEMON_OPTIONS_SET(daemon,...)      \
  MHD_NOWARN_COMPOUND_LITERALS_                     \
  MHD_daemon_options_set(daemon,                    \
    ((const struct MHD_DaemonOptionAndValue[])      \
       {__VA_ARGS__, MHD_D_OPTION_TERMINATE()}),       \
    MHD_OPTIONS_ARRAY_MAX_SIZE)                     \
  MHD_RESTORE_WARN_COMPOUND_LITERALS_
#  elif defined(MHD_USE_CPP_INIT_LIST)
} /* extern "C" */
#    include <vector>
extern "C"
{
/**
 * Set the requested options for the daemon.
 *
 * If any option fail other options may be or may be not applied.
 *
 * It should be used with helpers that creates required options, for example:
 *
 * MHD_DAEMON_OPTIONS_SET(d, MHD_D_OPTION_SUPPRESS_DATE_HEADER(MHD_YES),
 *                        MHD_D_OPTION_SOCK_ADDR(sa_len, sa))
 *
 * @param daemon the daemon to set the options
 * @param ... the list of the options, each option must be created
 *            by helpers MHD_D_OPTION_NameOfOption(option_value)
 * @return ::MHD_SC_OK on success,
 *         error code otherwise
 */
#    define MHD_DAEMON_OPTIONS_SET(daemon,...)      \
  MHD_NOWARN_CPP_INIT_LIST_                         \
  MHD_daemon_options_set(daemon,                      \
    (std::vector<struct MHD_DaemonOptionAndValue>   \
     {__VA_ARGS__,MHD_D_OPTION_TERMINATE()}).data(),   \
    MHD_OPTIONS_ARRAY_MAX_SIZE)                     \
  MHD_RESTORE_WARN_CPP_INIT_LIST_
#  endif
MHD_RESTORE_WARN_VARIADIC_MACROS_
#endif /* MHD_USE_VARARG_MACROS && MHD_USE_COMP_LIT_FUNC_PARAMS */


/**
 * Create parameter for #MHD_daemon_options_set() for work mode with
 * no internal threads.
 * The application periodically calls #MHD_daemon_process_blocking(), where
 * MHD internally checks all sockets automatically.
 * This is the default mode.
 * @return the object of struct MHD_DaemonOptionAndValue with requested values
 */
#define MHD_DAEMON_OPTION_WM_EXTERNAL_PERIODIC() \
  MHD_DAEMON_OPTION_WORK_MODE(MHD_WM_OPTION_EXTERNAL_PERIODIC())

/**
* Create parameter for #MHD_daemon_options_set() for work mode with
* an external event loop with level triggers.
* Application uses #MHD_SocketRegistrationUpdateCallback, level triggered
* sockets polling (like select() or poll()) and #MHD_daemon_event_update().
* @param cb_val the callback for sockets registration
* @param cb_cls_val the closure for the @a cv_val callback
* @return the object of struct MHD_DaemonOptionAndValue with requested values
*/
#define MHD_DAEMON_OPTION_WM_EXTERNAL_EVENT_LOOP_CB_LEVEL(cb_val,cb_cls_val) \
  MHD_DAEMON_OPTION_WORK_MODE( \
    MHD_WM_OPTION_EXTERNAL_EVENT_LOOP_CB_LEVEL((cb_val),(cb_cls_val)))

/**
 * Create parameter for #MHD_daemon_options_set() for work mode with
 * an external event loop with edge triggers.
 * Application uses #MHD_SocketRegistrationUpdateCallback, edge triggered
 * sockets polling (like epoll with EPOLLET) and #MHD_daemon_event_update().
 * @param cb_val the callback for sockets registration
 * @param cb_cls_val the closure for the @a cv_val callback
 * @return the object of struct MHD_DaemonOptionAndValue with requested values
 */
#define MHD_DAEMON_OPTION_WM_EXTERNAL_EVENT_LOOP_CB_EDGE(cb_val,cb_cls_val) \
  MHD_DAEMON_OPTION_WORK_MODE( \
    MHD_WM_OPTION_EXTERNAL_EVENT_LOOP_CB_EDGE((cb_val),(cb_cls_val)))

/**
 * Create parameter for #MHD_daemon_options_set() for work mode with
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
#define MHD_DAEMON_OPTION_WM_EXTERNAL_SINGLE_FD_WATCH() \
  MHD_DAEMON_OPTION_WORK_MODE(MHD_WM_OPTION_EXTERNAL_SINGLE_FD_WATCH())

/**
 * Create parameter for #MHD_daemon_options_set() for work mode with
 * one or more worker threads.
 * If number of threads is one, then daemon starts with single worker thread
 * that handles all connections.
 * If number of threads is larger than one, then that number of worker threads,
 * and handling of connection is distributed among the workers.
 * @param num_workers the number of worker threads, zero is treated as one
 * @return the object of struct MHD_DaemonOptionAndValue with requested values
 */
#define MHD_DAEMON_OPTION_WORKER_THREADS(num_workers) \
  MHD_DAEMON_OPTION_WORK_MODE(MHD_WM_OPTION_WORKER_THREADS(num_workers))

/**
 * Create parameter for #MHD_daemon_options_set() for work mode with
 * one internal thread for listening and additional threads per every
 * connection.  Use this if handling requests is CPU-intensive or blocking,
 * your application is thread-safe and you have plenty of memory (per
 * connection).
 * @return the object of struct MHD_DaemonOptionAndValue with requested values
 */
#define MHD_DAEMON_OPTION_THREAD_PER_CONNECTION() \
  MHD_DAEMON_OPTION_WORK_MODE(MHD_WM_OPTION_THREAD_PER_CONNECTION())


/* ******************* Event loop ************************ */


/**
 * Run websever operation with possible blocking.
 *
 * Supported only in #MHD_TM_EXTERNAL_PERIODIC and
 * #MHD_TM_EXTERNAL_SINGLE_FD_WATCH modes.
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
 * In #MHD_TM_EXTERNAL_PERIODIC mode if @a millisec parameter is not zero
 * this function calls #MHD_get_timeout()internally and use returned value
 * as maximum wait time if it less than value of @a millisec parameter.
 *
 * @param daemon the daemon to run
 * @param millisec the maximum time in milliseconds to wait for network and
 *                 other events. Note: there is no guarantee that function
 *                 blocks for the specified amount of time. The real processing
 *                 time can be shorter (if some data or connection timeout
 *                 comes earlier) or longer (if data processing requires more
 *                 time, especially in user callbacks).
 *                 If set to '0' then function does not block and processes
 *                 only already available data (if any). Zero value is
 *                 recommended when used in #MHD_TM_EXTERNAL_SINGLE_FD_WATCH
 *                 and the watched FD has been triggered.
 *                 If set to #MHD_WAIT_INDEFINITELY then function waits
 *                 for events indefinitely (blocks until next network activity
 *                 or connection timeout).
 *                 Always used as zero value in
 *                 #MHD_TM_EXTERNAL_SINGLE_FD_WATCH mode.
 * @return #MHD_SC_OK on success, otherwise
 *         an error code
 * @ingroup event
 */
MHD_EXTERN_ enum MHD_StatusCode
MHD_daemon_process_blocking (struct MHD_Daemon *daemon,
                             uint_fast64_t microsec)
MHD_FN_PAR_NONNULL_(1);

/**
 * Run webserver operations (without blocking unless in client
 * callbacks).
 *
 * Supported only in #MHD_TM_EXTERNAL_SINGLE_FD_WATCH mode.
 *
 * This function does the following: processes all incoming and outgoing data,
 * processes new connections, processes any timed-out connection, and does
 * other things required to run webserver.
 * Once all connections are processed, function returns.
 *
 * The optional @a next_max_wait pointer returns the same value as
 * if #MHD_daemon_get_timeout() would called immediately.
 *
 * @param daemon the daemon to run
 * @return #MHD_SC_OK on success, otherwise
 *         an error code
 * @ingroup event
 */
#define MHD_daemon_process_nonblocking(daemon) \
    MHD_daemon_process_blocking(daemon, 0)


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
 * @param[in] addr IP address of the client
 * @param addrlen number of bytes in @a addr
 * @param connection_cntx meta data the application wants to
 *        associate with the new connection object
 * @return #MHD_SC_OK on success
 *         error on failure
 * @ingroup specialized
 */
MHD_EXTERN_ enum MHD_StatusCode
MHD_daemon_add_connection (struct MHD_Daemon *daemon,
                           MHD_socket client_socket,
                           size_t addrlen,
                           const struct sockaddr *addr,
                           void *connection_cntx)
MHD_FN_PAR_NONNULL_ (1)
MHD_FN_PAR_IN_SIZE_(4,3);


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
};

struct MHD_ReservedStruct
{
  uint_fast64_t reserved1;
  void *reserved2;
};

union MHD_ConnectionOptionValue
{
  unsigned int v_uint;
  /**
   * Reserved member. Do not use.
   */
  struct MHD_ReservedStruct reserved;
};

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
/* Do not use directly */ // TODO: convert to explicict
#  define MHD_C_OPTION_UINT_SET_(option,uint_val)       \
  MHD_NOWARN_COMPOUND_LITERALS_                         \
  (const struct MHD_ConnectionOptionAndValue)           \
  {                                                     \
    .opt = (option),                                    \
    .val.v_uint = (uint_val)                            \
  }                                                     \
  MHD_RESTORE_WARN_COMPOUND_LITERALS_

/**
 * Terminate the list of the options
 * @return the terminating object of struct MHD_DaemonOptionAndValue
 */
#  define MHD_C_OPTION_TERMINATE()                      \
  MHD_NOWARN_COMPOUND_LITERALS_                         \
  (const struct MHD_DaemonOptionAndValue)               \
  {                                                     \
    .opt = (MHD_C_O_END)                                \
  }                                                     \
  MHD_RESTORE_WARN_COMPOUND_LITERALS_

#else  /* !MHD_USE_COMPOUND_LITERALS || !MHD_USE_DESIG_NEST_INIT */
MHD_NOWARN_UNUSED_FUNC_

/* Do not use directly */
static MHD_INLINE struct MHD_ConnectionOptionAndValue
MHD_C_OPTION_UINT_SET_(enum MHD_ConnectionOption option,
                       unsigned int uint_val)
{
  struct MHD_ConnectionOptionAndValue opt_val;

  opt_val.opt = option;
  opt_val.val.v_uint = uint_val;

  return opt_val;
}

/**
 * Terminate the list of the options
 * @return the terminating object of struct MHD_ConnectionOptionAndValue
 */
static MHD_INLINE struct MHD_ConnectionOptionAndValue
MHD_C_OPTION_TERMINATE(void)
{
  struct MHD_ConnectionOptionAndValue opt_val;

  opt_val.opt = MHD_C_O_END;

  return opt_val;
}

MHD_RESTORE_WARN_UNUSED_FUNC_
#endif /* !MHD_USE_COMPOUND_LITERALS || !MHD_USE_DESIG_NEST_INIT */

#define MHD_C_OPTION_TIMEOUT(v_uint) \
  MHD_C_OPTION_UINT_SET_(MHD_C_O_TIMEOUT,v_uint)
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
 *                        use MHD_OPTIONS_ARRAY_MAX_SIZE if options processing
 *                        must stop only at zero-termination option
 * @return ::MHD_SC_OK on success,
 *         error code otherwise
 */
MHD_EXTERN_ enum MHD_StatusCode
MHD_connection_options_set(
  struct MHD_Connection *connection,
  const struct MHD_ConnectionOptionAndValue *options,
  size_t options_max_num)
MHD_FN_PAR_NONNULL_ALL_;


/**
 * Set the requested single option for the connection.
 *
 * @param connection the connection to set the options
 * @param[in] options the pointer to the option
 * @return ::MHD_SC_OK on success,
 *         error code otherwise
 */
#define MHD_connection_option_set(connection, option_ptr) \
  MHD_connection_options_set(connection, options_ptr, 1)


#ifdef MHD_USE_VARARG_MACROS
MHD_NOWARN_VARIADIC_MACROS_
#  if defined(MHD_USE_COMPOUND_LITERALS) && defined(MHD_USE_COMP_LIT_FUNC_PARAMS)
/**
 * Set the requested options for the connection.
 *
 * If any option fail other options may be or may be not applied.
 *
 * It should be used with helpers that creates required options, for example:
 *
 * MHD_CONNECTION_OPTIONS_SET(d, MHD_C_OPTION_TIMEOUT(30))
 *
 * @param connection the connection to set the options
 * @param ... the list of the options, each option must be created
 *            by helpers MHD_C_OPTION_NameOfOption(option_value)
 * @return ::MHD_SC_OK on success,
 *         error code otherwise
 */
#    define MHD_CONNECTION_OPTIONS_SET(connection,...)  \
  MHD_NOWARN_COMPOUND_LITERALS_                         \
  MHD_connection_options_set(daemon,                    \
    ((const struct MHD_ConnectionOptionAndValue[])      \
       {__VA_ARGS__, MHD_C_OPTION_TERMINATE()}),        \
    MHD_OPTIONS_ARRAY_MAX_SIZE)                         \
  MHD_RESTORE_WARN_COMPOUND_LITERALS_
#  elif defined(MHD_USE_CPP_INIT_LIST)
} /* extern "C" */
#    include <vector>
extern "C"
{
/**
 * Set the requested options for the connection.
 *
 * If any option fail other options may be or may be not applied.
 *
 * It should be used with helpers that creates required options, for example:
 *
 * MHD_CONNECTION_OPTIONS_SET(d, MHD_C_OPTION_TIMEOUT(30))
 *
 * @param connection the connection to set the options
 * @param ... the list of the options, each option must be created
 *            by helpers MHD_C_OPTION_NameOfOption(option_value)
 * @return ::MHD_SC_OK on success,
 *         error code otherwise
 */
#    define MHD_CONNECTION_OPTIONS_SET(daemon,...)      \
  MHD_NOWARN_CPP_INIT_LIST_                             \
  MHD_daemon_options_set(daemon,                        \
    (std::vector<struct MHD_ConnectionOptionAndValue>   \
     {__VA_ARGS__,MHD_C_OPTION_TERMINATE()}).data(),    \
    MHD_OPTIONS_ARRAY_MAX_SIZE)                         \
  MHD_RESTORE_WARN_CPP_INIT_LIST_
#  endif
MHD_RESTORE_WARN_VARIADIC_MACROS_
#endif /* MHD_USE_VARARG_MACROS && MHD_USE_COMP_LIT_FUNC_PARAMS */


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
  MHD_VK_HEADER = 1
  ,
  /**
   * Cookies.  Note that the original HTTP header containing
   * the cookie(s) will still be available and intact.
   */
  MHD_VK_COOKIE = 2
  ,
  /**
   * GET (URI) arguments.
   */
  MHD_VK_GET_ARGUMENT = 4
  ,
  /**
   * POST data.
   * This is available only if a content encoding
   * supported by MHD is used, and only if the posted content
   * fits within the available memory pool.
   *
   * @warning The encoding "multipart/form-data" has more fields than just
   * "name" and "value". See #MHD_request_get_post_processor_values_cb() and
   * #MHD_request_get_post_processor_values_list(). In particular it could be
   * important to check used "Transfer-Encoding". While it is deprecated and
   * not used by modern clients, hypothetically it can be used.
   */
  MHD_VK_POSTDATA = 8
  ,
  /**
   * HTTP footer (only for HTTP 1.1 chunked encodings).
   */
  MHD_VK_FOOTER = 16
  ,
  /**
   * Header and footer values
   */
  MHD_VK_HEADER_FOOTER = MHD_VK_HEADER | MHD_VK_FOOTER,

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
MHD_FN_PAR_NONNULL_ (4) MHD_FN_PAR_OUT_(4);


/**
 * Get a particular header (or other kind of request data) value.
 * If multiple values match the kind, return any one of them.
 *
 * The returned pointer is valid until the response is queued.
 * If the data is needed beyond this point, it should be copied.
 *
 * @param request request to get values from
 * @param kind what kind of value are we looking for
 * @param key the header to look for, NULL to lookup 'trailing' value without a key
 * @return NULL if no such item was found
 * @ingroup request
 */
MHD_EXTERN_ const struct MHD_String *
MHD_request_get_value (struct MHD_Request *request,
                       enum MHD_ValueKind kind,
                       const char *key)
MHD_FN_PAR_NONNULL_ (1)
MHD_FN_PAR_NONNULL_ (3) MHD_FN_PAR_CSTR_(3);



/**
 * @defgroup httpcode HTTP response codes.
 * These are the status codes defined for HTTP responses.
 * @{
 */
/* See http://www.iana.org/assignments/http-status-codes/http-status-codes.xhtml */
enum MHD_FIXED_ENUM_APP_SET_ MHD_HTTP_StatusCode
{

  MHD_HTTP_STATUS_CONTINUE = 100
  ,
  MHD_HTTP_STATUS_SWITCHING_PROTOCOLS = 101
  ,
  MHD_HTTP_STATUS_PROCESSING = 102
  ,
  MHD_HTTP_STATUS_OK = 200
  ,
  MHD_HTTP_STATUS_CREATED = 201
  ,
  MHD_HTTP_STATUS_ACCEPTED = 202
  ,
  MHD_HTTP_STATUS_NON_AUTHORITATIVE_INFORMATION = 203
  ,
  MHD_HTTP_STATUS_NO_CONTENT = 204
  ,
  MHD_HTTP_STATUS_RESET_CONTENT = 205
  ,
  MHD_HTTP_STATUS_PARTIAL_CONTENT = 206
  ,
  MHD_HTTP_STATUS_MULTI_STATUS = 207
  ,
  MHD_HTTP_STATUS_ALREADY_REPORTED = 208
  ,
  MHD_HTTP_STATUS_IM_USED = 226
  ,
  MHD_HTTP_STATUS_MULTIPLE_CHOICES = 300
  ,
  MHD_HTTP_STATUS_MOVED_PERMANENTLY = 301
  ,
  MHD_HTTP_STATUS_FOUND = 302
  ,
  MHD_HTTP_STATUS_SEE_OTHER = 303
  ,
  MHD_HTTP_STATUS_NOT_MODIFIED = 304
  ,
  MHD_HTTP_STATUS_USE_PROXY = 305
  ,
  MHD_HTTP_STATUS_SWITCH_PROXY = 306 /* IANA: unused */
  ,
  MHD_HTTP_STATUS_TEMPORARY_REDIRECT = 307
  ,
  MHD_HTTP_STATUS_PERMANENT_REDIRECT = 308
  ,
  MHD_HTTP_STATUS_BAD_REQUEST = 400
  ,
  MHD_HTTP_STATUS_UNAUTHORIZED = 401
  ,
  MHD_HTTP_STATUS_PAYMENT_REQUIRED = 402
  ,
  MHD_HTTP_STATUS_FORBIDDEN = 403
  ,
  MHD_HTTP_STATUS_NOT_FOUND = 404
  ,
  MHD_HTTP_STATUS_METHOD_NOT_ALLOWED = 405
  ,
  MHD_HTTP_STATUS_NOT_ACCEPTABLE = 406
  ,
  MHD_HTTP_STATUS_PROXY_AUTHENTICATION_REQUIRED = 407
  ,
  MHD_HTTP_STATUS_REQUEST_TIMEOUT = 408
  ,
  MHD_HTTP_STATUS_CONFLICT = 409
  ,
  MHD_HTTP_STATUS_GONE = 410
  ,
  MHD_HTTP_STATUS_LENGTH_REQUIRED = 411
  ,
  MHD_HTTP_STATUS_PRECONDITION_FAILED = 412
  ,
  MHD_HTTP_STATUS_PAYLOAD_TOO_LARGE = 413
  ,
  MHD_HTTP_STATUS_URI_TOO_LONG = 414
  ,
  MHD_HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE = 415
  ,
  MHD_HTTP_STATUS_RANGE_NOT_SATISFIABLE = 416
  ,
  MHD_HTTP_STATUS_EXPECTATION_FAILED = 417
  ,
  MHD_HTTP_STATUS_MISDIRECTED_REQUEST = 421
  ,
  MHD_HTTP_STATUS_UNPROCESSABLE_ENTITY = 422
  ,
  MHD_HTTP_STATUS_LOCKED = 423
  ,
  MHD_HTTP_STATUS_FAILED_DEPENDENCY = 424
  ,
  MHD_HTTP_STATUS_UNORDERED_COLLECTION = 425 /* IANA: unused */
  ,
  MHD_HTTP_STATUS_UPGRADE_REQUIRED = 426
  ,
  MHD_HTTP_STATUS_PRECONDITION_REQUIRED = 428
  ,
  MHD_HTTP_STATUS_TOO_MANY_REQUESTS = 429
  ,
  MHD_HTTP_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE = 431
  ,
  MHD_HTTP_STATUS_NO_RESPONSE = 444 /* IANA: unused */
  ,
  MHD_HTTP_STATUS_RETRY_WITH = 449 /* IANA: unused */
  ,
  MHD_HTTP_STATUS_BLOCKED_BY_WINDOWS_PARENTAL_CONTROLS = 450  /* IANA: unused */
  ,
  MHD_HTTP_STATUS_UNAVAILABLE_FOR_LEGAL_REASONS = 451
  ,
  MHD_HTTP_STATUS_INTERNAL_SERVER_ERROR = 500
  ,
  MHD_HTTP_STATUS_NOT_IMPLEMENTED = 501
  ,
  MHD_HTTP_STATUS_BAD_GATEWAY = 502
  ,
  MHD_HTTP_STATUS_SERVICE_UNAVAILABLE = 503
  ,
  MHD_HTTP_STATUS_GATEWAY_TIMEOUT = 504
  ,
  MHD_HTTP_STATUS_HTTP_VERSION_NOT_SUPPORTED = 505
  ,
  MHD_HTTP_STATUS_VARIANT_ALSO_NEGOTIATES = 506
  ,
  MHD_HTTP_STATUS_INSUFFICIENT_STORAGE = 507
  ,
  MHD_HTTP_STATUS_LOOP_DETECTED = 508
  ,
  MHD_HTTP_STATUS_BANDWIDTH_LIMIT_EXCEEDED = 509  /* IANA: unused */
  ,
  MHD_HTTP_STATUS_NOT_EXTENDED = 510
  ,
  MHD_HTTP_STATUS_NETWORK_AUTHENTICATION_REQUIRED = 511

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
MHD_FN_PURE_;

/** @} */ /* end of group httpcode */


/**
 * @defgroup versions HTTP versions
 * These strings should be used to match against the first line of the
 * HTTP header.
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
  MHD_HTTP_VERSION_2_0 = 3
  ,
  MHD_HTTP_VERSION_3_0 = 4
  ,
  MHD_HTTP_VERSION_FUTURE = 99
};

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
MHD_FN_PURE_;

/**
 * HTTP/1.0 identification string
 */
#define MHD_HTTP_VERSION_1_0 "HTTP/1.0"
/**
 * HTTP/1.1 identification string
 */
#define MHD_HTTP_VERSION_1_1 "HTTP/1.1"
/**
 * HTTP/2 identification string.
 * Not used by the HTTP protocol (except non-TLS handshake), useful for logs and
 * similar proposes.
 */
#define MHD_HTTP_VERSION_2 "HTTP/2"
/**
 * HTTP/3 identification string.
 * Not used by the HTTP protocol, useful for logs and similar proposes.
 */
#define MHD_HTTP_VERSION_3 "HTTP/3"

/** @} */ /* end of group versions */


/**
 * Resume handling of network data for suspended request.  It is
 * safe to resume a suspended request at any time.  Calling this
 * function on a request that was not previously suspended will
 * result in undefined behaviour.
 *
 * If you are using this function in ``external'' select mode, you must
 * make sure to run #MHD_run() afterwards (before again calling
 * #MHD_get_fdset(), as otherwise the change may not be reflected in
 * the set returned by #MHD_get_fdset() and you may end up with a
 * request that is stuck until the next network activity.
 *
 * @param[in,out] request the request to resume
 */
MHD_EXTERN_ void
MHD_request_resume (struct MHD_Request *request)
MHD_FN_PAR_NONNULL_ALL_;


/* ************** Action and Response manipulation functions **************** */

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
 * @param[in,out] requests the request for which the action is generated
 * @param suspend_microsec the maximum duration of suspension after which
 *                         the request is automatically resumed, if not
 *                         resumed earlier by #MHD_request_resume(),
 *                         the precise resume moment is not guaranteed, it
 *                         may happen later (but not earlier) depending
 *                         on timer granularity and the system load;
 *                         if set to #MHD_WAIT_INDEFINITELY (or higher)
 *                         the request is not resumed automatically
 * @return action to cause a request to be suspended.
 */
MHD_EXTERN_ const struct MHD_Action *
MHD_action_suspend (struct MHD_Request *request,
                    uint_fast64_t suspend_microsec)
MHD_FN_RETURNS_NONNULL_ MHD_FN_PAR_NONNULL_ALL_;

/**
 * Converts a @a response to an action.  If @a MHD_RESP_OPT_BOOL_REUSABLE
 * is not set, the reference to the @a response is consumed
 * by the conversion. If #MHD_RESP_OPT_BOOL_REUSABLE is #MHD_YES,
 * then the @a response can be used again to create actions in
 * the future.
 * However, the @a response is frozen by this step and
 * must no longer be modified (i.e. by setting headers).
 *
 * @param[in] response the response to convert,
 *                     if NULL then this function is equivalent to
 *                     #MHD_action_close_connection() call
 * @return pointer to the action, the action must be consumed
 *         otherwise response object may leak;
 *         NULL if failed (no memory), when failed
 *         the response object is consumed and need not
 *         to be "destroyed".
 */
MHD_EXTERN_ const struct MHD_Action *
MHD_action_from_response (struct MHD_Request *request,
                          struct MHD_Response *response);


/**
 * Flags for special handling of responses.
 */
enum MHD_ResponseOptionBool
{
  /**
   * Not a real option, terminate the list of options
   */
  MHD_RESP_OPT_BOOL_END = 0
  ,
  /**
   * Make the response object re-usable.
   * The response will not be consumed by MHD_action_from_response() and
   * must be destroyed by MHD_response_destroy().
   * Useful if the response is often used to reply.
   */
  MHD_RESP_OPT_BOOL_REUSABLE = 1
  ,
  /**
   * Force close connection after sending the response, prevents keep-alive
   * connections and adds "Connection: close" header.
   */
  MHD_RESP_OPT_BOOL_CONN_CLOSE = 21
  ,
  /**
   * Force use of chunked encoding even if the response content size is known.
   * Ignored when the reply cannot have body/content.
   */
  MHD_RESP_OPT_BOOL_CHUNKED_ENC = 22
  ,
  /**
   * Enable sending of "Connection: keep-alive" header even for
   * HTTP/1.1 clients when "Keep-Alive" connection is used.
   * Disabled by default for HTTP/1.1 clients as per RFC.
   */
  MHD_RESP_OPT_BOOL_SEND_KEEP_ALIVE_HEADER = 41
  ,
  /**
   * Only respond in conservative (dumb) HTTP/1.0-compatible mode.
   * Response still use HTTP/1.1 version in header, but always close
   * the connection after sending the response and do not use chunked
   * encoding for the response.
   * You can also set the #MHD_RESP_OPT_BOOL_HTTP_1_0_SERVER flag to force
   * HTTP/1.0 version in the response.
   * Responses are still compatible with HTTP/1.1.
   * This option can be used to communicate with some broken client, which
   * does not implement HTTP/1.1 features, but advertises HTTP/1.1 support.
   */
  MHD_RESP_OPT_BOOL_HTTP_1_0_COMPATIBLE_STRICT = 42
  ,
  /**
   * Only respond in HTTP/1.0-mode.
   * Contrary to the #MHD_RESP_OPT_BOOL_HTTP_1_0_COMPATIBLE_STRICT flag, the response's
   * HTTP version will always be set to 1.0 and keep-alive connections
   * will be used if explicitly requested by the client.
   * The "Connection:" header will be added for both "close" and "keep-alive"
   * connections.
   * Chunked encoding will not be used for the response.
   * Due to backward compatibility, responses still can be used with
   * HTTP/1.1 clients.
   * This option can be used to emulate HTTP/1.0 server (for response part
   * only as chunked encoding in requests (if any) is processed by MHD).
   */
  MHD_RESP_OPT_BOOL_HTTP_1_0_SERVER = 43
  ,
  /**
   * Disable sanity check preventing clients from manually
   * setting the HTTP content length option.
   * Allow to set several "Content-Length" headers. These headers will
   * be used even with replies without body.
   */
  MHD_RESP_OPT_BOOL_INSANITY_HEADER_CONTENT_LENGTH = 61
  ,
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
   */
  MHD_RESP_OPT_BOOL_HEAD_ONLY_RESPONSE = 81
};


// FIXME: use the same approach as for the daemon
MHD_EXTERN_ enum MHD_StatusCode
MHD_response_set_option_bool (struct MHD_Response *response,
                              enum MHD_ResponseOption ro,
                              enum MHD_Bool value)
MHD_FN_PAR_NONNULL_ALL_;

// FIXME: the suggested approach

struct MHD_ResponseOptionBoolSet
{
  enum MHD_ResponseOptionBool option;
  enum MHD_Bool value;
};

// FIXME: fully type-safe, options array can be built incrementally
// See https://github.com/babelouest/ulfius/blob/1ed26069fd7e1decd38e8d403a5649b0337893ff/src/ulfius.c#L1073
// for incrementally built options

/**
 * Set several options for the response object
 * @param response the response to set the options
 * @param options_array the pointer to the array with the options;
 *                      the array is read until first ::MHD_RESP_OPT_BOOL_END
 *                      option, but not more than @a max_num_options elements
 * @param max_num_options the maximum number of elements to read
 *                        from @a options_array, ignored if set to SIZE_MAX
 * @return #MHD_SC_OK if found,
 *         error code otherwise
 */
MHD_EXTERN_ enum MHD_StatusCode
MHD_response_set_options_bool (struct MHD_Response *response,
                               struct MHD_ResponseOptionBoolSet *options_array,
                               size_t max_num_options)
MHD_FN_PAR_NONNULL_ALL_;



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
   * The application terminated request without response.
   * @ingroup request
   */
  MHD_REQUEST_TERMINATED_BY_APP = 1
  ,
  /**
   * The request is not valid according to
   * HTTP specifications.
   * @ingroup request
   */
  MHD_REQUEST_TERMINATED_HTTP_PROTOCOL_ERROR = 2
  ,
  /**
   * The client terminated the connection by closing the socket
   * for writing (TCP half-closed) before sending complete request;
   * MHD aborted sending the response according to RFC 2616, section 8.1.4.
   * @ingroup request
   */
  MHD_REQUEST_TERMINATED_CLIENT_ABORT = 3
  ,
  /**
   * Error handling the connection due to resources exhausted.
   * @ingroup request
   */
  MHD_REQUEST_TERMINATED_NO_RESOURCES = 4
  ,
  /**
   * We had to close the session since MHD was being shut down.
   * @ingroup request
   */
  MHD_REQUEST_TERMINATED_DAEMON_SHUTDOWN = 5
  ,
  /**
   * No activity on the connection for the number of seconds specified using
   * #MHD_C_OPTION_TIMEOUT().
   * @ingroup request
   */
  MHD_REQUEST_TERMINATED_TIMEOUT_REACHED = 6
  ,
  /**
   * The connection was broken or TLS protocol error.
   * @ingroup request
   */
  MHD_REQUEST_TERMINATED_CONNECTION_ERROR = 7
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
};


/**
 * Signature of the callback used by MHD to notify the application
 * about completed requests.
 *
 * @param cls client-defined closure
 * @param data the details about the event
 * @param request_context request context value, as originally
 *         returned by the #MHD_EarlyUriLogCallback
 * @see #MHD_option_request_completion()
 * @ingroup request
 */
typedef void
(*MHD_RequestTerminationCallback) (void *cls,
                                   struct MHD_RequestTerminationData *data,
                                   void *request_context);


/**
 * Set a function to be called once MHD is finished with the
 * request.
 *
 * @param[in,out] response which response to set the callback for
 * @param termination_cb function to call, can be NULL to not use the callback
 * @param termination_cb_cls closure for @e termination_cb
 */
MHD_EXTERN_ enum MHD_StatusCode
MHD_response_set_option_termination_callback (
  struct MHD_Response *response,
  MHD_RequestTerminationCallback termination_cb,
  void *termination_cb_cls)
MHD_FN_PAR_NONNULL_ (1);


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

/**
 * The action type returned by Dynamic Content Creator callback
 */
struct MHD_DynamicContentCreatorAction;
/**
 * The context used for Dynamic Content Creator callback
 */
struct MHD_DynamicContentCreatorContext;


/**
 * Set action to "continue processing", the data is provided in the
 * buffer and/or in the zero-copy @a iov_data.
 * If data is provided both in the buffer and @a ivo_data then
 * data in the buffer sent first, following the iov data.
 * The total size of the data in the buffer and in @a iov_data must
 * be non-zero.
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
  const char *chunk_ext)
MHD_FN_PAR_NONNULL_ (1)
MHD_FN_PAR_CSTR_(4);

#define MHD_DCC_action_continue(ctx,data_size,chunk_ext) \
    MHD_DCC_action_continue_zc (ctx, data_size, NULL, chunk_ext)

/**
 * Set action to "finished".
 * If function failed for any reason, the action is automatically
 * set to "stop with error".
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
MHD_DCC_action_finished_with_footer (
  struct MHD_DynamicContentCreatorContext *ctx,
  size_t num_footers,
  const struct MHD_NameValueCStr *footers)
MHD_FN_PAR_NONNULL_ (1);


#define MHD_DCC_action_finished(action) \
  MHD_DCC_set_action_finished_with_footer (action, 0, NULL)


/**
 * Set action to "suspend".
 * If function failed for any reason, the action is automatically
 * set to "stop with error".
 * @param[in,out] ctx the pointer the context as provided to the callback
 * @return the pointer to the action if succeed,
 *         NULL (equivalent of MHD_DCC_action_abort())in case of any error
 */
MHD_EXTERN_ const struct MHD_DynamicContentCreatorAction *
MHD_DCC_action_suspend (struct MHD_DynamicContentCreatorContext *ctx)
MHD_FN_PAR_NONNULL_ (1)
MHD_FN_RETURNS_NONNULL_;

/**
 * Set action to "stop with error".
 * @param[in,out] ctx the pointer the context as provided to the callback
 * @return always NULL (the action "stop with error")
 */
#define MHD_DCC_action_abort(ctx) \
  MHD_STATIC_CAST_(const struct MHD_DynamicContentCreatorAction *, NULL)

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
 * @param max maximum number of bytes to copy to @a buf (size of @a buf)
 * @param[out] action the action to set,
 *                    the pointer is only valid until
 *                    the callback returns
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
 *           #MHD_HTTP_NO_CONTENT is only valid if @a size is 0;
 * @param size the size of the data portion of the response
 * @param buffer the @a size bytes containing the response's data portion,
 *               needs to be valid while the response is used
 * @param free_cb the callback to free any allocated data, called
 *                when response is being destroyed, can be NULL
 *                to skip the free/cleanup callback
 * @param free_cb_cls the parameter for @a free_cb
 * @return NULL on error (i.e. invalid arguments, out of memory)
 * @ingroup response
 */
MHD_EXTERN_ struct MHD_Response *
MHD_response_from_buffer (
  enum MHD_HTTP_StatusCode sc,
  size_t buffer_size,
  const char buffer[MHD_FN_PAR_DYN_ARR_SIZE_(buffer_size)],
  MHD_FreeCallback free_cb,
  void *free_cb_cls)
MHD_FN_PAR_IN_SIZE_(3,2);


/**
 * Create a response object with empty (zero size) body.
 *
 * The response object can be extended with header information and then be used
 * any number of times.
 * @param sc status code to use for the response
 */
#define MHD_response_from_empty(sc) \
  MHD_response_from_buffer (sc, 0, NULL, NULL, NULL)


/**
 * Create a response object.  The response object can be extended with
 * header information.
 *
 * @param sc status code to use for the response
 * @param size the size of the data portion of the response
 * @param buffer the @a size bytes containing the response's data portion,
 *               an internal copy will be made, there is no need to
 *               keep this data after return from this function
 * @return NULL on error (i.e. invalid arguments, out of memory)
 * @ingroup response
 */
MHD_EXTERN_ struct MHD_Response *
MHD_response_from_buffer_copy (
  enum MHD_HTTP_StatusCode sc,
  size_t buffer_size,
  const char buffer[MHD_FN_PAR_DYN_ARR_SIZE_(buffer_size)])
MHD_FN_PAR_IN_SIZE_(3,2);


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
 * @param iov_count the number of elements in @a iov
 * @param iov the array for response data buffers, an internal copy of this
 *        will be made
 * @param free_cb the callback to clean up any data associated with @a iov when
 *        the response is destroyed.
 * @param free_cb_cls the argument passed to @a free_cb
 * @return NULL on error (i.e. invalid arguments, out of memory)
 * @ingroup response
 */
MHD_EXTERN_ struct MHD_Response *
MHD_response_from_iovec (
  enum MHD_HTTP_StatusCode sc,
  unsigned int iov_count,
  const struct MHD_IoVec iov[MHD_FN_PAR_DYN_ARR_SIZE_(iov_count)],
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
 *        MHD build; see ::MHD_FEATURE_LARGE_FILE
 * @param size size of the data portion of the response;
 *        sizes larger than 2 GiB may be not supported by OS or
 *        MHD build; see ::MHD_FEATURE_LARGE_FILE
 * @return NULL on error (i.e. invalid arguments, out of memory)
 * @ingroup response
 */
MHD_EXTERN_ struct MHD_Response *
MHD_response_from_fd (enum MHD_HTTP_StatusCode sc,
                      int fd,
                      uint_fast64_t offset,
                      uint_fast64_t size)
MHD_FN_PAR_FD_READ_(2);

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
MHD_EXTERN_ struct MHD_Response *
MHD_response_from_pipe (enum MHD_HTTP_StatusCode sc,
                        int fd);


/**
 * Destroy response.
 * Should be called if response was created but not consumed.
 * Also must be called if response has #MHD_RESP_OPT_BOOL_REUSABLE
 * set. The actual destroy can be happen later, if the response
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
MHD_response_add_header (struct MHD_Response *response,
                         const char *name,
                         const char *value)
MHD_FN_PAR_NONNULL_ (1)
MHD_FN_PAR_NONNULL_ (2) MHD_FN_PAR_CSTR_(2)
MHD_FN_PAR_NONNULL_ (3) MHD_FN_PAR_CSTR_(3);


/**
 * Add a header with predefined (standard) name to the response.
 *
 * @param response response to add a header to
 * @param stk the code of the predefined header
 * @param value the value of the header to add,
 *              an internal copy of the string will be made
 * @return #MHD_SC_OK on success,
 *         error code otherwise
 * @ingroup response
 */
MHD_EXTERN_ enum MHD_StatusCode
MHD_response_add_predef_header (struct MHD_Response *response,
                                enum MHD_PredefinedHeader stk,
                                const char *content)
MHD_FN_PAR_NONNULL_ (1)
MHD_FN_PAR_NONNULL_ (3) MHD_FN_PAR_CSTR_(3);


/* ************ (b) Upload and PostProcessor functions ********************** */


/**
 * Action telling MHD to continue processing the upload.
 *
 * @param req the request to make an action
 * @return action operation, never NULL
 */
MHD_EXTERN_ const struct MHD_Action *
MHD_action_continue (struct MHD_Request *req);


/**
 * Action telling MHD to close the connection hard
 * (kind-of breaking HTTP specification).
 *
 * @param req the request to make an action
 * @return action operation, always NULL
 */
#define MHD_action_close_connection(req) \
  MHD_STATIC_CAST_(const struct MHD_Action *, NULL)


/**
 * Function to process data uploaded by a client.
 *
 * @param cls argument given together with the function
 *        pointer when the handler was registered with MHD
 * @param request the request is being processed
 * @param content_data_size the size of the @a content_data,
 *                          zero if all data have been processed
 * @param[in] content_data the uploaded content data,
 *                         may be modified in the callback,
 *                         valid only until return from the callback,
 *                         NULL is all data have been processed
 * @return action specifying how to proceed, often
 *         #MHD_action_continue() if all is well,
 *         #MHD_action_suspend() to stop reading the upload until
 *              the request is resumed,
 *         MHD_action_close_connection to close the socket, or a response
 *         to discard the rest of the upload and return the data given
 */
typedef const struct MHD_Action *
(MHD_FN_PAR_NONNULL_ (2) MHD_FN_PAR_NONNULL_ (3)
 *MHD_UploadCallback)(void *upload_cls,
                      struct MHD_Request *request,
                      size_t content_data_size,
                      void *content_data);


/**
 * Create an action that handles an upload.
 *
 * If @a uc_inc is NULL and upload cannot fit the allocated buffer
 * then request is aborted without response.
 *
 * @param request the request to create action for
 * @param upload_buffer_size how large should the upload buffer be.
 *                           May allocate memory from the large memory pool
 *                           if necessary and non-zero is given.
 *                           Must be zero if @a uc_full is NULL.
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
 * @return NULL on error (out of memory. both @a uc_full and @a uc_inc are NULL)
 * @ingroup action
 */
MHD_EXTERN_ const struct MHD_Action *
MHD_action_process_upload (
  struct MHD_Request *request,
  size_t upload_buffer_size,
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
 * @return NULL on error (out of memory. both @a uc_full and @a uc_inc are NULL)
 * @ingroup action
 */
#define MHD_action_process_upload_full(req,buff_size,uc,uc_cls) \
  MHD_action_process_upload(req, buff_size, uc, uc_cls, NULL, NULL)

/**
 * Create an action that handles an upload incrementally.
 *
 * @param request the request to create action for
 * @param uc the function to incrementally process the upload data
 * @param uc_cls closure for @a uc
 * @return NULL on error (out of memory. both @a uc_full and @a uc_inc are NULL)
 * @ingroup action
 */
#define MHD_action_process_upload_inc(req,uc,uc_cls) \
  MHD_action_process_upload(req, 0, NULL, NULL, uc, uc_cls)


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
 * @return action specifying how to proceed, often
 *         #MHD_action_continue() if all is well,
 *         #MHD_action_suspend() to stop reading the upload until
 *              the request is resumed,
 *         NULL to close the socket, or a response
 *         to discard the rest of the upload and return the data given
 */
typedef const struct MHD_Action *
(*MHD_PostDataReader) (struct MHD_Request *req,
                         void *cls,
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
typedef const struct MHD_Action *
(*MHD_PostDataFinished) (struct MHD_Request *req,
                        void *cls);


/**
 * @param pp_buffer_size how much data should the post processor
 *   buffer in memory
 * @param pp_stream_limit values above which length should be
 *   given to @a iter for stream processing
 * @param enc the data encoding to use,
 *            set to #MHD_HTTP_POST_ENCODING_OTHER to detect automatically
 * @param reader function to call for "oversize" values in the stream,
 *               can be NULL
 * @param reader_cls closure for @a reader
 * @param done_cb called once all data has been processed for
 *   the final action; values smaller than @a pp_stream_limit that
 *   fit into @a pp_buffer_size will be available via
 *   #MHD_request_get_values_cb(), #MHD_request_get_values_list() and
 *   #MHD_request_get_post_processor_values()
 */
MHD_EXTERN_ struct MHD_Action *
MHD_action_post_processor (struct MHD_Request *req,
                           size_t pp_buffer_size,
                           size_t pp_stream_limit,
                           enum MHD_HTTP_PostEncoding enc,
                           MHD_PostDataReader reader,
                           void *reader_cls,
                           MHD_PostDataFinished done_cb,
                           void *done_cb_cls)
MHD_FN_PAR_NONNULL_ (2);


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
 * @param nvt the name, the value and the kind of the element
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
MHD_FN_PAR_NONNULL_ (3) MHD_FN_PAR_OUT_(3);

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
 * @param urh argument for #MHD_upgrade_action()s on this @a respose.
 *        Applications must eventually use this callback to (indirectly)
 *        perform the close() action on the @a sock.
 */
typedef void
(*MHD_UpgradeHandler)(void *cls,
                      struct MHD_Request *request,
                      size_t extra_in_size,
                      const char *extra_in,
                      MHD_socket sock,
                      struct MHD_UpgradeHandle *urh);


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
 * code (#MHD_HTTP_SWITCHING_PROTOCOLS).
 * Setting correct HTTP headers for the upgrade must be done
 * manually (this way, it is possible to implement most existing
 * WebSocket versions using this API; in fact, this API might be useful
 * for any protocol switch, not just WebSockets).
 *
 * As usual, the response object can be extended with header
 * information and then be used any number of times (as long as the
 * header information is not connection-specific).
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
    MHD_DIGEST_BASE_ALGO_MD5 | MHD_DIGEST_AUTH_ALGO_NON_SESSION,

  /**
   * The 'MD5-sess' algorithm.
   * Not supported by MHD for authentication.
   */
  MHD_DIGEST_AUTH_ALGO_MD5_SESSION =
    MHD_DIGEST_BASE_ALGO_MD5 | MHD_DIGEST_AUTH_ALGO_SESSION,

  /**
   * The 'SHA-256' algorithm, non-session version.
   */
  MHD_DIGEST_AUTH_ALGO_SHA256 =
    MHD_DIGEST_BASE_ALGO_SHA256 | MHD_DIGEST_AUTH_ALGO_NON_SESSION,

  /**
   * The 'SHA-256-sess' algorithm.
   * Not supported by MHD for authentication.
   */
  MHD_DIGEST_AUTH_ALGO_SHA256_SESSION =
    MHD_DIGEST_BASE_ALGO_SHA256 | MHD_DIGEST_AUTH_ALGO_SESSION,

  /**
   * The 'SHA-512-256' (SHA-512/256) algorithm.
   */
  MHD_DIGEST_AUTH_ALGO_SHA512_256 =
    MHD_DIGEST_BASE_ALGO_SHA512_256 | MHD_DIGEST_AUTH_ALGO_NON_SESSION,

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
  MHD_DIGEST_AUTH_MULT_ALGO_INVALID = MHD_DIGEST_AUTH_ALGO_INVALID,

  /**
   * The 'MD5' algorithm, non-session version.
   */
  MHD_DIGEST_AUTH_MULT_ALGO_MD5 = MHD_DIGEST_AUTH_ALGO_MD5,

  /**
   * The 'MD5-sess' algorithm.
   * Not supported by MHD for authentication.
   * Reserved value.
   */
  MHD_DIGEST_AUTH_MULT_ALGO_MD5_SESSION = MHD_DIGEST_AUTH_ALGO_MD5_SESSION,

  /**
   * The 'SHA-256' algorithm, non-session version.
   */
  MHD_DIGEST_AUTH_MULT_ALGO_SHA256 = MHD_DIGEST_AUTH_ALGO_SHA256,

  /**
   * The 'SHA-256-sess' algorithm.
   * Not supported by MHD for authentication.
   * Reserved value.
   */
  MHD_DIGEST_AUTH_MULT_ALGO_SHA256_SESSION =
    MHD_DIGEST_AUTH_ALGO_SHA256_SESSION,

  /**
   * The 'SHA-512-256' (SHA-512/256) algorithm, non-session version.
   */
  MHD_DIGEST_AUTH_MULT_ALGO_SHA512_256 = MHD_DIGEST_AUTH_ALGO_SHA512_256,

  /**
   * The 'SHA-512-256-sess' (SHA-512/256 session) algorithm.
   * Not supported by MHD for authentication.
   * Reserved value.
   */
  MHD_DIGEST_AUTH_MULT_ALGO_SHA512_256_SESSION =
    MHD_DIGEST_AUTH_ALGO_SHA512_256_SESSION,

  /**
   * SHA-256 or SHA-512/256 non-session algorithm, MHD will choose
   * the preferred or the matching one.
   */
  MHD_DIGEST_AUTH_MULT_ALGO_SHA_ANY_NON_SESSION =
    MHD_DIGEST_AUTH_ALGO_SHA256 | MHD_DIGEST_AUTH_ALGO_SHA512_256,

  /**
   * Any non-session algorithm, MHD will choose the preferred or
   * the matching one.
   */
  MHD_DIGEST_AUTH_MULT_ALGO_ANY_NON_SESSION =
    (0x3F) | MHD_DIGEST_AUTH_ALGO_NON_SESSION,

  /**
   * The SHA-256 or SHA-512/256 session algorithm.
   * Not supported by MHD.
   * Reserved value.
   */
  MHD_DIGEST_AUTH_MULT_ALGO_SHA_ANY_SESSION =
    MHD_DIGEST_AUTH_ALGO_SHA256_SESSION
    | MHD_DIGEST_AUTH_ALGO_SHA512_256_SESSION,

  /**
   * Any session algorithm.
   * Not supported by MHD.
   * Reserved value.
   */
  MHD_DIGEST_AUTH_MULT_ALGO_ANY_SESSION =
    (0x3F) | MHD_DIGEST_AUTH_ALGO_SESSION,

  /**
   * The MD5 algorithm, session or non-session.
   * Currently supported as non-session only.
   */
  MHD_DIGEST_AUTH_MULT_ALGO_MD5_ANY =
    MHD_DIGEST_AUTH_MULT_ALGO_MD5 | MHD_DIGEST_AUTH_MULT_ALGO_MD5_SESSION,

  /**
   * The SHA-256 algorithm, session or non-session.
   * Currently supported as non-session only.
   */
  MHD_DIGEST_AUTH_MULT_ALGO_SHA256_ANY =
    MHD_DIGEST_AUTH_MULT_ALGO_SHA256
    | MHD_DIGEST_AUTH_MULT_ALGO_SHA256_SESSION,

  /**
   * The SHA-512/256 algorithm, session or non-session.
   * Currently supported as non-session only.
   */
  MHD_DIGEST_AUTH_MULT_ALGO_SHA512_256_ANY =
    MHD_DIGEST_AUTH_MULT_ALGO_SHA512_256
    | MHD_DIGEST_AUTH_MULT_ALGO_SHA512_256_SESSION,

  /**
   * The SHA-256 or SHA-512/256 algorithm, session or non-session.
   * Currently supported as non-session only.
   */
  MHD_DIGEST_AUTH_MULT_ALGO_SHA_ANY_ANY =
    MHD_DIGEST_AUTH_MULT_ALGO_SHA_ANY_NON_SESSION
    | MHD_DIGEST_AUTH_MULT_ALGO_SHA_ANY_SESSION,

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
 * @param algo the algorithm for userhash calculations
 * @param username the username
 * @param realm the realm
 * @param[out] userhash_bin the output buffer for userhash as binary data;
 *                          if this function succeeds, then this buffer has
 *                          #MHD_digest_get_hash_size(algo) bytes of userhash
 *                          upon return
 * @param bin_buf_size the size of the @a userhash_bin buffer, must be
 *                     at least #MHD_digest_get_hash_size(algo) bytes long
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
                               void *userhash_bin)
MHD_FN_PURE_
MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_CSTR_(2) MHD_FN_PAR_CSTR_(3)
MHD_FN_PAR_OUT_SIZE_(4,3);


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
 * @param algo the algorithm for userhash calculations
 * @param username the username
 * @param realm the realm
 * @param bin_buf_size the size of the @a userhash_bin buffer, must be
 *                     at least #MHD_digest_get_hash_size(algo)*2+1 chars long
 * @param[out] userhash_hex the output buffer for userhash as hex string;
 *                          if this function succeeds, then this buffer has
 *                          #MHD_digest_get_hash_size(algo)*2 chars long
 *                          userhash zero-terminated string
 * @return MHD_SC_OK on success,
 *         error code otherwise
 * @sa #MHD_digest_auth_calc_userhash()
 * @note Available since #MHD_VERSION 0x00097701
 * @ingroup authentication
 */
MHD_EXTERN_ enum MHD_StatusCode
MHD_digest_auth_calc_userhash_hex (
  enum MHD_DigestAuthAlgo algo,
  const char *username,
  const char *realm,
  size_t hex_buf_size,
  char userhash_hex[MHD_FN_PAR_DYN_ARR_SIZE_(hex_buf_size)])
MHD_FN_PURE_
MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_CSTR_(2) MHD_FN_PAR_CSTR_(3)
MHD_FN_PAR_OUT_SIZE_(4,3);
;


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
   * The valid size should be #MHD_digest_get_hash_size(algo) bytes.
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
  struct MHD_StringNull realm;

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
  struct MHD_String username;

  /**
   * The userhash string.
   * Valid only if username type is userhash.
   * This is unqoted string without decoding of the hexadecimal
   * digits (as provided by the client).
   * The buffer pointed by the @a userhash_hex becomes invalid when the pointer
   * to the structure is freed by #MHD_free().
   * @sa #MHD_digest_auth_calc_userhash_hex()
   */
  struct MHD_String userhash_hex;

  /**
   * The userhash decoded to binary form.
   * Used only if username type is userhash, always NULL otherwise.
   * When not NULL, this points to binary sequence @a userhash_hex_len /2 bytes
   * long.
   * The valid size should be #MHD_digest_get_hash_size(algo) bytes.
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
MHD_FN_PAR_NONNULL_(1)
MHD_FN_PAR_NONNULL_(2) MHD_FN_PAR_CSTR_(2)
MHD_FN_PAR_NONNULL_(3) MHD_FN_PAR_CSTR_(3)
MHD_FN_PAR_NONNULL_(4) MHD_FN_PAR_CSTR_(4);


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
 * @param[out] userdigest_bin the output buffer for userdigest;
 *                            if this function succeeds, then this buffer has
 *                            #MHD_digest_get_hash_size(algo) bytes of
 *                            userdigest upon return
 * @param userdigest_bin the size of the @a userdigest_bin buffer, must be
 *                       at least #MHD_digest_get_hash_size(algo) bytes long
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
MHD_FN_PAR_CSTR_(2)
MHD_FN_PAR_CSTR_(3)
MHD_FN_PAR_CSTR_(4)
MHD_FN_PAR_OUT_SIZE_(6,5);


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
MHD_FN_PAR_CSTR_(2)
MHD_FN_PAR_CSTR_(3)
MHD_FN_PAR_CSTR_(4);


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
 *                 code, must not have #MHD_RESP_OPT_BOOL_REUSABLE enabled;
 *                 the NULL is tolerated (the result is NULL)
 * @param signal_stale if set to #MHD_YES then indication of stale nonce used in
 *                     the client's request is signalled by adding 'stale=true'
 *                     to the authentication header, this instructs the client
 *                     to retry immediately with the new nonce and the same
 *                     credentials, without asking user for the new password
 * @param mqop the QOP to use
 * @param malgo digest algorithm to use; if several algorithms are allowed
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
MHD_queue_auth_required_response (struct MHD_Request *request,
                                  const char *realm,
                                  const char *opaque,
                                  const char *domain,
                                  struct MHD_Response *response,
                                  enum MHD_Bool signal_stale,
                                  enum MHD_DigestAuthMultiQOP mqop,
                                  enum MHD_DigestAuthMultiAlgo algo,
                                  enum MHD_Bool userhash_support,
                                  enum MHD_Bool prefer_utf8)
MHD_FN_PAR_NONNULL_ (1) MHD_FN_PAR_NONNULL_ (2) MHD_FN_PAR_CSTR_(2)
MHD_FN_PAR_CSTR_(3) MHD_FN_PAR_CSTR_(4) MHD_FN_PAR_NONNULL_ (5);


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
 * See RFC 7617#section-2 for details.
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
 *                 code, must not have #MHD_RESP_OPT_BOOL_REUSABLE enabled;
 *                 the NULL is tolerated (the result is NULL)
 * @return pointer to the action on success,
 *         NULL on failure
 * @ingroup authentication
 */
MHD_EXTERN_ const struct MHD_Action *
MHD_queue_basic_auth_required_response (struct MHD_Connection *connection,
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
   * If disabled, no #MHD_COOKIE_KIND will be generated by MHD.
   * The result is placed in @a v_bool member.
   */
  MHD_LIB_INFO_FIXED_HAS_COOKIE_PARSING = 14
  ,
  /**
   * Get whether postprocessor is supported. If supported then
   * functions #MHD_create_post_processor(), #MHD_post_process() and
   * #MHD_destroy_post_processor() can
   * be used.
   * The result is placed in @a v_bool member.
   */
  MHD_LIB_INFO_FIXED_HAS_POSTPROCESSOR = 15
  ,
  /**
   * Get whether HTTP "Upgrade" is supported.
   * If supported then #MHD_ALLOW_UPGRADE, #MHD_upgrade_action() and
   * #MHD_create_response_for_upgrade() can be used.
   * The result is placed in @a v_bool member.
   */
  MHD_LIB_INFO_FIXED_HAS_UPGRADE = 16
  ,
  /**
   * Get whether HTTP Basic authorization is supported. If supported
   * then functions #MHD_basic_auth_get_username_password and
   * #MHD_queue_basic_auth_fail_response can be used.
   * The result is placed in @a v_bool member.
   */
  MHD_LIB_INFO_FIXED_HAS_BASIC_AUTH = 20
  ,
  /**
   * Get whether HTTP Digest authorization is supported. If
   * supported then options #MHD_OPTION_DIGEST_AUTH_RANDOM,
   * #MHD_OPTION_NONCE_NC_SIZE and
   * #MHD_digest_auth_check() can be used.
   * The result is placed in @a v_bool member.
   */
  MHD_LIB_INFO_FIXED_HAS_DIGEST_AUTH = 21
  ,
  /**
   * Get whether the early version the Digest Authorization (RFC 2069) is
   * supported (digest authorisation without QOP parameter).
   * Since #MHD_VERSION 0x00097701 it is always supported if Digest Auth
   * module is built.
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
   * Get whether TCP Fast Open is supported. If supported then
   * flag #MHD_USE_TCP_FASTOPEN and option
   * #MHD_OPTION_TCP_FASTOPEN_QUEUE_SIZE can be used.
   * The result is placed in @a v_bool member.
   */
  MHD_LIB_INFO_FIXED_HAS_TCP_FASTOPEN = 53
  ,
  /**
   * Get whether MHD support automatic detection of bind port number.
   * @sa #MHD_DAEMON_INFO_BIND_PORT
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
   * If supported then #MHD_create_response_from_fd(),
   * #MHD_create_response_from_fd64 #MHD_create_response_from_fd_at_offset()
   * and #MHD_create_response_from_fd_at_offset64() can be used with sizes and
   * offsets larger than 2 GiB. If not supported value of size+offset is
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
   * Get whether option #MHD_OPTION_HTTPS_CERT_CALLBACK is
   * supported.
   * The result is placed in @a v_bool member.
   */
  MHD_LIB_INFO_FIXED_HAS_TLS_CERT_CALLBACK = 101
  ,
  /**
  * Get whether password encrypted private key for HTTPS daemon is
  * supported. If supported then option
  * ::MHD_OPTION_HTTPS_KEY_PASSWORD can be used.
   * The result is placed in @a v_bool member.
  */
  MHD_LIB_INFO_FIXED_HAS_TLS_KEY_PASSWORD = 102
  ,
  /**
   * Get whether option #MHD_OPTION_HTTPS_CERT_CALLBACK2 is
   * supported.
   * The result is placed in @a v_bool member.
   */
  MHD_LIB_INFO_FIXED_HAS_TLS_CERT_CALLBACK2 = 103
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
   * The type of digest algorithm implemtation
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
MHD_FN_PAR_NONNULL_(2) MHD_FN_PAR_OUT_SIZE_(2,3)
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
    MHD_lib_get_info_fixed_sz((info),(data),sizeof(*(data)))

/**
 * Types of information about MHD,
 * used by #MHD_lib_get_dymanic_info_sz().
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
 * The data provided by #MHD_lib_get_dynamic_info_sz().
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
MHD_lib_get_info_dynamic_sz (enum MHD_LibDynamicInfo info_type,
                             union MHD_LibDynamicInfoData *return_data,
                             size_t return_data_size)
MHD_FN_PAR_NONNULL_(2) MHD_FN_PAR_OUT_SIZE_(2,3);

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
    MHD_lib_get_info_fixed_sz((info),(data),sizeof(*(data)))


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
   * Note: if port '0' was specified for #MHD_option_port(), returned
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
  MHD_socket v_socket;

  /**
   * File descriptor, except sockets
   */
  int v_fd;

  /**
   * Port number
   */
  uint_fast16_t v_port;

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
MHD_FN_PAR_NONNULL_ (3) MHD_FN_PAR_INOUT_SIZE_(3,4)
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
   * Available only for daemons stated in #MHD_TM_EXTERNAL_PERIODIC,
   * #MHD_TM_EXTERNAL_EVENT_LOOP_CB_LEVEL, #MHD_TM_EXTERNAL_EVENT_LOOP_CB_EDGE
   * or #MHD_TM_EXTERNAL_SINGLE_FD_WATCH modes.
   * The result is placed in @a v_uint64 member.
   */
  MHD_DAEMON_INFO_DYNAMIC_MAX_TIME_TO_WAIT = 1
  ,
  /**
   * Request the number of current connections handled by the daemon.
   * No extra arguments should be passed.
   * Note: when using MHD in external polling mode, this type of request
   * could be used only when #MHD_run()/#MHD_run_from_select is not
   * working in other thread at the same time.
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
  MHD_DAEMON_INFO_FIXED_SENTINEL = 65535
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
MHD_FN_PAR_NONNULL_ (3) MHD_FN_PAR_INOUT_SIZE_(3,4);

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
  MHD_socket v_fd;

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
MHD_FN_PAR_NONNULL_ (3) MHD_FN_PAR_INOUT_SIZE_(3,4)
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
  MHD_connection_get_info_fixed_sz ((connection),(info_type),(return_value), \
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
   * (possibly) set during a #MHD_NotifyConnectionCallback or provided vai
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
MHD_FN_PAR_NONNULL_ (3) MHD_FN_PAR_INOUT_SIZE_(3,4);


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
  MHD_connection_get_info_dynamic_sz ((connection),(info_type),(return_value), \
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
MHD_FN_PAR_NONNULL_ (3) MHD_FN_PAR_INOUT_SIZE_(3,4)
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
MHD_FN_PAR_NONNULL_ (3) MHD_FN_PAR_INOUT_SIZE_(3,4);


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
  enum MHD_HTTP_Version v_http_ver;

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
MHD_FN_PAR_NONNULL_ (3) MHD_FN_PAR_INOUT_SIZE_(3,4)
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
   * Get the number of GET parameters (the decoded part of the origianl
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
  MHD_REQUEST_INFO_DYNAMIC_UPLOAD_SIZE_PROCESSED = 12
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
  MHD_REQUEST_INFO_DYNAMIC_UPLOAD_SIZE_TO_PROCESS = 13
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
   * Returns the client-specific pointer to a `void *` that
   * is specific to this request. // TODO: check reference
   * The result is placed in @a v_pvoid member.
   */
  MHD_REQUEST_INFO_DYNAMIC_CLIENT_CONTEXT = 31
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
   * The pointer to void
   */
  void *v_pvoid;

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
MHD_FN_PAR_NONNULL_ (3) MHD_FN_PAR_INOUT_SIZE_(3,4)
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
 *
 * @param cls user specified value
 * @param file where the error occurred, could be NULL if MHD built without
 *             messages (only for embedded project)
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
  MHD_lib_set_panic_func (MHD_STATIC_CAST_(MHD_PanicCallback,NULL),NULL)


#endif
