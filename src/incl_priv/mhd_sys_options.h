/*
  This file is part of libmicrohttpd
  Copyright (C) 2016-2024 Karlson2k (Evgeny Grin)

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
 * @file src/include/mhd_sys_options.h
 * @brief  additional automatic macros for MHD_config.h
 * @author Karlson2k (Evgeny Grin)
 *
 * This file includes MHD_config.h and adds automatic macros based on values
 * in MHD_config.h, compiler built-in macros and commandline-defined macros
 * (but not based on values defined in other headers). Works also as a guard
 * to prevent double inclusion of MHD_config.h
 *
 * This file must be included always before other headers as this header
 * defines macros that control behaviour of other included headers.
 */

#ifndef MHD_SYS_OPTIONS_H
#define MHD_SYS_OPTIONS_H 1

#ifndef HAVE_CONFIG_H
#error HAVE_CONFIG_H must be defind
#endif

#include "mhd_config.h"

/**
 * Macro to make it easy to mark text for translation. Note that
 * we do not actually call gettext() in MHD, but we do make it
 * easy to create a ".po" file so that applications that do want
 * to translate error messages can do so.
 */
#define _(String) (String)

#ifdef HAVE_ATTR_VISIBILITY_DEFAULT
#  define MHD_VISIBILITY_EXTERN __attribute__((visibility ("default")))
#else
#  define MHD_VISIBILITY_EXTERN /* empty */
#endif

#if ! defined(_WIN32) || \
  (! defined(DLL_EXPORT)    /* Defined by libtool for shared version */ \
  && ! defined(MHD_W32DLL) /* Defined by MS VS projects for MHD DLL */)
#  define MHD_EXPORTED /* empty */
#else
#  define MHD_EXPORTED __declspec(dllexport)
#endif

#if defined(HAVE_ATTR_USED) \
  && (defined(PIC) || defined(DLL_EXPORT) || defined(MHD_W32DLL))
/* Used externally, only for functions in shared library */
#  define MHD_EXTERN_USED __attribute__((used))
#else
#  define MHD_EXTERN_USED /* empty */
#endif

#if defined(MHD_EXTERN_) && defined(BUILDING_MHD_LIB)
#  undef MHD_EXTERN_
#endif /* MHD_EXTERN_ && BUILDING_MHD_LIB */

#ifndef MHD_EXTERN_
#  ifdef BUILDING_MHD_LIB
/* Building MHD itself */
#    define MHD_EXTERN_ \
        extern MHD_VISIBILITY_EXTERN MHD_EXPORTED MHD_EXTERN_USED
#  else  /* ! BUILDING_MHD_LIB */
/* Test or example code, using MHD as a library */
#    define MHD_EXTERN_ extern
#  endif /* ! BUILDING_MHD_LIB */
#endif  /* ! MHD_EXTERN_ */

#ifdef HAVE_ATTR_VISIBILITY_HIDDEN
/* To be used with internal non-static functions, that can be potentially used
 * externally via function pointers */
#  define MHD_VISIBILITY_HIDDEN __attribute__((visibility ("hidden")))
#else
/* To be used with internal non-static functions, that can be potentially used
 * externally via function pointers */
#  define MHD_VISIBILITY_HIDDEN /* empty */
#endif

#ifdef HAVE_ATTR_VISIBILITY_INTERNAL
/* To be used with internal non-static functions */
#  define MHD_VISIBILITY_INTERNAL __attribute__((visibility ("internal")))
#else
/* To be used with internal non-static functions */
#  define MHD_VISIBILITY_INTERNAL MHD_VISIBILITY_HIDDEN
#endif

/* To be used with internal non-static functions */
#define MHD_INTERNAL MHD_VISIBILITY_INTERNAL

#ifdef HAVE_ATTR_PURE
#  define MHD_FN_PURE_ __attribute__((pure))
#else
#  define MHD_FN_PURE_ /* empty */
#endif

#ifdef HAVE_ATTR_CONST
#  define MHD_FN_CONST_ __attribute__((const))
#else
#  define MHD_FN_CONST_ MHD_FN_PURE_
#endif

#ifdef HAVE_ATTR_WARN_UNUSED_RES
#  define MHD_FN_MUST_CHECK_RESULT_ __attribute__ ((warn_unused_result))
#else
#  define MHD_FN_MUST_CHECK_RESULT_       /* empty */
#endif

#ifdef HAVE_ATTR_RET_NONNULL
#  define MHD_FN_RETURNS_NONNULL_ __attribute__ ((returns_nonnull))
#else
#  define MHD_FN_RETURNS_NONNULL_       /* empty */
#endif

#ifdef HAVE_ATTR_NONNULL_NUM
#  define MHD_FN_PAR_NONNULL_(param_num) __attribute__ ((nonnull (param_num)))
#else
#  define MHD_FN_PAR_NONNULL_(param_num)       /* empty */
#endif

#ifdef HAVE_ATTR_NONNULL
#  define MHD_FN_PAR_NONNULL_ALL_ __attribute__ ((nonnull))
#else
#  define MHD_FN_PAR_NONNULL_ALL_       /* empty */
#endif

#ifdef HAVE_ATTR_ACCESS_READ
#  define MHD_FN_PAR_IN_(param_num) \
        __attribute__ ((access (read_only,param_num)))
#else
#  define MHD_FN_PAR_IN_(param_num)       /* empty */
#endif

#ifdef HAVE_ATTR_ACCESS_READ_SIZE
#  define MHD_FN_PAR_IN_SIZE_(param_num,size_num) \
        __attribute__ ((access (read_only,param_num,size_num)))
#else
#  define MHD_FN_PAR_IN_SIZE_(param_num,size_num)       /* empty */
#endif

#ifdef HAVE_ATTR_ACCESS_READ_WRITE
#  define MHD_FN_PAR_OUT_(param_num) \
        __attribute__ ((access (write_only,param_num)))
#else
#  define MHD_FN_PAR_OUT_(param_num)       /* empty */
#endif

#ifdef HAVE_ATTR_ACCESS_WRITE
#  define MHD_FN_PAR_OUT_SIZE_(param_num,size_num) \
        __attribute__ ((access (write_only,param_num,size_num)))
#else
#  define MHD_FN_PAR_OUT_SIZE_(param_num,size_num)       /* empty */
#endif

#ifdef HAVE_ATTR_ACCESS_READ_WRITE
#  define MHD_FN_PAR_INOUT_(param_num) \
        __attribute__ ((access (read_write,param_num)))
#else
#  define MHD_FN_PAR_INOUT_(param_num)       /* empty */
#endif

#ifdef HAVE_ATTR_ACCESS_READ_WRITE_SIZE
#  define MHD_FN_PAR_INOUT_SIZE_(param_num,size_num) \
        __attribute__ ((access (read_write,param_num,size_num)))
#else
#  define MHD_FN_PAR_INOUT_SIZE_(param_num,size_num)       /* empty */
#endif

#ifdef HAVE_ATTR_FD_ARG_READ
#  define MHD_FN_PAR_FD_READ_(param_num) \
        __attribute__ ((fd_arg_read (param_num)))
#else
#  define MHD_FN_PAR_FD_READ_(param_num)       /* empty */
#endif

#ifdef HAVE_ATTR_NULL_TERM_STR
#  define MHD_FN_PAR_CSTR_(param_num) \
        __attribute__ ((null_terminated_string_arg (param_num)))
#else
#  define MHD_FN_PAR_CSTR_(param_num)       /* empty */
#endif

#ifdef HAVE_FUNC_PARAM_ARR_STATIC_FIXED
#  define MHD_FN_PAR_FIX_ARR_SIZE_(size)  static size
#else
#  define MHD_FN_PAR_FIX_ARR_SIZE_(size)  size
#endif

#ifdef HAVE_FUNC_PARAM_ARR_STATIC_VAR
#  define MHD_FN_PAR_DYN_ARR_SIZE_(size)  static size
#else
#  define MHD_FN_PAR_DYN_ARR_SIZE_(size)  1
#endif

#ifdef HAVE_ATTR_ENUM_EXTNS_CLOSED
#  define MHD_FIXED_ENUM_ __attribute__((enum_extensibility (closed)))
#else
#  define MHD_FIXED_ENUM_       /* empty */
#endif

#ifdef HAVE_ATTR_FLAG_ENUM
#  define MHD_FLAGS_ENUM_ __attribute__((flag_enum))
#else
#  define MHD_FLAGS_ENUM_       /* empty */
#endif /* MHD_FLAGS_ENUM_ */

#define MHD_FIXED_FLAGS_ENUM_ MHD_FIXED_ENUM_ MHD_FLAGS_ENUM_

/* 'inline' and 'restrict' are defined in mhd_config.h if needed */
#define MHD_INLINE inline

#define MHD_RESTRICT restrict

#ifdef BUILDING_MHD_LIB
#  define MHD_FIXED_ENUM_APP_SET_ /* empty */ /* handle unknown values set by the app */
#else
#  define MHD_FIXED_ENUM_APP_SET_ MHD_FIXED_ENUM_
#endif

#ifdef BUILDING_MHD_LIB
#  define MHD_FLAGS_ENUM_APP_SET_ MHD_FLAGS_ENUM_
#else
#  define MHD_FLAGS_ENUM_APP_SET_ MHD_FLAGS_ENUM_
#endif

#ifdef BUILDING_MHD_LIB
#  define MHD_FIXED_FLAGS_ENUM_APP_SET_ MHD_FLAGS_ENUM_ /* handle unknown values set by the app */
#else
#  define MHD_FIXED_FLAGS_ENUM_APP_SET_ MHD_FIXED_FLAGS_ENUM_
#endif

#ifdef BUILDING_MHD_LIB
#  define MHD_FIXED_ENUM_MHD_SET_ MHD_FIXED_ENUM_
#else
#  define MHD_FIXED_ENUM_MHD_SET_ /* empty */ /* enum can be extended in next MHD versions */
#endif

#ifdef BUILDING_MHD_LIB
#  define MHD_FLAGS_ENUM_MHD_SET_ MHD_FLAGS_ENUM_
#else
#  define MHD_FLAGS_ENUM_MHD_SET_ MHD_FLAGS_ENUM_
#endif

#ifdef BUILDING_MHD_LIB
#  define MHD_FIXED_FLAGS_ENUM_MHD_SET_ MHD_FIXED_FLAGS_ENUM_
#else
#  define MHD_FIXED_FLAGS_ENUM_MHD_SET_ MHD_FLAGS_ENUM_ /* enum can be extended in next MHD versions */
#endif

#ifdef BUILDING_MHD_LIB
#  define MHD_FIXED_ENUM_MHD_APP_SET_ /* empty */ /* handle unknown values set by the app */
#else
#  define MHD_FIXED_ENUM_MHD_APP_SET_ /* empty */ /* enum can be extended in next MHD versions */
#endif

#ifdef BUILDING_MHD_LIB
#  define MHD_FLAGS_ENUM_MHD_APP_SET_ MHD_FLAGS_ENUM_
#else
#  define MHD_FLAGS_ENUM_MHD_APP_SET_ MHD_FLAGS_ENUM_
#endif

#ifdef BUILDING_MHD_LIB
#  define MHD_FIXED_FLAGS_ENUM_MHD_APP_SET_ MHD_FLAGS_ENUM_ /* handle unknown values set by the app */
#else
#  define MHD_FIXED_FLAGS_ENUM_MHD_APP_SET_ MHD_FLAGS_ENUM_ /* enum can be extended in next MHD versions */
#endif

/**
 * Automatic string with the name of the current function
 */
#if defined(HAVE___FUNC__)
#  define MHD_FUNC_       __func__
#  define MHD_HAVE_MHD_FUNC_ 1
#elif defined(HAVE___FUNCTION__)
#  define MHD_FUNC_       __FUNCTION__
#  define MHD_HAVE_MHD_FUNC_ 1
#elif defined(HAVE___PRETTY_FUNCTION__)
#  define MHD_FUNC_       __PRETTY_FUNCTION__
#  define MHD_HAVE_MHD_FUNC_ 1
#else
#  define MHD_FUNC_       "**name unavailable**"
#  ifdef MHD_HAVE_MHD_FUNC_
#    undef MHD_HAVE_MHD_FUNC_
#  endif /* MHD_HAVE_MHD_FUNC_ */
#endif

/* Some platforms (FreeBSD, Solaris, W32) allow to override
   default FD_SETSIZE by defining it before including
   headers. */
#ifdef FD_SETSIZE
/* FD_SETSIZE defined in command line or in mhd_config.h */
#elif defined(_WIN32) || defined(__CYGWIN__)
/* Platform with WinSock and without overridden FD_SETSIZE */
#  ifdef _WIN64
#    define FD_SETSIZE 4096 /* Override default small value (64) */
#  else
#    define FD_SETSIZE 1024 /* Override default small value (64) */
#  endif
#else  /* !FD_SETSIZE && !W32 */
/* System default value of FD_SETSIZE is used */
#  define MHD_FD_SETSIZE_IS_DEFAULT_ 1
#endif /* !FD_SETSIZE && !W32 */

#if defined(HAVE_LINUX_SENDFILE) || defined(HAVE_FREEBSD_SENDFILE) || \
  defined(HAVE_DARWIN_SENDFILE)
/* Have any supported sendfile() function. */
#  define mhd_USE_SENDFILE 1
#endif /* HAVE_LINUX_SENDFILE || HAVE_FREEBSD_SENDFILE
          || HAVE_DARWIN_SENDFILE */

#if defined(mhd_THREADS_KIND_POSIX) || defined(mhd_THREADS_KIND_W32)
#  ifndef MHD_SUPPORT_THREADS
#    define MHD_SUPPORT_THREADS 1
#  endif
#endif /* mhd_THREADS_KIND_POSIX || mhd_THREADS_KIND_W32 */

#if defined(_WIN32) && ! defined(__CYGWIN__)
/**
 * Defined if the platform is native W32.
 * Not define on Cygwin.
 */
#  define mhd_W32_NATIVE        1
#endif
/**
 * Macro to drop 'const' qualifier from pointer.
 * Try to avoid compiler warning.
 * To be used *only* to deal with broken external APIs, which require non-const
 * pointer to unmodifiable data.
 * Must not be used to transform pointers for internal MHD needs.
 */
#ifdef HAVE_UINTPTR_T
#  define mhd_DROP_CONST(ptr)  ((void *) ((uintptr_t) ((const void *) (ptr))))
#elif defined(HAVE_INTPTR_T)
#  define mhd_DROP_CONST(ptr)  ((void *) ((intptr_t) ((const void *) (ptr))))
#else
#  define mhd_DROP_CONST(ptr)  ((void *) ((const void *) (ptr)))
#endif

/**
 * Cast signed integer to pointer
 */
#if defined(HAVE_INTPTR_T)
#  define mhd_INT_TO_PTR(i)  ((void *) ((intptr_t) (i)))
#else
#  define mhd_INT_TO_PTR(i)  ((void *) (i))
#endif

/**
 * Cast unsigned integer to pointer
 */
#if defined(HAVE_UINTPTR_T)
#  define mhd_UINT_TO_PTR(i)  ((void *) ((uintptr_t) (i)))
#else
#  define mhd_UINT_TO_PTR(i)  ((void *) (i))
#endif


#if defined(OS390)
#define _OPEN_THREADS
#define _OPEN_SYS_SOCK_IPV6
#define _OPEN_MSGQ_EXT
#define _LP64
#endif

#if defined(_WIN32) && ! defined(__CYGWIN__)
/* Declare POSIX-compatible names */
#  define _CRT_DECLARE_NONSTDC_NAMES 1
/* Do not warn about POSIX name usage */
#  define _CRT_NONSTDC_NO_WARNINGS 1
#  ifndef _WIN32_WINNT
#    define _WIN32_WINNT 0x0600
#  else /* _WIN32_WINNT */
#    if _WIN32_WINNT < 0x0501
#error "Headers for Windows XP or later are required"
#    endif /* _WIN32_WINNT < 0x0501 */
#  endif /* _WIN32_WINNT */
#  ifndef WIN32_LEAN_AND_MEAN
/* Do not include unneeded parts of W32 headers. */
#    define WIN32_LEAN_AND_MEAN 1
#  endif /* !WIN32_LEAN_AND_MEAN */
#endif /* _WIN32 && ! __CYGWIN__ */

#if defined(__MINGW32__)
#  ifdef __USE_MINGW_ANSI_STDIO
#    define __USE_MINGW_ANSI_STDIO 0 /* Force use native printf, the code is well-adapted */
#  endif
#endif

#if defined(__VXWORKS__) || defined(__vxworks) || defined(OS_VXWORKS)
#define RESTRICT __restrict__
#endif /* __VXWORKS__ || __vxworks || OS_VXWORKS */

#if defined(__linux__) && \
  (defined(HAVE_SENDFILE64) || defined(HAVE_LSEEK64) || defined(HAVE_PREAD64))
#  if ! defined(_LARGEFILE64_SOURCE)
/* On Linux, special macro is required to enable definitions of some xxx64 functions */
#    define _LARGEFILE64_SOURCE 1
#  endif
#endif

#ifdef HAVE_C11_GMTIME_S
/* Special macro is required to enable C11 definition of gmtime_s() function */
#define __STDC_WANT_LIB_EXT1__ 1
#endif /* HAVE_C11_GMTIME_S */

/* Ensure that exactly one of the two macros is always defined */
#if defined(NDEBUG) && defined(_DEBUG)
#error Both _DEBUG and NDEBUG are defined
#elif ! defined(_DEBUG) && ! defined(NDEBUG)
#  ifndef DEBUG /* Used by some toolchains */
#    define NDEBUG 1 /* Use NDEBUG by default */
#  else  /* DEBUG */
#    define _DEBUG 1 /* Non-standard macro */
#  endif /* DEBUG */
#endif /* !_DEBUG && !NDEBUG */

#if defined(MHD_FAVOR_FAST_CODE) && defined(MHD_FAVOR_SMALL_CODE)
#error MHD_FAVOR_FAST_CODE and MHD_FAVOR_SMALL_CODE are both defined.
#error Cannot favor speed and size at the same time.
#endif /* MHD_FAVOR_FAST_CODE && MHD_FAVOR_SMALL_CODE */

/* Define MHD_FAVOR_FAST_CODE to force fast code path or
   define MHD_FAVOR_SMALL_CODE to choose compact code path */
#if ! defined(MHD_FAVOR_FAST_CODE) && ! defined(MHD_FAVOR_SMALL_CODE)
/* Try to detect user preferences */
/* Defined by GCC and many compatible compilers */
#  if defined(__OPTIMIZE_SIZE__)
#    define MHD_FAVOR_SMALL_CODE 1
#  elif defined(__OPTIMIZE__)
#    define MHD_FAVOR_FAST_CODE 1
#  endif /* __OPTIMIZE__ */
#endif /* !MHD_FAVOR_FAST_CODE && !MHD_FAVOR_SMALL_CODE */

#if ! defined(MHD_FAVOR_FAST_CODE) && ! defined(MHD_FAVOR_SMALL_CODE)
/* Use faster code by default */
#  define MHD_FAVOR_FAST_CODE 1
#endif /* !MHD_FAVOR_FAST_CODE && !MHD_FAVOR_SMALL_CODE */

#if defined(MHD_FAVOR_SMALL_CODE) && defined(MHD_static_inline_)
#  undef MHD_static_inline_
#  define MHD_static_inline_ static inline /* give compiler more freedom */
#endif

#ifndef MHD_ASAN_ACTIVE
#if (defined(__GNUC__) || defined(_MSC_VER)) && defined(__SANITIZE_ADDRESS__)
#define MHD_ASAN_ACTIVE 1
#elif defined(__has_feature)
#if __has_feature (address_sanitizer)
#define MHD_ASAN_ACTIVE 1
#endif /* __has_feature(address_sanitizer) */
#endif /* __has_feature */
#endif /* MHD_ASAN_ACTIVE */

#if defined(MHD_ASAN_ACTIVE) && defined(HAVE_SANITIZER_ASAN_INTERFACE_H) && \
  (defined(FUNC_PTRCOMPARE_CAST_WORKAROUND_WORKS) || \
  (defined(FUNC_ATTR_PTRCOMPARE_WORKS) && \
  defined(FUNC_ATTR_PTRSUBTRACT_WORKS)) || \
  defined(FUNC_ATTR_NOSANITIZE_WORKS))
#ifndef MHD_ASAN_POISON_ACTIVE
/* User ASAN poisoning could be used */
#warning User memory poisoning is not active
#endif /* ! MHD_ASAN_POISON_ACTIVE */
#else  /* ! (MHD_ASAN_ACTIVE && HAVE_SANITIZER_ASAN_INTERFACE_H &&
           (FUNC_ATTR_PTRCOMPARE_WORKS || FUNC_ATTR_NOSANITIZE_WORKS))   */
#ifdef MHD_ASAN_POISON_ACTIVE
#error User memory poisoning is active, but conditions are not suitable
#endif /* MHD_ASAN_POISON_ACTIVE */
#endif /* ! (MHD_ASAN_ACTIVE && HAVE_SANITIZER_ASAN_INTERFACE_H &&
           (FUNC_ATTR_PTRCOMPARE_WORKS || FUNC_ATTR_NOSANITIZE_WORKS))   */

#ifndef _MSC_FULL_VER
#  define mhd_DATA_TRUNCATION_RUNTIME_CHECK_DISABLE /* empty */
#  define mhd_DATA_TRUNCATION_RUNTIME_CHECK_RESTORE /* empty */
#else  /* _MSC_FULL_VER */
#  define mhd_DATA_TRUNCATION_RUNTIME_CHECK_DISABLE \
        __pragma(runtime_checks("c", off))
#  define mhd_DATA_TRUNCATION_RUNTIME_CHECK_RESTORE \
        __pragma(runtime_checks("c", restore))
#endif /* _MSC_FULL_VER */


#if ! defined(mhd_W32_NATIVE)
/**
 * Indicate that suppression of SIGPIPE is required for some network
 * system calls.
 */
#  define mhd_SEND_SPIPE_SUPPRESS_NEEDED     1
#endif

#ifdef _DEBUG
#  ifndef MHD_NO_TLS_DEBUG_MESSAGES
#    ifndef mhd_USE_TLS_DEBUG_MESSAGES
/**
 * Enable debugging output on TLS library (if possible)
 */
#      define mhd_USE_TLS_DEBUG_MESSAGES    1
#    endif
#  endif
#endif

#ifndef mhd_DEBUG_EXTR_EVENTS
/* Use debug-print for external events processing */
/* #  define mhd_DEBUG_EXTR_EVENTS 1 */
#endif

#ifndef mhd_DEBUG_SUSPEND_RESUME
/* Use debug-print for suspending and resuming of the requests */
/* #  define mhd_DEBUG_SUSPEND_RESUME 1 */
#endif

#ifndef mhd_DEBUG_CONN_ADD_CLOSE
/* Use debug-print for adding and closing of the connections */
/* #  define mhd_DEBUG_CONN_ADD_CLOSE 1 */
#endif

#ifndef MHD_AUTH_DIGEST_DEF_TIMEOUT
#  define MHD_AUTH_DIGEST_DEF_TIMEOUT 90
#endif /* ! MHD_AUTH_DIGEST_DEF_TIMEOUT */
#ifndef MHD_AUTH_DIGEST_DEF_MAX_NC
#  define MHD_AUTH_DIGEST_DEF_MAX_NC 1000
#endif /* ! MHD_AUTH_DIGEST_DEF_MAX_NC */

/* Eclipse parse compatibility */
#ifdef __CDT_PARSER__
#  undef MHD_NORETURN_
#  define MHD_NORETURN_ __attribute__((__noreturn__))
#endif

/* Avoid interference with third-party headers */
#undef HAVE_CONFIG_H

#endif /* MHD_SYS_OPTIONS_H */
