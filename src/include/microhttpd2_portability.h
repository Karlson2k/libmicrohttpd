MHD_C_DECLRATIONS_START_HERE_
/* *INDENT-OFF* */


// FIXME: Move this block to the main header for higher visibility?

/* If generic headers don't work on your platform, include headers which define
   'va_list', 'size_t', 'uint_least16_t', 'uint_fast32_t', 'uint_fast64_t',
   'struct sockaddr', and then "#define MHD_HAVE_SYS_HEADERS_INCLUDED" before
   including "microhttpd2.h".
   When 'MHD_HAVE_SYS_HEADERS_INCLUDED' is defined the following "standard"
   includes won't be used (which might be a good idea, especially on platforms
   where they do not exist).
   */
#ifndef MHD_HAVE_SYS_HEADERS_INCLUDED
#  include <stdarg.h>
#  ifndef MHD_SYS_BASE_TYPES_H
     /* Headers for uint_fastXX_t, size_t */
#    include <stdint.h>
#    include <stddef.h>
#    include <sys/types.h> /* This header is actually optional */
#  endif
#  ifndef MHD_SYS_SOCKET_TYPES_H
     /* Headers for 'struct sockaddr' */
#    if !defined(_WIN32) || defined(__CYGWIN__)
#      include <sys/socket.h>
#    else
     /* Prevent conflict of <winsock.h> and <winsock2.h> */
#      if !defined(_WINSOCK2API_) && !defined(_WINSOCKAPI_)
#        ifndef WIN32_LEAN_AND_MEAN
       /* Do not use unneeded parts of W32 headers. */
#          define WIN32_LEAN_AND_MEAN 1
#        endif /* !WIN32_LEAN_AND_MEAN */
#        include <winsock2.h>
#      endif
#    endif
#  endif
#endif

#ifndef __cplusplus
#  define MHD_STATIC_CAST_(type,value) \
        ((type) (value))
#else
#  define MHD_STATIC_CAST_(type,value) \
        (static_cast<type>(value))
#endif

/**
 * Constant used to indicate that options array is limited by zero-termination
 */
#define MHD_OPTIONS_ARRAY_MAX_SIZE \
        MHD_STATIC_CAST_ (size_t,~MHD_STATIC_CAST_(size_t, 0))


/* Define MHD_W32DLL when using MHD as W32 .DLL to speed up linker a little */
#ifndef MHD_EXTERN_
#  if ! defined(_WIN32) || ! defined(MHD_W32LIB)
#    define MHD_EXTERN_ extern
#  else /* defined(_WIN32) && defined(MHD_W32LIB) */
#    define MHD_EXTERN_ extern __declspec(dllimport)
#  endif
#endif

// FIXME: Move this block to the main header for higher visibility? Users should know what is the 'MHD_Socket'

#ifndef MHD_INVALID_SOCKET
/**
 * MHD_Socket is type for socket FDs
 */
#  if ! defined(_WIN32) || defined(_SYS_TYPES_FD_SET)
#    define MHD_POSIX_SOCKETS 1
typedef int MHD_Socket;
#    define MHD_INVALID_SOCKET (-1)
#  else /* !defined(_WIN32) || defined(_SYS_TYPES_FD_SET) */
#    define MHD_WINSOCK_SOCKETS 1
typedef SOCKET MHD_Socket;
#    define MHD_INVALID_SOCKET (INVALID_SOCKET)
#  endif /* !defined(_WIN32) || defined(_SYS_TYPES_FD_SET) */
#endif /* MHD_INVALID_SOCKET */


/* Compiler macros for internal needs */

/* Stringify macro parameter literally */
#define MHD_MACRO_STR__(x) #x
/* Stringify macro parameter after expansion */
#define MHD_MACRO_STR_(x) MHD_MACRO_STR__ (x)

/* Concatenate macro parameters literally */
#define MHD_MACRO_CAT__(a,b) a ## b
/* Concatenate macro parameters after expansion */
#define MHD_MACRO_CAT_(a,b) MHD_MACRO_CAT__ (a,b)

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
  && (! defined(__STDC__) || defined(_MSC_EXTENSIONS))
/* Visual C with extensions */
#    define MHD_HAS_MSC_EXTENSION 1
#  endif
#else  /* ! _MSC_FULL_VER */
#  define MHD_MSC_MINV(version) (0)
#endif /* ! _MSC_FULL_VER */

#if defined(__STDC_VERSION__) && ! defined(__cplusplus)
#  define MHD_C_MINV(version)   (__STDC_VERSION__ >= (version))
#else
#  define MHD_C_MINV(version)   (0)
#endif

#define MHD_C_MINV_99     MHD_C_MINV (199901)


#ifndef __cplusplus
#  define MHD_CXX_MINV(version) (0)
#elif ! defined(_MSC_FULL_VER) || ! defined(_MSVC_LANG)
#  define MHD_CXX_MINV(version) ((__cplusplus+0) >= version)
#else
#  define MHD_CXX_MINV(version) \
        ((__cplusplus+0) >= version) || ((_MSVC_LANG+0) >= version)
#endif

/* Use compound literals? */
#if ! defined(MHD_NO_COMPOUND_LITERALS)
#  if ! defined(MHD_USE_COMPOUND_LITERALS)
#    if MHD_C_MINV_99
#      define MHD_USE_COMPOUND_LITERALS   1
#    elif MHD_GNUC_MINV (3,0) && ! defined(__STRICT_ANSI__)
/* This may warn in "pedantic" compilation mode */
#      define MHD_USE_COMPOUND_LITERALS   1
/* Compound literals are an extension */
#      define MHD_USE_COMPOUND_LITERALS_EXT     1
#    elif defined(MHD_HAS_MSC_EXTENSION) && MHD_MSC_MINV (1800) \
  && ! defined(__cplusplus)
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
#  if ! defined(MHD_NO_COMP_LIT_FUNC_PARAMS)
#    if ! defined(MHD_USE_COMP_LIT_FUNC_PARAMS)
#      if ! defined(__cplusplus)
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
#if ! defined(MHD_NO_DESIGNATED_INIT)
#  if ! defined(MHD_USE_DESIGNATED_INIT)
#    if MHD_C_MINV_99
#      define MHD_USE_DESIGNATED_INIT   1
#    elif defined(__cplusplus) && defined(__cpp_designated_initializers)
#      define MHD_USE_DESIGNATED_INIT   1
#    elif (MHD_GNUC_MINV (3,0) && ! defined(__STRICT_ANSI__) \
  && ! defined(__cplusplus)) \
  || (defined(__GNUG__) && MHD_GNUC_MINV (4,7))
/* This may warn in "pedantic" compilation mode */
#      define MHD_USE_DESIGNATED_INIT   1
/* Designated initializers are an extension */
#      define MHD_USE_DESIGNATED_INIT_EXT       1
#    elif defined(MHD_HAS_MSC_EXTENSION) && MHD_MSC_MINV (1800)
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
#if defined(MHD_USE_DESIGNATED_INIT) && ! defined(__cplusplus)
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
#if ! defined(MHD_NO_CPP_INIT_LIST)
#  if ! defined(MHD_USE_CPP_INIT_LIST)
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
#if ! defined(MHD_NO_VARARG_MACROS)
#  if ! defined(MHD_USE_VARARG_MACROS)
#    if MHD_C_MINV_99
#      define MHD_USE_VARARG_MACROS   1
#    elif MHD_CXX_MINV (201103)
#      define MHD_USE_VARARG_MACROS   1
#    elif MHD_GNUC_MINV (3,0) && ! defined(__STRICT_ANSI__)
/* This may warn in "pedantic" compilation mode */
#      define MHD_USE_VARARG_MACROS   1
/* Variable arguments macros are an extension */
#      define MHD_USE_VARARG_MACROS_EXT 1
#    elif defined(MHD_HAS_MSC_EXTENSION) && MHD_MSC_MINV (1400)
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
#if ! defined(MHD_NO_VLA)
#  if ! defined(MHD_USE_VLA)
#    if MHD_C_MINV_99 && (! defined(__STDC_NO_VLA__))
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

#if ! defined(MHD_INLINE)
#  if defined(inline)
/* Assume that proper value of 'inline' was already defined */
#    define MHD_INLINE inline
#  elif MHD_C_MINV_99
/* C99 (and later) supports 'inline' */
#    define MHD_INLINE inline
#  elif defined(__cplusplus)
/* C++ always supports 'inline' */
#    define MHD_INLINE inline
#  elif MHD_GNUC_MINV (3,0) && ! defined(__STRICT_ANSI__)
#    define MHD_INLINE __inline__
#  elif defined(MHD_HAS_MSC_EXTENSION) && MHD_MSC_MINV (1400)
#    define MHD_INLINE __inline
#  else
#    define MHD_INLINE /* empty */
#  endif
#endif /* MHD_INLINE */

#if ! defined(MHD_RESTRICT)
#  if defined(restrict)
/* Assume that proper value of 'restrict' was already defined */
#    define MHD_RESTRICT restrict
#  elif MHD_C_MINV_99
/* C99 (and later) supports 'restrict' */
#    define MHD_RESTRICT restrict
#  elif (MHD_GNUC_MINV (3,0) || MHD_CLANG_MINV(3,0))\
  && ! defined(__STRICT_ANSI__)
#    define MHD_RESTRICT __restrict__
#  elif defined(MHD_HAS_MSC_EXTENSION) && MHD_MSC_MINV (1400)
#    define MHD_RESTRICT __restrict
#  else
#    define MHD_RESTRICT /* empty */
#  endif
#endif /* MHD_INLINE */


#if ! defined(MHD_NO__PRAGMA)
#  if MHD_GNUC_MINV (4,6) && ! defined(__clang__)
/* '_Pragma()' support was added in GCC 3.0.0
      * 'pragma push/pop' support was added in GCC 4.6.0 */
#    define MHD_WARN_PUSH_ _Pragma("GCC diagnostic push")
#    define MHD_WARN_POP_  _Pragma("GCC diagnostic pop")
#    define MHD_WARN_IGNORE_(warn) \
        _Pragma(MHD_MACRO_STR_(GCC diagnostic ignored MHD_MACRO_STR__(warn)))
#    ifdef MHD_USE_VARARG_MACROS_EXT
#      define MHD_NOWARN_VARIADIC_MACROS_ \
        MHD_WARN_PUSH_ MHD_WARN_IGNORE_ (-Wvariadic-macros)
#      define MHD_RESTORE_WARN_VARIADIC_MACROS_ MHD_WARN_POP_
#    endif
#    ifdef MHD_USE_COMPOUND_LITERALS_EXT
#      define MHD_NOWARN_COMPOUND_LITERALS_     __extension__
#      define MHD_RESTORE_WARN_COMPOUND_LITERALS_       /* empty */
#    endif
#    define MHD_NOWARN_UNUSED_FUNC_ \
        MHD_WARN_PUSH_ MHD_WARN_IGNORE_ (-Wunused-function)
#    define MHD_RESTORE_WARN_UNUSED_FUNC_ MHD_WARN_POP_
#  elif MHD_CLANG_MINV (3,1)
#    define MHD_WARN_PUSH_ _Pragma("clang diagnostic push")
#    define MHD_WARN_POP_  _Pragma("clang diagnostic pop")
#    define MHD_WARN_IGNORE_(warn) \
        _Pragma(MHD_MACRO_STR_(clang diagnostic ignored MHD_MACRO_STR__(warn)))
#    ifdef MHD_USE_VARARG_MACROS_EXT
#      define MHD_NOWARN_VARIADIC_MACROS_ \
        MHD_WARN_PUSH_ \
        MHD_WARN_IGNORE_ (-Wvariadic-macros) \
        MHD_WARN_IGNORE_ (-Wc++98-compat-pedantic)
#      define MHD_RESTORE_WARN_VARIADIC_MACROS_ MHD_WARN_POP_
#    else  /* ! MHD_USE_VARARG_MACROS_EXT */
#      define MHD_NOWARN_VARIADIC_MACROS_ \
        MHD_WARN_PUSH_ MHD_WARN_IGNORE_ (-Wc++98-compat-pedantic)
#      define MHD_RESTORE_WARN_VARIADIC_MACROS_ MHD_WARN_POP_
#    endif
#    ifdef MHD_USE_CPP_INIT_LIST
#      define MHD_NOWARN_CPP_INIT_LIST_ \
        MHD_WARN_PUSH_ MHD_WARN_IGNORE_ (-Wc++98-compat)
#      define MHD_RESTORE_WARN_CPP_INIT_LIST_ MHD_WARN_POP_
#    endif
#    ifdef MHD_USE_COMPOUND_LITERALS_EXT
#      define MHD_NOWARN_COMPOUND_LITERALS_ \
        MHD_WARN_PUSH_ MHD_WARN_IGNORE_ (-Wc99-extensions)
#      define MHD_RESTORE_WARN_COMPOUND_LITERALS_ MHD_WARN_POP_
#    endif
#    define MHD_NOWARN_UNUSED_FUNC_ \
        MHD_WARN_PUSH_ MHD_WARN_IGNORE_ (-Wunused-function)
#    define MHD_RESTORE_WARN_UNUSED_FUNC_ MHD_WARN_POP_
#  elif MHD_MSC_MINV (1500)
#    define MHD_WARN_PUSH_ __pragma(warning(push))
#    define MHD_WARN_POP_  __pragma(warning(pop))
#    define MHD_WARN_IGNORE_(warn)      __pragma(warning(disable:warn))
#    define MHD_NOWARN_UNUSED_FUNC_ \
        MHD_WARN_PUSH_ MHD_WARN_IGNORE_ (4514)
#    define MHD_RESTORE_WARN_UNUSED_FUNC_ MHD_WARN_POP_
#  endif
#endif /*!  MHD_NO__PRAGMA */

#ifndef MHD_WARN_PUSH_
#  define MHD_WARN_PUSH_        /* empty */
#endif
#ifndef MHD_WARN_POP_
#  define MHD_WARN_POP_         /* empty */
#endif
#ifndef MHD_WARN_IGNORE_
#  define MHD_WARN_IGNORE_(ignored)     /* empty */
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
#  if MHD_GNUC_MINV (4,8) && ! defined (__clang__) /* GCC >= 4.8 */
/* Print warning when the macro is processed (if not excluded from processing).
 * To be used outside other macros */
#    define MHD_DEPR_MACRO_(msg) _Pragma(MHD_MACRO_STR_(GCC warning msg))
/* Print warning message when another macro which includes this macro is used */
#    define MHD_DEPR_IN_MACRO_(msg) MHD_DEPR_MACRO_ (msg)
#  elif (MHD_CLANG_MINV (3,3) && ! defined(__apple_build_version__)) \
  || MHD_CLANG_MINV (5,0)
/* clang >= 3.3 (or XCode's clang >= 5.0) */
/* Print warning when the macro is processed (if not excluded from processing).
 * To be used outside other macros */
#    define MHD_DEPR_MACRO_(msg) _Pragma(MHD_MACRO_STR_(clang warning msg))
/* Print warning message when another macro which includes this macro is used */
#    define MHD_DEPR_IN_MACRO_(msg) MHD_DEPR_MACRO_ (msg)
#  elif MHD_MSC_MINV (1500)
/* Print warning when the macro is processed (if not excluded from processing).
 * To be used outside other macros */
#    define MHD_DEPR_MACRO_(msg) \
        __pragma(message (__FILE__ "(" MHD_MACRO_STR_ ( __LINE__) ") : " \
        "warning MHDWARN01 : " msg))
/* Print warning message when another macro which includes this macro is used */
#    define MHD_DEPR_IN_MACRO_(msg) MHD_DEPR_MACRO_ (msg)
#  elif MHD_GNUC_MINV (3,0) /* 3.0 <= GCC < 4.8 */
/* Print warning when the macro is processed (if not excluded from processing).
 * To be used outside other macros */
#    define MHD_DEPR_MACRO_(msg) _Pragma(MHD_MACRO_STR_(message msg))
#  elif MHD_CLANG_MINV (2,9)
/* Print warning when the macro is processed (if not excluded from processing).
 * To be used outside other macros */
#    define MHD_DEPR_MACRO_(msg) _Pragma(MHD_MACRO_STR_(message msg))
/* Print warning message when another macro which includes this macro is used */
#    define MHD_DEPR_IN_MACRO_(msg) MHD_DEPR_MACRO_ (msg)
/* #  elif defined(SOMEMACRO) */ /* add compiler-specific macros here if required */
#  endif
#endif /* !MHD_DEPR_MACRO_ */

#ifndef MHD_DEPR_FUNC_
#  if MHD_GNUC_MINV (5,0) || MHD_CLANG_MINV (2,9)
/* GCC >= 5.0 or clang >= 2.9 */
#    define MHD_DEPR_FUNC_(msg) __attribute__((deprecated (msg)))
#  elif  MHD_GNUC_MINV (3,1) || defined(__clang__)
/* 3.1 <= GCC < 5.0 or clang < 2.9 */
#    define MHD_DEPR_FUNC_(msg) __attribute__((__deprecated__))
#  elif MHD_MSC_MINV (1400)
/* VS 2005 or later */
#    define MHD_DEPR_FUNC_(msg) __declspec(deprecated (msg))
#  elif MHD_MSC_MINV (1310)
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
#  ifndef MHD_FIXED_ENUM_
#    if __has_attribute (enum_extensibility)
/* Enum will not be extended */
#      define MHD_FIXED_ENUM_ __attribute__((enum_extensibility (closed)))
#    endif /* enum_extensibility */
#  endif
#  ifndef MHD_FLAGS_ENUM_
#    if __has_attribute (flag_enum)
/* Enum is a bitmap */
#      define MHD_FLAGS_ENUM_ __attribute__((flag_enum))
#    endif /* flag_enum */
#  endif
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

/* Override detected value of MHD_FN_RETURNS_NONNULL_ by defining it before
 * including the header */
#    if __has_attribute (returns_nonnull) && \
  ! defined(MHD_FN_RETURNS_NONNULL_)
/**
 * MHD_FN_RETURNS_NONNULL_ indicates that function never returns NULL.
 */
#      define MHD_FN_RETURNS_NONNULL_ __attribute__ ((returns_nonnull))
#    endif /* returns_nonnull && !MHD_FN_RETURNS_NONNULL_ */

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
        __attribute__ ((access (read_only,param_num)))
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
        __attribute__ ((access (read_only,param_num,size_num)))
#      endif /* !MHD_FN_PAR_IN_SIZE_ */

/* Override detected value of MHD_FN_PAR_OUT_ by defining it before
 * including the header */
#      if ! defined(MHD_FN_PAR_OUT_)
/**
 * MHD_FN_PAR_OUT_ indicates function parameter points to data
 * that could be written by the function, but not read.
 */
#        define MHD_FN_PAR_OUT_(param_num) \
        __attribute__ ((access (write_only,param_num)))
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
        __attribute__ ((access (write_only,param_num,size_num)))
#      endif /* !MHD_FN_PAR_OUT_SIZE_ */

/* Override detected value of MHD_FN_PAR_INOUT_ by defining it before
 * including the header */
#      if ! defined(MHD_FN_PAR_INOUT_)
/**
 * MHD_FN_PAR_INOUT_ indicates function parameter points to data
 * that could be both read and written by the function.
 */
#        define MHD_FN_PAR_INOUT_(param_num) \
        __attribute__ ((access (read_write,param_num)))
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
        __attribute__ ((access (read_write,param_num,size_num)))
#      endif /* !MHD_FN_PAR_INOUT_SIZE_ */

#    endif /* access */

/* Override detected value of MHD_FN_PAR_FD_READ_ by defining it before
 * including the header */
#    if __has_attribute (fd_arg_read) && \
  ! defined(MHD_FN_PAR_FD_READ_)
/**
 * MHD_FN_PAR_FD_READ_ indicates function parameter is file descriptor that
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
 * MHD_FN_PAR_CSTR_ indicates function parameter is file descriptor that
 * must be in open state and available for reading
 */
#      define MHD_FN_PAR_CSTR_(param_num) \
        __attribute__ ((null_terminated_string_arg (param_num)))
#    endif /* null_terminated_string_arg && !MHD_FN_PAR_CSTR_ */

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
#ifndef MHD_FN_RETURNS_NONNULL_
#  define MHD_FN_RETURNS_NONNULL_       /* empty */
#endif /* ! MHD_FN_RETURNS_NONNULL_ */
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
