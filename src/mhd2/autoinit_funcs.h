/*
 *  AutoinitFuncs: Automatic Initialisation and Deinitialisation Functions
 *  Copyright(C) 2014-2024 Karlson2k (Evgeny Grin)
 *
 *  This header is free software; you can redistribute it and / or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This header is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this header; if not, see
 *  <http://www.gnu.org/licenses/>.
 */

/*
   General usage is simple: include this header, define two functions
   with zero parameters (void) and any return type: one for initialisation and
   one for deinitialisation, add
   AIF_SET_INIT_AND_DEINIT_FUNCS(FuncInitName, FuncDeInitName) to the code,
   and functions will be automatically called during application startup
   and shutdown.
   This is useful for libraries as libraries don't have direct access
   to the main() function.

   Example:
   -------------------------------------------------
   #include <stdlib.h>
   #include "autoinit_funcs.h"

   int someVar;
   void* somePtr;

   void libInit(void)
   {
     someVar = 3;
     // Calling other library functions could be unsafe the as the order
     // of initialisation of libraries is not strictly defined
     //somePtr = malloc(100);
   }

   void libDeinit(void)
   {
     // Calling other library functions could be unsafe
     //free(somePtr);
   }

   AIF_SET_INIT_AND_DEINIT_FUNCS(libInit,libDeinit);
   -------------------------------------------------

   If initialiser or deinitialiser function is not needed, just use
   an empty function as a placeholder.

   This header should work with GCC, clang, MSVC (2010 or later) and
   SunPro / Sun Studio / Oracle Solaris Studio / Oracle Developer Studio
   compiler and other compatible compilers.
   Supported C and C++ languages; application, static and dynamic (DLL)
   libraries; non-optimized (Debug) and optimised (Release) compilation
   and linking.

   Besides the main macro mentioned above, the header defines other helper
   macros prefixed with AIF_. These macros can be used directly, but they
   are not designed to be defined externally.

   The header behaviour could be adjusted by defining various AUTOINIT_FUNCS_*
   macros before including the header.

   For more information see the header code and comments in the code.
 */
#ifndef AIF_HEADER_INCLUDED
#define AIF_HEADER_INCLUDED 1

/**
* The header version number in packed BCD form.
* (For example, version 1.9.30-1 would be 0x01093001)
*/
#define AIF_VERSION 0x02000100

/* Define AUTOINIT_FUNCS_NO_WARNINGS to disable all custom warnings
   in this header */
#ifdef AUTOINIT_FUNCS_NO_WARNINGS
#  ifndef AUTOINIT_FUNCS_NO_WARNINGS_W32_ARCH
#    define AUTOINIT_FUNCS_NO_WARNINGS_W32_ARCH 1
#  endif
#  ifndef AUTOINIT_FUNCS_NO_WARNINGS_SUNPRO_C
#    define AUTOINIT_FUNCS_NO_WARNINGS_SUNPRO_C 1
#  endif
#endif

/* If possible - check for supported attributes */
#ifdef __has_attribute
#  if __has_attribute (constructor) && __has_attribute (destructor)
#    define AIF_GNUC_ATTR_CONSTR_SUPPORTED 1
#  else  /* ! __has_attribute (constructor) || ! __has_attribute (destructor) */
#    define AIF_GNUC_ATTR_CONSTR_NOT_SUPPORTED 1
#  endif /* ! __has_attribute (constructor) || ! __has_attribute (destructor) */
#endif /* __has_attribute */

#if defined(__GNUC__) && __GNUC__ < 2 \
  && ! defined(AIF_GNUC_ATTR_CONSTR_NOT_SUPPORTED) \
  && ! defined(AIF_GNUC_ATTR_CONSTR_SUPPORTED)
#  define AIF_GNUC_ATTR_CONSTR_NOT_SUPPORTED 1
#endif

/* "__has_attribute__ ((constructor))" is supported by GCC, clang and
   Sun/Oracle compiler starting from version 12.1. */
#if (defined(AIF_GNUC_ATTR_CONSTR_SUPPORTED) \
  || defined(__GNUC__) || defined(__clang__) \
  || (defined(__SUNPRO_C) && __SUNPRO_C + 0 >= 0x5100)) && \
  ! defined(AIF_GNUC_ATTR_CONSTR_NOT_SUPPORTED)

#  define AIF_GNUC_SET_INIT_AND_DEINIT(FI,FD) \
        void __attribute__ ((constructor)) AIF_GNUC_init_helper_ ## FI (void);  \
        void __attribute__ ((destructor)) AIF_GNUC_deinit_helper_ ## FD (void); \
        void __attribute__ ((constructor)) AIF_GNUC_init_helper_ ## FI (void)   \
        { (void) (FI) (); } \
        void __attribute__ ((destructor)) AIF_GNUC_deinit_helper_ ## FD (void)  \
        { (void) (FD) (); } \
        struct AIF_GNUC_dummy_str_ ## FI {int i;}

#elif defined(_WIN32) && defined(_MSC_FULL_VER) && _MSC_VER + 0 >= 1600 && \
  ! defined(__CYGWIN__)

/* Make sure that your project/sources define:
   _LIB if building a static library (_LIB is ignored if _CONSOLE is defined);
   _USRDLL if building DLL-library;
   not defined both _LIB and _USRDLL if building an application */

/* Stringify macros */
#  define AIF_INSTRMACRO(a) #a                /* Strigify helper */
#  define AIF_STRMACRO(a) AIF_INSTRMACRO (a)  /* Expand and strigify */

/* Concatenate macros */
#  define AIF_INCONCAT(a,b) a ## b           /* Concatenate helper */
#  define AIF_CONCAT(a,b) AIF_INCONCAT (a,b) /* Expand and concatenate */

/* Use "C" linkage for variables to simplify symbols decoration */
#  ifdef __cplusplus
#    define AIF_W32_INITVARDECL extern "C"
#    define AIF_W32_INITHELPERFUNCDECL static
#  else
#    define AIF_W32_INITVARDECL extern
#    define AIF_W32_INITHELPERFUNCDECL static
#  endif

/* How variables are decorated by compiler */
#  if (defined(_WIN32) || defined(_WIN64)) \
  && ! defined(_M_IX86) && ! defined(_X86_)
#    if ! defined(_M_X64) && ! defined(_M_AMD64) && ! defined(_x86_64_) \
  && ! defined(_M_ARM) && ! defined(_M_ARM64)
#      ifndef AUTOINIT_FUNCS_NO_WARNINGS_W32_ARCH
#pragma message(__FILE__ "(" AIF_STRMACRO(__LINE__) ") : warning AIFW001 : " \
  "Untested architecture, linker may fail with unresolved symbols")
#      endif /* ! AUTOINIT_FUNCS_NO_WARNINGS_W32_ARCH */
#    endif /* ! _M_X64 && ! _M_AMD64 && ! _x86_64_ && ! _M_ARM && ! _M_ARM64 */
#    define AIF_W32_VARDECORPREFIX
#    define AIF_W32_DECORVARNAME(v) v
#    define AIF_W32_VARDECORPREFIXSTR ""
#  elif defined(_WIN32) && (defined(_M_IX86) || defined(_X86_))
#    define AIF_W32_VARDECORPREFIX _
#    define AIF_W32_DECORVARNAME(v) _ ## v
#    define AIF_W32_VARDECORPREFIXSTR "_"
#  else
#error Do not know how to decorate symbols for this architecture
#  endif


/* Internal variable prefix (can be any) */
#  define AIF_W32_INITHELPERVARNAME(f) _aif_init_ptr_ ## f
#  define AIF_W32_INITHELPERVARNAMEDECORSTR(f) \
        AIF_W32_VARDECORPREFIXSTR AIF_STRMACRO (AIF_W32_INITHELPERVARNAME (f))


/* Sections (segments) for pointers to initialisers */

/* Semi-officially suggested section for early initialisers (called before
   C++ objects initialisers), "void" return type */
#  define AIF_W32_SEG_STAT_INIT_EARLY1     ".CRT$XCT"
/* Guessed section name for early initialisers (called before
   C++ objects initialisers, after first initialisers), "void" return type */
#  define AIF_W32_SEG_STAT_INIT_EARLY2     ".CRT$XCTa"
/* Semi-officially suggested section for late initialisers (called after
   C++ objects initialisers), "void" return type */
#  define AIF_W32_SEG_STAT_INIT_LATE       ".CRT$XCV"

/* Unsafe sections (segments) for pointers to initialisers */

/* C++ lib initialisers, "void" return type (reserved by the system!) */
#  define AIF_W32_SEG_STAT_INIT_CXX_LIB    ".CRT$XCL"
/* C++ user initialisers, "void" return type (reserved by the system!) */
#  define AIF_W32_SEG_STAT_INIT_CXX_USER   ".CRT$XCU"

/* Declare section (segment), put variable pointing to init function to
   chosen segment, force linker to always include variable to avoid omitting
   by optimiser */
/* These initialisation function must be declared as
   void __cdecl FuncName(void) */
/* Note: "extern" with initialisation value means that variable is declared AND
   defined. */
#  define AIF_W32_INIT_VFPTR_IN_SEG(S,F)              \
        __pragma(section(S, long, read))               \
        __pragma(comment(linker, "/INCLUDE:"            \
        AIF_W32_INITHELPERVARNAMEDECORSTR (F)))          \
        AIF_W32_INITVARDECL __declspec(allocate (S)) void \
        (__cdecl * AIF_W32_INITHELPERVARNAME (F))(void) = &F

/* Unsafe sections (segments) for pointers to initialisers with
   "int" return type */

/* C lib initialisers, "int" return type (reserved by the system!).
   These initialisers are called before others. */
#  define AIF_W32_SEG_STAT_INIT_C_LIB      ".CRT$XIL"
/* C user initialisers, "int" return type (reserved by the system!).
   These initialisers are called before others. */
#  define AIF_W32_SEG_STAT_INIT_C_USER     ".CRT$XIU"

/* Declare section (segment), put variable pointing to init function to
   chosen segment, force linker to always include variable to avoid omitting
   by optimiser */
/* These initialisation function must be declared as
   int __cdecl FuncName(void) */
/* Startup process is aborted if initialiser returns non-zero */
/* Note: "extern" with initialisation value means that variable is declared AND
   defined. */
#  define AIF_W32_INIT_IFPTR_IN_SEG(S,F)                 \
        __pragma(section(S, long, read))                  \
        __pragma(comment(linker,                           \
        "/INCLUDE:" AIF_W32_INITHELPERVARNAMEDECORSTR (F))) \
        AIF_W32_INITVARDECL __declspec(allocate (S)) int     \
        (__cdecl * AIF_W32_INITHELPERVARNAME (F))(void) = &F

/* Not recommended / unsafe */
/* "lib" initialisers are called before "user" initialisers */
/* "C" initialisers are called before "C++" initialisers */
#  define AIF_W32_REG_STAT_INIT_C_USER(F)   \
        AIF_W32_FPTR_IN_SEG (AIF_W32_SEG_STAT_INIT_C_USER,F)
#  define AIF_W32_REG_STAT_INIT_C_LIB(F)    \
        AIF_W32_FPTR_IN_SEG (AIF_W32_SEG_STAT_INIT_C_LIB,F)
#  define AIF_W32_REG_STAT_INIT_CXX_USER(F) \
        AIF_W32_FPTR_IN_SEG (AIF_W32_SEG_STAT_INIT_CXX_USER,F)
#  define AIF_W32_REG_STAT_INIT_CXX_LIB(F)  \
        AIF_W32_FPTR_IN_SEG (AIF_W32_SEG_STAT_INIT_CXX_LIB,F)

/* Declare macros for different initialisers sections */

/* Macro can be used several times to register several initialisers */
/* Once function is registered as initialiser, it will be called automatically
   during application startup or library loading */
#  define AIF_W32_REG_STAT_INIT_EARLY1(F) \
        AIF_W32_INIT_VFPTR_IN_SEG (AIF_W32_SEG_STAT_INIT_EARLY1,F)
#  define AIF_W32_REG_STAT_INIT_EARLY2(F) \
        AIF_W32_INIT_VFPTR_IN_SEG (AIF_W32_SEG_STAT_INIT_EARLY2,F)
#  define AIF_W32_REG_STAT_INIT_LATE(F)   \
        AIF_W32_INIT_VFPTR_IN_SEG (AIF_W32_SEG_STAT_INIT_LATE,F)

#  ifndef _DLL
/* Sections (segments) for pointers to deinitialisers */

/* These section are not used when common rutime (CRT, the C library) is used
   as DLL. In such case only sections in CRT DLL are used for deinitialisation
   pointers. */

/* The section name based on semi-documented deinitialisation procedure,
   functions called before first C deinitialisers, "void" return type */
#    define AIF_W32_SEG_STAT_DEINIT_FIRST      ".CRT$XPAa"
/* The section name based on semi-documented deinitialisation procedure,
   functions called after AIF_W32_SEG_STAT_DEINIT_FIRST deinitialisers and
   before first C deinitialisers, "void" return type */
#    define AIF_W32_SEG_STAT_DEINIT_SECOND     ".CRT$XPAb"
/* The section name based on semi-documented deinitialisation procedure,
   functions called after AIF_W32_SEG_STAT_DEINIT_SECOND deinitialisers and
   before first C deinitialisers, "void" return type */
#    define AIF_W32_SEG_STAT_DEINIT_THIRD      ".CRT$XPAc"

/* Internal variable prefix (can be any) */
#    define AIF_W32_DEINITHELPERVARNAME(f) _aif_deinit_ptr_ ## f
#    define AIF_W32_DEINITHELPERVARNAMEDECORSTR(f) \
        AIF_W32_VARDECORPREFIXSTR AIF_STRMACRO (AIF_W32_DEINITHELPERVARNAME (f))

/* The macro to declare section (segment), put variable pointing to deinit
   function to chosen segment, force linker to always include variable to
   avoid omitting by optimiser */
/* These deinitialisation function must be declared as
   void __cdecl FuncName(void) */
/* Note: "extern" with initialisation value means that variable is declared AND
   defined. */
#    define AIF_W32_DEINIT_VFPTR_IN_SEG(S,F)          \
        __pragma(section(S, long, read))               \
        __pragma(comment(linker, "/INCLUDE:"            \
        AIF_W32_DEINITHELPERVARNAMEDECORSTR (F)))        \
        AIF_W32_INITVARDECL __declspec(allocate (S)) void \
        (__cdecl * AIF_W32_DEINITHELPERVARNAME (F))(void) = &F

/* Declare macros for different deinitialisers sections */
/* Macro can be used several times to register several deinitialisers */
/* Once function is registered as initialiser, it will be called automatically
   during application shutdown or library unloading */
#    define AIF_W32_REG_STAT_DEINIT_EARLY(F)  \
        AIF_W32_DEINIT_VFPTR_IN_SEG (AIF_W32_SEG_STAT_DEINIT_FIRST,F)
#    define AIF_W32_REG_STAT_DEINIT_LATE1(F)  \
        AIF_W32_DEINIT_VFPTR_IN_SEG (AIF_W32_SEG_STAT_DEINIT_SECOND,F)
#    define AIF_W32_REG_STAT_DEINIT_LATE2(F)  \
        AIF_W32_DEINIT_VFPTR_IN_SEG (AIF_W32_SEG_STAT_DEINIT_THIRD,F)

#  endif /* ! _DLL */

/* Choose main register macro based on language and program type */
/* Assuming that _LIB or _USRDLL is defined for static or DLL-library */
/* Macro can be used several times to register several initialisers */
/* Once function is registered as initialiser, it will be called automatically
   during application startup */
/* Define AUTOINIT_FUNCS_FORCE_EARLY_INIT to force register as early
   initialiser */
/* Define AUTOINIT_FUNCS_FORCE_LATE_INIT to force register as late
   initialiser */
/* By default C++ static or DLL-library code and any C code and will be
   registered as early initialiser, while C++ non-library code will be
   registered as late initialiser */
#  if (! defined(__cplusplus) || \
  defined(_LIB) || defined(_USRDLL) || \
  defined(AUTOINIT_FUNCS_FORCE_EARLY_INIT)) && \
  ! defined(AUTOINIT_FUNCS_FORCE_LATE_INIT)
/* Use early initialiser and late deinitialiser */
#    if defined(_LIB) || defined(_USRDLL)
/* Static or DLL library */
#      define AIF_W32_REGISTER_STAT_INIT(F)  AIF_W32_REG_STAT_INIT_EARLY1 (F)
#      ifdef AIF_W32_REG_STAT_DEINIT_LATE2
#        define AIF_W32_REGISTER_STAT_DEINIT(F) \
        AIF_W32_REG_STAT_DEINIT_LATE2 (F)
#      endif
#    else
/* Application code */
#      define AIF_W32_REGISTER_STAT_INIT(F)  AIF_W32_REG_STAT_INIT_EARLY2 (F)
#      ifdef AIF_W32_REG_STAT_DEINIT_LATE1
#        define AIF_W32_REGISTER_STAT_DEINIT(F) \
        AIF_W32_REG_STAT_DEINIT_LATE1 (F)
#      endif
#    endif
#  else
/* Use late initialiser and early deinitialiser */
#    define AIF_W32_REGISTER_STAT_INIT(F)     AIF_W32_REG_STAT_INIT_LATE (F)
#    ifdef AIF_W32_REG_STAT_DEINIT_EARLY
#      define AIF_W32_REGISTER_STAT_DEINIT(F) \
        AIF_W32_REG_STAT_DEINIT_EARLY (F)
#    endif
#  endif


/* Static deinit registration on W32 could be risky as it works only
   if CRT is used as static lib (not as DLL) and relies on correct
   definition of "_DLL" macro by build system. */
/* If "_DLL" macro is correctly defined, static deinitialiser registration
   can be enabled by defining AUTOINIT_FUNCS_ALLOW_W32_STAT_DEINIT macro.
   If it is used, it can save from including an extra header. */
#  if defined(AIF_W32_REGISTER_STAT_DEINIT) \
  && defined(AUTOINIT_FUNCS_ALLOW_W32_STAT_DEINIT)
#    define AIF_W32_SET_STAT_INIT_AND_DEINIT(FI,FD)        \
        AIF_W32_INITHELPERFUNCDECL void                     \
        __cdecl AIF_W32_stat_init_helper_ ## FI (void);      \
        AIF_W32_INITHELPERFUNCDECL void                       \
        __cdecl AIF_W32_stat_deinit_helper_ ## FD (void);      \
        AIF_W32_INITHELPERFUNCDECL void                         \
        __cdecl AIF_W32_stat_init_helper_ ## FI (void)           \
        { (void) (FI) (); }                                       \
        AIF_W32_INITHELPERFUNCDECL void                            \
        __cdecl AIF_W32_stat_deinit_helper_ ## FD (void)            \
        { (void) (FD) (); }                                          \
        AIF_W32_REGISTER_STAT_INIT (AIF_W32_stat_init_helper_ ## FI); \
        AIF_W32_REGISTER_STAT_DEINIT (AIF_W32_stat_deinit_helper_ ## FD)
#  else

/* Note: 'atexit()' is just a wrapper for '_onexit()' on W32 */
#    include <stdlib.h> /* required for _onexit() */

#    define AIF_W32_SET_STAT_INIT_AND_DEINIT(FI,FD)   \
        AIF_W32_INITHELPERFUNCDECL void                \
        __cdecl AIF_W32_stat_init_helper_ ## FI (void); \
        AIF_W32_INITHELPERFUNCDECL int                   \
        __cdecl AIF_W32_stat_deinit_helper_ ## FD (void); \
        AIF_W32_INITHELPERFUNCDECL void                    \
        __cdecl AIF_W32_stat_init_helper_ ## FI (void)      \
        { (void) (FI) ();                                    \
          _onexit (&AIF_W32_stat_deinit_helper_ ## FD); }     \
        AIF_W32_INITHELPERFUNCDECL int                         \
        __cdecl AIF_W32_stat_deinit_helper_ ## FD (void)        \
        { (void) (FD) (); return ! 0; }                          \
        AIF_W32_REGISTER_STAT_INIT (AIF_W32_stat_init_helper_ ## FI)
#  endif

#endif /* _WIN32 && _MSC_VER + 0 >= 1600 && ! _GNUC_ATTR_CONSTR_SUPPORTED */


#if defined(_WIN32) && ! defined(__CYGWIN__) && \
  (defined(_USRDLL) || defined(DLL_EXPORT))

#  if defined(__MINGW32__) || defined(__MINGW64__)
/* The minimal portable set of the headers to pull in the definitions of "BOOL",
   "WINAPI", "HINSTANCE", "DWORD" and "LPVOID" */
/* Thi minimal set does not work with MS headers as they depend on some vital
   macros defined only in the "windows.h" header only */
#    include <windef.h>
#    include <winnt.h>
#  else
#    ifndef WIN32_LEAN_AND_MEAN
#      define WIN32_LEAN_AND_MEAN 1
#    endif
#    include <windows.h>
#  endif

#  ifdef DLL_PROCESS_ATTACH
#    define AIF_W32_DLL_PROCESS_ATTACH  DLL_PROCESS_ATTACH
#  else
#    define AIF_W32_DLL_PROCESS_ATTACH  1
#  endif
#  ifdef DLL_PROCESS_DETACH
#    define AIF_W32_DLL_PROCESS_DETACH  DLL_PROCESS_DETACH
#  else
#    define AIF_W32_DLL_PROCESS_DETACH  0
#  endif

/* When process is terminating, DLL should not perform a cleanup, leaving
   allocated resources to be cleaned by the system. This is because some
   threads may be explicitly terminated without proper cleanup, and some
   system resources, including process heap, could be in inconsistent state.
   Define AUTOINIT_FUNCS_USE_UNSAFE_DLL_DEINIT to enable calling of deinit
   function such situations.
   Note: if AUTOINIT_FUNCS_USE_UNSAFE_DLL_DEINIT is defined and the DLL is
   delay-loaded, then both the initialiser and the deinitialiser could be
   called late (or last), breaking requirement for calling deinitialisers in
   reverse order of initialisers. */
#  ifndef AUTOINIT_FUNCS_USE_UNSAFE_DLL_DEINIT
#    define AIF_W32_IS_DLL_DEINIT_SAFE(pReserved)       (NULL == (pReserved))
#  else
#    define AIF_W32_IS_DLL_DEINIT_SAFE(pReserved)       TRUE
#  endif

/* If DllMain is already present in user's code,
   define AUTOINIT_FUNCS_CALL_USR_DLLMAIN and
   rename user's DllMain to usr_DllMain.
   The usr_DllMain() must be declared (or full defined) before using the macro
   for setting initialiser and deinitialiser. Alternatively, if usr_DllMain()
   is another file (or after the macro), define macro
   AUTOINIT_FUNCS_DECLARE_USR_DLLMAIN to enable automatic declaration of this
   function.
   Define AUTOINIT_FUNCS_USR_DLLMAIN_NAME to user function name if usr_DllMain
   is not suitable. */
#  ifndef AUTOINIT_FUNCS_CALL_USR_DLLMAIN
#    define AIF_W32_CALL_USER_DLLMAIN(h,r,p)    TRUE
#  else  /* AUTOINIT_FUNCS_CALL_USR_DLLMAIN */
#    ifndef AUTOINIT_FUNCS_USR_DLLMAIN_NAME
#      define AIF_W32_USR_DLLMAIN_NAME usr_DllMain
#    else
#      define AIF_W32_USR_DLLMAIN_NAME AUTOINIT_FUNCS_USR_DLLMAIN_NAME
#    endif
#    define AIF_W32_CALL_USER_DLLMAIN(h,r,p)    \
        AIF_W32_USR_DLLMAIN_NAME ((h),(r),(p))
#    ifdef AUTOINIT_FUNCS_DECLARE_USR_DLLMAIN
#      define AIF_DECL_USR_DLLMAIN \
        BOOL WINAPI AIF_W32_USR_DLLMAIN_NAME (HINSTANCE hinst, DWORD reason, \
                                              LPVOID pReserved);
#    endif
#  endif /* AUTOINIT_FUNCS_CALL_USR_DLLMAIN */

#  ifndef AIF_DECL_USR_DLLMAIN
#    define AIF_DECL_USR_DLLMAIN /* empty */
#  endif

#  define AIF_W32_SET_DLL_INIT_AND_DEINIT(FI,FD) \
        BOOL WINAPI DllMain (HINSTANCE hinst, DWORD reason, LPVOID pReserved); \
        AIF_DECL_USR_DLLMAIN                                                   \
        BOOL WINAPI DllMain (HINSTANCE hinst, DWORD reason, LPVOID pReserved)  \
        { BOOL aif_ret; (void) hinst;                                          \
          if (AIF_W32_DLL_PROCESS_ATTACH == reason) {                          \
            (void) (FI) ();                                                    \
            aif_ret = AIF_W32_CALL_USER_DLLMAIN (hinst, reason, pReserved);    \
            if (! aif_ret && NULL != pReserved) { (void) (FD) (); } }          \
          else if (AIF_W32_DLL_PROCESS_DETACH == reason) {                     \
            aif_ret = AIF_W32_CALL_USER_DLLMAIN (hinst, reason, pReserved);    \
            if (AIF_W32_IS_DLL_DEINIT_SAFE (pReserved)) { (void) (FD) (); } }  \
          else aif_ret = AIF_W32_CALL_USER_DLLMAIN (hinst, reason, pReserved); \
          return aif_ret;                                                      \
        } struct AIF_W32_dummy_strc_ ## FI {int i;}
#endif /* _WIN32 && ! __CYGWIN__ && (_USRDLL || DLL_EXPORT) */


/* Define AUTOINIT_FUNCS_FORCE_STATIC_REG if you want to set main macro
   AIF_SET_INIT_AND_DEINIT_FUNCS to static version even if building a DLL.
   Static registration works for DLL too, but less precise and flexible. */

#if defined(AIF_W32_SET_DLL_INIT_AND_DEINIT)      \
  && ! (defined(AUTOINIT_FUNCS_PREFER_STATIC_REG) \
  && (defined(AIF_GNUC_SET_INIT_AND_DEINIT)       \
  || defined(AIF_W32_SET_STAT_INIT_AND_DEINIT)))

#  define AIF_SET_INIT_AND_DEINIT_FUNCS(FI,FD) \
        AIF_W32_SET_DLL_INIT_AND_DEINIT (FI,FD)
/* Indicate that automatic initialisers/deinitialisers are supported */
#  define AIF_AUTOINIT_FUNCS_ARE_SUPPORTED 1

#elif defined(AIF_GNUC_SET_INIT_AND_DEINIT)

#  define AIF_SET_INIT_AND_DEINIT_FUNCS(FI,FD) \
        AIF_GNUC_SET_INIT_AND_DEINIT (FI,FD)
/* Indicate that automatic initialisers/deinitialisers are supported */
#  define AIF_AUTOINIT_FUNCS_ARE_SUPPORTED 1

#elif defined(AIF_W32_SET_STAT_INIT_AND_DEINIT)

#  define AIF_SET_INIT_AND_DEINIT_FUNCS(FI,FD) \
        AIF_W32_SET_STAT_INIT_AND_DEINIT (FI,FD)
/* Indicate that automatic initialisers/deinitialisers are supported */
#  define AIF_AUTOINIT_FUNCS_ARE_SUPPORTED 1

#else

/* Define AUTOINIT_FUNCS_EMIT_ERROR_IF_NOT_SUPPORTED before inclusion of
   this header to abort compilation if automatic initialisers/deinitialisers
   are not supported */
#  ifdef AUTOINIT_FUNCS_EMIT_ERROR_IF_NOT_SUPPORTED
#error User-defined initialiser and deinitialiser functions are not supported
#  endif /* AUTOINIT_FUNCS_EMIT_ERROR_IF_NOT_SUPPORTED */

#  if defined(__SUNPRO_C) && (defined(sun) || defined(__sun)) \
  && (defined(__SVR4) || defined(__svr4__))
/* "#parama init(func_name)" can be used. "func_name" must be declared.
   The form is "void func_name(void)". */
#    define AIF_PRAGMA_INIT_SUPPORTED        1
/* "#parama fini(func_name)" can be used. "func_name" must be declared.
   The form is "void func_name(void)". */
#    define AIF_PRAGMA_FINI_SUPPORTED        1
#    if ! defined(AUTOINIT_FUNCS_NO_WARNINGS_SUNPRO_C)
#warning The compiler supports "#pragma init(func1)" and "#pragma fini(func2)"
#warning Use "pragma" to set initialiser and deinitialiser functions
#    endif
#  endif

/* "Not supported" implementation */
#  define AIF_SET_INIT_AND_DEINIT_FUNCS(FI,FD) /* No-op */
/* Indicate that automatic initialisers/deinitialisers are not supported */
#  define AIF_AUTOINIT_FUNCS_ARE_NOT_SUPPORTED 1

#endif
#endif /* !AIF_HEADER_INCLUDED */
