# Backported macros from autoconf git master + a few custom patches

# This file is part of Autoconf.			-*- Autoconf -*-
# Programming languages support.
# Copyright (C) 2001-2017, 2020-2023 Free Software Foundation, Inc.

# This file is part of Autoconf.  This program is free
# software; you can redistribute it and/or modify it under the
# terms of the GNU General Public License as published by the
# Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# Under Section 7 of GPL version 3, you are granted additional
# permissions described in the Autoconf Configure Script Exception,
# version 3.0, as published by the Free Software Foundation.
#
# You should have received a copy of the GNU General Public License
# and a copy of the Autoconf Configure Script Exception along with
# this program; see the files COPYINGv3 and COPYING.EXCEPTION
# respectively.  If not, see <https://www.gnu.org/licenses/>.

# Written by David MacKenzie, with help from
# Akim Demaille, Paul Eggert,
# François Pinard, Karl Berry, Richard Pixley, Ian Lance Taylor,
# Roland McGrath, Noah Friedman, david d zuhn, and many others.

# ---- Backported macros only ----

AC_DEFUN([_AC_C_C89_TEST_GLOBALS],
[m4_divert_text([INIT_PREPARE],
[[# Test code for whether the C compiler supports C89 (global declarations)
ac_c_conftest_c89_globals='
/* Does the compiler advertise C89 conformance?
   Do not test the value of __STDC__, because some compilers set it to 0
   while being otherwise adequately conformant. */
#if !defined __STDC__
# error "Compiler does not advertise C89 conformance"
#endif

#include <stddef.h>
#include <stdarg.h>
struct stat;
/* Most of the following tests are stolen from RCS 5.7 src/conf.sh.  */
struct buf { int x; };
struct buf * (*rcsopen) (struct buf *, struct stat *, int);
static char *e (char **p, int i)
{
  return p[i];
}
static char *f (char * (*g) (char **, int), char **p, ...)
{
  char *s;
  va_list v;
  va_start (v,p);
  s = g (p, va_arg (v,int));
  va_end (v);
  return s;
}

/* C89 style stringification. */
#define noexpand_stringify(a) #a
const char *stringified = noexpand_stringify(arbitrary+token=sequence);

/* C89 style token pasting.  Exercises some of the corner cases that
   e.g. old MSVC gets wrong, but not very hard. */
#define noexpand_concat(a,b) a##b
#define expand_concat(a,b) noexpand_concat(a,b)
extern int vA;
extern int vbee;
#define aye A
#define bee B
int *pvA = &expand_concat(v,aye);
int *pvbee = &noexpand_concat(v,bee);

/* OSF 4.0 Compaq cc is some sort of almost-ANSI by default.  It has
   function prototypes and stuff, but not \xHH hex character constants.
   These do not provoke an error unfortunately, instead are silently treated
   as an "x".  The following induces an error, until -std is added to get
   proper ANSI mode.  Curiously \x00 != x always comes out true, for an
   array size at least.  It is necessary to write \x00 == 0 to get something
   that is true only with -std.  */
int osf4_cc_array ['\''\x00'\'' == 0 ? 1 : -1];

/* IBM C 6 for AIX is almost-ANSI by default, but it replaces macro parameters
   inside strings and character constants.  */
#define FOO(x) '\''x'\''
int xlc6_cc_array[FOO(a) == '\''x'\'' ? 1 : -1];

int test (int i, double x);
struct s1 {int (*f) (int a);};
struct s2 {int (*f) (double a);};
int pairnames (int, char **, int *(*)(struct buf *, struct stat *, int),
               int, int);'
]])])


AC_DEFUN([_AC_C_C99_TEST_GLOBALS],
[m4_divert_text([INIT_PREPARE],
[[# Test code for whether the C compiler supports C99 (global declarations)
ac_c_conftest_c99_globals='
// Does the compiler advertise C99 conformance?
#if !defined __STDC_VERSION__ || __STDC_VERSION__ < 199901L
# error "Compiler does not advertise C99 conformance"
#endif

#include <stdbool.h>
extern int puts (const char *);
extern int printf (const char *, ...);
extern int dprintf (int, const char *, ...);
extern void *malloc (size_t);
extern void free (void *);

// Check varargs macros.  These examples are taken from C99 6.10.3.5.
// dprintf is used instead of fprintf to avoid needing to declare
// FILE and stderr.
#define debug(...) dprintf (2, __VA_ARGS__)
#define showlist(...) puts (#__VA_ARGS__)
#define report(test,...) ((test) ? puts (#test) : printf (__VA_ARGS__))
static void
test_varargs_macros (void)
{
  int x = 1234;
  int y = 5678;
  debug ("Flag");
  debug ("X = %d\n", x);
  showlist (The first, second, and third items.);
  report (x>y, "x is %d but y is %d", x, y);
}

// Check long long types.
#define BIG64 18446744073709551615ull
#define BIG32 4294967295ul
#define BIG_OK (BIG64 / BIG32 == 4294967297ull && BIG64 % BIG32 == 0)
#if !BIG_OK
  #error "your preprocessor is broken"
#endif
#if BIG_OK
#else
  #error "your preprocessor is broken"
#endif
static long long int bignum = -9223372036854775807LL;
static unsigned long long int ubignum = BIG64;

struct incomplete_array
{
  int datasize;
  double data[];
};

struct named_init {
  int number;
  const wchar_t *name;
  double average;
};

typedef const char *ccp;

static inline int
test_restrict (ccp restrict text)
{
  // See if C++-style comments work.
  // Iterate through items via the restricted pointer.
  // Also check for declarations in for loops.
  for (unsigned int i = 0; *(text+i) != '\''\0'\''; ++i)
    continue;
  return 0;
}

// Check varargs and va_copy.
static bool
test_varargs (const char *format, ...)
{
  va_list args;
  va_start (args, format);
  va_list args_copy;
  va_copy (args_copy, args);

  const char *str = "";
  int number = 0;
  float fnumber = 0;

  while (*format)
    {
      switch (*format++)
	{
	case '\''s'\'': // string
	  str = va_arg (args_copy, const char *);
	  break;
	case '\''d'\'': // int
	  number = va_arg (args_copy, int);
	  break;
	case '\''f'\'': // float
	  fnumber = va_arg (args_copy, double);
	  break;
	default:
	  break;
	}
    }
  va_end (args_copy);
  va_end (args);

  return *str && number && fnumber;
}
'
]])])


AC_DEFUN([_AC_C_C11_TEST_GLOBALS],
[m4_divert_text([INIT_PREPARE],
[[# Test code for whether the C compiler supports C11 (global declarations)
ac_c_conftest_c11_globals='
// Does the compiler advertise C11 conformance?
#if !defined __STDC_VERSION__ || __STDC_VERSION__ < 201112L
# error "Compiler does not advertise C11 conformance"
#endif

// Check _Alignas.
char _Alignas (double) aligned_as_double;
char _Alignas (0) no_special_alignment;
extern char aligned_as_int;
char _Alignas (0) _Alignas (int) aligned_as_int;

// Check _Alignof.
enum
{
  int_alignment = _Alignof (int),
  int_array_alignment = _Alignof (int[100]),
  char_alignment = _Alignof (char)
};
_Static_assert (0 < -_Alignof (int), "_Alignof is signed");

// Check _Noreturn.
_Noreturn int does_not_return (void) { for (;;) continue; }

// Check _Static_assert.
struct test_static_assert
{
  int x;
  _Static_assert (sizeof (int) <= sizeof (long int),
                  "_Static_assert does not work in struct");
  long int y;
};

// Check UTF-8 literals.
#define u8 syntax error!
char const utf8_literal[] = u8"happens to be ASCII" "another string";

// Check duplicate typedefs.
typedef long *long_ptr;
typedef long int *long_ptr;
typedef long_ptr long_ptr;

// Anonymous structures and unions -- taken from C11 6.7.2.1 Example 1.
struct anonymous
{
  union {
    struct { int i; int j; };
    struct { int k; long int l; } w;
  };
  int m;
} v1;
'
]])])


# AC_LANG_CALL(C)(PROLOGUE, FUNCTION)
# -----------------------------------
# Avoid conflicting decl of main.
m4_define([AC_LANG_CALL(C)],
[AC_LANG_PROGRAM([$1
m4_if([$2], [main], ,
[/* Override any GCC internal prototype to avoid an error.
   Use char because int might match the return type of a GCC
   builtin and then its argument prototype would still apply.
   The 'extern "C"' is for builds by C++ compilers;
   although this is not generally supported in C code supporting it here
   has little cost and some practical benefit (sr 110532).  */
#ifdef __cplusplus
extern "C"
#endif
char $2 (void);])], [return $2 ();])])


# AC_LANG_FUNC_LINK_TRY(C)(FUNCTION)
# ----------------------------------
# Don't include <ctype.h> because on OSF/1 3.0 it includes
# <sys/types.h> which includes <sys/select.h> which contains a
# prototype for select.  Similarly for bzero.
#
# This test used to merely assign f=$1 in main(), but that was
# optimized away by HP unbundled cc A.05.36 for ia64 under +O3,
# presumably on the basis that there's no need to do that store if the
# program is about to exit.  Conversely, the AIX linker optimizes an
# unused external declaration that initializes f=$1.  So this test
# program has both an external initialization of f, and a use of f in
# main that affects the exit status.
#
m4_define([AC_LANG_FUNC_LINK_TRY(C)],
[AC_LANG_PROGRAM(
[/* Define $1 to an innocuous variant, in case <limits.h> declares $1.
   For example, HP-UX 11i <limits.h> declares gettimeofday.  */
#define $1 innocuous_$1

/* System header to define __stub macros and hopefully few prototypes,
   which can conflict with char $1 (void); below.  */

#include <limits.h>
#undef $1

/* Override any GCC internal prototype to avoid an error.
   Use char because int might match the return type of a GCC
   builtin and then its argument prototype would still apply.  */
#ifdef __cplusplus
extern "C"
#endif
char $1 (void);
/* The GNU C library defines this for functions which it implements
    to always fail with ENOSYS.  Some functions are actually named
    something starting with __ and the normal name is an alias.  */
#if defined __stub_$1 || defined __stub___$1
choke me
#endif
], [return $1 ();])])


# AC_C_BIGENDIAN ([ACTION-IF-TRUE], [ACTION-IF-FALSE], [ACTION-IF-UNKNOWN],
#                 [ACTION-IF-UNIVERSAL])
# -------------------------------------------------------------------------
AC_DEFUN([AC_C_BIGENDIAN],
[AH_VERBATIM([WORDS_BIGENDIAN],
[/* Define WORDS_BIGENDIAN to 1 if your processor stores words with the most
   significant byte first (like Motorola and SPARC, unlike Intel). */
#if defined AC_APPLE_UNIVERSAL_BUILD
# if defined __BIG_ENDIAN__
#  define WORDS_BIGENDIAN 1
# endif
#else
# ifndef WORDS_BIGENDIAN
#  undef WORDS_BIGENDIAN
# endif
#endif])dnl
 AC_CACHE_CHECK([whether byte ordering is bigendian], [ac_cv_c_bigendian],
   [ac_cv_c_bigendian=unknown
    # See if we're dealing with a universal compiler.
    AC_COMPILE_IFELSE(
	 [AC_LANG_SOURCE(
	    [[#ifndef __APPLE_CC__
	       not a universal capable compiler
	     #endif
	     typedef int dummy;
	    ]])],
	 [
	# Check for potential -arch flags.  It is not universal unless
	# there are at least two -arch flags with different values.
	ac_arch=
	ac_prev=
	for ac_word in $CC $CFLAGS $CPPFLAGS $LDFLAGS; do
	 if test -n "$ac_prev"; then
	   case $ac_word in
	     i?86 | x86_64 | ppc | ppc64)
	       if test -z "$ac_arch" || test "$ac_arch" = "$ac_word"; then
		 ac_arch=$ac_word
	       else
		 ac_cv_c_bigendian=universal
		 break
	       fi
	       ;;
	   esac
	   ac_prev=
	 elif test "x$ac_word" = "x-arch"; then
	   ac_prev=arch
	 fi
       done])
    if test $ac_cv_c_bigendian = unknown; then
      # See if sys/param.h defines the BYTE_ORDER macro.
      AC_COMPILE_IFELSE(
	[AC_LANG_PROGRAM(
	   [[#include <sys/types.h>
	     #include <sys/param.h>
	   ]],
	   [[#if ! (defined BYTE_ORDER && defined BIG_ENDIAN \\
		     && defined LITTLE_ENDIAN && BYTE_ORDER && BIG_ENDIAN \\
		     && LITTLE_ENDIAN)
	      bogus endian macros
	     #endif
	   ]])],
	[# It does; now see whether it defined to BIG_ENDIAN or not.
	 AC_COMPILE_IFELSE(
	   [AC_LANG_PROGRAM(
	      [[#include <sys/types.h>
		#include <sys/param.h>
	      ]],
	      [[#if BYTE_ORDER != BIG_ENDIAN
		 not big endian
		#endif
	      ]])],
	   [ac_cv_c_bigendian=yes],
	   [ac_cv_c_bigendian=no])])
    fi
    if test $ac_cv_c_bigendian = unknown; then
      # See if <limits.h> defines _LITTLE_ENDIAN or _BIG_ENDIAN (e.g., Solaris).
      AC_COMPILE_IFELSE(
	[AC_LANG_PROGRAM(
	   [[#include <limits.h>
	   ]],
	   [[#if ! (defined _LITTLE_ENDIAN || defined _BIG_ENDIAN)
	      bogus endian macros
	     #endif
	   ]])],
	[# It does; now see whether it defined to _BIG_ENDIAN or not.
	 AC_COMPILE_IFELSE(
	   [AC_LANG_PROGRAM(
	      [[#include <limits.h>
	      ]],
	      [[#ifndef _BIG_ENDIAN
		 not big endian
		#endif
	      ]])],
	   [ac_cv_c_bigendian=yes],
	   [ac_cv_c_bigendian=no])])
    fi
    if test $ac_cv_c_bigendian = unknown; then
      # Compile a test program.
      AC_RUN_IFELSE(
	[AC_LANG_PROGRAM([AC_INCLUDES_DEFAULT],
	   [[
	     /* Are we little or big endian?  From Harbison&Steele.  */
	     union
	     {
	       long int l;
	       char c[sizeof (long int)];
	     } u;
	     u.l = 1;
	     return u.c[sizeof (long int) - 1] == 1;
	   ]])],
	[ac_cv_c_bigendian=no],
	[ac_cv_c_bigendian=yes],
	[# Try to guess by grepping values from an object file.
	 AC_LINK_IFELSE(
	   [AC_LANG_SOURCE(
	      [[unsigned short int ascii_mm[] =
		  { 0x4249, 0x4765, 0x6E44, 0x6961, 0x6E53, 0x7953, 0 };
		unsigned short int ascii_ii[] =
		  { 0x694C, 0x5454, 0x656C, 0x6E45, 0x6944, 0x6E61, 0 };
		int use_ascii (int i) {
		  return ascii_mm[i] + ascii_ii[i];
		}
		unsigned short int ebcdic_ii[] =
		  { 0x89D3, 0xE3E3, 0x8593, 0x95C5, 0x89C4, 0x9581, 0 };
		unsigned short int ebcdic_mm[] =
		  { 0xC2C9, 0xC785, 0x95C4, 0x8981, 0x95E2, 0xA8E2, 0 };
		int use_ebcdic (int i) {
		  return ebcdic_mm[i] + ebcdic_ii[i];
		}
		int
		main (int argc, char **argv)
		{
		  /* Intimidate the compiler so that it does not
		     optimize the arrays away.  */
		  char *p = argv[0];
		  ascii_mm[1] = *p++; ebcdic_mm[1] = *p++;
		  ascii_ii[1] = *p++; ebcdic_ii[1] = *p++;
		  return use_ascii (argc) == use_ebcdic (*p);
		}]])],
	   [if grep BIGenDianSyS conftest$ac_exeext >/dev/null; then
	      ac_cv_c_bigendian=yes
	    fi
	    if grep LiTTleEnDian conftest$ac_exeext >/dev/null ; then
	      if test "$ac_cv_c_bigendian" = unknown; then
		ac_cv_c_bigendian=no
	      else
		# finding both strings is unlikely to happen, but who knows?
		ac_cv_c_bigendian=unknown
	      fi
	    fi])])
    fi])
 case $ac_cv_c_bigendian in #(
   yes)
     m4_default([$1],
       [AC_DEFINE([WORDS_BIGENDIAN], 1)]);; #(
   no)
     $2 ;; #(
   universal)
dnl Note that AC_APPLE_UNIVERSAL_BUILD sorts less than WORDS_BIGENDIAN;
dnl this is a necessity for proper config header operation.  Warn if
dnl the user did not specify a config header but is relying on the
dnl default behavior for universal builds.
     m4_default([$4],
       [AC_CONFIG_COMMANDS_PRE([m4_ifset([AH_HEADER], [],
	 [m4_warn([obsolete],
	   [AC_C_BIGENDIAN should be used with AC_CONFIG_HEADERS])])])dnl
	AC_DEFINE([AC_APPLE_UNIVERSAL_BUILD],1,
	  [Define if building universal (internal helper macro)])])
     ;; #(
   *)
     m4_default([$3],
       [AC_MSG_ERROR([unknown endianness
 presetting ac_cv_c_bigendian=no (or yes) will help])]) ;;
 esac
])# AC_C_BIGENDIAN


# AC_C_VARARRAYS
# --------------
# Check whether the C compiler supports variable-length arrays.
AC_DEFUN([AC_C_VARARRAYS],
[
  AC_CACHE_CHECK([for variable-length arrays],
    ac_cv_c_vararrays,
    [AC_COMPILE_IFELSE([AC_LANG_SOURCE(
[[	#ifndef __STDC_NO_VLA__
	#error __STDC_NO_VLA__ not defined
	#endif
]])],
       [ac_cv_c_vararrays='no: __STDC_NO_VLA__ is defined'],
       [AC_COMPILE_IFELSE(
	  [AC_LANG_PROGRAM(
	     [[/* Test for VLA support.  This test is partly inspired
		  from examples in the C standard.  Use at least two VLA
		  functions to detect the GCC 3.4.3 bug described in:
		  https://lists.gnu.org/archive/html/bug-gnulib/2014-08/msg00014.html
		  */
	       #ifdef __STDC_NO_VLA__
		syntax error;
	       #else
		 extern int n;
		 static int B[100];
		 int fvla (int m, int C[m][m]);

		 static int
		 simple (int count, int all[static count])
		 {
		   return all[count - 1];
		 }

		 int
		 fvla (int m, int C[m][m])
		 {
		   typedef int VLA[m][m];
		   VLA x;
		   int D[m];
		   static int (*q)[m] = &B;
		   int (*s)[n] = q;
		   return C && &x[0][0] == &D[0] && &D[0] == s[0];
		 }
	       #endif
	       ]])],
	  [ac_cv_c_vararrays=yes],
	  [ac_cv_c_vararrays=no])])])
  if test "$ac_cv_c_vararrays" = yes; then
    dnl This is for compatibility with Autoconf 2.61-2.69.
    AC_DEFINE([HAVE_C_VARARRAYS], 1,
      [Define to 1 if C supports variable-length arrays.])
  elif test "$ac_cv_c_vararrays" = no; then
    AC_DEFINE([__STDC_NO_VLA__], 1,
      [Define to 1 if C does not support variable-length arrays, and
       if the compiler does not already define this.])
  fi
])

