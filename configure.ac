# This file is part of libmicrohttpd.
# (C) 2006-2021 Christian Grothoff (and other contributing authors)
# (C) 2014-2022 Evgeny Grin (Karlson2k)
#
# libmicrohttpd is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published
# by the Free Software Foundation; either version 3, or (at your
# option) any later version.
#
# libmicrohttpd is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with libmicrohttpd; see the file COPYING.  If not, write to the
# Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
# Boston, MA 02110-1301, USA.
#
#
# Process this file with autoconf to produce a configure script.
#
#
AC_PREREQ([2.64])
LT_PREREQ([2.4.0])
AC_INIT([GNU libmicrohttpd],[0.9.75],[libmicrohttpd@gnu.org])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADERS([MHD_config.h])
AC_CONFIG_MACRO_DIR([m4])
m4_pattern_forbid([^_?MHD_[A-Z_]+_CC_])dnl

LIB_VERSION_CURRENT=72
LIB_VERSION_REVISION=0
LIB_VERSION_AGE=60
AC_SUBST([LIB_VERSION_CURRENT])
AC_SUBST([LIB_VERSION_REVISION])
AC_SUBST([LIB_VERSION_AGE])


PACKAGE_VERSION_MAJOR='m4_car(m4_unquote(m4_split(AC_PACKAGE_VERSION, [\.])))'
PACKAGE_VERSION_MINOR='m4_argn(2, m4_unquote(m4_split(AC_PACKAGE_VERSION, [\.])))'
PACKAGE_VERSION_SUBMINOR='m4_argn(3, m4_unquote(m4_split(AC_PACKAGE_VERSION, [\.])))'
AS_VAR_ARITH([MHD_W32_DLL_SUFF],[[$LIB_VERSION_CURRENT - $LIB_VERSION_AGE]])
AC_SUBST([PACKAGE_VERSION_MAJOR])
AC_SUBST([PACKAGE_VERSION_MINOR])
AC_SUBST([PACKAGE_VERSION_SUBMINOR])
AC_SUBST([MHD_W32_DLL_SUFF])
AC_CONFIG_FILES([src/microhttpd/microhttpd_dll_res.rc])

MHD_LIB_CPPFLAGS=""
MHD_LIB_CFLAGS=""
MHD_LIB_LDFLAGS=""
MHD_LIBDEPS=""
# for pkg-config
MHD_REQ_PRIVATE=''
MHD_LIBDEPS_PKGCFG=''

AS_IF([test -z "$CC" && test -z "$CPP"], [
  AC_MSG_CHECKING([[whether z/OS special settings are required]])
  AS_IF([test `uname -s` = "OS/390"],
    [
      # configure binaries for z/OS
      AS_IF([test -z "$CC"],
            [CC=`pwd`"/contrib/xcc"
             chmod +x $CC || true])
      AS_IF([test -z "$CPP"],
            CPP="c89 -E")
      AC_MSG_RESULT([[yes]])
    ],
    [AC_MSG_RESULT([[no]])]
  )
])


AC_MSG_CHECKING([for build type])
AC_ARG_ENABLE([build-type],
  [AS_HELP_STRING([[--enable-build-type=TYPE]],
  [enable build TYPE, a set of configuration parameters; individual settings ]
  [(asserts, sanitizers, compiler and linker flags) can be overridden by ]
  [additional configure parameters (debug, debugger, neutral, release, release-compact, ]
  [release-hardened) [neutral]])],
  [], [enable_build_type=neutral])
AS_IF([test "x${enable_build_type}" = "x"], [enable_build_type="neutral"])
AS_VAR_IF([enable_build_type], ["no"], [enable_build_type="neutral"])
AS_VAR_IF([enable_build_type], ["yes"], [AC_MSG_ERROR([[Missing TYPE for --enable-build-type=]])])
AS_CASE([${enable_build_type}],
  [debug], [AC_MSG_RESULT([debug. Defaults: enable asserts, sanitizers (if any supported), debug information, compiler optimisation for debugging])],
  [debugger], [AC_MSG_RESULT([debugger. Defaults: enable asserts, disable sanitizers, debug information, no compiler optimisation, static lib])],
  [neutral], [AC_MSG_RESULT([neutral. Defaults: use only user-specified compiler and linker flags])],
  [release], [AC_MSG_RESULT([release. Defaults: disable asserts, enable compiler optimisations])],
  [release-compact], [AC_MSG_RESULT([release-compact. Defaults: disable asserts, enable compiler optimisations for size, enable compact code])],
  [release-hardened], [AC_MSG_RESULT([release-hardened. Defaults: disable asserts, enable compiler optimisations, enable linker and compiler hardening])],
  [AC_MSG_ERROR([[Unknown build type: ${enable_build_type}]])]
)
AS_VAR_IF([enable_build_type], ["neutral"], [:],
  [
    # For all non-neutral build types do not use automatic "-g -O2" for CFLAGS
    AS_IF([test -z "${CFLAGS}"], [CFLAGS=""])
  ]
)
AS_VAR_IF([enable_build_type], ["debugger"],
  [ # Build only static version unless something else is specified by the user
    AS_IF([test -z "${enable_static}" || test "x${enable_static}" = "xyes"],
      [
        AS_IF([test -z "${enable_shared}"], 
          [
            enable_shared="no"
            enable_static="yes"
          ]
        )
      ],
      [
        AS_CASE([${enable_static}],[*libmicrohttpd*],
          [AS_IF([test -z "${enable_shared}"], [enable_shared="no"])],
        )
      ]
    )
  ]
)
AS_CASE([${enable_build_type}],[debug|debugger],
  [ AS_IF([test -z "${enable_silent_rules}"], [ enable_silent_rules="yes" ])]
)

AM_INIT_AUTOMAKE([gnu] [check-news] [filename-length-max=99] [tar-v7] [silent-rules] [subdir-objects])

# Checks for programs.
AC_PROG_AWK
AC_PROG_GREP
AC_PROG_FGREP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_CANONICAL_HOST
m4_version_prereq([2.70],
  [
# Find C compiler and compiler options to support
# the latest C standard (C11). Fallback to C99 and C89
# if later C versions are not supported.
AC_PROG_CC
  ],
  [
# Find C compiler and compiler options to support
# the latest C standard (C99). Fallback to C89
# if later C versions are not supported.
AC_PROG_CC_STDC
  ]
)

# Workaround for libgcrypt
AS_IF([[test "x$lt_sysroot" != "x" && test "x$SYSROOT" = "x"]], [[SYSROOT="$lt_sysroot"]])
user_CFLAGS="$CFLAGS"
user_LDFLAGS="$LDFLAGS"
user_CPPFLAGS="$CPPFLAGS"

CFLAGS_ac=""
LDFLAGS_ac=""
CPPFLAGS_ac=""

MHD_SYS_EXT([CPPFLAGS_ac])
CPPFLAGS="${CPPFLAGS_ac} ${user_CPPFLAGS}"
LT_INIT([win32-dll])
LT_LANG([Windows Resource])

AC_ARG_ENABLE([compact-code],
  [AS_HELP_STRING([[--enable-compact-code]],
  [enable use of a reduced size version of the code, resulting in smaller ]
  [binaries with a slight performance hit [auto]])],
  [], [enable_compact_code=auto])
AS_IF([test "x${enable_compact_code}" = "x"], [enable_compact_code="auto"])
AH_TEMPLATE([[MHD_FAVOR_SMALL_CODE]], [Define to '1' to use compact code version])
AH_TEMPLATE([[MHD_FAVOR_FAST_CODE]], [Define to '1' to use fast (and larger) code version])
AS_UNSET([compact_code_MSG])
AS_CASE([${enable_compact_code}], [auto],
  [
    # Parameter not set.
    # Check preprocessor macros
    AC_CHECK_DECL([MHD_FAVOR_SMALL_CODE],
      [
        enable_compact_code="yes"
        compact_code_MSG="enabled by preprocessor macro"
      ],
      [],[/* no includes */]
    )
    AC_CHECK_DECL([MHD_FAVOR_FAST_CODE],
      [
        AS_VAR_IF([enable_compact_code],["yes"],
          [AC_MSG_ERROR([Both MHD_FAVOR_SMALL_CODE and MHD_FAVOR_FAST_CODE macros are defined])]
        )
        enable_compact_code="no"
        compact_code_MSG="set by preprocessor macro"
      ],[],[/* no includes */]
    )

    AS_VAR_IF([enable_compact_code], ["auto"], 
      [
        # No preference by preprocessor macros
        AC_CACHE_CHECK([whether compiler is configured to optimize for size],
          [mhd_cv_cc_optim_size],
          [
            AC_COMPILE_IFELSE(
              [
                AC_LANG_PROGRAM([[
#ifndef __OPTIMIZE_SIZE__
#error Looks like compiler does not optimize for size
choke me now
#endif
              ]],[])
              ],
              [mhd_cv_cc_optim_size="yes"],[mhd_cv_cc_optim_size="no"]
            )
          ]
        )
        AS_VAR_IF([mhd_cv_cc_optim_size], ["yes"],
          [
            enable_compact_code="yes"
            compact_code_MSG="enabled automatically as compiler optimizes for size"
            AC_DEFINE([MHD_FAVOR_SMALL_CODE],[1])
          ]
        )
      ]
    )

    AS_VAR_IF([enable_compact_code], ["auto"], 
      [
        # No preference by preprocessor macros and compiler flags
        AS_CASE([${enable_build_type}],[*-compact],
          [
            enable_compact_code="yes"
            compact_code_MSG="enabled by --enable-build-type=${enable_build_type}"
            AC_DEFINE([MHD_FAVOR_SMALL_CODE],[1])
          ]
        )
      ]
    )

    AS_VAR_IF([enable_compact_code], ["auto"], 
      [
        # No preference
        enable_compact_code="no"
        compact_code_MSG="by default"
        AC_DEFINE([MHD_FAVOR_FAST_CODE],[1])
      ]
    )
  ],
  [yes],
  [
    compact_code_MSG="enabled by configure parameter"
    AC_CHECK_DECL([MHD_FAVOR_SMALL_CODE],
      [],
      [AC_DEFINE([MHD_FAVOR_SMALL_CODE],[1])],[/* no includes */]
    )
    AC_CHECK_DECL([MHD_FAVOR_FAST_CODE],
      [AC_MSG_ERROR([MHD_FAVOR_FAST_CODE macro is defined, --enable-compact-code could not be used])
      ],
      [],[/* no includes */]
    )
  ],
  [no],
  [
    compact_code_MSG="disabled by configure parameter"
    AC_CHECK_DECL([MHD_FAVOR_FAST_CODE],
      [],
      [AC_DEFINE([MHD_FAVOR_FAST_CODE],[1])],[/* no includes */]
    )
    AC_CHECK_DECL([MHD_FAVOR_SMALL_CODE],
      [AC_MSG_ERROR([MHD_FAVOR_SMALL_CODE macro is defined, --disable-compact-code could not be used])
      ],
      [],[/* no includes */]
    )
  ],
  [AC_MSG_ERROR([[Unknown parameter value: --enable-compact-code=${enable_compact_code}]])]
)

AC_MSG_CHECKING([whether to use a reduced size version of the code])
AC_MSG_RESULT([${enable_compact_code} (${compact_code_MSG})])


CFLAGS="${user_CFLAGS}"
# Compiler options to always enable (if supported)
MHD_FIND_ADD_CC_CFLAG([CFLAGS_ac], [-fno-strict-aliasing], [-qnoansialias])
# '-qlonglong' is XLC option for C89, not used with C99 or later
MHD_CHECK_ADD_CC_CFLAG([-qlonglong], [CFLAGS_ac])

# Set basic optimisation flags
AS_VAR_IF([enable_build_type],["neutral"],[],
  [ # Any non-neutral build types
    AC_CACHE_CHECK([whether workarounds for clang or clang-based compiler are required],
      [mhd_cv_cc_clang_based],
      [
        AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
#if ! defined(__clang__) && ! defined(__llvm__)
#error Compiler is not clang-based
choke me now
#endif
              ]]
            )
          ],
          [mhd_cv_cc_clang_based="yes"],[mhd_cv_cc_clang_based="no"]
        )
      ]
    )
  ]
)
AS_CASE([${enable_build_type}],[debug|debugger],
  [ # Debug build or build for walking with debugger
    CFLAGS="${user_CFLAGS}"
    AS_VAR_IF([enable_build_type],["debug"],
      [
        # Clang has ASAN (pointer compare) broken when '-Og' optimisations are used
        AS_IF([test "x${enable_sanitizers}" != "xno" && test "x${mhd_cv_cc_clang_based}" = "xyes"],
          [MHD_CHECK_ADD_CC_CFLAG([-O0], [CFLAGS_ac])],
          [MHD_FIND_ADD_CC_CFLAG([CFLAGS_ac], [-Og], [-O0])]
        )
      ],
      [MHD_CHECK_ADD_CC_CFLAG([-O0], [CFLAGS_ac])]
    )
    CFLAGS="${CFLAGS_ac} ${user_CFLAGS}"
  ]
)
AS_CASE([${enable_build_type}],[release|release-*],
  [ # All release types
    AS_VAR_IF([enable_build_type],["release-compact"],
      [
        CPPFLAGS="${CPPFLAGS_ac} ${user_CPPFLAGS}"
        AC_CHECK_DECL([MHD_FAVOR_SMALL_CODE],[],
          [AC_CHECK_DECL([MHD_FAVOR_FAST_CODE],[],
            [MHD_APPEND_FLAG_TO_VAR([CPPFLAGS_ac],[-DMHD_FAVOR_SMALL_CODE=1])],
            [/* no includes */])],[/* no includes */])
        CPPFLAGS="${CPPFLAGS_ac} ${user_CPPFLAGS}"
        CFLAGS="${user_CFLAGS}"
        MHD_FIND_ADD_CC_CFLAG([CFLAGS_ac], [-Oz], [-Os], [-O])
	    CFLAGS="${CFLAGS_ac} ${user_CFLAGS}"
      ],
      [ # All non-compact release types
        CPPFLAGS="${CPPFLAGS_ac} ${user_CPPFLAGS}"
        AC_CHECK_DECL([MHD_FAVOR_SMALL_CODE],[],
          [AC_CHECK_DECL([MHD_FAVOR_FAST_CODE],[],
            [MHD_APPEND_FLAG_TO_VAR([CPPFLAGS_ac],[-DMHD_FAVOR_FAST_CODE=1])],
            [/* no includes */])],[/* no includes */])
        CPPFLAGS="${CPPFLAGS_ac} ${user_CPPFLAGS}"
        CFLAGS="${user_CFLAGS}"
        MHD_FIND_ADD_CC_CFLAG([CFLAGS_ac], [-O2], [-O])
	    CFLAGS="${CFLAGS_ac} ${user_CFLAGS}"
      ]
    )
  ]
)

AS_VAR_IF([enable_build_type],["neutral"],[],
  [ # Any non-neutral build types
    MHD_CHECK_ADD_CC_CFLAGS([-Wall -Wnull-dereference], [CFLAGS_ac])
    MHD_CHECK_ADD_CC_CFLAGS([-Wdeclaration-after-statement -Wimplicit -Wnested-externs], [CFLAGS_ac])
    MHD_CHECK_ADD_CC_CFLAGS([-Wredundant-decls -Wtrampolines -Wunsafe-loop-optimizations], [CFLAGS_ac])
    MHD_CHECK_ADD_CC_CFLAGS([-Wpoison-system-directories], [CFLAGS_ac])
    CFLAGS="${CFLAGS_ac} ${user_CFLAGS}"
    LDFLAGS="${user_LDFLAGS}"
    MHD_CHECK_ADD_CC_LDFLAG([-Wl,--warn-common], [LDFLAGS_ac])
    LDFLAGS="${LDFLAGS_ac} ${user_LDFLAGS}"
  ]
)
AS_CASE([${enable_build_type}],[debug|debugger],
  [ # Debug build or build for walking with debugger
    CFLAGS="${user_CFLAGS}"
    MHD_FIND_ADD_CC_CFLAG([CFLAGS_ac], [-ggdb3], [-g3], [-ggdb], [-g])
    MHD_CHECK_ADD_CC_CFLAGS([-Wextra -Wdouble-promotion], [CFLAGS_ac])
    MHD_FIND_ADD_CC_CFLAG_IFELSE(
      [
        # clang produce warning when string pointer is used as a format specifier for v*printf() function
        AS_VAR_IF([mhd_cv_cc_clang_based],["yes"],[MHD_CHECK_ADD_CC_CFLAG([-Wno-format-nonliteral], [CFLAGS_ac])])
      ],[],
      [CFLAGS_ac], [-Wformat=2], [-Wformat]
    )
    MHD_CHECK_ADD_CC_CFLAGS([-Wformat-overflow -Wformat-truncation -Wformat-security -Wformat-signedness], [CFLAGS_ac])
    MHD_CHECK_ADD_CC_CFLAGS([-Wmissing-include-dirs -Wshift-overflow=2 -Wstringop-overflow=4 -Walloc-zero], [CFLAGS_ac])
    MHD_CHECK_ADD_CC_CFLAGS([-Wduplicated-branches -Wduplicated-cond -Wfloat-equal -Wshadow -Wpointer-arith], [CFLAGS_ac])
    MHD_FIND_ADD_CC_CFLAG([CFLAGS_ac], [-Wshadow-all], [-Wshadow])
    MHD_CHECK_ADD_CC_CFLAGS([-Wbad-function-cast -Wcast-qual -Wwrite-strings -Wconversion], [CFLAGS_ac])
    MHD_FIND_ADD_CC_CFLAG([CFLAGS_ac], [-Wcast-align=strict], [-Wcast-align])
    MHD_CHECK_ADD_CC_CFLAGS([-Wjump-misses-init -Wlogical-op -Waggregate-return -Wstrict-prototypes], [CFLAGS_ac])
    MHD_CHECK_ADD_CC_CFLAGS([-Wold-style-definition -Wmissing-declarations -Wmissing-prototypes], [CFLAGS_ac])
    MHD_CHECK_ADD_CC_CFLAGS([-Wuninitialized -Winit-self -Wshift-negative-value -Wswitch-enum], [CFLAGS_ac])
    MHD_FIND_ADD_CC_CFLAG([CFLAGS_ac], [-Wstrict-overflow=4], [-Wstrict-overflow])
    MHD_FIND_ADD_CC_CFLAG([CFLAGS_ac], [-Wnormalized=nfkc], [-Wnormalized])
    MHD_CHECK_ADD_CC_CFLAGS([-Walloca -Wbidi-chars=any -Warray-bounds -Wpacked -Wvariadic-macros], [CFLAGS_ac])
    MHD_CHECK_ADD_CC_CFLAGS([-Wundef], [CFLAGS_ac])

    MHD_CHECK_ADD_CC_CFLAGS([-Wanon-enum-enum-conversion -Warray-bounds-pointer-arithmetic -Wassign-enum], [CFLAGS_ac])
    MHD_CHECK_ADD_CC_CFLAGS([-Wbit-int-extension -Wbitfield-enum-conversion -Wparentheses -Wbool-operation], [CFLAGS_ac])
    MHD_CHECK_ADD_CC_CFLAGS([-Wcast-function-type -Wcomma -Wcomment -Wcompound-token-split], [CFLAGS_ac])
    MHD_CHECK_ADD_CC_CFLAGS([-Wconditional-uninitialized -Wdeprecated], [CFLAGS_ac])
    MHD_CHECK_ADD_CC_CFLAGS([-Wdocumentation-pedantic -Wempty-init-stmt -Wenum-conversion -Wexpansion-to-defined], [CFLAGS_ac])
    MHD_CHECK_ADD_CC_CFLAGS([-Wflexible-array-extensions -Wloop-analysis -Wformat-pedantic], [CFLAGS_ac])
    MHD_CHECK_ADD_CC_CFLAGS([-Wformat-type-confusion -Wfour-char-constants], [CFLAGS_ac])
    MHD_CHECK_ADD_CC_CFLAGS([-Wgcc-compat -Wgnu-anonymous-struct -Wgnu-compound-literal-initializer], [CFLAGS_ac])
    MHD_CHECK_ADD_CC_CFLAGS([-Wgnu-conditional-omitted-operand -Wgnu-designator -Wgnu-empty-initializer], [CFLAGS_ac])
    MHD_CHECK_ADD_CC_CFLAGS([-Wgnu-empty-struct -Wgnu-flexible-array-initializer -Wgnu-folding-constant], [CFLAGS_ac])
    MHD_CHECK_ADD_CC_CFLAGS([-Wgnu-null-pointer-arithmetic -Wgnu-pointer-arith -Wgnu-redeclared-enum], [CFLAGS_ac])
    MHD_CHECK_ADD_CC_CFLAGS([-Wgnu-union-cast -Wgnu-variable-sized-type-not-at-end -Widiomatic-parentheses], [CFLAGS_ac])
    MHD_CHECK_ADD_CC_CFLAGS([-Wmissing-noreturn -Wmissing-variable-declarations -Wnested-anon-types], [CFLAGS_ac])
    MHD_CHECK_ADD_CC_CFLAGS([-Wnewline-eof -Wover-aligned -Wredundant-parens], [CFLAGS_ac])
    MHD_CHECK_ADD_CC_CFLAGS([-Wshift-sign-overflow -Wtautological-compare -Wunaligned-access], [CFLAGS_ac])
    MHD_CHECK_ADD_CC_CFLAGS([-Wunused -Wzero-as-null-pointer-constant -Wzero-length-array], [CFLAGS_ac])
    MHD_CHECK_CC_CFLAG([-Wused-but-marked-unused],[CFLAGS_ac],
      [
        AC_CACHE_CHECK([whether $[]CC -Wused-but-marked-unused works with system headers],
          [mhd_cv_wused_but_marked_unused_sys_header],
          [
            SAVE_ac_c_werror_flag="$ac_c_werror_flag"
            ac_c_werror_flag="yes"
            CFLAGS="${CFLAGS_ac} -Wused-but-marked-unused ${user_CFLAGS}"
            AC_COMPILE_IFELSE(
              [
                AC_LANG_SOURCE([[
#include <stdio.h>

int main(void)
{
  char buf[16];
  return (int) snprintf(buf, 16, "test");
}
                  ]]
                )
              ],
              [mhd_cv_wused_but_marked_unused_sys_header="yes"],
              [mhd_cv_wused_but_marked_unused_sys_header="no"]
            )
            ac_c_werror_flag="$SAVE_ac_c_werror_flag"
          ]
        )
        AS_VAR_IF([mhd_cv_wused_but_marked_unused_sys_header],["yes"],
          [MHD_APPEND_FLAG_TO_VAR([CFLAGS_ac],[-Wused-but-marked-unused])]
        )
      ]
    )
    #
    # Removed flags:
    #
    # -Wdisabled-macro-expansion - warns about macros from system headers

    CFLAGS="${CFLAGS_ac} ${user_CFLAGS}"
    LDFLAGS="${user_LDFLAGS}"
    MHD_CHECK_ADD_CC_LDFLAG([-Wl,--enable-long-section-names], [LDFLAGS_ac])
    LDFLAGS="${LDFLAGS_ac} ${user_LDFLAGS}"
  ]
)
AS_CASE([${enable_build_type}],[release|release-*],
  [ # All release types
    CFLAGS="${user_CFLAGS}"
    AS_VAR_IF([enable_build_type],["release-compact"],
      [],
      [ # All non-compact release types
        MHD_CHECK_ADD_CC_CFLAGS([-fsched-pressure -fira-loop-pressure -fmerge-all-constants], [CFLAGS_ac]) # These flags may improve size, recheck with LTO and linker garbage collection
        MHD_CHECK_ADD_CC_CFLAGS([-ftree-partial-pre -fgcse-after-reload -fipa-pta], [CFLAGS_ac])
        MHD_CHECK_ADD_CC_CFLAGS([-fisolate-erroneous-paths-attribute -ffinite-loops -floop-nest-optimize], [CFLAGS_ac])
        MHD_CHECK_ADD_CC_CFLAGS([-fpredictive-commoning -frename-registers], [CFLAGS_ac])
        MHD_CHECK_ADD_CC_CFLAGS([-ftree-loop-distribute-patterns -fpeel-loops -fsplit-loops -ftree-vectorize], [CFLAGS_ac])
      ]
    )

    AS_VAR_IF([enable_build_type],["release-hardened"],
      [
        MHD_CHECK_ADD_CC_CFLAGS([-Wformat-security -Wstack-protector], [CFLAGS_ac])
        MHD_CHECK_ADD_CC_CFLAGS([-Wuninitialized -Winit-self -Walloc-zero -Wbidi-chars=any], [CFLAGS_ac])
      ]
    )
    AS_VAR_IF([enable_build_type],["release"],
      [ # Flags are not suitable for 'compact' and for 'hardened'
        MHD_CHECK_ADD_CC_CFLAGS([-ffast-math -fno-trapping-math], [CFLAGS_ac])
      ]
    )
    CFLAGS="${CFLAGS_ac} ${user_CFLAGS}"
    # W32-specific
    LDFLAGS="${user_LDFLAGS}"
    MHD_CHECK_ADD_CC_LDFLAG([-Wl,--disable-long-section-names], [LDFLAGS_ac])
    LDFLAGS="${LDFLAGS_ac} ${user_LDFLAGS}"
  ]
)
CFLAGS="${CFLAGS_ac} ${user_CFLAGS}"
# Additional flags are checked and added at the end of 'configure'

# Check for headers that are ALWAYS required
AC_CHECK_HEADERS_ONCE([stdio.h string.h stdint.h errno.h limits.h fcntl.h], [],
  [AC_MSG_ERROR([Compiling libmicrohttpd requires standard POSIX headers files])], [AC_INCLUDES_DEFAULT])

# Check for basic optional headers
AC_CHECK_HEADERS([stddef.h stdlib.h inttypes.h sys/types.h sys/stat.h unistd.h], [], [], [AC_INCLUDES_DEFAULT])

# Check for clock-specific optional headers
AC_CHECK_HEADERS([sys/time.h time.h], [], [], [AC_INCLUDES_DEFAULT])

# Check for system information and parameters optional headers
AC_CHECK_HEADERS([endian.h machine/endian.h sys/endian.h sys/byteorder.h \
                  sys/machine.h machine/param.h sys/param.h sys/isa_defs.h \
                  sys/ioctl.h], [], [], [AC_INCLUDES_DEFAULT])

# Check for network and sockets optional headers
AC_CHECK_HEADERS([sys/socket.h sys/select.h netinet/in.h arpa/inet.h \
                  netinet/ip.h netinet/tcp.h net/if.h \
                  netdb.h sockLib.h inetLib.h], [], [],
  [AC_INCLUDES_DEFAULT
   [
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif /* HAVE_SYS_TYPES_H */
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif /* HAVE_INTTYPES_H */
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif /* HAVE_SYS_SOCKET_H */
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif /* HAVE_NETINET_IN_H */
#ifdef HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif /* HAVE_NETINET_IP_H */
#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif /* HAVE_NETINET_TCP_H */
  ]]
)

# Check for other optional headers
AC_CHECK_HEADERS([sys/msg.h sys/mman.h signal.h], [], [], [AC_INCLUDES_DEFAULT])

AC_CHECK_HEADER([[search.h]],
  [
    MHD_CHECK_LINK_RUN([[for proper tsearch(), tfind() and tdelete()]],[[mhd_cv_sys_tsearch_usable]],
	  [
	    AS_CASE([$host_os],
	      [openbsd*],
	      [[ # Some OpenBSD versions have wrong return value for tdelete()
	        mhd_cv_sys_tsearch_usable='assuming no'
	      ]],
	      [netbsd*],
	      [[ # NetBSD had leaked root node for years
	        mhd_cv_sys_tsearch_usable='assuming no'
	      ]],
	      [[mhd_cv_sys_tsearch_usable='assuming yes']]
	    )
	  ],
	  [
	    AC_LANG_SOURCE(
	      [[
#ifdef HAVE_STDDEF_H
#include <stddef.h>
#endif /* HAVE_STDDEF_H */
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif /* HAVE_STDLIB_H */

#include <stdio.h>
#include <search.h>

static int cmp_func(const void *p1, const void *p2)
{
  return (*((const int *)p1)) - (*((const int *)p2));
}

int main(void)
{
  int ret = 0; 
  void *root_ptr = NULL;
  int element1 = 1;
  int **element_ptr_ptr1;
  int **element_ptr_ptr2;
  
  element_ptr_ptr1 =
    (int **) tsearch ((void*) &element1, &root_ptr, &cmp_func);
  if (NULL == element_ptr_ptr1)
  {
    fprintf (stderr, "NULL pointer has been returned when tsearch() called for the first time.\n");
    return ++ret;
  }
  if (*element_ptr_ptr1 != &element1)
  {
    fprintf (stderr, "Wrong pointer has been returned when tsearch() called for the first time.\n");
    return ++ret;
  }
  if (NULL == root_ptr)
  {
    fprintf (stderr, "Root pointer has not been set by tsearch().\n");
    return ++ret;
  }
  
  element_ptr_ptr2 =
    (int **) tsearch ((void*) &element1, &root_ptr, &cmp_func);
  if (NULL == element_ptr_ptr2)
  {
    fprintf (stderr, "NULL pointer has been returned when tsearch() called for the second time.\n");
    return ++ret;
  }
  if (*element_ptr_ptr2 != &element1)
  {
    fprintf (stderr, "Wrong pointer has been returned when tsearch() called for the second time.\n");
    ++ret;
  }
  if (element_ptr_ptr2 != element_ptr_ptr1)
  {
    fprintf (stderr, "Wrong element has been returned when tsearch() called for the second time.\n");
    ++ret;
  }
  
  element_ptr_ptr2 =
    (int **) tfind ((void*) &element1, &root_ptr, &cmp_func);
  if (NULL == element_ptr_ptr2)
  {
    fprintf (stderr, "NULL pointer has been returned by tfind().\n");
    ++ret;
  }
  if (*element_ptr_ptr2 != &element1)
  {
    fprintf (stderr, "Wrong pointer has been returned when by tfind().\n");
    ++ret;
  }
  if (element_ptr_ptr2 != element_ptr_ptr1)
  {
    fprintf (stderr, "Wrong element has been returned when tsearch() called for the second time.\n");
    ++ret;
  }
  
  element_ptr_ptr1 =
    (int **) tdelete ((void*) &element1, &root_ptr, &cmp_func);
  if (NULL == element_ptr_ptr1)
  {
    fprintf (stderr, "NULL pointer has been returned by tdelete().\n");
    ++ret;
  }
  if (NULL != root_ptr)
  {
    fprintf (stderr, "Root pointer has not been set to NULL by tdelete().\n");
    ++ret;
  }
  
  return ret;
}
	      ]]
	    )
	  ],
	  [AC_DEFINE([[MHD_USE_SYS_TSEARCH]], [[1]], [Define to 1 if you have properly working tsearch(), tfind() and tdelete() functions.])]
	)
  ],
  [], [AC_INCLUDES_DEFAULT]
)
AM_CONDITIONAL([MHD_USE_SYS_TSEARCH], [[test "x$mhd_cv_sys_tsearch_usable" = "xyes" || test "x$mhd_cv_sys_tsearch_usable" = "xassuming yes"]])

# Optional headers used for tests
AC_CHECK_HEADERS([sys/sysctl.h netinet/ip_icmp.h netinet/icmp_var.h], [], [],
  [[
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif /* HAVE_SYS_TYPES_H */
#ifdef HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h>
#endif /* HAVE_SYS_SYSCTL_H */
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif /* HAVE_SYS_SOCKET_H */
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif /* HAVE_NETINET_IN_H */
#ifdef HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif /* HAVE_NETINET_IP_H */
#ifdef HAVE_NETINET_IP_ICMP_H
#include <netinet/ip_icmp.h>
#endif /* HAVE_NETINET_IP_ICMP_H */
  ]]
)

AC_ARG_ENABLE([compiler-hardening],
  [AS_HELP_STRING([--enable-compiler-hardening], [enable compiler security checks])],
  [],
  [AS_CASE([${enable_build_type}],[*-hardened],
    [enable_compiler_hardening='yes'],[enable_compiler_hardening='no'])]
)
AS_VAR_IF([enable_compiler_hardening],["yes"],
  [
    CPPFLAGS="${CPPFLAGS_ac} ${user_CPPFLAGS}"
    AC_CHECK_DECL([_FORTIFY_SOURCE],
      [MHD_APPEND_FLAG_TO_VAR([CPPFLAGS_ac],[-U_FORTIFY_SOURCE])],
      [],[/* no includes */])
    MHD_APPEND_FLAG_TO_VAR([CPPFLAGS_ac],[-D_FORTIFY_SOURCE=2])
    CPPFLAGS="${CPPFLAGS_ac} ${user_CPPFLAGS}"
    CFLAGS="${user_CFLAGS}"
    MHD_FIND_ADD_CC_CFLAG([CFLAGS_ac],[-fstack-protector-strong],[-fstack-protector-all],[-fstack-protector])
    MHD_CHECK_ADD_CC_CFLAGS([-fstack-clash-protection],[CFLAGS_ac])
    MHD_FIND_ADD_CC_CFLAG([CFLAGS_ac],[-ftrivial-auto-var-init=pattern],[-ftrivial-auto-var-init=zero])
    CFLAGS="${CFLAGS_ac} ${user_CFLAGS}"
    AS_IF([test "x${enable_static}" = "xyes" && test "x${pic_mode}" != "xyes"],
      [
        # PIE static lib can be used within non-PIE application, but
        # PIE static lib cannot be used in non-PIE shared lib. Let's assume
        # that static lib will not be used in shared lib
        # All "pie" flags will be used automatically by libtool only
        # for static library objects.
        CFLAGS="${user_CFLAGS}"
        # Perform tests here with "-pie" enabled
        LDFLAGS="${LDFLAGS_ac} -pie ${user_LDFLAGS}"
        MHD_CHECK_ADD_CC_CFLAG([-fPIE],[CFLAGS_ac],
          [
            MHD_APPEND_FLAG_TO_VAR([LDFLAGS_ac],[-pie])
          ],
          [
            MHD_CHECK_ADD_CC_CFLAG([-fpie],[CFLAGS_ac],
              [
                MHD_APPEND_FLAG_TO_VAR([LDFLAGS_ac],[-pie])
              ]
            )
          ]
        )
        CFLAGS="${CFLAGS_ac} ${user_CFLAGS}"
        LDFLAGS="${LDFLAGS_ac} ${user_LDFLAGS}"
      ]
    )
    CFLAGS="${CFLAGS_ac} ${user_CFLAGS}"
    LDFLAGS="${LDFLAGS_ac} ${user_LDFLAGS}"
  ]
)

# Linker hardening options
# Currently these options are ELF specific, they don't work on Darwin and W32
AC_ARG_ENABLE([linker-hardening],
  [AS_HELP_STRING([--enable-linker-hardening], [enable linker security fixups])],
  [],
  [AS_CASE([${enable_build_type}],[*-hardened],
    [enable_linker_hardening='yes'],[enable_linker_hardening='no'])]
)
AS_VAR_IF([enable_linker_hardening],["yes"],
  [
    CFLAGS="${CFLAGS_ac} ${user_CFLAGS}"
    LDFLAGS="${user_LDFLAGS}"
    MHD_CHECK_ADD_CC_LDFLAG([-Wl,-z,relro],[LDFLAGS_ac],
      [MHD_CHECK_ADD_CC_LDFLAG([-Wl,-z,now],[LDFLAGS_ac])])
    # Actually should be "noexec" by default, but let's try to enforce it.
    MHD_CHECK_ADD_CC_LDFLAG([-Wl,-z,noexecstack],[LDFLAGS_ac])
    # W32-specific. Some are enabled by default, but they will be enfored to be sure.
    MHD_CHECK_ADD_CC_LDFLAGS([-Wl,--large-address-aware -Wl,--enable-auto-image-base],[LDFLAGS_ac])
    MHD_CHECK_ADD_CC_LDFLAGS([-Wl,--dynamicbase -Wl,--nxcompat -Wl,--high-entropy-va],[LDFLAGS_ac])
    LDFLAGS="${LDFLAGS_ac} ${user_LDFLAGS}"
  ]
)


AH_TEMPLATE([[HAVE_STDBOOL_H]], [Define to 1 i][f you have the <stdbool.h> header file and <stdbool.h> defines 'bool' type.])
AH_TEMPLATE([[HAVE_REAL_BOOL]], [Define to 1 i][f you have the real boolean type.])
AH_TEMPLATE([[bool]], [Define to type name which will be used as boolean type.])
AC_CHECK_HEADER([stdbool.h],
  [
   AC_CHECK_TYPE([bool],
     [
      AC_DEFINE([[HAVE_STDBOOL_H]], [[1]])
      AC_DEFINE([[HAVE_REAL_BOOL]], [[1]])
     ],
     [
      AC_MSG_WARN([[Header <stdbool.h> is present, but "bool" type cannot be detected. Check compiler flags.]])
      AC_DEFINE([[bool]], [[int]])
     ], [
#include <stdbool.h>
        ]
   )
  ],
  [
   AC_CHECK_TYPE([bool],
     [AC_DEFINE([[HAVE_REAL_BOOL]], [[1]])],
     [
      AC_CHECK_TYPE([_Bool],
        [
         AC_DEFINE([[HAVE_REAL_BOOL]], [[1]])
         AC_DEFINE([[bool]], [[_Bool]])
        ],
        [
         AC_DEFINE([[bool]], [[int]])
        ], []
      )
     ], []
   )
  ],
  [AC_INCLUDES_DEFAULT]
)

AC_CACHE_CHECK([[whether "true" is defined or builtin]], [[mhd_cv_macro_true_defined]],
  [AC_COMPILE_IFELSE(
     [AC_LANG_PROGRAM(
        [[
#ifdef HAVE_STDBOOL_H
#include <stdbool.h>
#endif
        ]], [[
#if defined(true)
    /* dummy */
#else
    (void)true;
#endif
        ]])
     ], [[mhd_cv_macro_true_defined='yes']], [[mhd_cv_macro_true_defined='no']])
  ])
AS_VAR_IF([[mhd_cv_macro_true_defined]], [["yes"]], [[:]],
  [AC_DEFINE([[true]],[[(!0)]], [Define to value interpreted by compiler as boolean "true", if "true" is not defined by system headers.])])

AC_CACHE_CHECK([[whether "false" is defined or builtin]], [[mhd_cv_macro_false_defined]],
  [AC_COMPILE_IFELSE(
     [AC_LANG_PROGRAM(
        [[
#ifdef HAVE_STDBOOL_H
#include <stdbool.h>
#endif
        ]], [[
#if !defined(false)
    (void)false;
#else
    /* dummy */
#endif
        ]])
     ], [[mhd_cv_macro_false_defined='yes']], [[mhd_cv_macro_false_defined='no']])
  ])
AS_VAR_IF([[mhd_cv_macro_false_defined]], [["yes"]], [[:]],
  [AC_DEFINE([[false]],[[0]], [Define to value interpreted by compiler as boolean "false", if "false" is not defined by system headers.])])

AC_CACHE_CHECK([[whether "true" and "false" could be used]], [[mhd_cv_macro_true_false_valid]],
  [AC_COMPILE_IFELSE(
     [AC_LANG_PROGRAM(
        [[
#ifdef HAVE_STDBOOL_H
#include <stdbool.h>
#endif
        ]], [[
          int var1[true ? 1 : -1] = { 1 };
          int var2[false ? -1 : 1] = { 2 };
          int var3[!true ? -1 : 1] = { 3 };
          int var4[!false ? 1 : -1] = { 4 };
          if (var1[0] == var2[0] || var3[0] == var4[0])
            return 1;
        ]])
     ], [[mhd_cv_macro_true_false_valid='yes']], [[mhd_cv_macro_true_false_valid='no']])
  ])
AS_VAR_IF([[mhd_cv_macro_true_false_valid]], [["yes"]], [[:]],
  [AC_MSG_ERROR([[Value of "true" or value of "false" is not valid. Check config.log for details.]])])


AX_CHECK_COMPILE_FLAG([[-Werror=attributes]],
  [
   AC_MSG_CHECKING([[whether -Werror=attributes actually works]])
   CFLAGS="${CFLAGS_ac} ${user_CFLAGS} -Werror=attributes"
   AC_COMPILE_IFELSE([AC_LANG_PROGRAM(
       [[__attribute__((non_existing_attrb_dummy)) static int SimpleFunc(void) {return 3;}]],
       [[int r = SimpleFunc(); if (r) return r;]])],
     [
       AC_MSG_RESULT([[no]])
       errattr_CFLAGS=""
     ], [
       AC_MSG_RESULT([[yes]])
       errattr_CFLAGS="-Werror=attributes"
     ])
   CFLAGS="${CFLAGS_ac} ${user_CFLAGS}"
  ],
                      [[errattr_CFLAGS=""]], [], [])

AC_MSG_CHECKING([[for function inline keywords supported by $CC]])
CFLAGS="${CFLAGS_ac} ${user_CFLAGS} $errattr_CFLAGS"
inln_prfx="none"
# Prefer always inline functions
for inln_prfx_chk in InlineWithAttr __forceinline inline __inline__ __inline _inline _Inline
do
  # Try to link to avoid "symbol undefined" problems at build time
  AS_IF([[test "x$inln_prfx_chk" = "xInlineWithAttr"]],
    [
     AS_IF([[test "x$errattr_CFLAGS" = "x"]],
       [[ # Skip test with attribute as negative result can't be detected
          inln_prfx_chk="__forceinline" # use next value
       ]],[[inln_prfx_chk="inline __attribute__((always_inline))"]])
    ])
  AC_LINK_IFELSE(
    [
     AC_LANG_PROGRAM(
       [[
#ifdef __cplusplus
#error This test is only for C.
choke me
#endif
#ifdef HAVE_STDBOOL_H
#include <stdbool.h>
#endif
         static $inln_prfx_chk bool cmpfn(int x, int y)
         { return x > y; }
         static $inln_prfx_chk int sumfn(int x, int y)
         { return x + y; }
       ]],[[
       int a = 1, b = 100, c;
       if (cmpfn(a, b))
         c = sumfn(a, b);
       else
         c = 0 - sumfn(a, b);
       if (c)
         return 0;
       ]])
    ],
    [[ inln_prfx="$inln_prfx_chk" ]])
  test "x$inln_prfx" != "xnone" && break
done
AS_IF([[test "x$inln_prfx" != "xnone"]],
      [
       AC_DEFINE([INLINE_FUNC],[1],[Define to 1 if your C compiler supports inline functions.])
       AC_DEFINE_UNQUOTED([_MHD_static_inline],[static $inln_prfx],[Define to prefix which will be used with MHD static inline functions.])
      ], [
       AC_DEFINE([_MHD_static_inline],[static],[Define to prefix which will be used with MHD static inline functions.])
      ])
AC_MSG_RESULT([[$inln_prfx]])
CFLAGS="${CFLAGS_ac} ${user_CFLAGS}"

AC_CHECK_HEADERS([stdalign.h], [], [], [AC_INCLUDES_DEFAULT])
AC_CACHE_CHECK([[for C11 'alignof()' support]], [[mhd_cv_c_alignof]],
  [AC_COMPILE_IFELSE(
     [AC_LANG_PROGRAM(
        [[
#ifdef HAVE_STDALIGN_H
#include <stdalign.h>
#endif
        ]], [[
          int var1[(alignof(int) >= 2) ? 1 : -1];
          int var2[alignof(unsigned int) - 1];
          int var3[(alignof(char) > 0) ? 1 : -1];
          int var4[(alignof(long) >= 4) ? 1 : -1];

          /* Mute compiler warnings */
          var1[0] = var2[0] = var3[0] = 0;
          var4[0] = 1;
          if (var1[0] + var2[0] + var3[0] == var4[0])
            return 1;
        ]])
     ], [
          AC_COMPILE_IFELSE(
		    [AC_LANG_PROGRAM(
		        [[
#ifdef HAVE_STDALIGN_H
#include <stdalign.h>
#endif
		        ]], [[
		          /* Should fail if 'alignof()' works */
		          int var1[alignof(nonexisting_type) - 1];

		          /* Mute compiler warnings */
		          var1[0] = 1;
		          if (var1[0] + 1 == 1)
		            return 1;
		        ]])
		    ], [[mhd_cv_c_alignof='no']], [[mhd_cv_c_alignof='yes']])
        ], [[mhd_cv_c_alignof='no']])
  ])
AS_VAR_IF([mhd_cv_c_alignof], ["yes"],
  [AC_DEFINE([[HAVE_C_ALIGNOF]], [1], [Define to 1 if your compiler supports 'alignof()'])])


# Check system type
AC_MSG_CHECKING([[for target host OS]])
AS_CASE(["$host_os"],
 [*darwin* | *rhapsody* | *macosx*],
 [AC_DEFINE([OSX],[1],[This is an OS X system])
     mhd_host_os='Darwin'
     AC_MSG_RESULT([[$mhd_host_os]])],
 [kfreebsd*-gnu],
 [AC_DEFINE([SOMEBSD],[1],[This is a BSD system])
     AC_DEFINE([FREEBSD],[1],[This is a FreeBSD system])
     mhd_host_os='FreeBSD kernel with GNU userland'
     AC_MSG_RESULT([[$mhd_host_os]])],
 [freebsd*],
 [AC_DEFINE([SOMEBSD],[1],[This is a BSD system])
     AC_DEFINE([FREEBSD],[1],[This is a FreeBSD system])
     mhd_host_os='FreeBSD'
     AC_MSG_RESULT([[$mhd_host_os]])],
 [openbsd*],
 [AC_DEFINE([SOMEBSD],[1],[This is a BSD system])
     AC_DEFINE([OPENBSD],[1],[This is an OpenBSD system])
     mhd_host_os='OpenBSD'
     AC_MSG_RESULT([[$mhd_host_os]])],
 [netbsd*],
 [AC_DEFINE([SOMEBSD],[1],[This is a BSD system])
     AC_DEFINE([NETBSD],[1],[This is a NetBSD system])
     mhd_host_os='NetBSD'
     AC_MSG_RESULT([[$mhd_host_os]])],
 [*solaris*],
 [AC_DEFINE([SOLARIS],[1],[This is a Solaris system])
     AC_DEFINE([_REENTRANT],[1],[Need with solaris or errno does not work])
     mhd_host_os='Solaris'
     AC_MSG_RESULT([[$mhd_host_os]])
     AC_SEARCH_LIBS([gethostbyname], [nsl])
     AC_SEARCH_LIBS([socket], [socket])],
  [*linux*],
  [AC_DEFINE([LINUX],[1],[This is a Linux kernel])
     mhd_host_os='Linux'
     AC_MSG_RESULT([[$mhd_host_os]])],
  [*cygwin*],
  [AC_DEFINE([CYGWIN],[1],[This is a Cygwin system])
     mhd_host_os='Windows/Cygwin'
     AC_MSG_RESULT([[$mhd_host_os]])
     os_is_windows=yes],
  [*mingw*],
  [
    AC_DEFINE([MINGW],[1],[This is a MinGW system])
     AC_DEFINE([WINDOWS],[1],[This is a Windows system])
     mhd_host_os='Windows/MinGW'
     AC_MSG_RESULT([[$mhd_host_os]])
     LIBS="-lws2_32 ${LIBS}"
     AC_CHECK_HEADERS([winsock2.h ws2tcpip.h], [], [AC_MSG_ERROR([[Winsock2 headers are required for W32]])], [AC_INCLUDES_DEFAULT])
     AC_CACHE_CHECK([for MS lib utility], [ac_cv_use_ms_lib_tool],
       [mslibcheck=`lib 2>&1`
        AS_IF([echo "$mslibcheck" | $GREP -e '^Microsoft (R) Library Manager' - >/dev/null],
          [ac_cv_use_ms_lib_tool=yes],
          [ac_cv_use_ms_lib_tool=no])
         ])
     AS_IF([test "x$ac_cv_use_ms_lib_tool" = "xyes"],
       [AC_SUBST([MS_LIB_TOOL], [[lib]])])
     AC_SUBST([lt_cv_objdir])
     os_is_windows=yes
     os_is_native_w32=yes
   ],
   [*openedition*],
   [AC_DEFINE([OS390],[1],[This is a OS/390 system])
     mhd_host_os='OS/390'
     AC_MSG_RESULT([[$mhd_host_os]])],
   [gnu*],
   [AC_DEFINE([[GNU_HURD]], [[1]], [Define to `1' if host machine runs on GNU Hurd.])
     mhd_host_os='GNU Hurd'
     AC_MSG_RESULT([[$mhd_host_os]])
    ],
    [
     AC_MSG_RESULT([unrecognised OS])
     mhd_host_os="${host_os}"
     AC_MSG_WARN([Unrecognised OS $host_os])
     AC_DEFINE([OTHEROS],1,[Some strange OS])
 ])

AM_CONDITIONAL([CYGWIN_TARGET], [[test "x$os_is_windows" = "xyes" && \
                                  test "x${os_is_native_w32}" != "xyes"]])

AS_VAR_IF([os_is_windows], ["yes"],
  [
    AC_MSG_CHECKING([[whether target W32 version is specified by precompiler defines]])
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
/* Note: check logic is reversed for easy log reading */
#ifdef WINVER
#error WINVER is defined
choke me now;
#endif
#ifdef _WIN32_WINNT
#error _WIN32_WINNT is defined
choke me now;
#endif
#ifdef NTDDI
#error NTDDI is defined
choke me now;
#endif
        ]],[[(void)0]])
      ], [[mhd_w32_ver_preselect=no]], [[mhd_w32_ver_preselect=yes]]
    )
    AC_MSG_RESULT([[${mhd_w32_ver_preselect}]])
    AC_CHECK_HEADERS([windows.h sdkddkver.h], [], [], [AC_INCLUDES_DEFAULT])
    AS_VAR_IF([mhd_w32_ver_preselect],["yes"],
     [
       AC_MSG_CHECKING([[for specified target W32 version]])
       AS_UNSET([[mhd_w32_ver]])
       AS_UNSET([[mhd_w32_ver_msg]])
       AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#if _WIN32_WINNT+0 < 0x0501
/* Check before headers inclusion */
#error _WIN32_WINNT is less than 0x0501
choke me now;
#endif

#ifdef HAVE_SDKDDKVER_H
#include <sdkddkver.h>
#endif
#ifdef HAVE_WINDOWS_H
#include <windows.h>
#endif

#if _WIN32_WINNT+0 < 0x0501
#error _WIN32_WINNT is less than 0x0501
choke me now;
#endif
           ]],[[(void)0]])
         ], [], [
           AC_MSG_RESULT([[pre-WinXP]])
           AC_MSG_ERROR([[libmicrohttpd cannot be compiled for Windows version before Windows XP]])
         ]
       )
       AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#ifdef HAVE_SDKDDKVER_H
#include <sdkddkver.h>
#endif
#ifdef HAVE_WINDOWS_H
#include <windows.h>
#endif

#if _WIN32_WINNT+0 == 0x0501
#error _WIN32_WINNT is 0x0501
choke me now;
#endif
#if _WIN32_WINNT+0 == 0x0502
#error _WIN32_WINNT is 0x0502
choke me now;
#endif
           ]],[[(void)0]])
         ], [], [
           mhd_w32_ver="WinXP"
           mhd_w32_ver_msg="WinXP (selected by precompiler flags)"
         ]
       )
       AS_VAR_SET_IF([mhd_w32_ver], [],
         [
           AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#ifdef HAVE_SDKDDKVER_H
#include <sdkddkver.h>
#endif
#ifdef HAVE_WINDOWS_H
#include <windows.h>
#endif

#if _WIN32_WINNT+0 < 0x0600
#error _WIN32_WINNT is less than 0x0600 but greater than 0x0502
choke me now;
#endif
                ]],[[(void)0]])
             ], [], [
               AC_MSG_ERROR([[_WIN32_WINNT value is wrong (less than 0x0600 but greater than 0x0502)]])
             ]
           )

           AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#ifdef HAVE_SDKDDKVER_H
#include <sdkddkver.h>
#endif
#ifdef HAVE_WINDOWS_H
#include <windows.h>
#endif

#if _WIN32_WINNT+0 == 0x0600
#error _WIN32_WINNT is 0x0600
choke me now;
#endif
                ]],[[(void)0]])
             ], [], [
               mhd_w32_ver="Vista"
               mhd_w32_ver_msg="Vista (selected by precompiler flags)"
             ]
           )
         ]
       )

       AS_VAR_SET_IF([mhd_w32_ver], [],
         [
           AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#ifdef HAVE_SDKDDKVER_H
#include <sdkddkver.h>
#endif
#ifdef HAVE_WINDOWS_H
#include <windows.h>
#endif

#if _WIN32_WINNT+0 > 0x0600
#error _WIN32_WINNT is greater than 0x0600
choke me now;
#endif
                ]],[[(void)0]])
             ], [
               mhd_w32_ver="unknown"
               mhd_w32_ver_msg="unknown (cannot be detected)"
             ], [
               mhd_w32_ver="newer than Vista"
               mhd_w32_ver_msg="newer than Vista (selected by precompiler flags)"
             ]
           )
         ]
       )
       AC_MSG_RESULT([[${mhd_w32_ver}]])
     ], [
       mhd_w32_ver="Vista"
       mhd_w32_ver_msg="Vista (default, override by CPPFLAGS=-D_WIN32_WINNT=0xNNNN)"
       CPPFLAGS_ac="${CPPFLAGS_ac} -D_WIN32_WINNT=0x0600"
       CPPFLAGS="${CPPFLAGS_ac} ${user_CPPFLAGS}"
       AC_MSG_CHECKING([[whether headers accept _WIN32_WINNT=0x0600]])
       AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#ifdef HAVE_SDKDDKVER_H
#include <sdkddkver.h>
#endif
#ifdef HAVE_WINDOWS_H
#include <windows.h>
#endif
#include <stdio.h>
            ]],[[(void)0]])
         ], [
           AC_MSG_RESULT([[yes]])
         ], [
           AC_MSG_RESULT([[no]])
           AC_MSG_ERROR([Headers do not accept _WIN32_WINNT=0x0600. Consider override target W32 version by CPPFLAGS=-D_WIN32_WINNT=0xNNNN])
         ]
       )
     ]
    )
  ]
)

AS_IF([test "x${os_is_windows}" = "xyes" && test "x${os_is_native_w32}" = "xyes"],
  [
    AC_CACHE_CHECK([W32 run-time library type], [mhd_cv_wctr_type],
      [
        AC_EGREP_CPP([MHDMARKER: UCRT run-time library in use!], [
#include <stdio.h>
#if defined(_UCRT)
#define CRT_STR "MHDMARKER: UCRT run-time library in use!"
#endif
#if defined(__MSVCRT_VERSION__)
#if (__MSVCRT_VERSION__ >= 0xE00) && (__MSVCRT_VERSION__ < 0x1000)
#define CRT_STR "MHDMARKER: UCRT run-time library in use!"
#endif
#if (__MSVCRT_VERSION__ > 0x1400)
#define CRT_STR "MHDMARKER: UCRT run-time library in use!"
#endif
#endif

#ifndef CRT_STR
#define CRT_STR "MHDMARKER: MSVCRT run-time library in use!"
#endif

int main(void)
{
  printf ("%\n", CRT_STR);
  return 0;
}
          ],
          [mhd_cv_wctr_type="ucrt"], [mhd_cv_wctr_type="msvcrt"])
      ]
    )
    mhd_host_os="${mhd_host_os}-${mhd_cv_wctr_type}"
    AS_VAR_IF([mhd_cv_wctr_type], ["msvcrt"],
      [
        # Use CFLAGS here to override user-supplied wrong CPPFLAGS. Durty trick, but choice is limited.
        AX_APPEND_COMPILE_FLAGS([-U__USE_MINGW_ANSI_STDIO -D__USE_MINGW_ANSI_STDIO=0], [CFLAGS_ac])
        AC_SUBST([W32CRT], [MSVCRT])
      ], [AC_SUBST([W32CRT], [UCRT])]
    )

    CFLAGS="${CFLAGS_ac} ${user_CFLAGS}"
    LDFLAGS="${user_LDFLAGS}"
    AS_CASE([$mhd_w32_ver],
      [WinXP],
      [MHD_CHECK_ADD_CC_LDFLAG([-Wl,--major-subsystem-version,5,--minor-subsystem-version,1],[LDFLAGS_ac])],
      [Vista],
      [MHD_CHECK_ADD_CC_LDFLAG([-Wl,--major-subsystem-version,6,--minor-subsystem-version,0],[LDFLAGS_ac])]
    )
    LDFLAGS="${LDFLAGS_ac} ${user_LDFLAGS}"
  ]
)
CFLAGS="${CFLAGS_ac} ${user_CFLAGS}"


AC_ARG_WITH([threads],
   [AS_HELP_STRING([--with-threads=LIB],[choose threading library (posix, w32, auto, none) [auto]])],
   [], [with_threads='auto'])
AS_CASE([[$with_threads]],
  [[win32]], [[with_threads='w32']],
  [[pthreads]], [[with_threads='posix']],
  [[posix]], [[:]],
  [[w32]], [[:]],
  [[none]], [[with_threads='none']],
  [[no]], [[with_threads='none']],
  [[auto]], [[:]],
    [AC_MSG_ERROR([[incorrect parameter "$with_threads" specified for --with-threads]])]
)

# Check for posix threads support, regardless of configure parameters as
# testsuite uses only posix threads.
AX_PTHREAD(
  [
    mhd_have_posix_threads='yes'
    AC_DEFINE([[HAVE_PTHREAD_H]],[[1]],[Define to 1 if you have the <pthread.h> header file.])
	AC_CACHE_CHECK([[whether pthread_sigmask(3) is available]],
	  [[mhd_cv_func_pthread_sigmask]], [dnl
	  save_LIBS="$LIBS"
	  LIBS="$PTHREAD_LIBS $LIBS"
  	  CFLAGS="${CFLAGS_ac} ${PTHREAD_CFLAGS} ${user_CFLAGS}"
	  AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <signal.h>]],
	    [[
	      sigset_t nset, oset;
	      sigemptyset (&nset);
	      sigaddset (&nset, SIGPIPE);
	      if (0 != pthread_sigmask(SIG_BLOCK, &nset, &oset)) return 1;
	    ]])],
	    [[mhd_cv_func_pthread_sigmask="yes"]],[[mhd_cv_func_pthread_sigmask="no"]])
	  LIBS="${save_LIBS}"
      CFLAGS="${CFLAGS_ac} ${user_CFLAGS}"
	])
	AS_VAR_IF([mhd_cv_func_pthread_sigmask],["yes"],
	  [AC_DEFINE([[HAVE_PTHREAD_SIGMASK]],[[1]],[Define to 1 if you have the pthread_sigmask(3) function.])])
  ],[[mhd_have_posix_threads='no']])
AM_CONDITIONAL([HAVE_POSIX_THREADS],[test "x$mhd_have_posix_threads" = "xyes"])

mhd_have_w32_threads='no'
AS_IF([[test "x$with_threads" = "xauto"]],
 [
 AS_IF([[test "x$os_is_windows" = "xyes"]],
   [
    AC_MSG_CHECKING([[for W32 threads]])
    AC_LINK_IFELSE(
      [AC_LANG_PROGRAM([[
#include <windows.h>
         ]], [ HANDLE h = CreateThread(NULL, 0, NULL, NULL, 0, NULL);])]
      , [[mhd_have_w32_threads='yes']], [[mhd_have_w32_threads='no']]
      )
    AC_MSG_RESULT([[$mhd_have_w32_threads]])
   ])
 ]
)

AC_MSG_CHECKING([[for threading lib to use with libmicrohttpd ($with_threads)]])
AS_IF([test "x$with_threads" = "xposix"],
  [ # forced posix threads
    AS_IF([test "x$mhd_have_posix_threads" = "xyes"], [USE_THREADS='posix'],
      [ AS_IF([[test "x$os_is_windows" = "xyes"]] ,
          [ AC_MSG_ERROR([[Posix threads are not available. Try to configure --with-threads=auto]])],
          [ AC_MSG_ERROR([[No threading lib is available. Consider installing pthreads]])] )
      ])
    ])
AS_IF([test "x$with_threads" = "xw32"],
  [ # forced w32 threads
    AS_IF([[test "x$mhd_have_w32_threads" = "xyes"]],
      [[ USE_THREADS='w32' ]],
      [ AC_MSG_ERROR([[W32 threads are not available. Try to configure --with-threads=auto]])])
    ])
AS_IF([test "x$with_threads" = "xauto"],
      [# automatic threads lib selection
       AS_IF([[test "x$os_is_native_w32" = "xyes" && test "x$mhd_have_w32_threads" = "xyes"]] ,
        [[ USE_THREADS='w32' ]] ,
        [[ test "x$mhd_have_posix_threads" = "xyes" ]], [[ USE_THREADS='posix' ]],
        [[ test "x$mhd_have_w32_threads" = "xyes" ]], [[ USE_THREADS='w32' ]],
        [ AC_MSG_ERROR([[No threading lib is available. Consider installing pthreads]]) ]
        )])
AS_IF([test "x$with_threads" = "xnone"],
   [USE_THREADS='none'])

AS_IF([test "x$USE_THREADS" = "xposix"],
  [CC="$PTHREAD_CC"
  AC_DEFINE([MHD_USE_POSIX_THREADS],[1],[define to use pthreads])
  MHD_LIB_CFLAGS="$MHD_LIB_CFLAGS $PTHREAD_CFLAGS"
  MHD_LIBDEPS="$PTHREAD_LIBS $MHD_LIBDEPS"
  MHD_LIBDEPS_PKGCFG="$PTHREAD_LIBS $MHD_LIBDEPS_PKGCFG"],
  [AS_IF([test "x$USE_THREADS" = "xw32"],
   [AC_DEFINE([MHD_USE_W32_THREADS],[1],[define to use W32 threads])])])
AM_CONDITIONAL([USE_POSIX_THREADS], [test "x$USE_THREADS" = "xposix"])
AM_CONDITIONAL([USE_W32_THREADS], [test "x$USE_THREADS" = "xw32"])
AM_CONDITIONAL([USE_THREADS], [test "x$USE_THREADS" != "xnone"])
AM_CONDITIONAL([DISABLE_THREADS], [test "x$USE_THREADS" = "xnone"])
AC_MSG_RESULT([$USE_THREADS])

AC_ARG_ENABLE([[thread-names]],
   [AS_HELP_STRING([--disable-thread-names],[do not set names on MHD generated threads [auto]])],
   [], [enable_thread_names='auto'])

AS_IF([test "x$enable_thread_names" != "xno" && test "x$USE_THREADS" = "xposix"],[
  # Check for thread name function
  HAVE_THREAD_NAME_FUNC="no"
  SAVE_LIBS="$LIBS"
  LIBS="$PTHREAD_LIBS $LIBS"
  CFLAGS="${CFLAGS_ac} $PTHREAD_CFLAGS ${user_CFLAGS}"
  AC_CHECK_HEADERS([pthread_np.h],[],[],
    [
AC_INCLUDES_DEFAULT
      [
#include <pthread.h>
      ]
    ])

  # Try to find how to set thread name by thread attributes.
  # If pthread_attr_setname_np(3) is not declared, it's not possible to detect
  # form of pthread_attr_setname_np(3) due to C "feature" "implicit declaration".
  AC_CHECK_DECL([[pthread_attr_setname_np]],[],[],[[
#include <pthread.h>
#ifdef HAVE_PTHREAD_NP_H
#include <pthread_np.h>
#endif
]])

  AS_IF([[test "x$ac_cv_have_decl_pthread_attr_setname_np" = "xyes"]],
    [AC_MSG_CHECKING([[for pthread_attr_setname_np(3) in NetBSD or OSF1 form]])
     AC_LINK_IFELSE(
      [AC_LANG_PROGRAM([[
#include <pthread.h>
#ifdef HAVE_PTHREAD_NP_H
#include <pthread_np.h>
#endif
]], [[
      pthread_attr_t thr_attr;
      pthread_attr_init(&thr_attr);
      pthread_attr_setname_np(&thr_attr, "name", 0);
      pthread_attr_destroy(&thr_attr);
        ]])],
        [AC_DEFINE([[HAVE_PTHREAD_ATTR_SETNAME_NP_NETBSD]], [[1]], [Define if you have NetBSD form (or OSF1 form) of pthread_attr_setname_np(3) function.])
         HAVE_THREAD_NAME_FUNC="yes"
         AC_MSG_RESULT([[yes]])],
        [AC_MSG_RESULT([[no]])]
        )
    ])

  AS_IF([[test "x$HAVE_THREAD_NAME_FUNC" != "xyes" && test "x$ac_cv_have_decl_pthread_attr_setname_np" = "xyes"]],
    [AC_MSG_CHECKING([[for pthread_attr_setname_np(3) in IBM i or Solaris form]])
     AC_LINK_IFELSE(
      [AC_LANG_PROGRAM([[
#include <pthread.h>
#ifdef HAVE_PTHREAD_NP_H
#include <pthread_np.h>
#endif
]], [[
      pthread_attr_t thr_attr;
      pthread_attr_init(&thr_attr);
      pthread_attr_setname_np(&thr_attr, "name");
      pthread_attr_destroy(&thr_attr);
        ]])],
        [AC_DEFINE([[HAVE_PTHREAD_ATTR_SETNAME_NP_IBMI]], [[1]], [Define if you have IBM i form (or Solaris form) of pthread_attr_setname_np(3) function.])
         HAVE_THREAD_NAME_FUNC="yes"
         AC_MSG_RESULT([[yes]])],
        [AC_MSG_RESULT([[no]])]
        )
    ])

  # Try to find how to set thread name for started thread - less convenient
  # than setting name by attributes.
  # If pthread_setname_np(3) is not declared, it's not possible to detect
  # form of pthread_setname_np(3) due to C "feature" "implicit declaration".
  AS_IF([[test "x$HAVE_THREAD_NAME_FUNC" != "xyes"]],
    [AC_CHECK_DECL([[pthread_setname_np]],[],[],[[
#include <pthread.h>
#ifdef HAVE_PTHREAD_NP_H
#include <pthread_np.h>
#endif
       ]])
    ])

  AS_IF([[test "x$HAVE_THREAD_NAME_FUNC" != "xyes" && test "x$ac_cv_have_decl_pthread_setname_np" = "xyes"]],
    [AC_MSG_CHECKING([[for pthread_setname_np(3) in NetBSD or OSF1 form]])
     AC_LINK_IFELSE(
      [AC_LANG_PROGRAM([[
#include <pthread.h>
#ifdef HAVE_PTHREAD_NP_H
#include <pthread_np.h>
#endif
]], [[int res = pthread_setname_np(pthread_self(), "name", 0); if (res) return res;]])],
        [AC_DEFINE([[HAVE_PTHREAD_SETNAME_NP_NETBSD]], [[1]], [Define if you have NetBSD form (or OSF1 form) of pthread_setname_np(3) function.])
         HAVE_THREAD_NAME_FUNC="yes"
         AC_MSG_RESULT([[yes]])],
        [AC_MSG_RESULT([[no]])]
        )
    ])

  AS_IF([[test "x$HAVE_THREAD_NAME_FUNC" != "xyes" && test "x$ac_cv_have_decl_pthread_setname_np" = "xyes"]],
    [AC_MSG_CHECKING([[for pthread_setname_np(3) in GNU/Linux form]])
     AC_LINK_IFELSE(
       [AC_LANG_PROGRAM([[
#include <pthread.h>
#ifdef HAVE_PTHREAD_NP_H
#include <pthread_np.h>
#endif
]], [[int res = pthread_setname_np(pthread_self(), "name"); if (res) return res;]])],
        [AC_DEFINE([[HAVE_PTHREAD_SETNAME_NP_GNU]], [[1]], [Define if you have GNU/Linux form of pthread_setname_np(3) function.])
         HAVE_THREAD_NAME_FUNC="yes"
         AC_MSG_RESULT([[yes]])],
        [AC_MSG_RESULT([[no]])]
        )
    ])

  AS_IF([[test "x$HAVE_THREAD_NAME_FUNC" != "xyes" && test "x$ac_cv_have_decl_pthread_setname_np" = "xyes"]],
    [AC_MSG_CHECKING([[for pthread_setname_np(3) in Darwin form]])
     AC_LINK_IFELSE(
       [AC_LANG_PROGRAM([[
#include <pthread.h>
#ifdef HAVE_PTHREAD_NP_H
#include <pthread_np.h>
#endif
]], [[int res = pthread_setname_np("name"); if (res) return res;]])],
        [AC_DEFINE([[HAVE_PTHREAD_SETNAME_NP_DARWIN]], [[1]], [Define if you have Darwin form of pthread_setname_np(3) function.])
         HAVE_THREAD_NAME_FUNC="yes"
         AC_MSG_RESULT([[yes]])],
        [AC_MSG_RESULT([[no]])]
        )
    ])

  AS_IF([[test "x$HAVE_THREAD_NAME_FUNC" != "xyes"]],
    [
     AC_CHECK_DECL([[pthread_set_name_np]],
       [
        AC_MSG_CHECKING([[for pthread_set_name_np(3) in FreeBSD form]])
        AC_LINK_IFELSE(
          [AC_LANG_PROGRAM([[
#include <pthread.h>
#ifdef HAVE_PTHREAD_NP_H
#include <pthread_np.h>
#endif
]], [[pthread_set_name_np(pthread_self(), "name");]])],
          [AC_DEFINE([[HAVE_PTHREAD_SET_NAME_NP_FREEBSD]], [[1]], [Define if you have FreeBSD form of pthread_set_name_np(3) function.])
           HAVE_THREAD_NAME_FUNC="yes"
           AC_MSG_RESULT([[yes]])],
          [AC_MSG_RESULT([[no]])]
          )
       ],[],[[
#include <pthread.h>
#ifdef HAVE_PTHREAD_NP_H
#include <pthread_np.h>
#endif
       ]]
     )
    ])

  LIBS="$SAVE_LIBS"
  CFLAGS="${CFLAGS_ac} ${user_CFLAGS}"
])

AS_IF([[test "x$enable_thread_names" != "xno"]],
  [
    AC_MSG_CHECKING([[whether to enable thread names]])
    AC_COMPILE_IFELSE(
     [AC_LANG_PROGRAM([], [[
#ifdef MHD_NO_THREAD_NAMES
#error Thread names are disabled.
choke me
#endif

/* Keep in sync with mhd_threads.h */
#if defined(MHD_USE_POSIX_THREADS) && (defined(HAVE_PTHREAD_ATTR_SETNAME_NP_NETBSD) || defined(HAVE_PTHREAD_ATTR_SETNAME_NP_IBMI) || \
    defined(HAVE_PTHREAD_SETNAME_NP_GNU) || defined(HAVE_PTHREAD_SET_NAME_NP_FREEBSD) || defined(HAVE_PTHREAD_SETNAME_NP_DARWIN) || \
    defined(HAVE_PTHREAD_SETNAME_NP_NETBSD) )
(void) 0; /* no-op */
#elif defined(MHD_USE_W32_THREADS) && defined(_MSC_FULL_VER)
(void) 0; /* no-op */
#else
#error No thread name function is available.
choke me
#endif
       ]])
     ], [
       enable_thread_names='yes'
     ], [
       AS_IF([[test "x$enable_thread_names" = "xyes"]],
         [
           AC_MSG_RESULT([[no]])
           AC_MSG_ERROR([[thread names was explicitly requested, but thread name function is not available]])
         ])
       enable_thread_names='no'
     ])
  AC_MSG_RESULT([[$enable_thread_names]])
  ])

AS_IF([[test "x$enable_thread_names" = "xno"]],
  [AC_DEFINE([[MHD_NO_THREAD_NAMES]], [[1]], [Define to 1 to disable setting name on generated threads])])

AM_CONDITIONAL(HAVE_W32, [test "x$os_is_native_w32" = "xyes"])
w32_shared_lib_exp=no
AS_IF([test "x$enable_shared" = "xyes" && test "x$os_is_native_w32" = "xyes"],
  [
    AS_IF([test "x$ac_cv_use_ms_lib_tool" = "xyes" || test -n "$DLLTOOL"],
      [
        w32_shared_lib_exp=yes
        use_expfile="no"
        AS_VAR_IF([ac_cv_use_ms_lib_tool], ["yes"], [use_expfile="yes"],
          [
            AC_CACHE_CHECK([whether $DLLTOOL supports export file generation], [mhd_cv_dlltool_expfile],
              [
                AS_IF([AC_RUN_LOG([$DLLTOOL -e conftest.exp >&2 ])],
                  [
                    AS_IF([test -f conftest.exp], [mhd_cv_dlltool_expfile="yes"], [mhd_cv_dlltool_expfile="no"])
                  ], [mhd_cv_dlltool_expfile="no"]
                )
                rm -f conftest.exp
              ]
            )
            use_expfile="${mhd_cv_dlltool_expfile}"
          ]
        )
      ],
      [
        AC_MSG_WARN([[GNU dlltool or MS lib.exe is required for creating shared library export on W32]])
        AC_MSG_WARN([[Export library libmicrohttpd.lib will not be created]])
      ]
    )
  ]
)
AM_CONDITIONAL([W32_SHARED_LIB_EXP], [test "x$w32_shared_lib_exp" = "xyes"])
AM_CONDITIONAL([USE_MS_LIB_TOOL], [test "x$ac_cv_use_ms_lib_tool" = "xyes"])
AM_CONDITIONAL([USE_EXPORT_FILE], [test "x$use_expfile" = "xyes"])

MHD_CHECK_SOCKET_SHUTDOWN_TRIGGER([AC_DEFINE([HAVE_LISTEN_SHUTDOWN],[1],[can use shutdown on listen sockets])])
AM_CONDITIONAL([HAVE_LISTEN_SHUTDOWN], [test "x$mhd_cv_host_shtdwn_trgr_select" = "xyes"])

# SENDMSG. Should we check for SCM_RIGHTS instead?
# https://lists.x.org/archives/xorg-devel/2013-November/038687.html
AC_SEARCH_LIBS([sendmsg], [socket], [AC_DEFINE([HAVE_SENDMSG],[1],[Define if your platform supports sendmsg])])
MHD_CHECK_FUNC([writev],
  [[#include <sys/uio.h>]],
  [[
    struct iovec iov[2];
    char some_str[4] = "OK\n";
    iov[0].iov_base = (void *) some_str;
    iov[0].iov_len = 3;
    if (0 > writev(1, iov, 1))
      return 2;
  ]]
)

AC_C_BIGENDIAN
AC_C_VARARRAYS

AC_CACHE_CHECK([[whether __func__ magic-macro is available]],
  [[mhd_cv_macro___func___avail]], [dnl
  AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <stddef.h>]],[[const char *funcname = __func__ ; if (NULL == funcname) return 1;]])],
    [[mhd_cv_macro___func___avail="yes"]],[[mhd_cv_macro___func___avail="no"]])
])
AS_VAR_IF([mhd_cv_macro___func___avail], ["yes"],
  [AC_DEFINE([HAVE___FUNC__], [1], [Define to 1 if your compiler supports __func__ magic-macro.])],
  [
    AC_CACHE_CHECK([[whether __FUNCTION__ magic-macro is available]],
      [[mhd_cv_macro___function___avail]], [dnl
      AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <stddef.h>]],[[const char *funcname = __FUNCTION__ ; if (NULL == funcname) return 1;]])],
        [[mhd_cv_macro___function___avail="yes"]],[[mhd_cv_macro___function___avail="no"]])
    ])
    AC_DEFINE([HAVE___FUNCTION__], [1], [Define to 1 if your compiler supports __FUNCTION__ magic-macro.])
  ]
)
AC_CACHE_CHECK([[whether __builtin_bswap32() is available]],
  [[mhd_cv_func___builtin_bswap32_avail]], [dnl
  AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include<stdint.h>]], [[uint32_t a = 1; uint32_t b = __builtin_bswap32(a); a = b; (void) a;]])],
    [[mhd_cv_func___builtin_bswap32_avail="yes"]],[[mhd_cv_func___builtin_bswap32_avail="no"]])
])
AS_IF([[test "x$mhd_cv_func___builtin_bswap32_avail" = "xyes"]],
  [AC_DEFINE([[MHD_HAVE___BUILTIN_BSWAP32]], [[1]], [Define to 1 if you have __builtin_bswap32() builtin function])])
AC_CACHE_CHECK([[whether __builtin_bswap64() is available]],
  [[mhd_cv_func___builtin_bswap64_avail]], [dnl
  AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include<stdint.h>]], [[uint64_t a = 1; uint64_t b = __builtin_bswap64(a); a = b; (void) a;]])],
    [[mhd_cv_func___builtin_bswap64_avail="yes"]], [[mhd_cv_func___builtin_bswap64_avail="no"]])
])
AS_IF([[test "x$mhd_cv_func___builtin_bswap64_avail" = "xyes"]],
  [AC_DEFINE([[MHD_HAVE___BUILTIN_BSWAP64]], [[1]], [Define to 1 if you have __builtin_bswap64() builtin function])])

AC_CHECK_PROG([HAVE_CURL_BINARY],[curl],[yes],[no])
AM_CONDITIONAL([HAVE_CURL_BINARY],[test "x$HAVE_CURL_BINARY" = "xyes"])
AC_CHECK_PROG([HAVE_MAKEINFO_BINARY],[makeinfo],[yes],[no])
AM_CONDITIONAL([HAVE_MAKEINFO_BINARY],[test "x$HAVE_MAKEINFO_BINARY" = "xyes"])
AM_CONDITIONAL(W32_STATIC_LIB, [test "x$os_is_native_w32" = "xyes"  && test "x$enable_static" = "xyes"])


AC_ARG_ENABLE([[doc]],
  [AS_HELP_STRING([[--disable-doc]], [do not build any documentation])], ,
    [enable_doc=yes])
test "x$enable_doc" = "xno" || enable_doc=yes
AM_CONDITIONAL([BUILD_DOC], [test "x$enable_doc" = "xyes"])

AC_ARG_ENABLE([[examples]],
  [AS_HELP_STRING([[--disable-examples]], [do not build any examples])], ,
    [enable_examples=yes])
test "x$enable_examples" = "xno" || enable_examples=yes
AM_CONDITIONAL([BUILD_EXAMPLES], [test "x$enable_examples" = "xyes"])

AC_ARG_ENABLE([[heavy-tests]],
  [AS_HELP_STRING([[--enable-heavy-tests[=SCOPE]]], [use SCOPE of heavy tests in test-suite. WARNING:]
  [a dedicated host with minimal number of background processes and no network]
  [activity is recommended to enable. (basic, full)])], [],
    [enable_heavy_tests=no])
use_heavy_tests="no"
use_vheavy_tests="no"
use_heavy_tests_MSG="no"
AS_CASE([${enable_heavy_tests}],
  [yes|basic],
  [
  	enable_heavy_tests="basic"
    use_heavy_tests="yes"
    use_vheavy_tests="no"
    use_heavy_tests_MSG="yes, basic heavy tests (a dedicated host is recommended)"
  ],
  [all|full],
  [
  	enable_heavy_tests="full"
    use_heavy_tests="yes"
    use_vheavy_tests="yes"
    use_heavy_tests_MSG="yes, full set of heavy tests (a dedicated host is recommended)"
  ],
  [no],
  [
    use_heavy_tests="no"
    use_vheavy_tests="no"
    use_heavy_tests_MSG="no"
  ],
  [AC_MSG_ERROR([[Unknown parameter value: --enable-heavy-tests=${enable_heavy_tests}]])]
)
AS_VAR_IF([use_heavy_tests], ["yes"],
  [
    HEAVY_TESTS_NOTPARALLEL='.NOTPARALLEL:'
    AC_DEFINE([_MHD_HEAVY_TESTS], [1], [Define to 1 to enable "heavy" test paths.])
    AS_VAR_IF([use_vheavy_tests], ["yes"],
      [AC_DEFINE([_MHD_VHEAVY_TESTS], [1], [Define to 1 to enable "very heavy" test paths.])]
    )
  ],
  [
    HEAVY_TESTS_NOTPARALLEL=" "
  ]
)
AM_CONDITIONAL([HEAVY_TESTS],[test "x$use_heavy_tests" = "xyes"])

AC_ARG_ENABLE([[poll]],
  [AS_HELP_STRING([[--enable-poll[=ARG]]], [enable poll support (yes, no, auto) [auto]])],
    [enable_poll=${enableval}],
    [enable_poll='auto']
  )

AS_IF([test "$enable_poll" != "no"],
  [
    AS_IF([test "$os_is_native_w32" != "yes"],
      [
        AC_CHECK_HEADERS([poll.h],
          [
            MHD_CHECK_FUNC([poll],
              [[
#include <poll.h>
              ]],
              [[
  struct pollfd fds[2];
  
  fds[0].fd = 0;
  fds[0].events = POLLIN;
  if (0 > poll(fds, 1, 0))
    return 2;
              ]], 
              [have_poll='yes'], [have_poll='no']
            )
          ], [], [AC_INCLUDES_DEFAULT]
        )
      ],
      [
        AC_MSG_CHECKING([for WSAPoll()])
        AC_LINK_IFELSE(
          [
            AC_LANG_PROGRAM(
              [[
#include <winsock2.h>
              ]],[[
WSAPOLLFD fda[2];
WSAPoll(fda, 2, 0);
              ]]
            )
          ],
          [
            have_poll='yes'
            AC_DEFINE([HAVE_POLL],[1])
          ],
          [have_poll='no']
        )
        AC_MSG_RESULT([$have_poll])
      ]
    )
    AS_IF([test "$enable_poll" = "yes" && test "$have_poll" != "yes"],
      [AC_MSG_ERROR([[Support for poll was explicitly requested but cannot be enabled on this platform.]])])
    enable_poll="$have_poll"
  ]
)

AC_ARG_ENABLE([[epoll]],
  [AS_HELP_STRING([[--enable-epoll[=ARG]]], [enable epoll support (yes, no, auto) [auto]])],
    [enable_epoll=${enableval}],
    [enable_epoll='auto']
  )

AS_IF([test "$enable_epoll" != "no"],
  [
    AX_HAVE_EPOLL
    AS_IF([test "${ax_cv_have_epoll}" = "yes"],
      [
        AC_DEFINE([[EPOLL_SUPPORT]],[[1]],[Define to 1 to enable epoll support])
        enable_epoll='yes'
      ],
      [
        AS_IF([test "$enable_epoll" = "yes"],
          [AC_MSG_ERROR([[Support for epoll was explicitly requested but cannot be enabled on this platform.]])]
        )
        enable_epoll='no'
      ]
    )
  ]
)

AM_CONDITIONAL([MHD_HAVE_EPOLL], [[test "x$enable_epoll" = xyes]])

AS_IF([test "x$enable_epoll" = "xyes"],
  AC_CACHE_CHECK([for epoll_create1()],
                 [mhd_cv_have_epoll_create1], [
    AC_LINK_IFELSE([
      AC_LANG_PROGRAM([[
#include <sys/epoll.h>
        ]], [[
  if (0 > epoll_create1(EPOLL_CLOEXEC))
    return 3;
        ]]
      )],
      [mhd_cv_have_epoll_create1=yes],
      [mhd_cv_have_epoll_create1=no])])
  AS_IF([test "x$mhd_cv_have_epoll_create1" = "xyes"],[
    AC_DEFINE([[HAVE_EPOLL_CREATE1]], [[1]], [Define if you have epoll_create1 function.])]))

AC_CACHE_CHECK([for supported 'noreturn' keyword], [mhd_cv_decl_noreturn],
  [
    mhd_cv_decl_noreturn="none"
    CFLAGS="${CFLAGS_ac} ${user_CFLAGS} ${errattr_CFLAGS}"
    for decl_noret in '_Noreturn' '__attribute__((__noreturn__))' '__declspec(noreturn)'
    do
      AC_LINK_IFELSE([AC_LANG_SOURCE(
          [[
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

${decl_noret} static void myexitfunc(int code)
{
#ifdef HAVE_STDLIB_H
  exit (code);
#else
  (void)code;
#endif
}

int main (int argc, char *const *argv)
{
  (void) argv;
  if (argc > 2)
    myexitfunc (2);
  return 0;
}
          ]]
        )], [mhd_cv_decl_noreturn="${decl_noret}"]
      )
      AS_IF([test "x${mhd_cv_decl_noreturn}" != "xnone"], [break])
    done
   CFLAGS="${CFLAGS_ac} ${user_CFLAGS}"
  ]
)
AS_VAR_IF([mhd_cv_decl_noreturn], ["none"],
  [AC_DEFINE([_MHD_NORETURN], [], [Define to supported 'noreturn' function declaration])],
  [AC_DEFINE_UNQUOTED([_MHD_NORETURN], [${mhd_cv_decl_noreturn}], [Define to supported 'noreturn' function declaration])]
)

# Check for types sizes
# Types sizes are used as an indirect indication of maximum allowed values for types
# which is used to exclude by preprocessor some compiler checks for values clips
# Assuming no staffing or uniform staffing for integer types
AC_CACHE_CHECK([size of tv_sec member of struct timeval], [mhd_cv_size_timeval_tv_sec],
  [
    AC_COMPUTE_INT([mhd_cv_size_timeval_tv_sec], [((long int)sizeof(test_var.tv_sec))],
      [[
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif /* HAVE_SYS_TIME_H */
#ifdef HAVE_TIME_H
#include <time.h>
#endif /* HAVE_TIME_H */
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif /* HAVE_SYS_TYPES_H */
struct timeval test_var;
      ]],
      [
        # The size is used only to exclude additional checks/comparison in code
        # to avoid compiler warnings. With larger size MHD code will use
        # additional checks which ensure that value will fit but it may produce
        # a harmless compiler warning.
        AC_MSG_WARN([The size cannot be determined, assuming 8.])
        mhd_cv_size_timeval_tv_sec=8
      ]
    )
  ]
)
AC_DEFINE_UNQUOTED([SIZEOF_STRUCT_TIMEVAL_TV_SEC], [$mhd_cv_size_timeval_tv_sec],
  [The size of `tv_sec' member of `struct timeval', as computed by sizeof])
AC_CHECK_SIZEOF([int64_t], [], [[#include <stdint.h>]])
AC_CHECK_SIZEOF([uint64_t], [], [[#include <stdint.h>]])
AC_CHECK_SIZEOF([int], [], [[#include <stdint.h>]])
AC_CHECK_SIZEOF([unsigned int], [], [[#include <stdint.h>]])
AC_CHECK_SIZEOF([unsigned long long], [], [[#include <stdint.h>]])
AC_CHECK_SIZEOF([size_t], [],
  [[
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif /* HAVE_STDLIB_H */
#ifdef HAVE_STDDEF_H
#include <stddef.h>
#endif /* HAVE_STDDEF_H */
#include <stdio.h>
  ]]
)

AC_CHECK_HEADERS([dlfcn.h],[have_tlsplugin=yes],[have_tlsplugin=no], [AC_INCLUDES_DEFAULT])
AM_CONDITIONAL([MHD_HAVE_TLS_PLUGIN], [[test "x$have_tlsplugin" = xyes]])

AC_CHECK_HEADERS([zlib.h],[have_zlib=yes],[have_zlib=no], [AC_INCLUDES_DEFAULT])
AM_CONDITIONAL([HAVE_ZLIB], [[test "x$have_zlib" = xyes]])

# Check for generic functions
MHD_CHECK_FUNC([random],
  [
AC_INCLUDES_DEFAULT
[#include <stdlib.h>
  ]],
  [[long int r = random(); (void)r;]],
  [],
  [
    MHD_CHECK_FUNC([rand],
      [
AC_INCLUDES_DEFAULT
[#include <stdlib.h>
      ]],
      [[int r = rand(); (void)r;]],
	)
  ]
)

AC_CHECK_MEMBERS([struct sockaddr_in.sin_len, struct sockaddr_in6.sin6_len,
                  struct sockaddr_storage.ss_len],
   [], [],
   [
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
   ])

MHD_CHECK_LINK_RUN([[for working getsockname()]],[[mhd_cv_getsockname_usable]],
  [[mhd_cv_getsockname_usable='assuming yes']],
  [
    AC_LANG_SOURCE(
      [[
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif
#ifdef HAVE_WS2TCPIP_H
#include <ws2tcpip.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif


static void zr_mem(void *ptr, socklen_t size)
{ char *mem = ptr; while(size--) {mem[0] = 0; mem++;} }

int main(void)
{
  const socklen_t c_addr_size = (socklen_t)sizeof(struct sockaddr_in);
  struct sockaddr_in sa;
  socklen_t addr_size;
  int ret = 1;
#if !defined(_WIN32) || defined(__CYGWIN__)
  int sckt;
  const int invld_sckt = -1;
#else
  SOCKET sckt;
  const SOCKET invld_sckt = INVALID_SOCKET;
  WSADATA wsa_data;

  if (0 != WSAStartup(MAKEWORD(2, 2), &wsa_data) || MAKEWORD(2, 2) != wsa_data.wVersion)
    return 20;
#endif

  sckt = socket (PF_INET, SOCK_STREAM, 0);
  if (invld_sckt != sckt)
  {
    zr_mem(&sa, c_addr_size);
    sa.sin_family = AF_INET;
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
    sa.sin_len = c_addr_size;
#endif
    if (0 == bind (sckt, (struct sockaddr *)&sa, c_addr_size))
    {
      if (0 == listen (sckt, 1))
      {
        addr_size = c_addr_size;
        if (0 == getsockname (sckt, (struct sockaddr  *)&sa, &addr_size))
        {
          if (c_addr_size >= addr_size)
          {
            if (0 != ntohs(sa.sin_port))
            { ret = 0;
            } else ret = 7;
          } else ret = 6;
        } else ret = 5;
      } else ret = 4;
    } else ret = 3;
  } else ret = 2;
#if !defined(_WIN32) || defined(__CYGWIN__)
  close (sckt);
#else
  closesocket (sckt);
  WSACleanup();
#endif
  return ret;
}
      ]]
    )
  ],
  [AC_DEFINE([[MHD_USE_GETSOCKNAME]], [[1]], [Define if you have usable `getsockname' function.])]
)

AC_CACHE_CHECK([for usable PAGESIZE macro], [mhd_cv_macro_pagesize_usable],
  [
    AC_LINK_IFELSE(
      [
        AC_LANG_PROGRAM(
          [[
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#ifndef PAGESIZE
#error No PAGESIZE macro defined
choke me now
#endif
          ]],
          [[
            long pgsz = PAGESIZE + 0;
            if (1 > pgsz) return 1;
          ]]
        )
      ],
      [[mhd_cv_macro_pagesize_usable="yes"]], [[mhd_cv_macro_pagesize_usable="no"]]
    )
  ]
)
AS_VAR_IF([[mhd_cv_macro_pagesize_usable]], [["yes"]],
  [
    AC_DEFINE([[MHD_USE_PAGESIZE_MACRO]],[[1]],[Define if you have usable PAGESIZE macro])
    AC_CACHE_CHECK([whether PAGESIZE macro could be used for static init], [mhd_cv_macro_pagesize_usable_static],
      [
        AC_LINK_IFELSE(
          [
            AC_LANG_PROGRAM(
              [[
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#ifndef PAGESIZE
#error No PAGESIZE macro defined
choke me now
#endif
static long ac_pgsz = PAGESIZE + 0;
              ]],
              [[
                if (1 > ac_pgsz) return 1;
              ]]
            )
          ],
          [[mhd_cv_macro_pagesize_usable_static="yes"]], [[mhd_cv_macro_pagesize_usable_static="no"]]
        )
      ]
    )
    AS_VAR_IF([[mhd_cv_macro_pagesize_usable_static]], [["yes"]],
      [AC_DEFINE([[MHD_USE_PAGESIZE_MACRO_STATIC]],[[1]],[Define if you have PAGESIZE macro usable for static init])]
    )
  ],
  [
    AC_CACHE_CHECK([for usable PAGE_SIZE macro], [mhd_cv_macro_page_size_usable],
      [
        AC_LINK_IFELSE(
          [
            AC_LANG_PROGRAM(
              [[
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#ifndef PAGE_SIZE
#error No PAGE_SIZE macro defined
choke me now
#endif
              ]],
              [[
                long pgsz = PAGE_SIZE + 0;
                if (1 > pgsz) return 1;
              ]]
            )
          ],
          [[mhd_cv_macro_page_size_usable="yes"]], [[mhd_cv_macro_page_size_usable="no"]]
        )
      ]
    )
    AS_VAR_IF([[mhd_cv_macro_page_size_usable]], [["yes"]],
      [
        AC_DEFINE([[MHD_USE_PAGE_SIZE_MACRO]],[[1]],[Define if you have usable PAGE_SIZE macro])
        AC_CACHE_CHECK([whether PAGE_SIZE macro could be used for static init], [mhd_cv_macro_page_size_usable_static],
          [
            AC_LINK_IFELSE(
              [
                AC_LANG_PROGRAM(
                  [[
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#ifndef PAGE_SIZE
#error No PAGE_SIZE macro defined
choke me now
#endif
static long ac_pgsz = PAGE_SIZE + 0;
                  ]],
                  [[
                    if (1 > ac_pgsz) return 1;
                  ]]
                )
              ],
              [[mhd_cv_macro_page_size_usable_static="yes"]], [[mhd_cv_macro_page_size_usable_static="no"]]
            )
          ]
        )
        AS_VAR_IF([[mhd_cv_macro_page_size_usable_static]], [["yes"]],
          [AC_DEFINE([[MHD_USE_PAGE_SIZE_MACRO_STATIC]],[[1]],[Define if you have PAGE_SIZE macro usable for static init])]
        )
      ]
    )
  ]
)

# Check for inter-thread signaling type
AC_ARG_ENABLE([[itc]],
  [AS_HELP_STRING([[--enable-itc=TYPE]], [use TYPE of inter-thread communication (pipe, socketpair, eventfd) [auto]])], [],
  [[enable_itc='auto']]
)

AS_CASE([[$enable_itc]],
  [[pipe]], [[:]],
  [[socketpair]], [[:]],
  [[eventfd]], [[:]],
  [[auto]], [AS_VAR_IF([[os_is_windows]], [["yes"]], [[enable_itc='socketpair']])],
  [[eventFD]], [[enable_itc='eventfd']],
  [[socket]], [[enable_itc='socketpair']],
  [[no]], [AC_MSG_ERROR([[inter-thread communication cannot be disabled]])],
    [AC_MSG_ERROR([[unrecognized type "$enable_itc" of inter-thread communication specified by "--enable-itc=$enable_itc"]])]
)
AS_UNSET([[use_itc]])

AS_IF([[test "x$enable_itc" = "xeventfd" || test "x$enable_itc" = "xauto"]],
  [
    MHD_CHECK_LINK_RUN([[for working eventfd(2)]],[[mhd_cv_eventfd_usable]],[[mhd_cv_eventfd_usable='assuming no']],
      [
        AC_LANG_SOURCE([[
#include <sys/eventfd.h>
#include <unistd.h>

int main(void)
{
  unsigned char buf[8];
  int ret;
  int efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
  if (0 > efd)
    return 2;
  ret = 0;
  buf[3] = 1;
  if (8 != write(efd, buf, 8))
    ret = 3;
  else
  {
    if (8 != read(efd, buf, 8))
      ret = 4;
  }
  close(efd);
  return ret;
}
          ]]
        )
      ],
      [
        use_itc='eventfd'
        enable_itc="$use_itc"
        AC_DEFINE([[_MHD_ITC_EVENTFD]], [[1]], [Define to use eventFD for inter-thread communication])
      ],
      [
        AS_VAR_IF([[enable_itc]], [["eventfd"]], [AC_MSG_ERROR([[eventfd(2) is not usable, consider using other type of inter-thread communication]])])
      ]
    )
    AS_VAR_IF([mhd_cv_eventfd_usable],["assuming no"],
      [AC_MSG_WARN([if you have 'eventfd' support enabled on your target system consider overriding test result by "mhd_cv_eventfd_usable=yes" configure parameter])]
    )
  ]
)

AS_IF([[test "x$enable_itc" = "xpipe" || test "x$enable_itc" = "xauto"]], [
  AS_VAR_IF([[os_is_native_w32]], [["yes"]], [], [
    AC_CACHE_CHECK([[whether pipe(3) is usable]], [[mhd_cv_pipe_usable]], [
      AC_LINK_IFELSE([
        AC_LANG_PROGRAM([
AC_INCLUDES_DEFAULT
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
        ], [[
          int arr[2];
          int res;
          res = pipe(arr);
          if (res != 0) return 33;
          close (arr[0]);
          close (arr[1]);
        ]])
      ], [[mhd_cv_pipe_usable='yes']], [[mhd_cv_pipe_usable='no']])
    ])
    AS_VAR_IF([[mhd_cv_pipe_usable]], [["yes"]], [
      use_itc='pipe'
      enable_itc="$use_itc"
      AC_DEFINE([[_MHD_ITC_PIPE]], [[1]], [Define to use pipe for inter-thread communication])
      MHD_CHECK_LINK_RUN([[whether pipe2(2) is usable]],[[mhd_cv_pipe2_usable]],
        [
          # Cross-compiling
          AS_CASE([${host_os}], [kfreebsd*-gnu], [[mhd_cv_pipe2_usable='assuming no']],
            [[mhd_cv_pipe2_usable='assuming yes']])
        ],
        [
          AC_LANG_PROGRAM([
AC_INCLUDES_DEFAULT
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
            ], [[
              int arr[2];
              int res;
              res = pipe2(arr, O_CLOEXEC | O_NONBLOCK);
              if (res != 0) return 33;
              close (arr[0]);
              close (arr[1]);
            ]]
          )
        ],
        [AC_DEFINE([[HAVE_PIPE2_FUNC]], [[1]], [Define if you have usable pipe2(2) function])]
      )
    ], [
      AS_VAR_IF([[enable_itc]], [["pipe"]], [AC_MSG_ERROR([[pipe(3) is not usable, consider using other type of inter-thread communication]])])
    ])
  ])
])

AS_IF([[test "x$enable_itc" = "xsocketpair" || test "x$enable_itc" = "xauto"]], [
  AS_VAR_IF([[os_is_native_w32]], [["yes"]], [[mhd_cv_socketpair_usable='yes']], [
    AC_CACHE_CHECK([[whether socketpair(3) is usable]], [[mhd_cv_socketpair_usable]], [
      AC_LINK_IFELSE([
        AC_LANG_PROGRAM([
AC_INCLUDES_DEFAULT
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
        ], [[
          int arr[2];
          int res;
#if defined(AF_LOCAL)
          res = socketpair(AF_LOCAL, SOCK_STREAM, 0, arr);
#elif defined(AF_UNIX)
          res = socketpair(AF_UNIX, SOCK_STREAM, 0, arr);
#else
#error AF_LOCAL and AF_UNIX are both undefined
          choke me now;
#endif
          if (res != 0) return 1
        ]])
      ], [[mhd_cv_socketpair_usable='yes']], [[mhd_cv_socketpair_usable='no']])
    ])
  ])
  AS_VAR_IF([[mhd_cv_socketpair_usable]], [["yes"]], [
    use_itc='socketpair'
    enable_itc="$use_itc"
    AC_DEFINE([[_MHD_ITC_SOCKETPAIR]], [[1]], [Define to use socketpair for inter-thread communication])
  ], [
    AS_VAR_IF([[enable_itc]], [["socketpair"]], [AC_MSG_ERROR([[socketpair(3) is not usable, consider using other type of inter-thread communication]])])
  ])
])

AS_IF([[test -z "$use_itc"]], [AC_MSG_ERROR([[cannot find usable type of inter-thread communication]])])


MHD_CHECK_FUNC([accept4],
  [[
#if defined(HAVE_SYS_TYPES_H)
#  include <sys/types.h>
#endif
#include <sys/socket.h>
  ]],
  [
  struct sockaddr sk_addr;
  socklen_t addr_size;
  if (0 > accept4(0, &sk_addr, &addr_size, 0))
    return 3;
  ]
)
MHD_CHECK_FUNC([gmtime_r],
  [[
#if defined(HAVE_SYS_TYPES_H)
#  include <sys/types.h>
#endif
#include <time.h>
  ]],
  [[
  time_t timer = (time_t) 0;
  struct tm res;
  
  if (&res != gmtime_r(&timer, &res))
    return 3;
  ]]
)
MHD_CHECK_FUNC([memmem],
  [[
#if defined(HAVE_STDDEF_H)
#  include <stddef.h>
#elif defined(HAVE_STDLIB_H)
#  include <stdlib.h>
#endif /* HAVE_STDLIB_H */
#include <string.h>
  ]],
  [[
  const char *haystack = "abc";
  size_t hslen = 3;
  const char *needle = "b";
  size_t needlelen = 1;
  
  if ((haystack + 1) != memmem(haystack, hslen, needle, needlelen))
    return 3;
  ]]
)
MHD_CHECK_FUNC([snprintf],
  [[
#include <stdio.h>
  ]],
  [[
  char buf[2];
  
  if (1 != snprintf(buf, 2, "a"))
    return 3;
  /* Do not use the next check to avoid compiler warning */
  /* if (4 != snprintf(buf, 2, "abcd"))
    return 4; */
  ]]
)
AC_CHECK_DECL([gmtime_s],
  [
    AC_MSG_CHECKING([[whether gmtime_s is in C11 form]])
    AC_LINK_IFELSE(
        [ AC_LANG_PROGRAM(
          [[
#define __STDC_WANT_LIB_EXT1__ 1
#include <time.h>
#ifdef __cplusplus
extern "C"
#endif
             struct tm* gmtime_s(const time_t* time, struct tm* result);
           ]], [[
             struct tm res;
             time_t t;
             gmtime_s (&t, &res);
          ]])
        ],
        [
          AC_DEFINE([HAVE_C11_GMTIME_S], [1], [Define to 1 if you have the `gmtime_s' function in C11 form.])
          AC_MSG_RESULT([[yes]])
        ],
        [
          AC_MSG_RESULT([[no]])
          AC_MSG_CHECKING([[whether gmtime_s is in W32 form]])
          AC_LINK_IFELSE(
            [ AC_LANG_PROGRAM(
              [[
#include <time.h>
#ifdef __cplusplus
extern "C"
#endif
errno_t gmtime_s(struct tm* _tm, const time_t* time);
              ]], [[
                 struct tm res;
                 time_t t;
                 gmtime_s (&res, &t);
              ]])
            ],
            [
              AC_DEFINE([HAVE_W32_GMTIME_S], [1], [Define to 1 if you have the `gmtime_s' function in W32 form.])
              AC_MSG_RESULT([[yes]])
            ],
            [AC_MSG_RESULT([[no]])
            ])
        ])
  ], [],
  [[#define __STDC_WANT_LIB_EXT1__ 1
#include <time.h>]])


AC_CHECK_DECL([SOCK_NONBLOCK], [AC_DEFINE([HAVE_SOCK_NONBLOCK], [1], [SOCK_NONBLOCK is defined in a socket header])], [],
  [[
#if defined(HAVE_SYS_TYPES_H)
#  include <sys/types.h>
#endif
#if defined(HAVE_SYS_SOCKET_H)
#  include <sys/socket.h>
#elif defined(HAVE_WINSOCK2_H)
#  include <winsock2.h>
#endif
  ]]
)


AC_CHECK_DECL([[clock_gettime]],
  [
   SAVE_LIBS="$LIBS"
   AC_SEARCH_LIBS([clock_gettime], [rt],
     [
      AC_DEFINE([HAVE_CLOCK_GETTIME], [1], [Have clock_gettime])
      AS_VAR_IF([[ac_cv_search_clock_gettime]],[["none required"]], [],
        [
         MHD_LIBDEPS="$ac_cv_search_clock_gettime $MHD_LIBDEPS"
         MHD_LIBDEPS_PKGCFG="$ac_cv_search_clock_gettime $MHD_LIBDEPS_PKGCFG"
        ])
     ], [], [$MHD_LIBDEPS])
   LIBS="$SAVE_LIBS"
  ], [], [[
#include <time.h>
  ]])

AC_MSG_CHECKING([[for clock_get_time]])
AC_LINK_IFELSE(
  [AC_LANG_PROGRAM(
    [[
#include <mach/clock.h>
#include <mach/mach.h>
    ]],
    [[
      clock_serv_t cs;
      mach_timespec_t mt;
      host_get_clock_service(mach_host_self(), SYSTEM_CLOCK, &cs);
      clock_get_time(cs, &mt);
      mach_port_deallocate(mach_task_self(), cs);
    ]])
  ],
  [
    AC_DEFINE([HAVE_CLOCK_GET_TIME], [1], [Define to 1 if you have `clock_get_time', `host_get_clock_service' and `mach_port_deallocate' functions.])
    AC_MSG_RESULT([[yes]])
  ],
  [AC_MSG_RESULT([[no]])
  ])

AC_MSG_CHECKING([[for gethrtime]])
AC_LINK_IFELSE(
  [AC_LANG_PROGRAM(
    [[
#ifdef HAVE_SYS_TIME_H
/* Solaris define gethrtime() in sys/time.h */
#include <sys/time.h>
#endif /* HAVE_SYS_TIME_H */
#ifdef HAVE_TIME_H
/* HP-UX define gethrtime() in time.h */
#include <time.h>
#endif /* HAVE_TIME_H */
    ]], [[hrtime_t hrt = gethrtime(); ]])
  ],
  [
    AC_DEFINE([HAVE_GETHRTIME], [1], [Define to 1 if you have `gethrtime' function.])
    AC_MSG_RESULT([[yes]])
  ],
  [AC_MSG_RESULT([[no]])
  ])

AS_VAR_IF([ac_cv_header_time_h], ["yes"],
  [
    AC_CACHE_CHECK([[for C11 timespec_get()]], [mhd_cv_func_timespec_get],
      [
        AC_LINK_IFELSE(
          [
            AC_LANG_PROGRAM(
              [[
#include <time.h>

#ifndef TIME_UTC
#error TIME_UTC must be defined to use timespec_get()
choke me now
#endif
              ]],
              [[
  struct timespec ts;
  if (TIME_UTC != timespec_get (&ts, TIME_UTC))
    return 1;
              ]]
            )
          ], [[mhd_cv_func_timespec_get="yes"]], [[mhd_cv_func_timespec_get="no"]]
        )
      ]
    )
    AS_VAR_IF([mhd_cv_func_timespec_get], ["yes"],
      [AC_DEFINE([HAVE_TIMESPEC_GET], [1], [Define to 1 if you have C11 `mhd_cv_func_timespec_get' function and TIME_UTC macro.])]
    )
  ]
)

MHD_CHECK_FUNC([[gettimeofday]],
  [[
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif /* HAVE_SYS_TIME_H */
#ifdef HAVE_TIME_H
#include <time.h>
#endif /* HAVE_TIME_H */
  ]],
  [[
  struct timeval tv;
  if (0 != gettimeofday (&tv, (void*) 0))
    return 1;
  ]]
)

# IPv6
AC_MSG_CHECKING(for IPv6)
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <stdio.h>
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif
#ifdef HAVE_WS2TCPIP_H
#include <ws2tcpip.h>
#endif
]], [[
int af=AF_INET6;
int pf=PF_INET6;
struct sockaddr_in6 sa;
printf("%d %d %p\n", af, pf, &sa);
]])],[
have_inet6=yes;
AC_DEFINE([HAVE_INET6], [1], [Provides IPv6 headers])
],[
have_inet6=no
])
AC_MSG_RESULT($have_inet6)

MHD_CHECK_FUNC([[sysconf]], [[#include <unistd.h>]], [[long a = sysconf(0); if (a) return 1;]])

MHD_CHECK_FUNC([[sysctl]], [[
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h>
#endif
#ifdef HAVE_STDDEF_H
#include <stddef.h>
#endif
  ]], [[int mib[2] = {CTL_KERN, KERN_MAXPROC}; i][f (sysctl(mib, 2, NULL, NULL, NULL, 0)) return 1;]]
)

MHD_CHECK_FUNC([[sysctlbyname]], [[
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h>
#endif
#ifdef HAVE_STDDEF_H
#include <stddef.h>
#endif
  ]], [[sysctlbyname("test", NULL, NULL, NULL, 0);]]
)

MHD_CHECK_FUNC([[usleep]], [[#include <unistd.h>]], [[usleep(100000);]])
MHD_CHECK_FUNC([[nanosleep]], [[#include <time.h>]], [[struct timespec ts2, ts1 = {0, 0}; nanosleep(&ts1, &ts2);]])

HIDDEN_VISIBILITY_CFLAGS=""
AH_TEMPLATE([_MHD_EXTERN],[defines how to decorate public symbols w][hile building the library])
CFLAGS="${user_CFLAGS}"
MHD_CHECK_CC_CFLAG([-fvisibility=hidden],[CFLAGS_ac],
  [
    # NOTE: require setting of errattr_CFLAGS above
    CFLAGS="${CFLAGS_ac} -fvisibility=hidden ${user_CFLAGS} ${errattr_CFLAGS}"
    AC_CACHE_CHECK([whether $CC supports __attribute__((visibility("default")))],[mhd_cv_cc_attr_visibility],
      [
        AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
extern __attribute__((visibility("default"))) int test_extrn_func(void);

int test_extrn_func(void) {return 0;}
              ]])
          ],
          [mhd_cv_cc_attr_visibility="yes"],[mhd_cv_cc_attr_visibility="no"]
        )
      ]
    )
    AS_VAR_IF([mhd_cv_cc_attr_visibility],["yes"],
      [
        HIDDEN_VISIBILITY_CFLAGS="-fvisibility=hidden"
        AS_IF([test "x$os_is_native_w32" = "xyes" && test "x$enable_shared" = "xyes"],
          [AC_DEFINE([_MHD_EXTERN], [__attribute__((visibility("default"))) __declspec(dllexport) extern])],
          [AC_DEFINE([_MHD_EXTERN], [__attribute__((visibility("default"))) extern])]
        )
      ],
      [
        AC_MSG_WARN([$CC supports -fvisibility, but does not support __attribute__((visibility("default"))). Check compiler and compiler flags.])
        AC_DEFINE([_MHD_EXTERN], [extern])
      ]
    )
  ],[AC_DEFINE([_MHD_EXTERN], [extern])]
)
CFLAGS="${CFLAGS_ac} ${user_CFLAGS}"
AC_SUBST([HIDDEN_VISIBILITY_CFLAGS])

# libcurl (required for testing)
AC_ARG_ENABLE([curl],
  [AS_HELP_STRING([--disable-curl],[disable cURL based testcases])],
  [enable_curl=${enableval}])
curl=0
AS_IF([test "$enable_curl" != "no"],
 [LIBCURL_CHECK_CONFIG([yes],[7.16.4],[enable_curl=yes],
    [
      AS_IF([test "x$enable_curl" = "xyes"],
       [AC_MSG_WARN([[cURL-based tests cannot be enabled because libcurl is missing]])])
      enable_curl=no
    ])
])
AM_CONDITIONAL([RUN_LIBCURL_TESTS], [test "x$enable_curl" = "xyes"])
AS_IF([test "x$enable_curl" = "xyes"],
  [MSG_CURL="yes"],
  [MSG_CURL="no, many unit tests will not run"]
)

mhd_have_libmagic="no"
SAVE_LIBS="$LIBS"
LIBS="-lmagic $LIBS"
AC_MSG_CHECKING([[for suitable libmagic]])
AC_LINK_IFELSE(
  [AC_LANG_PROGRAM(
    [AC_INCLUDES_DEFAULT
     [
#include <magic.h>
    ]],
    [[
      char var_data[256];
      const char *var_mime;
      magic_t var_magic = magic_open (MAGIC_MIME_TYPE);
      (void)magic_load (var_magic, NULL);
      var_data[0] = 0;
      var_mime = magic_buffer (var_magic, var_data, 1);
      magic_close (var_magic);
    ]]
   )
  ],
  [
    AC_DEFINE([MHD_HAVE_LIBMAGIC], [1], [Define to 1 if you have suitable libmagic.])
    mhd_have_libmagic="yes"
    AC_MSG_RESULT([[yes]])
  ],
  [AC_MSG_RESULT([[no]])
  ]
)
LIBS="$SAVE_LIBS"
AM_CONDITIONAL([MHD_HAVE_LIBMAGIC], [[test "x$mhd_have_libmagic" = "xyes"]])

# large file support (> 4 GB)
AC_SYS_LARGEFILE
AC_FUNC_FSEEKO
MHD_CHECK_FUNC([lseek64],
  [[
#if defined(HAVE_SYS_TYPES_H)
#  include <sys/types.h>
#endif
#include <unistd.h>
  ]],
  [[
  if (((off64_t) -1) == lseek64(0, (off64_t) 0, SEEK_SET))
    return 3;
  ]]
)
MHD_CHECK_FUNC([pread64],
  [[
#if defined(HAVE_SYS_TYPES_H)
#  include <sys/types.h>
#endif
#include <unistd.h>
  ]],
  [[
  char buf[5];
  if (0 > pread64(0, (void *) buf, 1, (off64_t) 0))
    return 3;
  ]]
)
MHD_CHECK_FUNC([pread],
  [[
#if defined(HAVE_SYS_TYPES_H)
#  include <sys/types.h>
#endif
#include <unistd.h>
  ]],
  [[
  char buf[5];
  if (0 > pread(0, (void *) buf, 1, 0))
    return 3;
  ]]
)


# check for various sendfile functions
AC_ARG_ENABLE([sendfile],
   [AS_HELP_STRING([--disable-sendfile],
               [disable usage of sendfile() for HTTP connections [auto]])],
   [],
   [enable_sendfile="auto"])
AS_CASE([$enable_sendfile],
  [[auto | yes]],[[found_sendfile="no"]],
  [[no]],[[found_sendfile="disabled"]],
  [AC_MSG_ERROR([[unknown value specified: --enable-sendfile=$enable_sendfile]])]
)
AS_VAR_IF([[found_sendfile]], [["no"]],
  [
    AC_MSG_CHECKING([[for Linux-style sendfile(2)]])
    AC_LINK_IFELSE(
      [AC_LANG_PROGRAM(
        [[
#include <sys/sendfile.h>

static void empty_func(void)
{
/* Check for declaration */
  (void)sendfile;
}
/* Declare again to check form match */
ssize_t sendfile(int, int, off_t*, size_t);
        ]],
        [[
          int fd1=0, fd2=2;
          off_t o = 0;
          size_t s = 5;
          ssize_t r;
          r = sendfile (fd1, fd2, &o, s);
          if (r)
            empty_func();
        ]]
       )
      ],
      [
        AC_DEFINE([HAVE_LINUX_SENDFILE], [1], [Define to 1 if you have linux-style sendfile(2).])
        found_sendfile="yes, Linux-style"
        AC_MSG_RESULT([[yes]])
        MHD_CHECK_FUNC([sendfile64],
          [[
#include <sys/sendfile.h>
          ]],
          [[
  off64_t f_offset = (off64_t) 0;
  if (0 > sendfile64 (0, 1, &f_offset, 1))
    return 3;
          ]]
        )
      ],
      [AC_MSG_RESULT([[no]])
      ]
    )
  ]
)
AS_VAR_IF([[found_sendfile]], [["no"]],
  [
   AC_MSG_CHECKING([[for FreeBSD-style sendfile(2)]])
   AC_LINK_IFELSE(
     [AC_LANG_PROGRAM(
       [[
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>

static void empty_func(void)
{
/* Check for declaration */
  (void)sendfile;
}
/* Declare again to check form match */
int sendfile(int, int, off_t, size_t,
             struct sf_hdtr*, off_t*, int);
       ]],
       [[
         int fd1=0, fd2=1;
         off_t o = 0;
         size_t s = 5;
         off_t r1;
         int r2;
         r2 = sendfile (fd1, fd2, o, s, (void*)0, &r1, 0);
         if (r2)
           empty_func();
       ]]
      )
     ],
     [
       AC_DEFINE([HAVE_FREEBSD_SENDFILE], [1], [Define to 1 if you have FreeBSD-style sendfile(2).])
       found_sendfile="yes, FreeBSD-style"
       AC_MSG_RESULT([[yes]])
     ],
     [AC_MSG_RESULT([[no]])
     ]
   )
  ]
)
AS_VAR_IF([[found_sendfile]], [["no"]],
  [
   AC_MSG_CHECKING([[for Darwin-style sendfile(2)]])
   AC_LINK_IFELSE(
     [AC_LANG_PROGRAM(
       [[
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>

static void empty_func(void)
{
/* Check for declaration */
  (void)sendfile;
}
/* Declare again to check form match */
int sendfile(int, int, off_t, off_t*,
             struct sf_hdtr *, int);
       ]],
       [[
         int fd=0, s=1;
         off_t o = 0;
         off_t l = 5;
         int r;
         r = sendfile (fd, s, o, &l, (void*)0, 0);
         if (r)
           empty_func();
       ]]
      )
     ],
     [
       AC_DEFINE([HAVE_DARWIN_SENDFILE], [1], [Define to 1 if you have Darwin-style sendfile(2).])
       found_sendfile="yes, Darwin-style"
       AC_MSG_RESULT([[yes]])
     ],
     [AC_MSG_RESULT([[no]])
     ]
   )
  ]
)

AS_VAR_IF([[found_sendfile]], [["no"]],
  [
   AC_MSG_CHECKING([[for Solaris-style sendfile(3)]])
   SAVE_LIBS="$LIBS"
   LIBS="-lsendfile $LIBS"
   AC_LINK_IFELSE(
     [AC_LANG_PROGRAM(
       [[
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sendfile.h>

static void empty_func(void)
{
/* Check for declaration */
  (void)sendfile;
}
/* Declare again to check form match */
ssize_t sendfile(int out_fd, int in_fd,
                 off_t *off, size_t len);
       ]],
       [[
         int fd1=0, fd2=1;
         off_t o = 0;
         size_t l = 5;
         ssize_t r;
         r = sendfile (fd1, fd2, &o, l);
         if (r)
           empty_func();
       ]]
      )
     ],
     [
       AC_DEFINE([HAVE_SOLARIS_SENDFILE], [1], [Define to 1 if you have Solaris-style sendfile(3).])
       found_sendfile="yes, Solaris-style"
       MHD_LIBDEPS="-lsendfile $MHD_LIBDEPS"
       MHD_LIBDEPS_PKGCFG="-lsendfile $MHD_LIBDEPS_PKGCFG"
       AC_MSG_RESULT([[yes]])
       MHD_CHECK_FUNC([sendfile64],
         [[
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
         ]],
         [[
  off64_t f_offset = (off64_t) 0;
  if (0 > sendfile64 (0, 1, &f_offset, 1))
    return 3;
         ]]
       )
     ],
     [AC_MSG_RESULT([[no]])
     ]
   )
   LIBS="$SAVE_LIBS"
  ]
)
AS_IF([[test "x$found_sendfile" = "xno" && test "x$enable_sendfile" = "xyes"]],
  [AC_MSG_ERROR([[sendfile() usage was requested by configure parameter, but no usable sendfile() function is detected]])]
)

# optional: have error messages ?
AC_MSG_CHECKING([[whether to generate error messages]])
AC_ARG_ENABLE([messages],
   [AS_HELP_STRING([--disable-messages],
               [disable MHD error messages])],
   [enable_messages=${enableval}],
   [enable_messages=yes])
AS_IF([[test "x$enable_messages" = "xyes"]],
  [ AC_DEFINE([HAVE_MESSAGES],[1],[Define to 1 to enable support for error messages.]) ],
  [[ enable_messages=no ]])
AC_MSG_RESULT([[$enable_messages]])


# optional: have postprocessor?
AC_MSG_CHECKING([[whether to enable postprocessor]])
AC_ARG_ENABLE([postprocessor],
   [AS_HELP_STRING([--disable-postprocessor],
               [disable MHD PostProcessor functionality])],
   [enable_postprocessor=${enableval}],
   [enable_postprocessor=yes])
AS_IF([[test "x$enable_postprocessor" != "xno"]],
  [ enable_postprocessor=yes
    AC_DEFINE([HAVE_POSTPROCESSOR],[1],[Define to 1 if libmicrohttpd is compiled with postprocessor support.]) ])
AM_CONDITIONAL([HAVE_POSTPROCESSOR], [test "x$enable_postprocessor" != "xno"])
AC_MSG_RESULT([[$enable_postprocessor]])


# optional: have zzuf, socat?
run_zzuf_tests="no"
AS_VAR_IF([use_heavy_tests],["yes"],
  [
    AS_VAR_IF([enable_curl],["yes"],
      [
        AC_CHECK_PROG([have_zzuf],[zzuf],[yes],[no])
        AS_VAR_IF([have_zzuf],["yes"],
          [
            AC_CHECK_PROG([have_socat],[socat],[yes],[no])
            AS_VAR_IF([have_socat],["yes"],
              [
                run_zzuf_tests="yes"
                run_zzuf_tests_MSG="yes"
              ],
              [
                run_zzuf_tests="no"
                run_zzuf_tests_MSG="no, socat tool not found"
              ]
            )
          ],
          [
            run_zzuf_tests="no"
            run_zzuf_tests_MSG="no, zzuf tool not found"
          ]
        )
      ],
      [
        run_zzuf_tests="no"
        run_zzuf_tests_MSG="no, tests with libcurl are not enabled"
      ]
    )
  ],
  [
    run_zzuf_tests="no"
    run_zzuf_tests_MSG="no, heavy tests are not enabled"
  ]
)
AM_CONDITIONAL([RUN_ZZUF_TESTS],[test "x$run_zzuf_tests" = "xyes"])

have_gnutls=no
have_gnutls_sni=no
have_gcrypt=no
AS_UNSET([GNUTLS_CPPFLAGS])
AS_UNSET([GNUTLS_LDFLAGS])

# optional: HTTPS support.  Enabled by default
AC_ARG_ENABLE([https],
   [AS_HELP_STRING([--enable-https],
               [enable HTTPS support (yes, no, auto)[auto]])],
   [enable_https=${enableval}])
AS_IF([test "x$enable_https" != "xno"],[
#
# Next block is large unindented block
#

# gnutls
have_gnutls_pkgcfg=no
AC_MSG_CHECKING([[how to find GnuTLS library]])
AC_ARG_WITH([[gnutls]],
   [AS_HELP_STRING([[--with-gnutls[=PFX]]],[use GnuTLS for HTTPS support, optional PFX overrides pkg-config data for GnuTLS headers (PFX/include) and libs (PFX/lib)])],
   [
    AS_CASE([$with_gnutls],
     [no],[
        AC_MSG_RESULT([[GnuTLS disabled]])
        AS_UNSET([GNUTLS_CPPFLAGS])
        AS_UNSET([GNUTLS_CFLAGS])
        AS_UNSET([GNUTLS_LDFLAGS])
        AS_UNSET([GNUTLS_LIBS])
      ],
      [yes],[
        AC_MSG_RESULT([[automatically, forced]])
      ],
      [
        AC_MSG_RESULT([[-I$with_gnutls/include -L$with_gnutls/lib -lgnutls]])
        SAVE_LIBS="$LIBS"
        LDFLAGS="${LDFLAGS_ac} -L$with_gnutls/lib ${user_LDFLAGS}"
        CPPFLAGS="${CPPFLAGS_ac} -I$with_gnutls/include ${user_CPPFLAGS}"
        have_gnutls_pkgcfg=no
          AC_CHECK_HEADERS([gnutls/gnutls.h],
            [AC_CHECK_LIB([gnutls], [gnutls_priority_set],
              [
                GNUTLS_CPPFLAGS="-I$with_gnutls/include"
                GNUTLS_LDFLAGS="-L$with_gnutls/lib"
                GNUTLS_LIBS="-lgnutls"
                have_gnutls=yes
              ])], [], [AC_INCLUDES_DEFAULT])
        AS_IF([test "x$have_gnutls" != "xyes"], [AC_MSG_ERROR([can't find usable libgnutls at specified prefix $with_gnutls])])
        CPPFLAGS="${CPPFLAGS_ac} ${user_CPPFLAGS}"
        CFLAGS="${CFLAGS_ac} ${user_CFLAGS}"
        LDFLAGS="${LDFLAGS_ac} ${user_LDFLAGS}"
        LIBS="$SAVE_LIBS"
      ])
   ],
   [AC_MSG_RESULT([[automatically]])
   ])

AS_IF([test "x$with_gnutls" != "xno" && test "x$have_gnutls" != "xyes"],
  [
    AC_CACHE_CHECK([[whether to add pkg-config special search directories]], [mhd_cv_pkgconf_add_dirs],
     [
      AS_IF([[test "x$host_os" = "xsolaris2.11" && test "x$cross_compiling" = "xno"]],
       [
        AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
char size_chk[7-sizeof(char*)];
#if defined(_LP64) || defined(__LP64__) || defined(__x86_64) || defined(__x86_64__)
#error This is 64-bit target.
choke me now
#endif
#if defined(__amd64) || defined(__amd64__) || defined(__sparcv9) || defined(__sparc_v9__)
#error This is 64-bit target.
choke me now
#endif
           ]], [[]]
          )
         ],
         [
          mhd_cv_pkgconf_add_dirs='/usr/lib/pkgconfig/gnutls-3'
         ],
         [
          AS_IF([[test "x$host_cpu" = "xx86_64" || test "x$host_cpu" = "xi386"]],
                  [[mhd_cv_pkgconf_add_dirs='/usr/lib/amd64/pkgconfig/gnutls-3:/usr/lib/amd64/pkgconfig']],
                [[test "x$host_cpu" = "xsparc"]],
                  [[mhd_cv_pkgconf_add_dirs='/usr/lib/sparkv9/pkgconfig/gnutls-3:/usr/lib/sparkv9/pkgconfig']],
                  [[mhd_cv_pkgconf_add_dirs='/usr/lib/64/pkgconfig/gnutls-3:/usr/lib/64/pkgconfig']]
          )
         ]
        )
       ],
       [[ mhd_cv_pkgconf_add_dirs='no' ]]
      )
     ]
    )
    AS_IF([[test "x$mhd_cv_pkgconf_add_dirs" != "xno"]],
     [
      test "x$PKG_CONFIG_PATH" = "x" || PKG_CONFIG_PATH="${PKG_CONFIG_PATH}${PATH_SEPARATOR}"
      PKG_CONFIG_PATH="${PKG_CONFIG_PATH}${mhd_cv_pkgconf_add_dirs}"
      export PKG_CONFIG_PATH
     ]
    )
    PKG_CHECK_MODULES(GNUTLS, [[gnutls]],
      [
       have_gnutls_pkgcfg='yes'
       SAVE_LIBS="$LIBS"
       CFLAGS="${CFLAGS_ac} $GNUTLS_CFLAGS ${user_CFLAGS}"
       LIBS="$GNUTLS_LIBS $LIBS"
       AC_MSG_CHECKING([[whether GnuTLS is usable]])
       AC_LINK_IFELSE([
         AC_LANG_PROGRAM([[
#include <gnutls/gnutls.h>
          ]], [[
                gnutls_session_t session;
                gnutls_priority_t priorities;
                gnutls_global_init();
                gnutls_priority_init(&priorities, "NORMAL", NULL);
                gnutls_init(&session, GNUTLS_SERVER);
                gnutls_priority_set(session, priorities);
          ]])],
          [
           AC_MSG_RESULT([[yes]])
           have_gnutls=yes
           # GNUTLS_CFLAGS is actually CPPFLAGS
           GNUTLS_CPPFLAGS="$GNUTLS_CFLAGS"
           # GNUTLS_LDFLAGS is a combination of LDFLAGS and LIBS
           GNUTLS_LDFLAGS="$GNUTLS_LIBS"
          ],
          [
           AC_MSG_RESULT([[no]])
           have_gnutls=no
          ])

       AS_IF([test "x$have_gnutls" != "xyes"],
         [
          AC_MSG_WARN([pkg-config reports that GnuTLS is present, but GnuTLS can't be used])
          AS_UNSET([GNUTLS_CPPFLAGS])
          AS_UNSET([GNUTLS_CFLAGS])
          AS_UNSET([GNUTLS_LDFLAGS])
          AS_UNSET([GNUTLS_LIBS])
         ]
       )
       CPPFLAGS="${CPPFLAGS_ac} ${user_CPPFLAGS}"
       CFLAGS="${CFLAGS_ac} ${user_CFLAGS}"
       LDFLAGS="${LDFLAGS_ac} ${user_LDFLAGS}"
       LIBS="$SAVE_LIBS"
      ],
      [
       # check for GnuTLS at default paths
       have_gnutls_pkgcfg='no'
       AC_CHECK_HEADERS([gnutls/gnutls.h],
        [AC_CHECK_LIB([gnutls], [gnutls_priority_set],
          [
            GNUTLS_LIBS="-lgnutls"
            have_gnutls=yes
          ])], [], [AC_INCLUDES_DEFAULT])
      ])
  ])

have_gcrypt='unknown'
AS_IF([test "x$with_gnutls" != "xno" && test "x$have_gnutls" != "xyes"],
  [
   AM_PATH_LIBGCRYPT([1.2.2], [have_gcrypt=yes], [have_gcrypt=no])
   AS_IF([[test "x$have_gcrypt" = "xyes"]],
     [
       SAVE_LIBS="$LIBS"
       CFLAGS="${CFLAGS_ac} $LIBGCRYPT_CFLAGS ${user_CFLAGS}"
       # LIBGCRYPT_CFLAGS can be actually a CPPFLAGS, so check them both
       CPPFLAGS="${CPPFLAGS_ac} $LIBGCRYPT_CFLAGS ${user_CPPFLAGS}"
       AC_CHECK_HEADERS([gcrypt.h], [], [have_gcrypt=no], [AC_INCLUDES_DEFAULT])
       # Check for GnuTLS with gcrypt flags
       LDFLAGS="${LDFLAGS_ac} ${LIBGCRYPT_LIBS} ${user_LDFLAGS}"
       # A bit of hack: unset cache variable to force recheck
       AS_UNSET([ac_cv_header_gnutls_gnutls_h])
       AC_CHECK_HEADERS([gnutls/gnutls.h],
        [AS_UNSET([ac_cv_lib_gnutls_gnutls_priority_set]) # A bit of hack: unset cache variable to force recheck
         AC_CHECK_LIB([gnutls], [gnutls_priority_set],
          [
            GNUTLS_CPPFLAGS="$LIBGCRYPT_CFLAGS"
            GNUTLS_CFLAGS="$LIBGCRYPT_CFLAGS"
            GNUTLS_LDFLAGS="$LIBGCRYPT_LIBS"
            GNUTLS_LIBS="-lgnutls"
            have_gnutls=yes
          ])], [], [AC_INCLUDES_DEFAULT])
       CPPFLAGS="${CPPFLAGS_ac} ${user_CPPFLAGS}"
       CFLAGS="${CFLAGS_ac} ${user_CFLAGS}"
       LDFLAGS="${LDFLAGS_ac} ${user_LDFLAGS}"
       LIBS="$SAVE_LIBS"
     ]
   )
  ]
)
AS_IF([test "x$have_gnutls" != "xyes" && test "x$with_gnutls" = "xyes"],
      [AC_MSG_ERROR([[can't find usable libgnutls]])])

  AS_IF([test "x$have_gnutls" = "xyes"],
    [
     SAVE_LIBS="$LIBS"
     CPPFLAGS="${CPPFLAGS_ac} ${GNUTLS_CPPFLAGS} ${user_CPPFLAGS}"
     CFLAGS="${CFLAGS_ac} ${GNUTLS_CFLAGS} ${user_CFLAGS}"
     LDFLAGS="${LDFLAGS_ac} ${GNUTLS_LDFLAGS} ${user_LDFLAGS}"
     LIBS="$GNUTLS_LIBS $LIBS"
     AC_MSG_CHECKING([[for gnutls_privkey_import_x509_raw()]])
     AC_LINK_IFELSE([
       AC_LANG_PROGRAM([[
#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
          ]], [[
            gnutls_datum_t data;
            gnutls_privkey_t key = 0;
#ifndef gnutls_load_file
            (void)gnutls_load_file; /* Check for declaration. */
#endif
#ifndef gnutls_privkey_import_x509_raw
            (void)gnutls_privkey_import_x509_raw; /* Check for declaration. */
#endif
            gnutls_load_file("key.pem", &data);
            gnutls_privkey_import_x509_raw(key, &data, GNUTLS_X509_FMT_PEM, NULL, 0);
            gnutls_free(data.data);
          ]])], [[have_gnutls_sni=yes]], [[have_gnutls_sni=no]])
     AC_MSG_RESULT([[$have_gnutls_sni]])
     AC_CACHE_CHECK([[whether GnuTLS require libgcrypt initialisation]], [mhd_cv_gcrypt_required],
       [
        AC_COMPILE_IFELSE(
          [
           AC_LANG_PROGRAM(
             [
#include <gnutls/gnutls.h>
             ],
             [
#if !defined(GNUTLS_VERSION_NUMBER) || GNUTLS_VERSION_NUMBER+0 <= 0x020c14
#error Old versions of GnuTLS require libgcript initialisation
choke me now
#endif
             ]
           )
          ],
          [[mhd_cv_gcrypt_required='no']], [[mhd_cv_gcrypt_required='yes']]
        )
       ]
     )
     CPPFLAGS="${CPPFLAGS_ac} ${user_CPPFLAGS}"
     CFLAGS="${CFLAGS_ac} ${user_CFLAGS}"
     LDFLAGS="${LDFLAGS_ac} ${user_LDFLAGS}"
     LIBS="$SAVE_LIBS"
    ],
    [
     AS_UNSET([GNUTLS_CPPFLAGS])
     AS_UNSET([GNUTLS_LDFLAGS])
    ]
  )

  AS_IF([[test "x$mhd_cv_gcrypt_required" = "xyes" && test "x$have_gcrypt" = "xunknown"]],
    [
     AM_PATH_LIBGCRYPT([1.2.2], [have_gcrypt=yes], [have_gcrypt=no])
     AS_IF([[test "x$have_gcrypt" = "xyes"]],
       [
         CFLAGS="${CFLAGS_ac} ${LIBGCRYPT_CFLAGS} ${user_CFLAGS}"
         # LIBGCRYPT_CFLAGS can be actually a CPPFLAGS, so check them both
         CPPFLAGS="${CPPFLAGS_ac} ${LIBGCRYPT_CFLAGS} ${user_CPPFLAGS}"
         AC_CHECK_HEADERS([gcrypt.h], [], [have_gcrypt=no], [AC_INCLUDES_DEFAULT])
         CPPFLAGS="${CPPFLAGS_ac} ${user_CPPFLAGS}"
         CFLAGS="${CFLAGS_ac} ${user_CFLAGS}"
       ]
     )
    ]
  )

  AS_UNSET([[crypt_missing]])
  AS_IF([[test "x$have_gnutls" = "xyes"]],
    [
     AS_IF([[test "x$mhd_cv_gcrypt_required" = "xyes" && test "x$have_gcrypt" != "xyes"]],
       [
        crypt_missing="required libgcrypt"
        AS_IF([[test "x$enable_https" = "xyes" ]], [AC_MSG_ERROR([[HTTPS support cannot be enabled without $crypt_missing.]])])
        enable_https=no
        MSG_HTTPS="no (lacking $crypt_missing)"
        AS_UNSET([LIBGCRYPT_CFLAGS])
        AS_UNSET([LIBGCRYPT_LIBS])
        AS_UNSET([GNUTLS_CPPFLAGS])
        AS_UNSET([GNUTLS_CFLAGS])
        AS_UNSET([GNUTLS_LDFLAGS])
        AS_UNSET([GNUTLS_LIBS])
       ],
         [
          AC_DEFINE([[HTTPS_SUPPORT]],[[1]],[Define to 1 if libmicrohttpd is compiled with HTTPS support.])
          enable_https=yes
          AS_IF([[test "x$mhd_cv_gcrypt_required" = "xyes"]],
            [
             MSG_HTTPS="yes (using libgnutls and libgcrypt)"
	         MHD_TLS_LIB_CPPFLAGS="$LIBGCRYPT_CFLAGS $GNUTLS_CPPFLAGS"
             MHD_TLS_LIB_CFLAGS="$LIBGCRYPT_CFLAGS $GNUTLS_CFLAGS"
             MHD_TLS_LIB_LDFLAGS="$GNUTLS_LDFLAGS"
             MHD_TLS_LIBDEPS="$GNUTLS_LIBS $LIBGCRYPT_LIBS"
             AC_DEFINE([[MHD_HTTPS_REQUIRE_GCRYPT]], [[1]], [Define to `1' if HTTPS require initialisation of libgcrypt])
            ],
            [
             MSG_HTTPS="yes (using libgnutls)"
             AS_UNSET([LIBGCRYPT_CFLAGS])
             AS_UNSET([LIBGCRYPT_LIBS])
             MHD_TLS_LIB_CPPFLAGS="$GNUTLS_CPPFLAGS"
             MHD_TLS_LIB_CFLAGS="$GNUTLS_CFLAGS"
             MHD_TLS_LIB_LDFLAGS="$GNUTLS_LDFLAGS"
             MHD_TLS_LIBDEPS="$GNUTLS_LIBS"
            ]
          )
          AS_IF([[ test "x$have_gnutls_pkgcfg" = "xyes" ]],
            [ # remove GnuTLS from private libs in .pc file as it defined in Requires.private
              MHD_REQ_PRIVATE='gnutls'
              AS_IF([[test "x$mhd_cv_gcrypt_required" = "xyes"]],
                [[MHD_LIBDEPS_PKGCFG="$LIBGCRYPT_LIBS $MHD_LIBDEPS_PKGCFG"]]
              )
            ],
            [
              MHD_REQ_PRIVATE=''
              AS_IF([[test "x$mhd_cv_gcrypt_required" = "xyes"]],
                [[MHD_LIBDEPS_PKGCFG="$LIBGCRYPT_LIBS $MHD_LIBDEPS_PKGCFG"]]
              )
              MHD_LIBDEPS_PKGCFG="$GNUTLS_LIBS $MHD_LIBDEPS_PKGCFG"
          ])
         ]
     )
    ],
    [
     crypt_missing="libgnutls"
     AS_IF([[test "x$enable_https" = "xyes" ]], [AC_MSG_ERROR([[HTTPS support cannot be enabled without $crypt_missing.]])])
     enable_https=no
     MSG_HTTPS="no (lacking $crypt_missing)"
     AS_UNSET([LIBGCRYPT_CFLAGS])
     AS_UNSET([LIBGCRYPT_LIBS])
     AS_UNSET([GNUTLS_CPPFLAGS])
     AS_UNSET([GNUTLS_CFLAGS])
     AS_UNSET([GNUTLS_LDFLAGS])
     AS_UNSET([GNUTLS_LIBS])
    ]
  )
],[
  MSG_HTTPS="no (disabled)"
])

#
# End of large unindented block
#


AC_MSG_CHECKING(whether to support HTTPS)
AC_MSG_RESULT([$MSG_HTTPS])

AM_CONDITIONAL([HAVE_GNUTLS], [[test "x$have_gnutls" = "xyes"]])
AM_CONDITIONAL([HAVE_GNUTLS_SNI], [[test "x$have_gnutls_sni" = "xyes"]])
AM_CONDITIONAL([ENABLE_HTTPS], [test "x$enable_https" = "xyes"])
AM_CONDITIONAL([HTTPS_REQUIRE_GCRYPT], [[test "x$enable_https" = "xyes" && test "x$mhd_cv_gcrypt_required" = "xyes"]])
AC_SUBST([GNUTLS_CPPFLAGS])
AC_SUBST([GNUTLS_CFLAGS])
AC_SUBST([GNUTLS_LDFLAGS])
AC_SUBST([GNUTLS_LIBS])

AS_VAR_IF([have_gnutls], ["yes"],
  [
    AC_CACHE_CHECK([for GnuTLS quirks], [mhd_cv_gnutls_mthread_broken],
      [
        mhd_cv_gnutls_mthread_broken="no"
        AS_IF([test -r /etc/redhat-release],
          [
            AS_IF([$FGREP ' release 6.' /etc/redhat-release >/dev/null || $FGREP '(Santiago)' /etc/redhat-release >/dev/null],
              [mhd_cv_gnutls_mthread_broken="found"],
            )
          ]
        )
        AS_VAR_IF([mhd_cv_gnutls_mthread_broken], ["no"],
          [
            AS_IF([command -v rpm >/dev/null],
              [
                AS_IF([test "r`rpm -E '%{rhel}' 2>/dev/null`" = "r6"],
                  [mhd_cv_gnutls_mthread_broken="found"],
                )
              ]
            )
          ]
        )
      ]
    )
    AC_CACHE_CHECK([for gnutls-cli binary], [mhd_cv_gnutls_cli],
      [
        mhd_cv_gnutls_cli="no"
        AS_IF([command -v gnutls-cli >/dev/null 2>&1],
          [AS_IF([AC_RUN_LOG([gnutls-cli --version >&2])], [mhd_cv_gnutls_cli="yes"])]
        )
      ]
    )
  ]
)
AM_CONDITIONAL([HAVE_GNUTLS_MTHREAD_BROKEN], [[test "x${mhd_cv_gnutls_mthread_broken}" = "xfound"]])
AM_CONDITIONAL([USE_UPGRADE_TLS_TESTS], [[test "x${mhd_cv_gnutls_mthread_broken}" = "xno" || test "x${mhd_cv_gnutls_cli}" = "xyes"]])

# optional: HTTP Basic Auth support. Enabled by default
AC_MSG_CHECKING([[whether to support HTTP Basic authentication]])
AC_ARG_ENABLE([bauth],
		[AS_HELP_STRING([--disable-bauth],[disable HTTP Basic Authentication support])],
		[enable_bauth=${enableval}],
		[enable_bauth=yes])
AS_IF([[test "x$enable_bauth" != "xno"]],
  [ enable_bauth=yes
    AC_DEFINE([BAUTH_SUPPORT],[1],[Define to 1 if libmicrohttpd is compiled with Basic Auth support.]) ])
AM_CONDITIONAL([ENABLE_BAUTH], [test "x$enable_bauth" != "xno"])
AC_MSG_RESULT([[$enable_bauth]])

# optional: HTTP Digest Auth support. Enabled by default
AC_MSG_CHECKING([[whether to support HTTP Digest authentication]])
AC_ARG_ENABLE([dauth],
		[AS_HELP_STRING([--disable-dauth], [disable HTTP Digest Authentication support])],
		[enable_dauth="${enableval}"],
		[enable_dauth="yes"])
AS_IF([[test "x$enable_dauth" != "xno"]],
  [ enable_dauth=yes
    AC_DEFINE([DAUTH_SUPPORT],[1],[Define to 1 if libmicrohttpd is compiled with Digest Auth support.]) ])
AM_CONDITIONAL([ENABLE_DAUTH], [test "x$enable_dauth" != "xno"])
AC_MSG_RESULT([[$enable_dauth]])

AM_CONDITIONAL([HAVE_ANYAUTH],[test "x$enable_bauth" != "xno" || test "x$enable_dauth" != "xno"])

# optional: HTTP "Upgrade" support. Enabled by default
AC_MSG_CHECKING([[whether to support HTTP "Upgrade"]])
AC_ARG_ENABLE([[httpupgrade]],
    [AS_HELP_STRING([[--disable-httpupgrade]], [disable HTTP "Upgrade" support])],
    [AS_VAR_IF([[enable_httpupgrade]],[["no"]],[],[[enable_httpupgrade='yes']])],
    [[enable_httpupgrade='yes']])
AS_VAR_IF([[enable_httpupgrade]],[["yes"]],
  [
   AC_DEFINE([[UPGRADE_SUPPORT]],[[1]],[Define to 1 if libmicrohttpd is compiled with HTTP Upgrade support.]) ])
AM_CONDITIONAL([ENABLE_UPGRADE], [[test "x$enable_httpupgrade" = "xyes"]])
AC_MSG_RESULT([[$enable_httpupgrade]])

# optional: HTTP cookie parsing support. Enabled by default
AC_MSG_CHECKING([[whether to support HTTP cookie parsing]])
AC_ARG_ENABLE([[cookie]],
    [AS_HELP_STRING([[--disable-cookie]], [disable HTTP cookie parsing support])],
    [AS_VAR_IF([[enable_cookie]],[["no"]],[],[[enable_cookie='yes']])],
    [[enable_cookie='yes']])
AS_VAR_IF([[enable_cookie]],[["yes"]],
  [
   AC_DEFINE([[COOKIE_SUPPORT]],[[1]],[Define to 1 if libmicrohttpd is compiled with HTTP cookie parsing support.]) ])
AM_CONDITIONAL([ENABLE_COOKIE], [[test "x$enable_cookie" = "xyes"]])
AC_MSG_RESULT([[$enable_cookie]])

# optional: MD5 support for Digest Auth. Enabled by default.
AC_ARG_ENABLE([[md5]],
  [AS_HELP_STRING([[--enable-md5=TYPE]],
    [enable TYPE of MD5 hashing code (yes, no, builtin, tlslib) [yes if dauth enabled]])],
  [
    AS_VAR_IF([enable_md5],["internal"],[enable_md5='builtin'])
    AS_VAR_IF([enable_md5],["built-in"],[enable_md5='builtin'])
    AS_VAR_IF([enable_dauth],["yes"],[],
      [
        AS_VAR_IF([enable_md5],["no"],[],
          [
            AC_MSG_WARN([The parameter --enable-md5=${enable_md5} is ignored as Digest Authentication is disabled])
            enable_md5='no'
          ]
        )
      ]
    )
  ], [[enable_md5="${enable_dauth}"]]
)
AS_CASE([${enable_md5}],[yes|tlslib],
  [
    AS_IF([test "x${enable_compact_code}" != "xno" || test "x$enable_md5" = "xtlslib"],
      [
        AS_IF([test "x$enable_https" = "xyes"],
          [
            AC_CACHE_CHECK([whether GnuTLS supports MD5 hashing],[mhd_cv_gnutls_md5],
              [
                CFLAGS="${CFLAGS_ac} ${GNUTLS_CFLAGS} ${user_CFLAGS}"
                CPPFLAGS="${CPPFLAGS_ac} ${MHD_TLS_LIB_CPPFLAGS} ${user_CPPFLAGS}"
                CFLAGS="${CFLAGS_ac} ${MHD_TLS_LIB_CFLAGS} ${user_CFLAGS}"
                LDFLAGS="${LDFLAGS_ac} ${MHD_TLS_LIB_LDFLAGS} ${user_LDFLAGS}"
                save_LIBS="$LIBS"
                LIBS="${MHD_TLS_LIBDEPS} ${LIBS}"
                AC_LINK_IFELSE(
                  [
                    AC_LANG_PROGRAM(
                      [[
#include <gnutls/crypto.h>
                      ]],
                      [[
    gnutls_hash_hd_t hash_handle;
    unsigned char digest[16];
    int exit_code;

    if (0 == gnutls_hash_init(&hash_handle, GNUTLS_DIG_MD5))
    {
      if (0 == gnutls_hash(hash_handle, "", 1))
      {
        gnutls_hash_output(hash_handle, digest);
        if (0x93 == digest[0])
          exit_code = 0;
        else
          exit_code = 7;
      }
      else
        exit_code = 5;
      gnutls_hash_deinit(hash_handle, (void *)0);
    }
    else
      exit_code = 2;
    if (exit_code)
      return exit_code;
                      ]]
                    )
                  ],
                  [mhd_cv_gnutls_md5='yes'],[mhd_cv_gnutls_md5='no']
                )
                LIBS="${save_LIBS}"
                CFLAGS="${CFLAGS_ac} ${user_CFLAGS}"
                CPPFLAGS="${CPPFLAGS_ac} ${user_CPPFLAGS}"
                CFLAGS="${CFLAGS_ac} ${user_CFLAGS}"
                LDFLAGS="${LDFLAGS_ac} ${user_LDFLAGS}"
              ]
            )
            AS_VAR_IF([mhd_cv_gnutls_md5],["no"],
              [
                AS_VAR_IF([enable_md5],["tlslib"],
                  [AC_MSG_FAILURE([TLS library MD5 implementation is not available])]
                )
                enable_md5="builtin"
              ],
              [enable_md5="tlslib"]
            )
          ],
          [
            AS_VAR_IF([enable_md5],["tlslib"],
              [AC_MSG_ERROR([HTTPS is not enabled, TLS library MD5 implementation cannot be used])]
            )
            enable_md5="builtin"
          ]
        )
      ],
      [
        enable_md5="builtin"
      ]
    )
  ]
)
AC_MSG_CHECKING([[whether to support MD5]])
AS_UNSET([enable_md5_MSG])
AS_CASE([${enable_md5}],
  [builtin],[enable_md5_MSG='yes, built-in'],
  [tlslib],[enable_md5_MSG='yes, external (TLS library)'],
  [no],[enable_md5_MSG='no'],
  [yes],[AC_MSG_ERROR([configure internal error: unexpected variable value])],
  [AC_MSG_ERROR([Unrecognized parameter --enable-md5=${enable_md5}])]
)
AS_IF([test "x${enable_md5}" = "xbuiltin" || test "x${enable_md5}" = "xtlslib" ],
  [
    AC_DEFINE([[MHD_MD5_SUPPORT]],[[1]],
      [Define to 1 if libmicrohttpd is compiled with MD5 hashing support.])
  ]
)
AS_IF([test "x${enable_md5}" = "xtlslib" ],
  [
    AC_DEFINE([[MHD_MD5_TLSLIB]],[[1]],
      [Define to 1 if libmicrohttpd is compiled with MD5 hashing by TLS library.])
  ]
)
AM_CONDITIONAL([ENABLE_MD5], [[test "x${enable_md5}" = "xbuiltin" || test "x${enable_md5}" = "xtlslib" ]])
AM_CONDITIONAL([ENABLE_MD5_EXT], [[test "x${enable_md5}" = "xtlslib" ]])
AC_MSG_RESULT([[${enable_md5_MSG}]])

# optional: SHA-256 support for Digest Auth. Enabled by default.
AC_ARG_ENABLE([[sha256]],
  [AS_HELP_STRING([[--enable-sha256=TYPE]],
    [enable TYPE of SHA-256 hashing code (yes, no, builtin, tlslib) [yes if dauth enabled]])],
  [
    AS_VAR_IF([enable_sha256],["internal"],[enable_sha256='builtin'])
    AS_VAR_IF([enable_sha256],["built-in"],[enable_sha256='builtin'])
    AS_VAR_IF([enable_dauth],["yes"],[],
      [
        AS_VAR_IF([enable_sha256],["no"],[],
          [
            AC_MSG_WARN([The parameter --enable-sha256=${enable_sha256} is ignored as Digest Authentication is disabled])
            enable_sha256='no'
          ]
        )
      ]
    )
  ], [[enable_sha256="${enable_dauth}"]]
)
AS_CASE([${enable_sha256}],[yes|tlslib],
  [
    AS_IF([test "x${enable_compact_code}" != "xno" || test "x$enable_sha256" = "xtlslib"],
      [
        AS_IF([test "x$enable_https" = "xyes"],
          [
            AC_CACHE_CHECK([whether GnuTLS supports sha256 hashing],[mhd_cv_gnutls_sha256],
              [
                CFLAGS="${CFLAGS_ac} ${GNUTLS_CFLAGS} ${user_CFLAGS}"
                CPPFLAGS="${CPPFLAGS_ac} ${MHD_TLS_LIB_CPPFLAGS} ${user_CPPFLAGS}"
                CFLAGS="${CFLAGS_ac} ${MHD_TLS_LIB_CFLAGS} ${user_CFLAGS}"
                LDFLAGS="${LDFLAGS_ac} ${MHD_TLS_LIB_LDFLAGS} ${user_LDFLAGS}"
                save_LIBS="$LIBS"
                LIBS="${MHD_TLS_LIBDEPS} ${LIBS}"
                AC_LINK_IFELSE(
                  [
                    AC_LANG_PROGRAM(
                      [[
#include <gnutls/crypto.h>
                      ]],
                      [[
    gnutls_hash_hd_t hash_handle;
    unsigned char digest[32];
    int exit_code;

    if (0 == gnutls_hash_init(&hash_handle, GNUTLS_DIG_SHA256))
    {
      if (0 == gnutls_hash(hash_handle, "", 1))
      {
        gnutls_hash_output(hash_handle, digest);
        if (0x6e == digest[0])
          exit_code = 0;
        else
          exit_code = 7;
      }
      else
        exit_code = 5;
      gnutls_hash_deinit(hash_handle, (void *)0);
    }
    else
      exit_code = 2;
    if (exit_code)
      return exit_code;
                      ]]
                    )
                  ],
                  [mhd_cv_gnutls_sha256='yes'],[mhd_cv_gnutls_sha256='no']
                )
                LIBS="${save_LIBS}"
                CFLAGS="${CFLAGS_ac} ${user_CFLAGS}"
                CPPFLAGS="${CPPFLAGS_ac} ${user_CPPFLAGS}"
                CFLAGS="${CFLAGS_ac} ${user_CFLAGS}"
                LDFLAGS="${LDFLAGS_ac} ${user_LDFLAGS}"
              ]
            )
            AS_VAR_IF([mhd_cv_gnutls_sha256],["no"],
              [
                AS_VAR_IF([enable_sha256],["tlslib"],
                  [AC_MSG_FAILURE([TLS library SHA-256 implementation is not available])]
                )
                enable_sha256="builtin"
              ],
              [enable_sha256="tlslib"]
            )
          ],
          [
            AS_VAR_IF([enable_sha256],["tlslib"],
              [AC_MSG_ERROR([HTTPS is not enabled, TLS library SHA-256 implementation cannot be used])]
            )
            enable_sha256="builtin"
          ]
        )
      ],
      [
        enable_sha256="builtin"
      ]
    )
  ]
)
AC_MSG_CHECKING([[whether to support SHA-256]])
AS_UNSET([enable_sha256_MSG])
AS_CASE([${enable_sha256}],
  [builtin],[enable_sha256_MSG='yes, built-in'],
  [tlslib],[enable_sha256_MSG='yes, external (TLS library)'],
  [no],[enable_sha256_MSG='no'],
  [yes],[AC_MSG_ERROR([configure internal error: unexpected variable value])],
  [AC_MSG_ERROR([Unrecognized parameter --enable-sha256=${enable_sha256}])]
)
AS_IF([test "x${enable_sha256}" = "xbuiltin" || test "x${enable_sha256}" = "xtlslib" ],
  [
    AC_DEFINE([[MHD_SHA256_SUPPORT]],[[1]],
      [Define to 1 if libmicrohttpd is compiled with SHA-256 hashing support.])
  ]
)
AS_IF([test "x${enable_sha256}" = "xtlslib" ],
  [
    AC_DEFINE([[MHD_SHA256_TLSLIB]],[[1]],
      [Define to 1 if libmicrohttpd is compiled with SHA-256 hashing by TLS library.])
  ]
)
AM_CONDITIONAL([ENABLE_SHA256], [[test "x${enable_sha256}" = "xbuiltin" || test "x${enable_sha256}" = "xtlslib" ]])
AM_CONDITIONAL([ENABLE_SHA256_EXT], [[test "x${enable_sha256}" = "xtlslib" ]])
AC_MSG_RESULT([[${enable_sha256_MSG}]])

# optional: SHA-512/256 support for Digest Auth. Enabled by default.
AC_ARG_ENABLE([[sha512-256]],
  [AS_HELP_STRING([[--disable-sha512-256]],
    [disable SHA-512/256 hashing support for Digest Authentication])],
  [
    AS_VAR_IF([[enable_sha512_256]],[["yes"]],
      [
        AS_VAR_IF([enable_dauth],["yes"],[],
          [
            AC_MSG_WARN([The parameter --enable-sha512-256 is ignored as Digest Authentication is disabled])
            enable_sha512_256='no'
          ]
        )
      ],[[enable_sha512_256='no']]
    )
  ], [[enable_sha512_256="${enable_dauth}"]]
)
AC_MSG_CHECKING([[whether to support SHA-512/256]])
AS_UNSET([enable_sha512_256_MSG])
AS_CASE([${enable_sha512_256}],
  [yes],[enable_sha512_256_MSG='yes, built-in'],
  [no],[enable_sha512_256_MSG='no'],
  [AC_MSG_ERROR([Unrecognized parameter --enable-sha512-256=${enable_sha512_256}])]
)
AS_VAR_IF([[enable_sha512_256]],[["yes"]],
  [
   AC_DEFINE([[MHD_SHA512_256_SUPPORT]],[[1]],
     [Define to 1 if libmicrohttpd is compiled with SHA-512/256 hashing support.])
  ]
)
AM_CONDITIONAL([ENABLE_SHA512_256], [[test "x${enable_sha512_256}" = "xyes"]])
AC_MSG_RESULT([[${enable_sha512_256_MSG}]])

AS_IF([test "x$enable_dauth" != "xno"],
  [
    AS_IF([test "x${enable_md5}" = "xno" &&  test "x${enable_sha256}" = "xno" && test "x${enable_sha512_256}" != "xyes"],
      [AC_MSG_ERROR([At least one hashing algorithm must be enabled if Digest Auth is enabled])]
    )
  ]
)


AC_CACHE_CHECK([[for calloc()]], [[mhd_cv_have_func_calloc]],
  [
   AC_LINK_IFELSE([AC_LANG_PROGRAM([[
#include <stdlib.h>
       ]],[[void * ptr = calloc(1, 2); if (ptr) return 1;]])
     ],
     [[mhd_cv_have_func_calloc='yes']],
     [[mhd_cv_have_func_calloc='no']]
   )
  ]
)
AS_VAR_IF([[mhd_cv_have_func_calloc]], [["yes"]],
  [AC_DEFINE([[HAVE_CALLOC]], [[1]], [Define to 1 if you have the usable `calloc' function.])])

# Some systems have IPv6 disabled in kernel at run-time
AS_IF([[test "x${have_inet6}" = "xyes" && test "x${cross_compiling}" = "xno"]],
 [
   AC_CACHE_CHECK([whether IPv6 could be used for testing],[mhd_cv_ipv6_for_testing],
     [
       AC_RUN_IFELSE(
         [
           AC_LANG_SOURCE([[
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif
#ifdef HAVE_WS2TCPIP_H
#include <ws2tcpip.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif

static void zr_mem(void *ptr, socklen_t size)
{ char *mem = ptr; while(size--) {mem[0] = 0; mem++;} }

int main(void)
{
  int ret = 30;
  struct sockaddr_in6 sa;
#if !defined(_WIN32) || defined(__CYGWIN__)
  int sckt;
  const int invld_sckt = -1;
#else
  SOCKET sckt;
  const SOCKET invld_sckt = INVALID_SOCKET;
  WSADATA wsa_data;

  WSAStartup(MAKEWORD(2, 2), &wsa_data);
#endif
  zr_mem(&sa, sizeof(sa));
  sa.sin6_family = AF_INET6;
  sa.sin6_port = 0;
  sa.sin6_addr = in6addr_loopback;
#ifdef HAVE_STRUCT_SOCKADDR_IN6_SIN6_LEN
  sa.sin6_len = sizeof(sa);
#endif
  sckt = socket (PF_INET6, SOCK_STREAM, 0);
  if (invld_sckt != sckt)
  {
    if (0 == bind (sckt, (struct sockaddr *)&sa, sizeof(sa)))
    {
      if (0 == listen (sckt, 1))
        ret = 0;
      else
        ret = 1; /* listen() failed */
    } else ret = 2; /* bind() failed */
#if !defined(_WIN32) || defined(__CYGWIN__)
    close (sckt);
#else
    closesocket (sckt);
#endif
  } else ret = 3; /* socket() failed */
#if defined(_WIN32) && !defined(__CYGWIN__)
  WSACleanup();
#endif
  return ret;
}
           ]])
         ], [[mhd_cv_ipv6_for_testing="yes"]], [[mhd_cv_ipv6_for_testing="no"]], [[mhd_cv_ipv6_for_testing="no"]]
       )
     ]
   )
 ]
)
AS_VAR_IF([mhd_cv_ipv6_for_testing],["yes"],
	[AC_DEFINE([[USE_IPV6_TESTING]], [[1]], [Define to 1 if your kernel supports IPv6 and IPv6 is enabled and useful for testing.])]
)


# Check for fork() and waitpid(). They are used for tests.
AC_MSG_CHECKING([[for fork()]])
mhd_have_fork_waitpid='no'
AC_LINK_IFELSE(
  [
   AC_LANG_PROGRAM(
     [[
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
     ]], [[
  pid_t p = fork ();
  if (0 == p)
    return 1;
     ]])
  ], [
   AC_DEFINE([[HAVE_FORK]], [[1]], [Define to 1 if you have the usable `fork' function.])
   AC_MSG_RESULT([[yes]])

   AC_MSG_CHECKING([[for waitpid()]])
   AC_LINK_IFELSE(
     [
      AC_LANG_PROGRAM(
        [[
#include <sys/wait.h>
        ]], [[
     pid_t p = fork ();
     if (0 == p)
       return 1;
     waitpid (p, (void*)0, 0)
        ]])
     ], [
      AC_DEFINE([[HAVE_WAITPID]], [[1]], [Define to 1 if you have the usable `waitpid' function.])
      AC_MSG_RESULT([[yes]])
      mhd_have_fork_waitpid='yes'
    ],[
       AC_MSG_RESULT([[no]])
    ])
],[
   AC_MSG_RESULT([[no]])
])

AM_CONDITIONAL([HAVE_FORK_WAITPID], [test "x$mhd_have_fork_waitpid" = "xyes"])

# gcov compilation
AC_MSG_CHECKING(whether to compile with support for code coverage analysis)
AC_ARG_ENABLE([coverage],
              AS_HELP_STRING([--enable-coverage],
                             [compile the library with code coverage support]),
              [use_gcov=${enableval}],
              [use_gcov=no])
AC_MSG_RESULT($use_gcov)
AM_CONDITIONAL([USE_COVERAGE], [test "x$use_gcov" = "xyes"])

AX_COUNT_CPUS
AC_MSG_CHECKING([for number of CPU cores to use in tests])
AS_VAR_IF([use_heavy_tests], ["yes"],
  [
    # Enable usage of many core if heavy tests are enabled
    AS_IF([[test "$CPU_COUNT" -gt "32"]], [[CPU_COUNT="32"]])dnl Limit resource usage
  ],
  [
    # Limit usage to just a few cores if heavy tests are not enabled
    AS_IF([[test "$CPU_COUNT" -gt "6"]], [[CPU_COUNT="6"]])
    AS_IF([[test "$CPU_COUNT" -lt "2"]], [[CPU_COUNT="2"]])
  ]
)
AC_MSG_RESULT([$CPU_COUNT])


AC_ARG_ENABLE([[asserts]],
  [AS_HELP_STRING([[--enable-asserts]],
    [enable test build with debug asserts])],
  [],
  [enable_asserts='auto']
)
AS_UNSET([use_asserts_MSG])
AC_CACHE_CHECK([[whether NDEBUG macro is defined]], [mhd_cv_macro_ndebug_def],
  [
    AC_LINK_IFELSE(
      [
        AC_LANG_SOURCE([[
#ifndef NDEBUG
#error NDEBUG is NOT defined
chome me now
#endif

int main(void)
{
  return 0;
}
          ]]
        )
      ],
      [[mhd_cv_macro_ndebug_def='yes']],
      [[mhd_cv_macro_ndebug_def='no']]
    )
  ]
)
AS_VAR_IF([enable_asserts],["yes"],
  [
    AS_VAR_IF([mhd_cv_macro_ndebug_def],["yes"],
      [
        AC_MSG_FAILURE([Parameter --enable-asserts is specified, but NDEBUG macro is defined as well])
      ]
    )
    use_asserts_MSG="yes, enabled by configure parameter"
  ]
)
AC_CACHE_CHECK([[whether _DEBUG macro is defined]], [mhd_cv_macro__debug_def],
  [
    AC_LINK_IFELSE(
      [
        AC_LANG_SOURCE([[
#ifndef _DEBUG
#error _DEBUG is NOT defined
chome me now
#endif

int main(void)
{
  return 0;
}
          ]]
        )
      ],
      [[mhd_cv_macro__debug_def='yes']],
      [[mhd_cv_macro__debug_def='no']]
    )
  ]
)
AS_VAR_IF([enable_asserts],["no"],
  [
    AS_VAR_IF([mhd_cv_macro__debug_def],["yes"],
      [
        AC_MSG_FAILURE([Parameter --disable-asserts is specified, but _DEBUG macro is defined as well])
      ]
    )
    use_asserts_MSG="no, set by configure parameter"
  ]
)
AS_IF([test "x${mhd_cv_macro_ndebug_def}" = "xyes" && test "x${mhd_cv_macro__debug_def}" = "xyes"],
  [AC_MSG_FAILURE([Both NDEBUG and _DEBUG macros are defined])]
)
AS_VAR_IF([enable_asserts],["auto"],
  [
    AS_VAR_IF([mhd_cv_macro_ndebug_def],["yes"],
      [
        enable_asserts="no"
        use_asserts_MSG="no, set by NDEBUG preprocessor macro"
      ]
    )
  ]
)
AS_VAR_IF([enable_asserts],["auto"],
  [
    AS_VAR_IF([mhd_cv_macro__debug_def],["yes"],
      [
        enable_asserts="yes"
        use_asserts_MSG="yes, enabled by _DEBUG preprocessor macro"
      ]
    )
  ]
)
AS_VAR_IF([enable_asserts],["auto"],
  [
    AC_CACHE_CHECK([[whether DEBUG macro is defined]], [mhd_cv_macro_debug_def],
      [
        AC_LINK_IFELSE(
          [
            AC_LANG_SOURCE([[
#ifndef DEBUG
#error DEBUG is NOT defined
chome me now
#endif

int main(void)
{
  return 0;
}
              ]]
            )
          ],
          [[mhd_cv_macro_debug_def='yes']],
          [[mhd_cv_macro_debug_def='no']]
        )
      ]
    )
    AS_VAR_IF([mhd_cv_macro_debug_def],["yes"],
      [
        enable_asserts="yes"
        use_asserts_MSG="yes, enabled by DEBUG preprocessor macro"
      ]
    )
  ]
)
AC_MSG_CHECKING([[whether to enable debug asserts]])
AS_VAR_IF([enable_asserts],["auto"],
  [
    AS_CASE([${enable_build_type}],
      [debug|debugger],
      [
        enable_asserts="yes"
        use_asserts_MSG="yes, enabled by --enable-bulid-type=${enable_build_type}"
      ],
      [
        enable_asserts="no"
        use_asserts_MSG="no"
      ]
    )
  ]
)
AS_CASE([[$enable_asserts]], [[yes]], [[:]], [[no]], [[:]], [[enable_asserts='no']])
AC_MSG_RESULT([[${use_asserts_MSG=no}]])

AS_VAR_IF([[enable_asserts]], [["yes"]],
  [
    AS_VAR_IF([[mhd_cv_macro__debug_def]], [["yes"]], [:],
      [
        MHD_PREPEND_FLAG_TO_VAR([CPPFLAGS_ac],[-D_DEBUG=1])
        CPPFLAGS="${CPPFLAGS_ac} ${user_CPPFLAGS}"
      ]
    )
    AC_CACHE_CHECK([[whether system assert() is available]], [mhd_cv_sys_assert_avail],
      [
        AC_LINK_IFELSE(
          [
            AC_LANG_SOURCE([[
#include <assert.h>

static int pos_val(void) {return 5;}
static int neg_val(void) {return -5;}
int main(void)
{
  int pos_var = pos_val(), neg_var = neg_val();
  assert(neg_var > pos_var); /* Must trigger assert. */
  return pos_var + neg_var;
}
            ]])
          ],
          [[mhd_cv_sys_assert_avail='yes']],
          [[mhd_cv_sys_assert_avail='no']]
        )
      ]
    )
    AS_VAR_IF([[mhd_cv_sys_assert_avail]], [["no"]], [],
      [AC_DEFINE([[HAVE_ASSERT]], [[1]], [Define if you have usable assert() and assert.h])])
  ],
  [
    AS_VAR_IF([[mhd_cv_macro_ndebug_def]], [["yes"]], [:],
      [
        MHD_PREPEND_FLAG_TO_VAR([CPPFLAGS_ac],[-DNDEBUG=1])
        CPPFLAGS="${CPPFLAGS_ac} ${user_CPPFLAGS}"
      ]
    )
  ]
)

AS_UNSET([enabled_sanitizers])
TESTS_ENVIRONMENT_ac=""
AM_ASAN_OPTIONS=""
AM_UBSAN_OPTIONS=""
AM_LSAN_OPTIONS=""
AS_UNSET([ASAN_OPTIONS])
AS_UNSET([UBSAN_OPTIONS])
AS_UNSET([LSAN_OPTIONS])

AC_MSG_CHECKING([whether to enable run-time sanitizers])
AC_ARG_ENABLE([sanitizers],
  [AS_HELP_STRING([[--enable-sanitizers[=address,undefined,leak,user-poison]]],
  [enable run-time sanitizers, specify the list of types of sanitizers to enable, ]
  [leave the list empty (or set to "auto") to enable all supported and available ]
  [sanitizers, or specify "auto-fallback" to use sanitizers even without ]
  [installed sanitizer run-time library])],
  [], [AS_CASE([${enable_build_type}],[debug],
    [enable_sanitizers='auto-optional'],[enable_sanitizers='no'])]
)
AS_IF([test "x${enable_sanitizers}" = "x"], [enable_sanitizers="auto"])
AS_VAR_IF([enable_sanitizers], ["yes"], [enable_sanitizers="auto"])
AS_VAR_IF([enable_sanitizers], ["autofallback"], [enable_sanitizers="auto-fallback"])
AS_VAR_IF([enable_sanitizers], ["autooptional"], [enable_sanitizers="auto-optional"])
AS_IF([test "x${enable_sanitizers}" = "xno"],
  [
    enable_sanitizers="no"
    enable_san_address="no"
    enable_san_undef="no"
    enable_san_leak="no"
    enable_san_upoison="no"
  ],
  [test "x${enable_sanitizers}" = "xauto" || test "x${enable_sanitizers}" = "xauto-optional"],
  [
    AS_VAR_IF([enable_compiler_hardening],["yes"],
      [
        AS_VAR_IF([enable_sanitizers],["auto"],
          [AC_MSG_ERROR([sanitizers cannot be enabled with compiler hardnening])],
          [AC_MSG_WARN([sanitizers cannot be enabled with compiler hardnening])]
        )
        enable_sanitizers="no"
        enable_san_address="no"
        enable_san_undef="no"
        enable_san_leak="no"
        enable_san_upoison="no"
      ],
      [
        enable_san_address="auto"
        enable_san_undef="auto"
        enable_san_leak="auto"
        enable_san_upoison="auto"
      ]
    )
  ],
  [test "x${enable_sanitizers}" = "xauto-fallback"],
  [
    enable_san_address="auto"
    enable_san_undef="auto-fallback"
    enable_san_leak="auto"
    enable_san_upoison="auto"
  ],
  [
    AS_UNSET([san])
    enable_san_address="no"
    enable_san_undef="no"
    enable_san_leak="no"
    enable_san_upoison="no"
    for san in `AS_ECHO([${enable_sanitizers}]) | tr ',' ' '`
    do
      AS_CASE([$san],
        [address], [enable_san_address="yes"],
        [undefined], [enable_san_undef="yes"],
        [leak], [enable_san_leak="yes"],
        [user-poison|user_poison], [enable_san_upoison="yes"],
        [no|yes|auto|auto-fallback|autofallback], [AC_MSG_ERROR(["$san" cannot be used with other options for --enable-sanitizers=])],
        [AC_MSG_ERROR([Unknown parameter "$san" for --enable-sanitizers=])]
      )
    done
    AS_IF([test "x${enable_san_upoison}" = "xyes" && test "x${enable_san_address}" = "xno"],
      [AC_MSG_ERROR([User memory poisoning cannot be used without address sanitizer])]
    )
    enable_sanitizers="selected"
  ]
)
AS_CASE([${enable_sanitizers}],
  [selected], [AC_MSG_RESULT([selected])],
  [auto], [AC_MSG_RESULT([yes, detect and use supported sanitizers])],
  [auto-fallback], [AC_MSG_RESULT([yes, detect and use supported sanitizers even without run-time lib])],
  [auto-optional], [AC_MSG_RESULT([yes, detect and use supported sanitizers if any])],
  [AC_MSG_RESULT([no])]
)
AS_VAR_IF([enable_sanitizers], ["no"], [:],
 [
   AS_UNSET([san_FLAGS]) # the sanitizer flags to be added to both CFLAGS and LDFLAGS
   AS_UNSET([san_CFLAGS]) # the sanitizer flags to be added to CFLAGS
   AC_CACHE_CHECK([whether '-fsanitize=' works for $CC],
     [mhd_cv_cc_sanitizer_works],
     [
       CFLAGS="${CFLAGS_ac} -fsanitize=wrongFeatureName ${user_CFLAGS}"
       AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],[])],
         [mhd_cv_cc_sanitizer_works=no], [mhd_cv_cc_sanitizer_works=yes])
     ]
   )
   AS_VAR_IF([mhd_cv_cc_sanitizer_works], ["yes"],
     [
       AS_VAR_IF([enable_san_address], ["no"], [:],
         [
           AC_CACHE_CHECK([for address sanitizer], [mhd_cv_cc_sanitizer_address],
             [
               CFLAGS="${CFLAGS_ac} ${san_CFLAGS} ${san_FLAGS} -fsanitize=address ${user_CFLAGS}"
               AC_LINK_IFELSE([AC_LANG_PROGRAM([],[])],
                [mhd_cv_cc_sanitizer_address=yes], [mhd_cv_cc_sanitizer_address=no])
             ]
           )
           AS_VAR_IF([mhd_cv_cc_sanitizer_address],["yes"],
             [
               AC_DEFINE([MHD_ASAN_ACTIVE], [1], [Define to '1' if you have address sanitizer enabled])
               AX_APPEND_FLAG([-fsanitize=address], [san_FLAGS])
               enabled_sanitizers="${enabled_sanitizers}${enabled_sanitizers:+, }address"
               AS_VAR_IF([enable_san_leak], ["no"], [:],
                 [
                   AC_CACHE_CHECK([whether leak detect is not rejected by address sanitizer], [mhd_cv_cc_sanitizer_address_leak],
                     [
                       CFLAGS="${CFLAGS_ac} ${san_CFLAGS} ${san_FLAGS} ${user_CFLAGS}"
                       ASAN_OPTIONS="exitcode=88:detect_leaks=1:halt_on_error=1"
                       export ASAN_OPTIONS
                       AC_RUN_IFELSE([AC_LANG_PROGRAM([],[])],
                         [mhd_cv_cc_sanitizer_address_leak=yes], [mhd_cv_cc_sanitizer_address_leak=no],
                         [
                           # Cross-compiling with sanitizers?
                           mhd_cv_cc_sanitizer_address_leak='assuming no'
                         ]
                       )
                       AS_UNSET([ASAN_OPTIONS])
                     ]
                   )
                 ]
               )
               AC_CACHE_CHECK([for pointer compare sanitizer], [mhd_cv_cc_sanitizer_pointer_compare],
                 [
                   CFLAGS="${CFLAGS_ac} ${san_CFLAGS} ${san_FLAGS} -fsanitize=pointer-compare ${user_CFLAGS}"
                   AC_LINK_IFELSE([AC_LANG_PROGRAM([],[])],
                    [mhd_cv_cc_sanitizer_pointer_compare=yes], [mhd_cv_cc_sanitizer_pointer_compare=no])
                 ]
               )
               AS_VAR_IF([mhd_cv_cc_sanitizer_pointer_compare],["yes"],
                 [
                   AX_APPEND_FLAG([-fsanitize=pointer-compare], [san_FLAGS])
                   enabled_sanitizers="${enabled_sanitizers}${enabled_sanitizers:+, }pointer compare"
                 ]
               )
               AC_CACHE_CHECK([for pointer subtract sanitizer], [mhd_cv_cc_sanitizer_pointer_subtract],
                 [
                   CFLAGS="${CFLAGS_ac} ${san_CFLAGS} ${san_FLAGS} -fsanitize=pointer-subtract ${user_CFLAGS}"
                   AC_LINK_IFELSE([AC_LANG_PROGRAM([],[])],
                    [mhd_cv_cc_sanitizer_pointer_subtract=yes], [mhd_cv_cc_sanitizer_pointer_subtract=no])
                 ]
               )
               AS_VAR_IF([mhd_cv_cc_sanitizer_pointer_subtract],["yes"],
                 [
                   AX_APPEND_FLAG([-fsanitize=pointer-subtract], [san_FLAGS])
                   enabled_sanitizers="${enabled_sanitizers}${enabled_sanitizers:+, }pointer subtract"
                 ]
               )
               AS_VAR_IF([enable_san_upoison], ["no"], [:],
                 [
                   AC_CHECK_HEADERS([sanitizer/asan_interface.h], [], [], [AC_INCLUDES_DEFAULT])
                   AS_VAR_IF([ac_cv_header_sanitizer_asan_interface_h],["yes"],
                     [
                       AC_CACHE_CHECK([whether special function attribute is needed for user-poison], [mhd_cv_func_u_p_attribute_needed],
                         [
                           ASAN_OPTIONS="exitcode=88:detect_invalid_pointer_pairs=3:halt_on_error=1"
                           export ASAN_OPTIONS
                           CFLAGS="${CFLAGS_ac} ${san_CFLAGS} ${san_FLAGS} ${errattr_CFLAGS} ${user_CFLAGS}"
                           AC_RUN_IFELSE(
                             [
                               AC_LANG_SOURCE(
                                 [[
#include <stdint.h>
#include <stdlib.h>
#include <sanitizer/asan_interface.h>

static const size_t first_pos = 0;
static const size_t mid_pos = 64;
static const size_t last_pos = 128;
static const size_t zone_size = 16;
static const size_t buf_size = 128 + 16;

static int ptr_compare(void *ptr1, uint8_t *ptr2)
{
  if ((((uintptr_t) (uint8_t *)ptr1) >= ((uintptr_t)ptr2)))
    return ((char *) ptr1)[0] < ((char *) ptr2)[0];
  return ((char *) ptr1)[0] > ((char *) ptr2)[0];
}

static int ptr_subtract(void *ptr1, uint8_t *ptr2)
{
  return ((size_t)(((uintptr_t)(uint8_t*)ptr1) - ((uintptr_t)ptr2))) <= last_pos;
}

int main(int argc, char *argv[])
{
  char *buf = (char*) malloc (buf_size);
  char *a;
  char *b;
  int ret;

  (void) argv;
  if (NULL == buf)
    return 10;
  ASAN_POISON_MEMORY_REGION (buf + first_pos + zone_size, mid_pos - first_pos - zone_size);
  ASAN_POISON_MEMORY_REGION (buf + mid_pos + zone_size, last_pos - mid_pos - zone_size);

  if (0 < argc)
    a = buf + last_pos;
  else
    a = buf + first_pos;
  b = buf + mid_pos;

  *a = '0';
  *b = '9';

  if (ptr_compare((void *)a, (uint8_t*) b))
  {
    if (ptr_subtract((void *)a, (uint8_t*) b))
      ret = 0;
    else
      ret = 10;
  }
  else
    ret = 5;
  ASAN_UNPOISON_MEMORY_REGION (buf, buf_size);
  free (buf);

  return ret;
}
                                 ]]
                               )
                             ],
                             [mhd_cv_func_u_p_attribute_needed="no"], [mhd_cv_func_u_p_attribute_needed="yes"],
                             [
                               # Cross-compiling with sanitizers??
                               mhd_cv_func_up_attribute_needed='assuming no'
                             ]
                           )
                           AS_UNSET([ASAN_OPTIONS])
                         ]
                       )
                     ]
                   )
                   AS_VAR_IF([mhd_cv_func_u_p_attribute_needed],["yes"],[:],
                     [
                       AC_DEFINE([FUNC_PTRCOMPARE_CAST_WORKAROUND_WORKS],[1],[Define to '1' if cast to 'uintptr_t' works for safely processing user-poisoned pointer])
                     ]
                   )
                   AS_IF([test "x${mhd_cv_func_u_p_attribute_needed}" = "xyes" && test "x${ac_cv_header_sanitizer_asan_interface_h}" = "xyes"],
                     [
                       AC_CACHE_CHECK([whether '__attribute__((no_sanitize("pointer-compare")))' and '__attribute__((no_sanitize("pointer-subtract")))' work],
                         [mhd_cv_func_attribute_nosanitize_ptr],
                         [
                           ASAN_OPTIONS="exitcode=88:detect_invalid_pointer_pairs=3:halt_on_error=1"
                           export ASAN_OPTIONS
                           CFLAGS="${CFLAGS_ac} ${san_CFLAGS} ${san_FLAGS} ${errattr_CFLAGS} ${user_CFLAGS}"
                           AC_RUN_IFELSE(
                             [
                               AC_LANG_SOURCE(
                                 [[
#include <stdint.h>
#include <stdlib.h>
#include <sanitizer/asan_interface.h>

static const size_t first_pos = 0;
static const size_t mid_pos = 64;
static const size_t last_pos = 128;
static const size_t zone_size = 16;
static const size_t buf_size = 128 + 16;

__attribute__((no_sanitize("pointer-compare")))
static int ptr_compare(void *ptr1, uint8_t *ptr2)
{
  if ((((const uint8_t*)ptr1) >= ((const uint8_t*)ptr2)))
    return ((char *) ptr1)[0] < ((char *) ptr2)[0];
  return ((char *) ptr1)[0] > ((char *) ptr2)[0];
}

__attribute__((no_sanitize("pointer-subtract")))
static int ptr_subtract(void *ptr1, uint8_t *ptr2)
{
  return ((size_t)(((const uint8_t*)ptr1) - \
          ((const uint8_t*)ptr2))) <= last_pos;
}

int main(int argc, char *argv[])
{
  char *buf = (char*) malloc (buf_size);
  char *a;
  char *b;
  int ret;

  (void) argv;
  if (NULL == buf)
    return 10;
  ASAN_POISON_MEMORY_REGION (buf + first_pos + zone_size, mid_pos - first_pos - zone_size);
  ASAN_POISON_MEMORY_REGION (buf + mid_pos + zone_size, last_pos - mid_pos - zone_size);

  if (0 < argc)
    a = buf + last_pos;
  else
    a = buf + first_pos;
  b = buf + mid_pos;

  *a = '0';
  *b = '9';

  if (ptr_compare((void *)a, (uint8_t*) b))
  {
    if (ptr_subtract((void *)a, (uint8_t*) b))
      ret = 0;
    else
      ret = 10;
  }
  else
    ret = 5;
  ASAN_UNPOISON_MEMORY_REGION (buf, buf_size);
  free (buf);

  return ret;
}
                                 ]]
                               )
                             ],
                             [mhd_cv_func_attribute_nosanitize_ptr=yes], [mhd_cv_func_attribute_nosanitize_ptr=no],
                             [
                               # Cross-compiling with sanitizers??
                               mhd_cv_func_attribute_nosanitize_ptr='assuming no'
                             ]
                           )
                           AS_UNSET([ASAN_OPTIONS])
                         ]
                       )
                       AS_VAR_IF([mhd_cv_func_attribute_nosanitize_ptr], ["yes"],
                         [
                           AC_DEFINE([FUNC_ATTR_PTRCOMPARE_WORKS],[1],[Define to '1' if '__attribute__((no_sanitize("pointer-compare")))' works])
                           AC_DEFINE([FUNC_ATTR_PTRSUBTRACT_WORKS],[1],[Define to '1' if '__attribute__((no_sanitize("pointer-subtract")))' works])
                         ],
                         [
                           AC_CACHE_CHECK([whether '__attribute__((no_sanitize("address")))' works for pointers compare], [mhd_cv_func_attribute_nosanitize_addr],
                             [
                               ASAN_OPTIONS="exitcode=88:detect_invalid_pointer_pairs=3:halt_on_error=1"
                               export ASAN_OPTIONS
                               CFLAGS="${CFLAGS_ac} ${san_CFLAGS} ${san_FLAGS} ${errattr_CFLAGS} ${user_CFLAGS}"
                               AC_RUN_IFELSE(
                                 [
                                   AC_LANG_SOURCE(
                                     [[
#include <stdint.h>
#include <stdlib.h>
#include <sanitizer/asan_interface.h>

static const size_t first_pos = 0;
static const size_t mid_pos = 64;
static const size_t last_pos = 128;
static const size_t zone_size = 16;
static const size_t buf_size = 128 + 16;

__attribute__((no_sanitize("address")))
static int ptr_compare(void *ptr1, uint8_t *ptr2)
{
  if ((((const uint8_t*)ptr1) >= ((const uint8_t*)ptr2)))
    return ((char *) ptr1)[0] < ((char *) ptr2)[0];
  return ((char *) ptr1)[0] > ((char *) ptr2)[0];
}

__attribute__((no_sanitize("address")))
static int ptr_subtract(void *ptr1, uint8_t *ptr2)
{
  return ((size_t)(((const uint8_t*)ptr1) - \
          ((const uint8_t*)ptr2))) <= last_pos;
}

int main(int argc, char *argv[])
{
  char *buf = (char*) malloc (buf_size);
  char *a;
  char *b;
  int ret;

  (void) argv;
  if (NULL == buf)
    return 10;
  ASAN_POISON_MEMORY_REGION (buf + first_pos + zone_size, mid_pos - first_pos - zone_size);
  ASAN_POISON_MEMORY_REGION (buf + mid_pos + zone_size, last_pos - mid_pos - zone_size);

  if (0 < argc)
    a = buf + last_pos;
  else
    a = buf + first_pos;
  b = buf + mid_pos;

  *a = '0';
  *b = '9';

  if (ptr_compare((void *)a, (uint8_t*) b))
  {
    if (ptr_subtract((void *)a, (uint8_t*) b))
      ret = 0;
    else
      ret = 10;
  }
  else
    ret = 5;
  ASAN_UNPOISON_MEMORY_REGION (buf, buf_size);
  free (buf);

  return ret;
}
                                     ]]
                                   )
                                 ],
                                 [mhd_cv_func_attribute_nosanitize_addr=yes], [mhd_cv_func_attribute_nosanitize_addr=no],
                                 [
                                   # Cross-compiling with sanitizers??
                                   mhd_cv_func_attribute_nosanitize_addr='assuming no'
                                 ]
                               )
                               AS_UNSET([ASAN_OPTIONS])
                             ]
                           )
                           AS_VAR_IF([mhd_cv_func_attribute_nosanitize_addr], ["yes"],
                             [AC_DEFINE([FUNC_ATTR_NOSANITIZE_WORKS],[1],[Define to '1' if '__attribute__((no_sanitize("address")))' works for pointers compare])]
                           )
                         ]
                       )
                     ]
                   )
                 ]
               )
             ]
           )
           AS_IF([test "x${enable_san_address}" = "xyes" && test "x${mhd_cv_cc_sanitizer_address}" != "xyes"],
             [AC_MSG_ERROR([Address sanitizer cannot be enabled])]
           )
           enable_san_address="${mhd_cv_cc_sanitizer_address}"
         ]
       )
       AS_VAR_IF([enable_san_undef], ["no"], [:],
         [
           dnl Ensure that '#' will be processed correctly
           [
            test_undf_prog='
#include <stdio.h>

static void func_out_b(char *arr)
{
  arr[0] = 0;
  arr[16] = 2;
}

static unsigned int int_deref(void *ptr)
{
  return (*((unsigned int*)ptr)) + 2;
}

static int func1(void)
{
  char chr[16];
  func_out_b (chr);
  return (int) (int_deref(chr + 1) + int_deref(chr + 2));
}

int main(void)
{
  unsigned long ulvar;
  signed char ch1;
  ulvar = -1 * func1();
  ch1 = ulvar * 6UL;
  printf("%lu\n", ulvar + ch1);
  return 0;
}
            '
           ]
           AC_CACHE_CHECK([for undefined behavior sanitizer], [mhd_cv_cc_sanitizer_undefined],
             [
               CFLAGS="${CFLAGS_ac} ${san_FLAGS} ${san_CFLAGS} -fsanitize=undefined ${user_CFLAGS}"
               AC_LINK_IFELSE([AC_LANG_SOURCE([${test_undf_prog}])],
                [mhd_cv_cc_sanitizer_undefined=yes], [mhd_cv_cc_sanitizer_undefined=no])
             ]
           )
           AS_VAR_IF([mhd_cv_cc_sanitizer_undefined],["yes"],
             [
               AX_APPEND_FLAG([-fsanitize=undefined], [san_FLAGS])
               enabled_sanitizers="${enabled_sanitizers}${enabled_sanitizers:+, }undefined"
             ],
             [
               AS_CASE([${enable_san_undef}], [yes|auto-fallback],
                 [
                   AC_CACHE_CHECK([for undefined behavior sanitizer with '-fsanitize-undefined-trap-on-error'], [mhd_cv_cc_sanitizer_undefined_trap],
                     [
                       CFLAGS="${CFLAGS_ac} ${san_FLAGS} ${san_CFLAGS} -fsanitize=undefined -fsanitize-undefined-trap-on-error ${user_CFLAGS}"
                       AC_LINK_IFELSE([AC_LANG_SOURCE([${test_undf_prog}])],
                        [mhd_cv_cc_sanitizer_undefined_trap=yes], [mhd_cv_cc_sanitizer_undefined_trap=no])
                     ]
                   )
                   AS_VAR_IF([mhd_cv_cc_sanitizer_undefined_trap], ["yes"],
                     [
                       AX_APPEND_FLAG([-fsanitize=undefined], [san_FLAGS])
                       AX_APPEND_FLAG([-fsanitize-undefined-trap-on-error], [san_FLAGS])
                       enabled_sanitizers="${enabled_sanitizers}${enabled_sanitizers:+, }undefined"
                       AC_MSG_WARN([Enabled sanitizer without run-time library, error reporting will be limited])
                     ],
                     [
                       AS_IF([test -z "${enabled_sanitizers}"],
                         [
                           # Last resort
                           AC_CACHE_CHECK([for undefined behavior sanitizer with '-fsanitize-trap=all'], [mhd_cv_cc_sanitizer_undefined_trap_all],
                             [
                               CFLAGS="${CFLAGS_ac} ${san_FLAGS} ${san_CFLAGS} -fsanitize=undefined -fsanitize-trap=all ${user_CFLAGS}"
                               AC_LINK_IFELSE([AC_LANG_SOURCE([${test_undf_prog}])],
                                [mhd_cv_cc_sanitizer_undefined_trap_all=yes], [mhd_cv_cc_sanitizer_undefined_trap_all=no])
                             ]
                           )
                           AS_VAR_IF([mhd_cv_cc_sanitizer_undefined_trap_all],["yes"],
                             [
                               AX_APPEND_FLAG([-fsanitize=undefined], [san_FLAGS])
                               AX_APPEND_FLAG([-fsanitize-trap=all], [san_FLAGS])
                               CFLAGS="${CFLAGS_ac} ${san_FLAGS} ${san_CFLAGS} -fsanitize=undefined -fsanitize-trap=all ${user_CFLAGS}"
                               enabled_sanitizers="${enabled_sanitizers}${enabled_sanitizers:+, }undefined"
                               AC_MSG_WARN([Enabled sanitizer without run-time library, error reporting will be limited])
                             ]
                           )
                         ]
                       )
                     ]
                   )
                   AS_CASE(["$enabled_sanitizers"], [*undefined],
                     [
                       AS_VAR_IF([mhd_cv_cc_sanitizer_undefined], ["yes"],[],
                         [
                           # A workaround for broken clang which is trying to use UBSan lib
                           # even when instructed to not use it
                           CFLAGS="${CFLAGS_ac} ${san_FLAGS} ${san_CFLAGS} ${user_CFLAGS}"
                           AX_APPEND_LINK_FLAGS([-fsanitize-trap=implicit-conversion],
                             [san_FLAGS], [], [AC_LANG_SOURCE([${test_undf_prog}])])
                         ]
                       )
                     ]
                   )
                 ]
               )
             ]
           )
           AS_CASE(["$enabled_sanitizers"], [*undefined],
             [
               CFLAGS="${CFLAGS_ac} ${san_FLAGS} ${san_CFLAGS} ${user_CFLAGS}"
               AX_APPEND_LINK_FLAGS([-fsanitize=bounds-strict -fsanitize=local-bounds -fsanitize=implicit-conversion -fsanitize=nullability-arg],
                 [san_CFLAGS], [], [AC_LANG_SOURCE([${test_undf_prog}])])
             ]
           )
           AS_UNSET([test_undf_prog])
           AS_CASE(["$enabled_sanitizers"],
             [*undefined], [enable_san_undef="yes"],
             [
               AS_VAR_IF([enable_san_undef], [yes], [AC_MSG_ERROR([Undefined behavior sanitizer cannot be enabled])])
               enable_san_undef="no"
             ]
           )
         ]
       )
       AS_VAR_IF([enable_san_leak], ["no"], [:],
         [
           AC_CACHE_CHECK([for leak sanitizer], [mhd_cv_cc_sanitizer_leak],
             [
               CFLAGS="${CFLAGS_ac} ${san_FLAGS} ${san_CFLAGS} -fsanitize=leak ${user_CFLAGS}"
               AC_LINK_IFELSE([AC_LANG_PROGRAM([],[])],
                [mhd_cv_cc_sanitizer_leak=yes], [mhd_cv_cc_sanitizer_leak=no])
             ]
           )
           AS_VAR_IF([mhd_cv_cc_sanitizer_leak],["yes"],
             [
               AX_APPEND_FLAG([-fsanitize=leak], [san_FLAGS])
               enabled_sanitizers="${enabled_sanitizers}${enabled_sanitizers:+, }leak"
             ]
           )
           AS_IF([test "x${enable_san_leak}" = "xyes" && test "x${mhd_cv_cc_sanitizer_leak}" != "xyes"],
             [AC_MSG_ERROR([User poison cannot be enabled])]
           )
           enable_san_leak="${mhd_cv_cc_sanitizer_leak}"
         ]
       )
       AS_IF([test -z "${enabled_sanitizers}"],
         [
           AS_VAR_IF([enable_sanitizers], ["auto-optional"],
             [
               san_FLAGS=""
               san_CFLAGS=""
             ],
             [
               AC_MSG_ERROR([cannot find any sanitizer supported by $CC])
             ]
           )
         ],
         [
           AS_VAR_IF([enable_san_upoison], ["no"], [:],
             [
               AC_MSG_CHECKING([whether to enable user memory poisoning])
               AS_IF([test "x${mhd_cv_cc_sanitizer_address}" = "xyes" && test "x${ac_cv_header_sanitizer_asan_interface_h}" = "xyes" && \
                 (test "x${mhd_cv_func_u_p_attribute_needed}" != "xyes" || test "x${mhd_cv_func_attribute_nosanitize_ptr}" = "xyes" || \
                  test "x${mhd_cv_func_attribute_nosanitize_addr}" = "xyes")],
                 [
                   AC_DEFINE([MHD_ASAN_POISON_ACTIVE], [1], [Define to '1' if user memory poison is used])
                   enabled_sanitizers="${enabled_sanitizers}${enabled_sanitizers:+, }user-poison"
                   enable_san_upoison="yes"
                   AC_MSG_RESULT([yes])
                 ],
                 [
                   AC_MSG_RESULT([no])
                   AS_VAR_IF([enable_san_upoison], ["yes"],
                     [AC_MSG_ERROR([User memory poisoning cannot be enabled])])
                   enable_san_upoison="no"
                 ]
               )
             ]
           )
           AS_VAR_IF([enable_san_address], ["yes"],
             [
               CFLAGS="${CFLAGS_ac} ${san_FLAGS} ${san_CFLAGS} ${user_CFLAGS}"
               AC_CHECK_DECL([_FORTIFY_SOURCE],
                 [MHD_APPEND_FLAG_TO_VAR([CPPFLAGS_ac],[-U_FORTIFY_SOURCE])],
                 [],[/* no includes */])
               AX_APPEND_FLAG([-D_FORTIFY_SOURCE=0], [san_CFLAGS])
             ],
             [
               AS_CASE([$enable_sanitizers], [auto|auto-fallback],
                 [AC_MSG_WARN([$CC does not support address sanitizer])])
             ]
           )
           CFLAGS="${CFLAGS_ac} ${san_FLAGS} ${san_CFLAGS} ${user_CFLAGS}"
           # Always stop on sanitizer error
           AX_APPEND_COMPILE_FLAGS([-fno-sanitize-recover=all], [san_CFLAGS])
           # Get a better output for sanitizers error reporting
           AX_APPEND_COMPILE_FLAGS([-fno-omit-frame-pointer -fno-optimize-sibling-calls],
             [san_CFLAGS])
           AS_VAR_IF([enable_san_address], ["yes"],
             [
               AM_ASAN_OPTIONS="exitcode=88:strict_string_checks=1:detect_stack_use_after_return=1"
               AM_ASAN_OPTIONS="${AM_ASAN_OPTIONS}:check_initialization_order=1:strict_init_order=1:redzone=64"
               AM_ASAN_OPTIONS="${AM_ASAN_OPTIONS}:max_free_fill_size=1024:detect_invalid_pointer_pairs=3"
               AM_ASAN_OPTIONS="${AM_ASAN_OPTIONS}:handle_ioctl=1:halt_on_error=1"
               AS_VAR_IF([enable_san_upoison], ["yes"], [AM_ASAN_OPTIONS="${AM_ASAN_OPTIONS}:allow_user_poisoning=1"])
               AS_VAR_IF([enable_san_leak], ["yes"],
                 [AS_VAR_IF([mhd_cv_cc_sanitizer_address_leak], ["yes"],
                   [AM_ASAN_OPTIONS="${AM_ASAN_OPTIONS}:detect_leaks=1"])
                 ], [AM_ASAN_OPTIONS="${AM_ASAN_OPTIONS}:detect_leaks=0"]
               )
             ]
           )
           AS_VAR_IF([enable_san_undef], [yes],
             [AM_UBSAN_OPTIONS="exitcode=87:print_stacktrace=1:halt_on_error=1"])
           AS_VAR_IF([enable_san_leak], ["yes"],
             [AM_LSAN_OPTIONS="use_unaligned=1"]
           )
           TESTS_ENVIRONMENT_ac='\
    ASAN_OPTIONS="$(AM_ASAN_OPTIONS)" ; export ASAN_OPTIONS ; \
    UBSAN_OPTIONS="$(AM_UBSAN_OPTIONS)" ; export UBSAN_OPTIONS ; \
    LSAN_OPTIONS="$(AM_LSAN_OPTIONS)" ; export LSAN_OPTIONS ;'
         ]
       )
     ]
   )
   CFLAGS_ac="${CFLAGS_ac} ${san_FLAGS} ${san_CFLAGS}"
   CFLAGS="${CFLAGS_ac} ${user_CFLAGS}"
 ]
)

# Final flags that may interfere with autoconf detections
AS_CASE([${enable_build_type}],[debug|debugger],
  [ # Debug build or build for walking with debugger
    CFLAGS="${user_CFLAGS}"
    MHD_CHECK_ADD_CC_CFLAGS([-Wextra-semi -Wextra-semi-stmt], [CFLAGS_ac])
    CFLAGS="${CFLAGS_ac} ${user_CFLAGS}"
  ]
)

AM_CONDITIONAL([USE_SANITIZERS],
  [test -n "$enabled_sanitizers" && test "x$mhd_cv_cc_sanitizer_works" = "xyes"])
AC_SUBST([AM_ASAN_OPTIONS])
AC_SUBST([AM_UBSAN_OPTIONS])
AC_SUBST([AM_LSAN_OPTIONS])
AC_SUBST([TESTS_ENVIRONMENT_ac])

MHD_LIB_LDFLAGS="$MHD_LIB_LDFLAGS"

AC_SUBST([CPU_COUNT])
AC_SUBST([HEAVY_TESTS_NOTPARALLEL])
AM_SUBST_NOTMAKE([HEAVY_TESTS_NOTPARALLEL])
AC_SUBST(MHD_LIB_CPPFLAGS)
AC_SUBST(MHD_LIB_CFLAGS)
AC_SUBST(MHD_LIB_LDFLAGS)
AC_SUBST(MHD_LIBDEPS)
AC_SUBST(MHD_TLS_LIB_CPPFLAGS)
AC_SUBST(MHD_TLS_LIB_CFLAGS)
AC_SUBST(MHD_TLS_LIB_LDFLAGS)
AC_SUBST(MHD_TLS_LIBDEPS)

# for pkg-config
AC_SUBST([MHD_REQ_PRIVATE])
AC_SUBST([MHD_LIBDEPS_PKGCFG])

# Restore flags as set by the user
CFLAGS="${user_CFLAGS}"
LDFLAGS="${user_LDFLAGS}"
CPPFLAGS="${user_CPPFLAGS}"
AC_SUBST([CFLAGS])
AC_SUBST([LDFLAGS])
AC_SUBST([CPPFLAGS])
AC_SUBST([LIBS])

# Configure-defined flags
AC_SUBST([CFLAGS_ac])
AC_SUBST([LDFLAGS_ac])
AC_SUBST([CPPFLAGS_ac])

# Used for 'po' directory staff
AC_SUBST([ac_configure_args])
AC_SUBST([EMPTY_VAR], [[]])

# We define the paths here, because MinGW/GCC expands paths
# passed through the command line ("-DDIR=..."). This would
# lead to hard-coded paths ("C:\mingw\mingw\bin...") that do
# not contain the actual installation.
AC_DEFINE_DIR([MHD_PLUGIN_INSTALL_PREFIX], [libdir/libmicrohttpd], [tls plugins])


# should experimental code be compiled (code that may not yet compile)?
AC_MSG_CHECKING(whether to compile experimental code)
AC_ARG_ENABLE([experimental],
   [AS_HELP_STRING([--enable-experimental], [enable compiling experimental code])],
   [enable_experimental=${enableval}],
   [enable_experimental=no])
AC_MSG_RESULT($enable_experimental)
AM_CONDITIONAL([HAVE_EXPERIMENTAL], [test "x$enable_experimental" = "xyes"])


AC_CONFIG_FILES([libmicrohttpd.pc
w32/common/microhttpd_dll_res_vc.rc
Makefile
po/po-configure.ac
contrib/Makefile
doc/Makefile
doc/doxygen/libmicrohttpd.doxy
doc/doxygen/Makefile
doc/examples/Makefile
m4/Makefile
src/Makefile
src/include/Makefile
src/lib/Makefile
src/microhttpd/Makefile
src/microhttpd_ws/Makefile
src/examples/Makefile
src/testcurl/Makefile
src/testcurl/https/Makefile
src/testzzuf/Makefile])
AC_OUTPUT

# Finally: summary
# Format flags without extra spaces for visual beauty
fin_CPPFLAGS="$user_CPPFLAGS"
fin_CFLAGS="$user_CFLAGS"
fin_LDFLAGS="$user_LDFLAGS"
MHD_PREPEND_FLAG_TO_VAR([fin_CPPFLAGS],[$CPPFLAGS_ac])
MHD_PREPEND_FLAG_TO_VAR([fin_CFLAGS],[$CFLAGS_ac])
MHD_PREPEND_FLAG_TO_VAR([fin_LDFLAGS],[$LDFLAGS_ac])
fin_lib_CPPFLAGS="$user_CPPFLAGS"
fin_lib_CFLAGS="$user_CFLAGS"
fin_lib_LDFLAGS="$user_LDFLAGS"
MHD_PREPEND_FLAG_TO_VAR([fin_lib_CPPFLAGS],[$MHD_LIB_CPPFLAGS])
MHD_PREPEND_FLAG_TO_VAR([fin_lib_CFLAGS],[$MHD_LIB_CFLAGS])
MHD_PREPEND_FLAG_TO_VAR([fin_lib_LDFLAGS],[$MHD_LIB_LDFLAGS])
MHD_PREPEND_FLAG_TO_VAR([fin_lib_CPPFLAGS],[$CPPFLAGS_ac])
MHD_PREPEND_FLAG_TO_VAR([fin_lib_CFLAGS],[$CFLAGS_ac])
MHD_PREPEND_FLAG_TO_VAR([fin_lib_LDFLAGS],[$LDFLAGS_ac])
AC_MSG_NOTICE([Toolchain settings:
  CC=$CC
  User/system/default flags:
    CPPFLAGS="$user_CPPFLAGS"
    CFLAGS=  "$user_CFLAGS"
    LDFLAGS= "$user_LDFLAGS"
  Final set of the flags for tests and examples:
    CPPFLAGS="$fin_CPPFLAGS"
    CFLAGS=  "$fin_CFLAGS"
    LDFLAGS= "$fin_LDFLAGS"
  Final set of the flags for ${PACKAGE_NAME} library:
    CPPFLAGS="$fin_lib_CPPFLAGS"
    CFLAGS=  "$fin_lib_CFLAGS"
    LDFLAGS= "$fin_lib_LDFLAGS"
])
AS_UNSET([fin_CPPFLAGS])
AS_UNSET([fin_CFLAGS])
AS_UNSET([fin_LDFLAGS])
AS_UNSET([fin_lib_CPPFLAGS])
AS_UNSET([fin_lib_CFLAGS])
AS_UNSET([fin_lib_LDFLAGS])

AS_VAR_IF([os_is_windows], ["yes"],
  [os_ver_msg="
  Target W32 ver:    ${mhd_w32_ver_msg}"], [AS_UNSET([[os_ver_msg]])])


AC_MSG_NOTICE([GNU libmicrohttpd ${PACKAGE_VERSION} Configuration Summary:
  Target directory:  ${prefix}
  Cross-compiling:   ${cross_compiling}
  Operating System:  ${mhd_host_os}${os_ver_msg}
  Messages:          ${enable_messages}
  Cookie parsing:    ${enable_cookie}
  Postproc:          ${enable_postprocessor}
  HTTP "Upgrade":    ${enable_httpupgrade}
  Basic auth.:       ${enable_bauth}
  Digest auth.:      ${enable_dauth}
  MD5:               ${enable_md5_MSG}
  SHA-256:           ${enable_sha256_MSG}
  SHA-512/256:       ${enable_sha512_256_MSG}
  Shutdown of listening socket triggers select: ${mhd_cv_host_shtdwn_trgr_select}
  Inter-thread comm: ${use_itc}
  Threading lib:     ${USE_THREADS}
  poll support:      ${enable_poll=no}
  epoll support:     ${enable_epoll=no}
  sendfile used:     ${found_sendfile}
  HTTPS support:     ${MSG_HTTPS}
  Compact code:      ${enable_compact_code} (${compact_code_MSG})
  Use thread names:  ${enable_thread_names}
  Use debug asserts: ${use_asserts_MSG=no}
  Use sanitizers:    ${enabled_sanitizers:=no}
  Build docs:        ${enable_doc}
  Build examples:    ${enable_examples}
  Build static lib:  ${enable_static}
  Build shared lib:  ${enable_shared}
  Test with libcurl: ${MSG_CURL}
  Heavy tests:       ${use_heavy_tests_MSG}
  Fuzzing tests:     ${run_zzuf_tests_MSG=no}
])

AS_IF([test "x$enable_https" = "xyes"],
 [AC_MSG_NOTICE([HTTPS subsystem configuration:
  License         :  LGPL version 2.1 or any later version
 ])],
 [AC_MSG_NOTICE([
  License         :  LGPLv2.1+ or eCos
 ])])

AS_IF([test "x$enable_bauth" != "xyes" || \
   test "x$enable_dauth" != "xyes" || \
   test "x${enable_md5}" = "xno" || \
   test "x${enable_sha256}" = "xno" || \
   test "x${enable_sha512_256}" != "xyes" || \
   test "x$enable_httpupgrade" != "xyes" || \
   test "x$enable_cookie" != "xyes" || \
   test "x$enable_postprocessor" != "xyes"],
   [AC_MSG_NOTICE([WARNING: This will be a custom build with missing symbols. Do NOT use this build in a distribution. Building with these kinds of configure options is only for custom builds for embedded systems.])])
