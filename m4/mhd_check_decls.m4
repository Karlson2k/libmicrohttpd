# SYNOPSIS
#
#   MHD_CHECK_DECLS([SYMBOLS-TO-TEST], [INCLUDES])
#
# DESCRIPTION
#
#   This macro checks whether specific symbols is defined in the headers.
#   SYMBOLS-TO-TEST is s space-separated list of symbols to check.
#   The symbol could be a macro, a variable, a constant, a enum value,
#   a function name or other kind of symbols recognisable by compiler (or
#   preprocessor).
#   For every found symbol a relevant preprocessor macro is defined.
#   Unlike AC_CHECK_DECLS this m4 macro does not define preprocossor macro if
#   symbol is NOT found.
#
#   Example usage:
#
#     MHD_CHECK_DECLS([SSIZE_MAX OFF_T_MAX], [[#include <limits.h>]])
#
#
# LICENSE
#
#   Copyright (c) 2025 Karlson2k (Evgeny Grin) <k2k@drgrin.dev>
#
#   Copying and distribution of this file, with or without modification, are
#   permitted in any medium without royalty provided the copyright notice
#   and this notice are preserved. This file is offered as-is, without any
#   warranty.

#serial 1

AC_DEFUN([MHD_CHECK_DECLS],[dnl
m4_newline([[# Expansion of $0 macro starts here]])
m4_if(m4_index([$1], [(]),[-1],[],[dnl
m4_fatal([SYMBOLS-TO-TEST parameter (first macro argument) contains '('])])dnl m4_if
m4_if(m4_index([$1], [)]),[-1],[],[dnl
m4_fatal([SYMBOLS-TO-TEST parameter (first macro argument) contains ')'])])dnl m4_if
m4_if(m4_index([$1], [,]),[-1],[],[dnl
m4_fatal([SYMBOLS-TO-TEST parameter (first macro argument) contains ','])])dnl m4_if
m4_foreach_w([check_Symbol],[$1],
[AC_CHECK_DECL(check_Symbol,[dnl
AC_DEFINE([HAVE_DCLR_]m4_toupper(check_Symbol),[1],[Define to '1' if you have the declaration of ']check_Symbol['])dnl
],[],[$2])
])dnl
m4_newline([[# Expansion of $0 macro ends here]])
])
