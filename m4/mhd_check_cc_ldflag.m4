# SYNOPSIS
#
#   MHD_CHECK_CC_LDFLAG([FLAG-TO-TEST], [VARIABLE-TO-PREPEND-LDFLAGS],
#                       [ACTION-IF-SUPPORTED], [ACTION-IF-NOT-SUPPORTED])
#
# DESCRIPTION
#
#   This macro checks whether the specific compiler flag is supported.
#   The check is performing by prepending FLAG-TO-TEST to LDFLAGS, then
#   prepending value of VARIABLE-TO-PREPEND-LDFLAGS (if any) to LDFLAGS, and
#   then performing compile and link test. If test succeed without warnings,
#   then the flag is considered to be supported. Otherwise, if compile and link
#   without test flag can be done without any warning, the flag is considered
#   to be unsuppoted.
#
#   Example usage:
#
#     MHD_CHECK_CC_LDFLAG([-pie], [additional_LDFLAGS],
#                         [additional_LDFLAGS="${additional_LDFLAGS} -pie"])
#
#   Defined cache variable used in check so if any test will not work
#   correctly on some platform, user may simply fix it by giving cache
#   variable in configure parameters, for example:
#
#     ./configure mhd_cv_cc_fl_supp__wshadow=no
#
#   This simplify building from source on exotic platforms as patching
#   of configure.ac is not required to change results of tests.
#
# LICENSE
#
#   Copyright (c) 2022 Karlson2k (Evgeny Grin) <k2k@narod.ru>
#
#   Copying and distribution of this file, with or without modification, are
#   permitted in any medium without royalty provided the copyright notice
#   and this notice are preserved. This file is offered as-is, without any
#   warranty.

#serial 1

AC_DEFUN([MHD_CHECK_CC_LDFLAG],[dnl
_MHD_CHECK_CC_XFLAG([$1],[$2],[$3],[$4],[[LDFLAGS]])dnl
])
