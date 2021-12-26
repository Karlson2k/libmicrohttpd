#!/bin/bash

#
# This file applies optional libtool patches mainly for better MSys2 compatibility,
# especially for MSys2/Clang{64,32} toolchains.
# It's a pity that these patches haven't been sent upstream.
#
# Based on Debian SID baseline files as of December 2021.
#

patchesdir="$(dirname "$BASH_SOURCE")" || exit 2
test -n "$patchesdir" || exit 2

patches=(
  0003-Pass-various-flags-to-GCC.patch
  0006-Fix-strict-ansi-vs-posix-mod.patch
  0009-libtool-2.4.2.418-msysize-mod.patch
  0010-libtool-2.4.2-include-process-h-mod.patch
  0011-Pick-up-clang_rt-static-archives-compiler-internal-l.patch
  0012-Prefer-response-files-over-linker-scripts-for-mingw-mod.patch
  0013-Allow-statically-linking-compiler-support-libraries-mod.patch
  0014-Support-llvm-objdump-f-output-mod.patch
)

failed=( )

cd "${patchesdir}/../.." || exit 1

for patch in ${patches[@]}; do
  patch -N -p1 --no-backup-if-mismatch -r - -i "${patchesdir}/${patch}" || failed+=("$patch")
done

if [[ -n "${failed[@]}" ]]; then
  printf 'Failed patch: %s\n' "${failed[@]}" >&2
  exit 2
fi

exit 0
