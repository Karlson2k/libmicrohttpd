#!/bin/bash

#
# This file applies optional libtool patches mainly for better MSys2 compatibility,
# especially for MSys2/Clang{64,32} toolchains.
# It's a pity that these patches haven't been sent upstream.
#
# Based on Debian SID baseline files as of April 2023.
#

patchesdir=$(dirname $BASH_SOURCE) || exit 2
test -n "$patchesdir" || exit 2
cd "$patchesdir" || exit 2
patchesdir=$(pwd) || exit 2

patches=(
  0003-Pass-various-runtime-library-flags-to-GCC.mingw.mod.patch
  0006-Fix-strict-ansi-vs-posix.patch
  0009-libtool-2.4.2.418-msysize.patch
  0010-libtool-2.4.2-include-process-h.patch
  0011-Pick-up-clang_rt-static-archives-compiler-internal-l.patch
  0012-Prefer-response-files-over-linker-scripts-for-mingw-.patch
  0013-Allow-statically-linking-compiler-support-libraries-.patch
  0014-Support-llvm-objdump-f-output.patch
)

failed=( )

cd "${patchesdir}/../.." || exit 1

patch_params="-Nf -p1 --no-backup-if-mismatch -r - --read-only=fail"

for patch in ${patches[@]}; do
  patchfile="${patchesdir}/${patch}"
  # Load patch into memory for simplicity
  # Patches should not be very large
  if grep -Eq -e '^--- .*\/ltmain\.in(\.orig)?([[:space:]]|$)' "$patchfile" && grep -Eq -e '^--- .*\/ltmain\.sh(\.orig)?([[:space:]]|$)' "$patchfile"
  then
    patch_data=$(awk '/^diff .*\/ltmain\.in(\.orig)?$/||(/^--- / && $2 ~ /\/ltmain\.in(\.orig)?$/){h=1;s=1;next}/^-- ?$/{h=0;s=0}/^[^-+@ ]/{h||s=0}/^\+\+\+ /{h=0}!s' "$patchfile") || exit 2
  else
    patch_data=$(cat "$patchfile") || exit 2
  fi
  patch_data=$(echo "$patch_data" | sed -E -e '/^(diff|---|\+\+\+) / s|/ltmain\.in|/ltmain.sh|g' -) || exit 2
  patch_data=$(echo "$patch_data" | awk '(/^diff / && !/.*\/(ltmain\.sh|config\.guess|libtool\.m4|ltoptions\.m4)$/)||(/^--- / && $2 !~ /\/(ltmain\.sh|config\.guess|libtool\.m4|ltoptions\.m4)(\.orig)?$/){h=1;s=1;next}/^-- ?$/{h=0;s=0}/^[^-+@ ]/{h||s=0}/^\+\+\+ /{h=0}!s' -) || exit 2
  echo "*** Applying $patch..."
  if echo "$patch_data" | patch $patch_params -i -
  then
    echo "** $patch successfully applied."
  else
    echo "** $patch failed."
    failed+=("$patch")
  fi
  unset patch_data
done

echo ''

if [[ -n "${failed[@]}" ]]; then
  printf '* Failed patch: %s\n' "${failed[@]}" >&2
  exit 2
else
  echo "* All patches have been successfully applied."
fi

exit 0
