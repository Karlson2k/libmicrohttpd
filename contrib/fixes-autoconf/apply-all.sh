#!/bin/bash

#
# This file applies optional Autoconf patches for better MSys2 and new
# compiler compatibility.
#
# Based on Debian SID baseline files as of April 2023.
#

patchesdir=$(dirname $BASH_SOURCE) || exit 2
test -n "$patchesdir" || exit 2
cd "$patchesdir" || exit 2
patchesdir=$(pwd) || exit 2

patches=(
 # No patches currently
)

failed=( )

cd "${patchesdir}/../.." || exit 1

patch_params="-Nf -p1 --no-backup-if-mismatch -r - --read-only=fail"

for patch in ${patches[@]}; do
  patchfile="${patchesdir}/${patch}"
  echo "*** Applying $patch..."
  if echo "$patch_data" | patch $patch_params -i "$patchfile"
  then
    echo "** $patch successfully applied."
  else
    echo "** $patch failed."
    failed+=("$patch")
  fi
  unset patch_data
done


addl_file="c_backported.m4"
echo "*** Copying $addl_file"
cp -fT "${patchesdir}/$addl_file" "m4/$addl_file" || exit 2
echo "$addl_file copied."

echo ''

if [[ -n "${failed[@]}" ]]; then
  printf '* Failed patch: %s\n' "${failed[@]}" >&2
  exit 2
else
  echo "* All patches have been successfully applied."
fi

exit 0
