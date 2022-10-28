#!/bin/sh

mhd_listen_ip='127.0.0.1'
max_runtime_sec='300'

if test "x${ZZUF}" = "xno" ; then
  echo "zzuf command missing" 1>&2
  exit 77
fi

if command -v "${ZZUF}" > /dev/null 2>&1 ; then : ; else
  echo "zzuf command missing" 1>&2
  exit 77
fi

# zzuf cannot pass-through the return value of checked program
# so try the direct dry-run first to get possibe 77 or 99 codes
echo "## Dry-run of the $@..."
if "$@" --dry-run ; then
  echo "# Dry-run succeded."
else
  res_code=$?
  echo "Dry-run failed with exit code $res_code. $@ will not be run with zzuf." 1>&2
  exit $res_code
fi

# fuzz the input only for IP ${mhd_listen_ip}. libcurl uses another IP
# in this test therefore libcurl input is not fuzzed.
zzuf_all_params="--ratio=0.001:0.4 --autoinc --verbose --signal \
 --max-usertime=${max_runtime_sec} --check-exit --network \
 --allow=${mhd_listen_ip} --exclude=."

if test -n "${ZZUF_SEED}" ; then
  zzuf_all_params="${zzuf_all_params} --seed=${ZZUF_SEED}"
fi

if test -n "${ZZUF_FLAGS}" ; then
  zzuf_all_params="${zzuf_all_params} ${ZZUF_FLAGS}"
fi

# Uncomment the next line to see more data in logs
#zzuf_all_params="${zzuf_all_params} -dd"

echo "## Dry-run of the $@ with zzuf..."
if "$ZZUF" ${zzuf_all_params} "$@" --dry-run ; then
  echo "# Dry-run with zzuf succeded."
else
  res_code=$?
  echo "$@ cannot be run with zzuf. The test is skipped." 1>&2
  exit 77
fi

echo "## Real test of $@ with zzuf..."
"$ZZUF" ${zzuf_all_params} "$@"
exit $?
