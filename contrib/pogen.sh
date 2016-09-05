#!/bin/sh
find src -name "*.c" | grep -v \# | grep -v /test_ | grep -v /perf_  | grep -v _old | grep -v chat | grep -v .libs/ | sort  > po/POTFILES.in
grep -l _\( `find src -name "*.h"` | grep -v "platform.h" | grep -v _old | grep -v chat | sort >> po/POTFILES.in

