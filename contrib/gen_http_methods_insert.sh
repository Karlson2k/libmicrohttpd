#!/bin/bash

#
#   Generate header insert for HTTP methods
#

#   Copyright (c) 2015-2021 Karlson2k (Evgeny Grin) <k2k@yandex.ru>
#
#   Copying and distribution of this file, with or without modification, are
#   permitted in any medium without royalty provided the copyright notice
#   and this notice are preserved. This file is offered as-is, without any
#   warranty.

wget -nv http://www.iana.org/assignments/http-methods/methods.csv -O methods.csv || exit
echo Generating...
echo '/**
 * @defgroup methods HTTP methods
 * HTTP methods (as strings).
 * See: https://www.iana.org/assignments/http-methods/http-methods.xml
 * Registry export date: '"$(date -u +%Y-%m-%d)"'
 * @{
 */

/* Main HTTP methods. */' > header_insert_methods.h && \
gawk -e 'BEGIN {FPAT = "([^,]*)|(\"[^\"]+\")"}
function strnumcmp(s1, s2,  n1, n2, a1, a2)
{
  n1 = length(s1)
  n2 = length(s2)
  if (0 == n1 && 0 == n2)
    return 0
  if (0 == n1 && 0 < n2)
    return -1
  if (0 < n1 && 0 == n2)
    return 1
  n1 = match(s1, /^[^0-9]+/, a1)
  n2 = match(s2, /^[^0-9]+/, a2)
  if (0 != n1)
  {
    if (0 == n2)
      return 1
    if ((a1[0] "") < (a2[0] ""))
      return -1
    if ((a1[0] "") > (a2[0] ""))
      return 1
  }
  else
  {
    if (0 != n2)
      return -1
  }
  s1 = substr(s1, length(a1[0]) + 1)
  s2 = substr(s2, length(a2[0]) + 1)
  n1 = match(s1, /^[0-9]+/, a1)
  n2 = match(s2, /^[0-9]+/, a2)
  if (0 != n1)
  {
    if (0 == n2)
      return 1
    if ((a1[0] + 0) < (a2[0] + 0))
      return -1
    if ((a1[0] + 0) > (a2[0] + 0))
      return 1
  }
  else
  {
    if (0 != n2)
      return -1
  }
  return strnumcmp(substr(s1, length(a1[0]) + 1), substr(s2, length(a2[0]) + 1))
}

function sort_indices(i1, v1, i2, v2)
{
  return strnumcmp(gensub(/[^0-9A-Za-z]+/, " ", "g", i1), gensub(/[^0-9A-Za-z]+/, " ", "g", i2))
}

FNR > 1 {
  mthd_m = $1
  reference_m = $4
  gsub(/^\[|^"\[|\]"$|\]$/, "", reference_m)
  gsub(/\]\[/, "; ", reference_m)
  if (reference_m ~ /^RFC911[0-2]/ && mthd_m != "*") {
    if ($2 == "yes")
    { safe_m = "Safe.    " }
    else
    { safe_m = "Not safe." }
    if ($3 == "yes")
    { indem_m = "Idempotent.    " }
    else
    { indem_m = "Not idempotent." }
    idx_str = reference_m
    main_methods[idx_str] = sprintf ("%s\n", "/* " safe_m " " indem_m " " reference_m ". */")
    mthd_tkn = gensub(/\*/, "ASTERISK", "g", mthd_m)
    gsub(/[^a-zA-Z0-9_]/, "_", mthd_tkn)
    main_methods[idx_str] = (main_methods[idx_str] sprintf ("%-32s \"%s\"\n", "#define MHD_HTTP_METHOD_" toupper(mthd_tkn), mthd_m))
  }
}

END {
  n = asort(main_methods, main_methods, "sort_indices")
  for (i = 1; i <= n; i++)
    printf("%s", main_methods[i])
}
' methods.csv >> header_insert_methods.h && \
echo '
/* Additional HTTP methods. */' >> header_insert_methods.h && \
gawk -e 'BEGIN {FPAT = "([^,]*)|(\"[^\"]+\")"}
FNR > 1 {
  gsub(/^\[|^"\[|\]"$|\]$/, "", $4)
  gsub(/\]\[/, "; ", $4)
  if ($4 !~ /^RFC911[0-2]/ || $1 == "*") {
    if ($2 == "yes")
    { safe_m = "Safe.    " }
    else
    { safe_m = "Not safe." }
    if ($3 == "yes")
    { indem_m = "Idempotent.    " }
    else
    { indem_m = "Not idempotent." }
    print "/* " safe_m " " indem_m " " $4 ". */"
    mthd = gensub(/\*/, "ASTERISK", "g", $1)
    mthd = gensub(/[^a-zA-Z0-9_]/, "_", "g", mthd)
    printf ("%-38s \"%s\"\n", "#define MHD_HTTP_METHOD_" toupper(mthd), $1)
  }
}' methods.csv >> header_insert_methods.h && \
echo '
/** @} */ /* end of group methods */
' >> header_insert_methods.h &&
echo OK && \
rm methods.csv || exit
