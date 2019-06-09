#!/bin/bash

#
#   Generate code and header inserts for HTTP statues
#

#   Copyright (c) 2019 Karlson2k (Evgeny Grin) <k2k@yandex.ru>
#
#   Copying and distribution of this file, with or without modification, are
#   permitted in any medium without royalty provided the copyright notice
#   and this notice are preserved. This file is offered as-is, without any
#   warranty.

wget -nv https://www.iana.org/assignments/http-status-codes/http-status-codes-1.csv -O http-status-codes-1.csv || exit
echo Generating...
echo "/**
 * @defgroup httpcode HTTP response codes.
 * These are the status codes defined for HTTP responses.
 * See: https://www.iana.org/assignments/http-status-codes/http-status-codes.xhtml
 * Registry export date: $(date -u +%Y-%m-%d)
 * @{
 */
" > header_insert_statuses.h && \
gawk -e 'BEGIN {FPAT = "([^,]*)|(\"[^\"]+\")"}
FNR > 1 {
  gsub(/^\[|^"\[|\]"$|\]$/, "", $3)
  gsub(/\]\[/, "; ", $3)
  if ($1 == 306) { 
    $2 = "Switch Proxy" 
    $3 = "Not used! " $3
  }
  if ($2 != "Unassigned") {
    print "/* " $1 sprintf("%-24s", " \"" $2 "\". ") $3 ". */"
    print "#define MHD_HTTP_" toupper(gensub(/[^A-Za-z0-0]/, "_", "g", $2)) " "$1""
  } else {
    print ""
  }
}' http-status-codes-1.csv >> header_insert_statuses.h && \
echo '
/* Not registered non-standard codes */
/* 449 "Reply With".          MS IIS extension. */
#define MHD_HTTP_RETRY_WITH 449

/* 450 "Blocked by Windows Parental Controls". MS extension. */
#define MHD_HTTP_BLOCKED_BY_WINDOWS_PARENTAL_CONTROLS 450

/* 509 "Bandwidth Limit Exceeded". Apache extension. */
#define MHD_HTTP_BANDWIDTH_LIMIT_EXCEEDED 509
' >> header_insert_statuses.h && \
gawk -e 'BEGIN {
  FPAT = "([^,]*)|(\"[^\"]+\")"
  hundreds[1]="one"
  hundreds[2]="two"
  hundreds[3]="three"
  hundreds[4]="four"
  hundreds[5]="five"
  hundreds[6]="six"
  prev_num=0
}
FNR > 1 {
  gsub(/^\[|^"\[|\]"$|\]$/, "", $3)
  gsub(/\]\[/, "; ", $3)
  if ($1 % 100 == 0) {
    if ($1 != 100) { printf("\n};\n\n") }
    prev_num=$1 - 1;
    print "static const char *const " hundreds[$1/100] "_hundred[] = {"
  }
  if ($1 == 306) { 
    $2 = "Switch Proxy" 
    $3 = "Not used! " $3
  }
  if ($2 == "Unassigned") next
  while(++prev_num != $1) {
    if (prev_num == 449) {reason="Reply With"; desc="MS IIS extension";}
    else if (prev_num == 450) {reason="Blocked by Windows Parental Controls"; desc="MS extension";}
    else if (prev_num == 509) {reason="Bandwidth Limit Exceeded"; desc="Apache extension";}
    else {reason="Unknown"; desc="Not used";}
    printf (",\n  /* %s */ %-24s /* %s */", prev_num, "\"" reason "\"", desc)
  }
  if ($1 % 100 != 0) { print "," }
  printf ("  /* %s */ %-24s /* %s */", $1, "\""$2"\"", $3)
}
END {printf("\n};\n")}' http-status-codes-1.csv >> code_insert_statuses.c && \
echo OK && \
rm http-status-codes-1.csv || exit
