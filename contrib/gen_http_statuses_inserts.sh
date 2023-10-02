#!/bin/bash

#
#   Generate code and header inserts for HTTP statues
#

#   Copyright (c) 2019-2021 Karlson2k (Evgeny Grin) <k2k@yandex.ru>
#
#   Copying and distribution of this file, with or without modification, are
#   permitted in any medium without royalty provided the copyright notice
#   and this notice are preserved. This file is offered as-is, without any
#   warranty.

wget -nv https://www.iana.org/assignments/http-status-codes/http-status-codes-1.csv -O http-status-codes-1.csv || exit
echo Generating...
echo '/**
 * @defgroup httpcode HTTP response codes.
 * These are the status codes defined for HTTP responses.
 * See: https://www.iana.org/assignments/http-status-codes/http-status-codes.xhtml
 * Registry export date: '"$(date -u +%Y-%m-%d)"'
 * @{
 */
' > header_insert_statuses.h && \
gawk -e 'BEGIN {FPAT = "([^,]*)|(\"[^\"]+\")"}
FNR > 1 {
  gsub(/^\[|^"\[|\]"$|\]$/, "", $3)
  gsub(/\]\[/, "; ", $3)
  if (sub(/ *\(OBSOLETED\)/, "", $2)) {
    $3 = "(OBSOLETED) " $3
  }
  if ($1 == 306) {
    $2 = "Switch Proxy"
    $3 = "Not used! " $3
  }
  if ($2 != "Unassigned" && $2 != "(Unused)") {
    printf ("/* %s %-22s %s. */\n", $1, "\"" $2 "\".", $3)
    printf ("#define MHD_HTTP_%-27s %s\n", toupper(gensub(/[^A-Za-z0-0]/, "_", "g", $2)), $1)
  } else {
    print ""
  }
}' http-status-codes-1.csv >> header_insert_statuses.h && \
echo '
/* Not registered non-standard codes */
/* 449 "Reply With".          MS IIS extension. */
#define MHD_HTTP_RETRY_WITH                  449

/* 450 "Blocked by Windows Parental Controls". MS extension. */
#define MHD_HTTP_BLOCKED_BY_WINDOWS_PARENTAL_CONTROLS 450

/* 509 "Bandwidth Limit Exceeded". Apache extension. */
#define MHD_HTTP_BANDWIDTH_LIMIT_EXCEEDED    509
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
  prev_reason=""
  prev_desc=""
  num=0
  reason=""
  desc=""
}
FNR > 1 {
  gsub(/^\[|^"\[|\]"$|\]$/, "", $3)
  gsub(/\]\[/, "; ", $3)
  num = $1
  reason = $2
  desc = $3
  if (sub(/ *\(OBSOLETED\)/, "", reason)) {
    desc = "(OBSOLETED) " desc
  }
  if (num % 100 == 0) {
    if (num != 100) {
      printf ("  /* %s */ %-36s /* %s */\n};\n\n", prev_num, "_MHD_S_STR_W_LEN (\""prev_reason"\")", prev_desc)
    }
    prev_num = num;
    print "static const struct _MHD_cstr_w_len " hundreds[$1/100] "_hundred[] = {"
  }
  if (num == 306) { 
    reason = "Switch Proxy"
    desc = "Not used! " desc
  }
  if (reason == "Unassigned" || reason == "(Unused)") next
  if (prev_num != num)
    printf ("  /* %s */ %-36s /* %s */\n", prev_num, "_MHD_S_STR_W_LEN (\""prev_reason"\"),", prev_desc)
  while(++prev_num < num) {
    if (prev_num == 449) {prev_reason="Reply With"; prev_desc="MS IIS extension";}
    else if (prev_num == 450) {prev_reason="Blocked by Windows Parental Controls"; prev_desc="MS extension";}
    else if (prev_num == 509) {prev_reason="Bandwidth Limit Exceeded"; prev_desc="Apache extension";}
    else {prev_reason="Unknown"; prev_desc="Not used";}
    if (prev_reason=="Unknown") printf ("  /* %s */ %-36s /* %s */\n", prev_num, "{\""prev_reason"\", 0},", prev_desc)
    else printf ("  /* %s */ %-36s /* %s */\n", prev_num, "_MHD_S_STR_W_LEN (\""prev_reason"\"),", prev_desc)
  }
  prev_num = num
  prev_reason = reason
  prev_desc = desc
}
END {
  printf ("  /* %s */ %-36s /* %s */\n};\n", prev_num, "_MHD_S_STR_W_LEN (\""prev_reason"\")", prev_desc)
}' http-status-codes-1.csv > code_insert_statuses.c && \
echo OK && \
rm http-status-codes-1.csv || exit
