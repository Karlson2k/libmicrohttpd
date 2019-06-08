#!/bin/bash

#
#   Generate header insert for HTTP headers
#

#   Copyright (c) 2015-2019 Karlson2k (Evgeny Grin) <k2k@yandex.ru>
#
#   Copying and distribution of this file, with or without modification, are
#   permitted in any medium without royalty provided the copyright notice
#   and this notice are preserved. This file is offered as-is, without any
#   warranty.

wget -nv http://www.iana.org/assignments/message-headers/perm-headers.csv -O perm-headers.csv || exit
echo Generating...
echo '/**
 * @defgroup headers HTTP headers
 * These are the standard headers found in HTTP requests and responses.
 * See: http://www.iana.org/assignments/message-headers/message-headers.xml
 * Registry export date: '$(date -u +%Y-%m-%d)'
 * @{
 */

/* Main HTTP headers. */' > header_insert_headers.h && \
gawk -e 'BEGIN {FPAT = "([^,]*)|(\"[^\"]+\")"}
{
  if ($3 == "http") {
    gsub(/^\[|^"\[|\]"$|\]$/, "", $5)
    rfc_num = substr($5, 4, 4)
    if (rfc_num >= 7230 && rfc_num <= 7235)
    {
      gsub(/\]\[/, "; ", $5)
      if (length($4) == 0) 
      { $4 = "No category" }
      else
      { sub(/^./, toupper(substr($4, 1, 1)), $4) }
      print "/* " sprintf("%-14.14s", $4 ".") " " $5 " */"
      print "#define MHD_HTTP_HEADER_" toupper(gensub(/-/, "_", "g", $1)) " \""$1"\""
    }
  }
}' perm-headers.csv >> header_insert_headers.h && \
echo '
/* Additional HTTP headers. */' >> header_insert_headers.h && \
gawk -e 'BEGIN {FPAT = "([^,]*)|(\"[^\"]+\")"}
{
  if ($3 == "http") {
    gsub(/^\[|^"\[|\]"$|\]$/, "", $5)
    rfc_num = substr($5, 4, 4)
    if (!(rfc_num >= 7230 && rfc_num <= 7235))
    {
      gsub(/\]\[/, "; ", $5)
      if (length($4) == 0) 
      { $4 = "No category" }
      else
      { sub(/^./, toupper(substr($4, 1, 1)), $4) }
      print "/* " sprintf("%-14.14s", $4 ".") " " $5 " */"
      print "#define MHD_HTTP_HEADER_" toupper(gensub(/-/, "_", "g", $1)) " \""$1"\""
    }
  }
}' perm-headers.csv >> header_insert_headers.h && \
echo OK && \
rm perm-headers.csv || exit
