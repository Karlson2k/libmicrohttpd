#!/bin/bash

#
#   Generate header insert for HTTP headers
#

#   Copyright (c) 2015-2021 Karlson2k (Evgeny Grin) <k2k@yandex.ru>
#
#   Copying and distribution of this file, with or without modification, are
#   permitted in any medium without royalty provided the copyright notice
#   and this notice are preserved. This file is offered as-is, without any
#   warranty.

wget -nv https://www.iana.org/assignments/http-fields/field-names.csv -O perm-headers.csv || exit
echo Generating...
echo '/**
 * @defgroup headers HTTP headers
 * The standard headers found in HTTP requests and responses.
 * See: https://www.iana.org/assignments/http-fields/http-fields.xhtml
 * Registry export date: '"$(date -u +%Y-%m-%d)"'
 * @{
 */

/* Main HTTP headers. */' > header_insert_headers.h && \
gawk -e 'BEGIN {FPAT = "([^,]*)|(\"[^\"]+\")"}
FNR > 1 {
    gsub(/^\[|^"\[|\]"$|\]$/, "", $4)
    field_name = $1
    status = $3
    ref = $4
    comment = $5
    if(ref ~ /^RFC911[0-2]/ && status != "obsoleted")
    {
      gsub(/\]\[/, "; ", ref)
      if(length(status) == 0)
      { status = "No category" }
      else
      { sub(/^./, toupper(substr(status, 1, 1)), status) }
      field_name = gensub(/\*/, "ASTERISK", "g", field_name)
      field_name = gensub(/[^a-zA-Z0-9_]/, "_", "g", field_name)
      printf("/* %-14.14s %s */\n", status ".", ref)
      printf("#define MHD_HTTP_HEADER_%-12s \"%s\"\n", toupper(field_name), $1)
    }
}' perm-headers.csv >> header_insert_headers.h && \
echo '
/* Additional HTTP headers. */' >> header_insert_headers.h && \
gawk -e 'BEGIN {FPAT = "([^,]*)|(\"[^\"]+\")"}
FNR > 1 {
    gsub(/^\[|^"\[|\]"$|\]$/, "", $4)
    field_name = $1
    status = $3
    ref = $4
    comment = $5
    if(ref !~ /^RFC911[0-2]/ && status == "permanent")
    {
      gsub(/\]\[/, "; ", ref)
      sub(/^./, toupper(substr(status, 1, 1)), status)
      field_name = gensub(/\*/, "ASTERISK", "g", field_name)
      field_name = gensub(/[^a-zA-Z0-9_]/, "_", "g", field_name)
      printf("/* %-14.14s %s */\n", status ".", ref)
      printf("#define MHD_HTTP_HEADER_%-12s \"%s\"\n", toupper(field_name), $1)
    }
}' perm-headers.csv >> header_insert_headers.h && \
gawk -e 'BEGIN {FPAT = "([^,]*)|(\"[^\"]+\")"}
FNR > 1 {
    gsub(/^\[|^"\[|\]"$|\]$/, "", $4)
    field_name = $1
    status = $3
    ref = $4
    comment = $5
    if(ref !~ /^RFC911[0-2]/ && status == "provisional")
    {
      gsub(/\]\[/, "; ", ref)
      sub(/^./, toupper(substr(status, 1, 1)), status)
      field_name = gensub(/\*/, "ASTERISK", "g", field_name)
      field_name = gensub(/[^a-zA-Z0-9_]/, "_", "g", field_name)
      printf ("/* %-14.14s %s */\n", status ".", ref)
      printf ("#define MHD_HTTP_HEADER_%-12s \"%s\"\n", toupper(field_name), $1)
    }
}' perm-headers.csv >> header_insert_headers.h && \
gawk -e 'BEGIN {FPAT = "([^,]*)|(\"[^\"]+\")"}
FNR > 1 {
    gsub(/^\[|^"\[|\]"$|\]$/, "", $4)
    field_name = $1
    status = $3
    ref = $4
    comment = $5
    if(ref !~ /^RFC911[0-2]/ && status != "obsoleted" && status != "permanent" && status != "provisional" && status != "deprecated")
    {
      gsub(/\]\[/, "; ", ref)
      status = "No category"
      field_name = gensub(/\*/, "ASTERISK", "g", field_name)
      field_name = gensub(/[^a-zA-Z0-9_]/, "_", "g", field_name)
      printf("/* %-14.14s %s */\n", status ".", ref)
      printf("#define MHD_HTTP_HEADER_%-12s \"%s\"\n", toupper(field_name), $1)
    }
}' perm-headers.csv >> header_insert_headers.h && \
gawk -e 'BEGIN {FPAT = "([^,]*)|(\"[^\"]+\")"}
FNR > 1 {
    gsub(/^\[|^"\[|\]"$|\]$/, "", $4)
    field_name = $1
    status = $3
    ref = $4
    comment = $5
    if(ref !~ /^RFC911[0-2]/ && status == "deprecated")
    {
      gsub(/\]\[/, "; ", ref)
      sub(/^./, toupper(substr(status, 1, 1)), status)
      field_name = gensub(/\*/, "ASTERISK", "g", field_name)
      field_name = gensub(/[^a-zA-Z0-9_]/, "_", "g", field_name)
      printf("/* %-14.14s %s */\n", status ".", ref)
      printf("#define MHD_HTTP_HEADER_%-12s \"%s\"\n", toupper(field_name), $1)
    }
}' perm-headers.csv >> header_insert_headers.h && \
gawk -e 'BEGIN {FPAT = "([^,]*)|(\"[^\"]+\")"}
FNR > 1 {
    gsub(/^\[|^"\[|\]"$|\]$/, "", $4)
    field_name = $1
    status = $3
    ref = $4
    comment = $5
    if (status == "obsoleted")
    {
      gsub(/\]\[/, "; ", ref)
      sub(/^./, toupper(substr(status, 1, 1)), status)
      field_name = gensub(/\*/, "ASTERISK", "g", field_name)
      field_name = gensub(/[^a-zA-Z0-9_]/, "_", "g", field_name)
      printf("/* %-14.14s %s */\n", status ".", ref)
      printf("#define MHD_HTTP_HEADER_%-12s \"%s\"\n", toupper(field_name), $1)
    }
}' perm-headers.csv >> header_insert_headers.h && \
echo OK && \
rm perm-headers.csv || exit
