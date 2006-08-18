#!/bin/sh



echo -ne "Content-type: text/html\r\n\r\n"

echo -e "<HTML>\n"
echo -e "<BODY>\n"

echo -e "THis is a simple cgi file\n"
echo -e "$QUERY_STRING"
echo -e "</body>"
echo -e "</html>"

