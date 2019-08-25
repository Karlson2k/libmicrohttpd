#!/usr/bin/env bash

set -eu

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

if ! uncrustify --version >/dev/null; then
  echo "you need to install uncrustify for indentation"
  exit 1
fi

find "$DIR/../src" \( -name "*.cpp" -o -name "*.c" -o -name "*.h" \) \
  -exec uncrustify -c "$DIR/uncrustify.cfg" --replace --no-backup {} + \
  || true
