#!/bin/sh
# make sure configure was run with coverage enabled...
lcov --directory . --zerocounters
make check
lcov --directory . --capture --output-file app.info
mkdir /tmp/coverage
genhtml -o /tmp/coverage app.info
