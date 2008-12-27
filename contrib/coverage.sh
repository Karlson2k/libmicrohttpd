#!/bin/sh
# make sure configure was run with coverage enabled...
lcov --directory . --zerocounters
make check
for n in `find * -name "*.gc*" | grep libs`
do
  cd `dirname $n`
  mv `basename $n` ..
  cd -
done
lcov --directory . --capture --output-file app.info
mkdir /tmp/coverage
genhtml -o /tmp/coverage app.info
