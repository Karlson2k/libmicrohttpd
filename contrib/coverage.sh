#!/bin/sh
# make sure configure was run with coverage enabled...
lcov --directory . --zerocounters
make check
rm `find * -name "*_test.gc??"`  `find src/testcurl -name "*.gc??"` `find src/testzzuf -name "*.gc??"` `find src/examples -name "*.gc??"`
for n in `find * -name "*.gc*" | grep libs`
do
  cd `dirname $n`
  mv `basename $n` ..
  cd -
done
lcov --directory . --capture --output-file app.info
mkdir /tmp/coverage
genhtml -o /tmp/coverage app.info
