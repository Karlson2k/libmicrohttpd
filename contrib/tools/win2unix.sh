#!/bin/sh
for i in `find . -name "*" -xtype f`; do echo "Messing with $i";cat $i |tr -d \\r >.1; mv .1 $i ; done
