#!/bin/sh

# This file was added for compatibility with some automated build systems.
# It is recommended to use 'bootstrap' directly instead.

ag_srcdir="${0%/*}" && ag_srcdir="${ag_srcdir}${ag_srcdir:+/}"
"${ag_srcdir}./bootstrap" ${1+"$@"}
