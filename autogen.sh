#!/bin/sh
ag_srcdir="${0%/*}" && ag_srcdir="${ag_srcdir}${ag_srcdir:+/}"
"${ag_srcdir}bootstrap" ${1+"$@"}
