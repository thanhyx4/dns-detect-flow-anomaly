#!/bin/sh

#autoscan
#mv configure.scan configure.ac
autoheader
#libtoolize
aclocal -I m4
automake --add-missing --copy
autoconf
