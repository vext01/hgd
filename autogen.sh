#!/bin/sh
AUTOMAKE_VERSION=1.9 AUTOCONF_VERSION=2.67 autoreconf -vfi
# XXX figure out why this is present
rm config.h.in~
