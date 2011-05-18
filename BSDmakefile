OS!=uname -s

# we require linking libbsddev on linux
.if ${OS} == Linux
LDFLAGS+=-lbsd
.endif

PY_CONFIG=python2.6-config
PY_LDFLAGS!=${PY_CONFIG} --libs
PY_LDFLAGS+=-L/usr/local/lib
PY_CFLAGS!=${PY_CONFIG} --cflags

.include <Makefile.common>
