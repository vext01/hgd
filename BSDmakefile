OS!=uname -s

# == is not portable
# we require linking libbsddev on linux
.if ${OS} == Linux
LDFLAGS+=-lbsd
.endif

PY_CONFIG=python-config
PY_LDFLAGS!=${PY_CONFIG} --libs
PY_CFLAGS!=${PY_CONFIG} --cflags

.include <Makefile.common>
