OS=${shell uname -s}

# ifeq is not portable
# we require linking libbsddev on linux
ifeq (${OS},Linux)
LDFLAGS+=-lbsd
endif

PY_CONFIG=python-config
PY_LDFLAGS=${shell ${PY_CONFIG} --libs}
PY_CFLAGS=${shell ${PY_CONFIG} --cflags}

include Makefile.common
