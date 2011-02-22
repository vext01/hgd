OS=${shell uname -s}

# we require linking libbsddev on linux
ifeq (${OS},Linux)
LDFLAGS+=-lbsd
endif

include Makefile.common
