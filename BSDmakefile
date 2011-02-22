OS!=uname -s

# we require linking libbsddev on linux
.if ${OS} == Linux
LDFLAGS+=-lbsd
.endif

.include <Makefile.common>
