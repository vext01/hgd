CFLAGS=`pkg-config --cflags sqlite3`
LDFLAGS=`pkg-config --libs sqlite3`

.PHONY: all
all: hgd-playd

.PHONY: clean
clean:
	-rm hgd-playd common.o

common.o: common.c hgd.h

hgd-playd: common.o hgd-playd.c hgd.h
	${CC} ${CFLAGS} ${LDFLAGS} -g -o hgd-playd common.o hgd-playd.c

