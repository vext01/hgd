CPPFLAGS=`pkg-config --cflags sqlite3`
SQL_LDFLAGS=`pkg-config --libs sqlite3`
CFLAGS=-Wall -Wextra -g

.PHONY: all
all: hgd-playd hgd-netd hgdc

.PHONY: clean
clean:
	-rm hgd-playd hgd-netd hgdc common.o db.o

common.o: common.c hgd.h
db.o: db.c hgd.h

hgd-playd: common.o db.o hgd-playd.c hgd.h
	${CC} ${CPPFLAGS} ${CFLAGS} ${SQL_LDFLAGS} ${LDFLAGS} \
		-o hgd-playd db.o common.o hgd-playd.c

hgd-netd: common.o hgd-netd.c hgd.h db.o
	${CC} ${CPPFLAGS} ${CFLAGS} ${SQL_LDFLAGS} ${LDFLAGS} \
		-o hgd-netd common.o db.o hgd-netd.c

hgdc: common.o hgdc.c hgd.h
	${CC} ${CPPFLAGS} ${CFLAGS} ${LDFLAGS} -o hgdc common.o hgdc.c
