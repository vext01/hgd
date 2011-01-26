CPPFLAGS=`pkg-config --cflags sqlite3`
SQL_LDFLAGS=`pkg-config --libs sqlite3`
CFLAGS+=-Wall -Wextra -g

prefix?=/usr/local
mandir?=${prefix}/man/man1
sbindir?=${prefix}/sbin
bindir?=${prefix}/bin

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

.PHONY: install
install: hgd-playd hgd-netd hgdc
	${INSTALL} hgd-netd ${DESTDIR}${sbindir}
	${INSTALL} hgd-playd ${DESTDIR}${sbindir}
	${INSTALL} hgdc ${DESTDIR}${bindir}
	${INSTALL} man/hgd-netd.1 ${DESTDIR}${mandir}
	${INSTALL} man/hgd-playd.1 ${DESTDIR}${mandir}
	${INSTALL} man/hgdc.1 ${DESTDIR}${mandir}
