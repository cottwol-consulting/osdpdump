# Make file for osdpdump

# (C)Copyright 2021 Smithee Solutions LLC

PROGS=osdpdump convert-saleae
CC=clang
CFLAGS=-c -g -I../include -Wall -Werror
LINK=clang
LDFLAGS=-g -ljansson

all:	${PROGS}

build:	all
	mkdir -p ../opt/tester/bin
	cp ${PROGS} ../opt/tester/bin

test:	all
	echo run tests from the test directory

clean:
	rm -f core *.o ${PROGS}

convert-saleae:	convert-saleae.o Makefile
	${LINK} -o convert-saleae convert-saleae.o ${LDFLAGS}

osdpdump:	osdpdump.o osdpdump-decoding.o osdpdump-input.o osdpdump-prims.o osdpdump-report.o osdp-crc.o Makefile
	${LINK} -o osdpdump osdpdump.o osdpdump-decoding.o osdpdump-input.o osdpdump-prims.o osdpdump-report.o osdp-crc.o ${LDFLAGS}

convert-saleae.o:	convert-saleae.c
	${CC} ${CFLAGS} convert-saleae.c

osdpdump.o:	osdpdump.c ../include/osdpdump.h ../include/osdpdump-decoding.h
	${CC} ${CFLAGS} osdpdump.c

osdpdump-decoding.o:	osdpdump-decoding.c ../include/osdpdump.h ../include/osdpdump-decoding.h
	${CC} ${CFLAGS} osdpdump-decoding.c

osdpdump-input.o:	osdpdump-input.c ../include/osdpdump.h ../include/osdpdump-decoding.h
	${CC} ${CFLAGS} osdpdump-input.c

osdpdump-prims.o:	osdpdump-prims.c ../include/osdpdump.h
	${CC} ${CFLAGS} osdpdump-prims.c

osdpdump-report.o:	osdpdump-report.c ../include/osdpdump.h ../include/osdpdump-decoding.h
	${CC} ${CFLAGS} osdpdump-report.c

osdp-crc.o:	osdp-crc.c
	${CC} ${CFLAGS} osdp-crc.c

