# Make file for osdpdump

# (C)Copyright 2021-2023 Smithee Solutions LLC

PROGS=osdpdump
CC=clang
CFLAGS=-c -g -I../include -Wall -Werror
LINK=${CC}
LDFLAGS=-g -ljansson

all:	${PROGS}

build:	all
	mkdir -p ../opt/tester/bin
	cp ${PROGS} ../opt/tester/bin

test:	all
	echo run tests from the test directory

clean:
	rm -f core *.o ${PROGS}

osdpdump:	osdpdump.o osdpdump-analyze1.o osdpdump-decoding.o osdpdump-input.o \
	osdpdump-prims.o osdpdump-report.o osdpdump-vendor-lookup.o osdp-crc.o Makefile
	${LINK} -o osdpdump osdpdump.o osdpdump-analyze1.o osdpdump-decoding.o \
	  osdpdump-input.o osdpdump-prims.o osdpdump-report.o osdpdump-vendor-lookup.o osdp-crc.o ${LDFLAGS}

osdpdump.o:	osdpdump.c ../include/osdpdump.h ../include/osdpdump-decoding.h
	${CC} ${CFLAGS} osdpdump.c

osdpdump-analyze1.o:	osdpdump-analyze1.c
	${CC} ${CFLAGS} osdpdump-analyze1.c

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

osdp-vendor-lookup.o:	osdp-vendor-lookup.c
	${CC} ${CFLAGS} osdp-vendor-lookup.c

