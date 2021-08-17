# Make file for osdpdump

# (C)Copyright 2021 Smithee Solutions LLC

PROGS=osdpdump
CC=clang
CFLAGS=-c -g -I../include -Wall -Werror
LINK=clang
LDFLAGS=-g -ljansson

all:	${PROGS}

test:	all
	echo run tests from the test directory

clean:
	rm -f core *.o ${PROGS}

osdpdump:	osdpdump.o osdpdump-prims.o Makefile
	${LINK} -o osdpdump osdpdump.o osdpdump-prims.o ${LDFLAGS}

osdpdump.o:	osdpdump.c ../include/osdpdump.h
	${CC} ${CFLAGS} osdpdump.c

osdpdump-prims.o:	osdpdump-prims.c ../include/osdpdump.h
	${CC} ${CFLAGS} osdpdump-prims.c

