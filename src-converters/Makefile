# Make file for osdpcap coverters, part of osdpdump

# (C)Copyright 2021-2022 Smithee Solutions LLC

PROGS=convert-saleae import-hex
CC=clang
CFLAGS=-c -g -I../include -Wall -Werror
LINK=${CC}
LDFLAGS=-g

all:	${PROGS}

build:	all
	mkdir -p ../opt/tester/bin
	cp ${PROGS} ../opt/tester/bin

test:	all
	echo run tests from the test directory

clean:
	rm -f core *.o ${PROGS} a.out

convert-saleae:	convert-saleae.o Makefile
	${LINK} -o convert-saleae convert-saleae.o ${LDFLAGS}

import-hex:	import-hex.o Makefile
	${LINK} -o import-hex import-hex.o ${LDFLAGS}

convert-saleae.o:	convert-saleae.c
	${CC} ${CFLAGS} convert-saleae.c

import-hex.o:	import-hex.c
	${CC} ${CFLAGS} import-hex.c

