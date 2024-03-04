# make file for documentation for osdpdump

# (C)Copyright 2021-2024 Smithee Solutions LLC

DOC-PDF=osdpdump.pdf osdpdump_release-notice.pdf

all:	$(DOC-PDF)

build:	all
	mkdir -p ../opt/tester/etc
	cp ${DOC-PDF} ../opt/tester/etc

osdpdump.pdf:
	pandoc --toc -o osdpdump.pdf osdpdump.md

osdpdump_release-notice.pdf:
	pandoc --toc -o osdpdump_release-notice.pdf osdpdump_release-notice.md

clean:
	rm -f ${DOC-PDF}

