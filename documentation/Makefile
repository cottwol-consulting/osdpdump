# make file for documentation for osdpdump

# (C)Copyright 2021-2024 Smithee Solutions LLC

DOC-PDF=convert-saleae.pdf osdpdump.pdf release-notice.pdf

all:	$(DOC-PDF)

build:	all
	mkdir -p ../opt/tester/etc
	cp ${DOC-PDF} ../opt/tester/etc

convert-saleae.pdf:
	pandoc --toc -o convert-saleae.pdf convert-saleae.md

osdpdump.pdf:
	pandoc --toc -o osdpdump.pdf osdpdump.md

release-notice.pdf:
	pandoc --toc -o release-notice.pdf release-notice.md

clean:
	rm -f ${DOC-PDF}

