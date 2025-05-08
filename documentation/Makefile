# make file for documentation for osdpdump

# (C)Copyright 2021-2024 Smithee Solutions LLC

DOC-PDF=convert-saleae.pdf osdpdump.pdf release-notice.pdf osdp-test-tools.pdf

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

osdp-test-tools.pdf:
	pandoc --toc -o osdp-test-tools.pdf osdp-test-tools.md

clean:
	rm -f ${DOC-PDF}

