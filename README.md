# README #

Tools to decode dump and analyze a byte stream of OSDP (IEC 60839-11-5) traffic.
Includes a Saleae-to-osdpdump converter.

### What is this repository for? ###

* Decode OSDP traces
* Version 0.1.0-2

### How do I get set up? ###

* run make, copy 'osdpdump' and 'convert-salea' to /usr/local/share/bin.
* package coming soon.

### Configuration
Assumes Debian-class Linux.  Assumes OSDPCAP format (for now) or serial stream (future.)

* Dependencies
Debian Linux
CLANG

* How to run tests

Build the tool, use it to decode sample.osdpcap in the test directory.  Command line is:

osdpdump --format 1 --source ../test/sample.osdpcap >sample_osdpdump.log

* Deployment instructions

Capture traces from your EAC, save them in OSDPCAP.
Use the tool to process the file.

* Writing tests
* Code review
* Other guidelines

### Who do I talk to? ###

* Repo owner or admin
* Other community or team contact
