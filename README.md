# README #

Tool to decode dump and analyze a byte stream of OSDP (IEC 60839-11-5) traffic.

This README would normally document whatever steps are necessary to get your application up and running.

### What is this repository for? ###

* Decode OSDP traces
* Version 0.0.0-1

### How do I get set up? ###

* Summary of set up

clone repo
make
make package
install debian package

* Configuration
Assumes debian-class linux.  Assumes OSDPCAP format or serial stream.

* Dependencies
Debian Linux
CLANG

* How to run tests

Build the tool, use it to decode sample.osdpcap in the test directory.

* Deployment instructions

Capture traces from your EAC, save them in OSDPCAP.
Use the tool to process the file.

* Writing tests
* Code review
* Other guidelines

### Who do I talk to? ###

* Repo owner or admin
* Other community or team contact
