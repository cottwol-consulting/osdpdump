# README #

Tools to decode dump and analyze a byte stream of OSDP (IEC 60839-11-5) traffic.
Includes a Saleae-to-osdpdump converter.

### What is this repository for? ###

* Decode OSDP traces

### How to build ###

  make 2>stderr build
  cd package
  make amd64 (or arm64 for Pi)
  dpkg -i (the package)

### Configuration
Assumes Debian-class Linux.  Assumes OSDPCAP format (for now) or serial stream (future.)

* Dependencies
Debian Linux
clang

* How to run

  osdpdump --help

  osdpdump --format 1 --source ../test/sample.osdpcap >sample_osdpdump.log


* Deployment instructions

Capture traces from your EAC, save them in OSDPCAP format.
Use the tool to process the file.  Or, save from a Salea trace and convert it.

