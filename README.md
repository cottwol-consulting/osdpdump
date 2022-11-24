# README #

Tools to decode dump and analyze a byte stream of OSDP (IEC 60839-11-5) traffic.
Includes a Saleae-to-osdpdump converter.

### What is this repository for? ###

* Decode OSDP traces

### How to build ###

  make 2>stderr package

Then, install the package with dpkg:

  dpkg -i (the package)

### Configuration
Assumes Debian-class Linux.  Assumes OSDPCAP format (for now) or serial stream (future.)

* Dependencies
Debian Linux
clang
salea export format

* How to run

for osdpdump help:

  osdpdump --help

to convert an osdpcap file to a log:

  osdpdump --format 1 --source ../test/sample.osdpcap >sample_osdpdump.log

to convert a saleae trace:

1. from the digital channel do an export to csv format
2. use the converter (and then decode it.)

  convert-saleae <saleae-data-export.csv >saleae.osdpcap
  osdpdump --format 1 --source saleae.osdpcap

* Deployment instructions

Capture traces from your EAC, save them in OSDPCAP format.
Use the tool to process the file.  Or, save from a Salea trace and convert it.

