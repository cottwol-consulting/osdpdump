---
title: Saleae (.sal) to OSDPDump Converter
---

# Usage #

## Exporting data from Saleae Logic 2 ##

1. open the .sal file
2. select the channel with the non-inverted data (packets start with 0x53)
3. Click ___Analyzers___ on the right side.
4. Click the ___Async Serial___ button.
5. in the menu, select the appropriate channel.
6. In the Analyzers panel on the right click the "..." near (next line down to the right) the "Data" label.
7. Click "Export Table Data"
8. click the "all" radio button under Data.
9. Export the .csv file.

## Running the converter ##

Standard input is the .csv file, standard output is the osdpdump file.
Log messages are sent to standard error.

convert-saleae <saleae_data.csv >saleae_data.osdpdump 2>convert.log

## Building convert-saleae ##

Convert-saleae is in the OSDPDUMP repository on bitbucket.  Do a "make package" from the top level to
create a debian package file.

