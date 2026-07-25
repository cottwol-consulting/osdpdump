---
title: OSDPDUMP - OSDPCAP Decoder
---

An osdpcap decoder and anomaly detector.

# Usage #

osdpdump \<switches\>

:switches

-------------------------------------------------------------------
 Switch               Meaning
 -------              ---------------------------------------------
 --analyze=\[\<n\>\]  set analysis level to n (0-9,default 1)

 --format=\<n\>       set report format.  1=2-line with dump;
                       2=1-line, no dump, 3=, 4=summary only 

  --help              displays switches and usage.

  --pd-address=\<n\>    address (in decimal) of PD address to dump. 

  --source=\<file\>     set dump filename to read.

  --time-format=[0|1]  display timestamp(0) or delta (1)

  --verbosity=\<n\>     set message verbosity.  0=quiet, 3=normal, 9=debug.
-------------------------------------------------------------------

