# OSDP Test Tools #

/opt/tester/etc/

## OSDP Directives ##

The osdp-directives directory commands OSDP commands that can be injected into a running
libosdp-conformance instance through the unix socket.  

Example of sending a command to the ACU:

```
  sudo /opt/osdp-conformance/bin/open-osdp-kick ACU <oo_o00_perm-on-abort
```

Example of sending a command to the PD:
```
  sudo /opt/osdp-conformance/bin/open-osdp-kick PD <oo-tamper
```

## Scripts ##

The scripts directory is for testing convience scripts.

## Exercises and Test Data ##

Sample packets used in testing are in test-data.
Also included are some exercises (see exercises directory.)

### Installation of exercises ###

- unpack the tarball in the opsadmin1 home directory. 
- Copy the appropriate file to /opt/osdp-conformance/actions
- use kick to send the appropriate OSDP directive to the (ACU or PD.)

### Exercise: Light-on-Read ###

This exercises is used to make the test ACU send an LED command
upon receipt of an osdp_RAW message.  It does not process the card number,
it always responds.

## Dump Formatting Tools ##

- convert-saleae

- import-hex - reads lines of hex and converts to osdpcap format.


\newpage {}

# Annex Directive Exercises #

# oo-explicit-1440 #

This sends a very large packet to the PD.

The command is (trimmed):

```
{"command":"send-explicit","data":"53006E050462aabb1122334455667 ... 00000000000000000000004234"}
```
