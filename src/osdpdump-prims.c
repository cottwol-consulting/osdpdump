/*
  blah

  (C)2021 Smithee Solutions LLC
*/

#include <stdio.h>
#include <string.h>


#include <osdpdump.h>
char *osdp_strip_to_hexits(char *hex_string);


int
   osdpdump_hex_to_raw_bytes
    (OSDPDUMP_CONTEXT *ctx,
    char *hex_string,
    unsigned char *raw_bytes,
    int *returned_length)

{ /* osdp_dump_to_raw_bytes */

  int done;
  unsigned int octet;
  char octet_string [3];
  char *p;
  char *stripped_hex;
  int status;


  status = ST_OK;
  raw_bytes [0] = 0;
  *returned_length = 0;

  stripped_hex = osdp_strip_to_hexits(hex_string);
  p = stripped_hex;
  done = 0;
  while (!done)
  {
    if (strlen(p) < 2)
      done = 1;
    if (!done)
    {
      octet_string [0] = *p;
      octet_string [1] = *(p+1);
      octet_string [2] = 0;
      sscanf(octet_string, "%x", &octet);
      raw_bytes [*returned_length] = octet;
      (*returned_length) ++;
      p = p+2;
    };
  };
  return(status);

} /* osdp_dump_to_raw_bytes */


char *
  osdp_strip_to_hexits(char *hex_string)

{ /* osdp_strip_to_hexits */

  char *c;
  int done;
  int idx;
  static char temp_string [3*1024];


  idx =  0;
  done = 0;
  c = hex_string;
  while (!done)
  {
    if ((*c >= '0') && (*c <= '9'))
    { temp_string [idx] = *c; idx++; };
    if ((*c >= 'a') && (*c <= 'f'))
    { temp_string [idx] = *c; idx++; };
    if ((*c >= 'A') && (*c <= 'F'))
    { temp_string [idx] = *c; idx++; };
    c++;
    if (strlen(c) < 1)
      done = 1;
  }

  return(temp_string);

} /* osdp_strip_to_hexits */

