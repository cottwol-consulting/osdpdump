/*
  osdpdump-prims - primitives for dump processing

  (C)2021-2022 Smithee Solutions LLC

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

  1. Redistributions of source code must retain the above copyright notice,
  this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

  3. Neither the name of the copyright holder nor the names of its
  contributors may be used to endorse or promote products derived
  from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
  HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
  TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
  OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
  OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <stdio.h>
#include <string.h>


#include <osdpdump.h>


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

  stripped_hex = osdpdump_strip_to_hexits(hex_string);
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


/*
  osdpdump_strip_to_hexits - groom a character string so it's just hexits (0-9,a-f,A-F)
*/

char *
  osdpdump_strip_to_hexits(char *hex_string)

{ /* osdpdump_strip_to_hexits */

  char *c;
  int done;
  int idx;
  static char temp_string [8*1024];


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

} /* osdpdump_strip_to_hexits */

