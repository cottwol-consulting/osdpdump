/*
  osdpdump-decode-ext-id - decode extended id structure

  (C)2025-2026 Smithee Solutions LLC

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
#include <osdpdump-decoding.h>


int osdpdump_decode_extended_id
    (OSDPDUMP_CONTEXT *ctx,
    unsigned char *ext_id_response,
    int length)

{ /* osdpdump_decode_extended_id */

  int detlth;
  int done;
  unsigned char *p;
  int remaining;
  int status;
  char tmp_string [2048];


  status = 0;
  done = 0;
  p = ext_id_response;
  remaining = length;

  while (!done)
  {
    detlth = *(p+2)*256 + *(p+1);
    memset(tmp_string, 0, sizeof(tmp_string));
    switch(*p)
    {
    default:
      fprintf(stdout, "Unknown tag (%02X)\n", *p);
      status = -1;
      break;
    case OSDP_EXTID_TAG_FW_VERSION:
      memcpy(tmp_string, p+3, detlth);
      fprintf(stdout, "      Firmware: %s\n", tmp_string);
      p = p + 3 + detlth;
      remaining = remaining - 3 - detlth;
      break;
    case OSDP_EXTID_TAG_HARDWARE:
      memcpy(tmp_string, p+3, detlth);
      fprintf(stdout, "      Hardware: %s\n", tmp_string);
      p = p + 3 + detlth;
      remaining = remaining - 3 - detlth;
      break;
    case OSDP_EXTID_TAG_MFG:
      memcpy(tmp_string, p+3, detlth);
      fprintf(stdout, "  Manufacturer: %s\n", tmp_string);
      p = p + 3 + detlth;
      remaining = remaining - 3 - detlth;
      break;
    case OSDP_EXTID_TAG_PRODUCT:
      memcpy(tmp_string, p+3, detlth);
      fprintf(stdout, "       Product: %s\n", tmp_string);
      p = p + 3 + detlth;
      remaining = remaining - 3 - detlth;
      break;
    case OSDP_EXTID_TAG_SERIAL:
      memcpy(tmp_string, p+3, detlth);
      fprintf(stdout, "        Serial: %s\n", tmp_string);
      p = p + 3 + detlth;
      remaining = remaining - 3 - detlth;
      break;
    case OSDP_EXTID_TAG_URL:
      memcpy(tmp_string, p+3, detlth);
      fprintf(stdout, "           URL: %s\n", tmp_string);
      p = p + 3 + detlth;
      remaining = remaining - 3 - detlth;
      break;
    };
    if (status != 0)
      done = 1;
    if (remaining < 1)
      done = 1;
  };
  return(status);

}

