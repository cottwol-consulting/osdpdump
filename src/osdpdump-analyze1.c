/*
  osdpdump-analyze1 - analysis routines for OSDPDUMP.

  don't assume they were elegantly integrated.  some of this is bolted into the print routines.

  (C)2021-2023 Smithee Solutions LLC

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
#include <memory.h>
#include <stdlib.h>
#include <errno.h>


#include <osdpdump.h>


unsigned short int *mac_histo;


int
  osdpdump_mac_stats
    (OSDPDUMP_CONTEXT *ctx,
    unsigned char *mac)

{ /* osdpdump_mac_stats */

  unsigned short int mac_as_value;
  int status;


  status = ST_OK;
  if ((!mac_histo) && (ctx->print_format EQUALS OSDPDUMP_FMT_MAC))
  {
    ctx->histo_size = 0x100000000 * sizeof(unsigned short int);
fprintf(stderr, "DEBUG: about to malloc MAC histogram (size %ld.)\n", ctx->histo_size);
    mac_histo = malloc(ctx->histo_size);
fprintf(stderr, "DEBUG: mac_histo allocation %lX errno %d.\n", (unsigned long int)mac_histo, errno);
if (errno)
  exit(-1);
    memset(mac_histo, 0, ctx->histo_size);
  };
  memcpy(&mac_as_value, mac, 4);
  mac_histo [mac_as_value]++;

  return(status);

} /* osdpdump_mac_stats */


int osdpdump_mac_stats_init
  (OSDPDUMP_CONTEXT *ctx)

{ /* osdpdump_mac_stats_init */

  mac_histo = 0;
  ctx->histo_size = 0;

  return(ST_OK);
}

