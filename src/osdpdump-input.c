/*
  osdp-input - input low level processing

  (C)2021 Smithee Solutions LLC

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


unsigned char
  checksum
    (unsigned char *msg,
    int length)

{ /* checksum */

  unsigned char checksum;
  int i;
  int whole_checksum;


  whole_checksum = 0;
  for (i=0; i<length; i++)
  {
    whole_checksum = whole_checksum + msg [i];
    checksum = ~(0xff & whole_checksum)+1;
  };
  return (checksum);

} /* checksum */


/*
  osdpdump_accumulate_input - use data received to build up a packet

  Input:
    raw value

  Output:
    updates accumulated packet in context
*/
int
  osdpdump_accumulate_input
    (OSDPDUMP_CONTEXT *ctx,
    OSDPDUMP_INPUT *input_value)

{ /* osdpdump_accumulate_input */

  OSDPDUMP_INPUT *accumulated_message;
  int done;
  int status;


  status = ST_OSDPDUMP_NEED_MORE_DATA;
  accumulated_message = &(ctx->accumulated_message);
  done = 1;

  // if there's something there, try to use it.

  if (input_value->length > 0)
    done = 0;
  {
    while (!done)
    {
      status = osdpdump_packet_accumulate(ctx, input_value, accumulated_message);

      if (status EQUALS ST_OSDPDUMP_PACKET)
        done = 1;

      if (!done)
      {
        if (input_value->length < 1)
          done = 1;
      };
    };
  };
  return(status);

} /* osdpdump_accumulate_input */

