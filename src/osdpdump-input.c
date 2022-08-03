/*
  osdp-input - input low level processing

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


#include <jansson.h>


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
fprintf(stderr, "DEBUG: osdpdump_accumulate_input: while in-lth %d\n", input_value->length);
      status = osdpdump_packet_accumulate(ctx, input_value, accumulated_message);
fprintf(stderr, "osdpdump_packet_accumulate status was %d. r0 %02X s0 %c\n", status, input_value->raw_bytes [0], input_value->input_string [0]);

      if (status EQUALS ST_OSDPDUMP_PACKET)
        done = 1;

      if (!done)
      {
        if (input_value->length < 1)
          done = 1;
      };
fprintf(stderr, "DEBUG: exit while\n");
    };
  };
  return(status);

} /* osdpdump_accumulate_input */


/*
  osdpdump_read_input - reads various input types

  in principle.  for now, reads osdpcap.
*/


int
  osdpdump_read_input
    (OSDPDUMP_CONTEXT *ctx,
    OSDPDUMP_INPUT *input_value)

{ /* osdpdump_read_input */

  json_t *line_root;
  json_t *value;
  int status;
  char *status_io;
  json_error_t status_json;
  char line [8*1024]; // big enough for 1500 bytes as 2-digit octets with a space


  status = ST_OK;
  switch(ctx->input_source)
  {
  case OSDPDUMP_SOURCE_OSDPCAP:
    input_value->input_string [0] = 0; // init string to empty
    status_io = fgets(line, sizeof(line), ctx->dump_file_handle);
    if (status_io != NULL)
    {
      if (ctx->verbosity > 8)
        fprintf(stderr, "line (%d chars) %s\n", (int)strlen(line), line);
      strcpy(input_value->input_string, line);
      line_root = json_loads(input_value->input_string, 0, &status_json);
    }
    else
    {
      status = ST_OSDPDUMP_FILE_READ_ERROR;
    };
    if (status EQUALS ST_OK)
    {
      value = json_object_get(line_root, "timeSec");
      if (json_is_string(value))
        strcpy(input_value->time_seconds, json_string_value(value));
      else
        status = ST_OSDPDUMP_INPUT_ERROR_1;
      value = json_object_get(line_root, "timeNano");
      if (json_is_string(value))
        strcpy(input_value->time_nanoseconds, json_string_value(value));
      else
        status = ST_OSDPDUMP_INPUT_ERROR_2;

      value = json_object_get(line_root, "data");
      if (json_is_string(value))
        strcpy(input_value->input_string, json_string_value(value));
      else
        status = ST_OSDPDUMP_INPUT_ERROR_3;
      if (status EQUALS ST_OK)
        status = osdpdump_hex_to_raw_bytes(ctx, input_value->input_string, input_value->raw_bytes, &(input_value->length));
    };
    break;
  default:
    status = ST_OSDPDUMP_BAD_INPUT_FORMAT;
    break;
  };
  return(status);

} /* osdpdump_read_input */

