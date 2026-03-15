/*
  osdp-input - input low level processing

  (C)2021-2026 Smithee Solutions LLC

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
#include <osdpdump-decoding.h>


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


/*
  osdpdump_packet_accumulate - actually put the input in the packet
*/

int osdpdump_packet_accumulate
  (OSDPDUMP_CONTEXT *ctx,
  OSDPDUMP_INPUT *input_bytes,
  OSDPDUMP_INPUT *pkt)

{ /* osdpdump_packet_accumulate */

  unsigned char current_byte;
  int drop_octets;
  OSDPDUMP_WORKING_PACKET *packet;
  unsigned int pdu_length;
  int status;
  unsigned char temp_bytes [8*2048]; //max


  // assume we used it or trashed it and need more.

if (ctx->verbosity > 9)
{
  int i;
  fprintf(stderr, "DEBUG: input bytes (%d.)", input_bytes->length);
  for(i=0; i<input_bytes->length; i++)
    fprintf(stderr, " %02X", input_bytes->raw_bytes[i]);
  fprintf(stderr, "\n");
}
    memcpy(temp_bytes, input_bytes->raw_bytes+1, input_bytes->length);
  status = ST_OSDPDUMP_NEED_MORE_DATA;
  drop_octets = 0;
  packet = &(ctx->osdp_pdu);
  pdu_length = -1; // bogus so it doesn't match

  if (input_bytes->length > 0)
  {
    // take first byte
    input_bytes->length --;
    current_byte = input_bytes->raw_bytes [0];
    memset(temp_bytes, 0, sizeof(temp_bytes));
    memcpy(temp_bytes, input_bytes->raw_bytes+1, input_bytes->length);
    memcpy(input_bytes->raw_bytes, temp_bytes, input_bytes->length);
    input_bytes->raw_bytes [input_bytes->length] = 0x00;

    // depending on how much we have processing differs.

    switch(packet->octet_length)
    {
    case 0:
      // we're looking for the SOM
      if (current_byte EQUALS OSDP_IEC_SOM)
      {
        if (ctx->verbosity > 9)
          fprintf(stderr, "DEBUG: SOM detected? lth now %d.\n", packet->octet_length);
        packet->octets [packet->octet_length] = current_byte;
        packet->octet_length++;
        packet->completion_status = packet->completion_status | OSDPDUMP_COMPLETION_SOM;
        status = ST_OSDPDUMP_NEED_MORE_DATA;
      }
      else
      {
        drop_octets = 1;
      };
      break;
    case 1:
      // looking for address/command-response marker
      packet->octets [packet->octet_length] = current_byte;
      packet->octet_length++;
      status = ST_OSDPDUMP_NEED_MORE_DATA;
      break;
    case 2:
      // looking for first byte of length
      packet->octets [packet->octet_length] = current_byte;
      packet->octet_length++;
      status = ST_OSDPDUMP_NEED_MORE_DATA;
      break;
    case 3:
      // looking for second byte of length
      packet->octets [packet->octet_length] = current_byte;
      packet->octet_length++;
      status = ST_OSDPDUMP_NEED_MORE_DATA;
      pdu_length = (packet->octets [3] << 8) + packet->octets [2];
      if (pdu_length <= OSDPDUMP_PDU_MAX)
      {
        if (ctx->verbosity > 3)
          fprintf(stderr, "DEBUG: have length (0x%x)\n", pdu_length);
        status = ST_OSDPDUMP_NEED_MORE_DATA;
      }
      else
      {
        char tstring [1024];

        // input was bigger than a packet.  drop it and note it.

        sprintf(tstring, "  - Header Length %d. too large (>%d) - %d. bytes dropped.\n", pdu_length, OSDPDUMP_PDU_MAX, packet->octet_length);
        strcat(ctx->output_text, tstring);
        ctx->note_count ++;

        ctx->dropped_octets = ctx->dropped_octets + packet->octet_length;
        packet->octet_length = 0;
        status = ST_OSDPDUMP_NEED_MORE_DATA;
      };
      break;

    // for all other lengths just accept it for now.

    default:
      pdu_length = (packet->octets [3] << 8) + packet->octets [2];
      if (packet->octet_length < pdu_length)
      {
        packet->octets [packet->octet_length] = current_byte;
        packet->octet_length++;
        status = ST_OSDPDUMP_NEED_MORE_DATA;
      }; 
      break;
    };
    if (drop_octets)
      ctx->dropped_octets ++;
    if (packet->octet_length EQUALS pdu_length)
      status = ST_OSDPDUMP_PACKET;
  };
  if (ctx->verbosity > 3)
  {
    if ((ctx->verbosity > 9) && (pdu_length != -1))
      fprintf(stderr, "DEBUG: pktlth %X otxt %s\n", pdu_length, ctx->output_text);
  };
  return(status);

} /* osdpdump_packet_accumulate */


/*
  osdpdump_read_input - reads various input types

  in principle.  for now, reads osdpcap.
*/


int
  osdpdump_read_input
    (OSDPDUMP_CONTEXT *ctx,
    OSDPDUMP_INPUT *input_value)

{ /* osdpdump_read_input */

  extern char last_input_line [];
  char line [OSDPDUMP_STRING]; // big enough for 1500 bytes as 2-digit octets with a space
  json_t *line_root;
  json_t *value;
  int status;
  char *status_io;
  json_error_t status_json;
  char tstring [1024];


  status = ST_OK;
  switch(ctx->input_source)
  {
  case OSDPDUMP_SOURCE_OSDPCAP:
    input_value->input_string [0] = 0; // init string to empty
    memset(line, 0, sizeof(line));
    status_io = fgets(line, sizeof(line), ctx->dump_file_handle);
    if (status_io != NULL)
    {
      strcpy(last_input_line, line);
      if (ctx->verbosity > 9)
        fprintf(stderr, "DEBUG: l1 %d l2 %d l3 %u\n", OSDPDUMP_STRING, OSDPDUMP_PDU_MAX*3, (unsigned)strlen(line));
      if (ctx->verbosity > 8)
        fprintf(stderr, "Input line was %d. characters: %s", (int)strlen(line), line);
      if (status EQUALS ST_OK)
      {
        strcpy(input_value->input_string, line);
        line_root = json_loads(input_value->input_string, 0, &status_json);
      };
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
      {
        if (strlen(json_string_value(value)) > OSDPDUMP_INPUT_STRING_MAX)
        {
          // this is too long.  bail.
          sprintf(tstring, "Data too long (%d. char, expected %d) - aborting.\n", (int)strlen(line), OSDPDUMP_PDU_MAX*3);
          strcat(ctx->output_text, tstring);
          ctx->note_count ++;
          status = ST_OSDPDUMP_LINE_TOO_LONG;
        };
        if (status EQUALS ST_OK)
          strcpy(input_value->input_string, json_string_value(value));
      }
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

