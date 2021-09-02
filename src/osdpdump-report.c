/*
  osdpdump-report.c - reporting functions for osdpdump

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
#include <osdpdump-decoding.h>


int
  osdpdump_print
    (OSDPDUMP_CONTEXT *ctx)

{ /* osdpdump_print */

  int i;
  OSDPDUMP_WORKING_PACKET *packet;


  packet = &(ctx->osdp_pdu);
  switch(ctx->print_format)
  {
//comments are 3  case OSDPDUMP_FMT_2LINE:
  case OSDPDUMP_FMT_2LINE:
    osdpdump_print_one_line(ctx, packet);
    if (strlen(ctx->output_text) > 0)
    {
      fprintf(stdout, "%s", ctx->output_text);
      ctx->output_text [0] = 0;
    };
    fprintf(stdout, "P:%06d Dump:", ctx->current_packet_number);
    for (i=0; i<packet->octet_length; i++)
      fprintf(stdout, " %02x", packet->octets [i]);
    fprintf(stdout, "\n");
    break;
  case OSDPDUMP_FMT_1LINE:
    osdpdump_print_one_line(ctx, packet);
// yeah shouldn't do this here make options richer
    if (strlen(ctx->output_text) > 0)
    {
      fprintf(stdout, "%s", ctx->output_text);
      ctx->output_text [0] = 0;
    };
    break;
  default:
    osdpdump_print_one_line(ctx, packet);
    break;
  };
  return(0);

} /* osdpdump_print */


/*
  osdpdump_print_one_line - print a one-line summary of an OSDP packet.  hopefully greppable.

  Input:
    context
    the packet we're working on (assumed sane)

  Output:
    sends it's output to stdout

  ToDo:
    update to output to a buffer and handle the io elsewhere.
*/

void
  osdpdump_print_one_line
    (OSDPDUMP_CONTEXT *ctx,
    OSDPDUMP_WORKING_PACKET *packet)

{ /* osdpdump_print_one_line */

  char otmp [8*1024]; //maxstring large
  char otmp2 [1024]; //maxstring
  int payload_offset;


  payload_offset = 6; // before secure channel

  fprintf(stdout, "P:%06d ", ctx->current_packet_number);
  fprintf(stdout, "%s ", osdpdump_command_string(ctx, packet->command_response));
  fprintf(stdout, " A %2d.", packet->address);
  fprintf(stdout, " S%d", packet->sequence);
  if (packet->completion_status & OSDPDUMP_COMPLETION_SCB)
    fprintf(stdout, " SCS %2x", ctx->osdp_pdu.octets [1+1+2+1+1]);
  if (packet->completion_status & OSDPDUMP_COMPLETION_SCBK_D)
    fprintf(stdout, " (D)");

  // command-specific one-liners

  otmp [0] = 0;
  switch(packet->command_response)
  {
  case OSDP_IEC_FTSTAT:
    if (!(packet->completion_status & OSDPDUMP_COMPLETION_SCB))
    {
      sprintf(otmp,
" FtAction %x FtDelay-LSB %02x FtDelay-MSB %02x FtStatusDetail-LSB %02x FtStatusDetail-MSB %02x FtUpdateMsgMax-LSB %2x FtUpdateMsgMax-MSB %2x",
        packet->octets [payload_offset + 0],
        packet->octets [payload_offset + 1], packet->octets [payload_offset + 2],
        packet->octets [payload_offset + 3], packet->octets [payload_offset + 4],
        packet->octets [payload_offset + 5], packet->octets [payload_offset + 6]);
    };
    break;
  case OSDP_IEC_KEYPAD:
    {
      sprintf(otmp,
" Rdr %2x %d. digits first digit %02x",
        packet->octets [payload_offset + 0],
        packet->octets [payload_offset + 1],
        packet->octets [payload_offset + 2]);
    };
    break;
  case OSDP_IEC_NAK:
    sprintf(otmp, " Reason %02x", packet->octets [payload_offset + 0]);
    if (packet->payload_length > 1)
    {
      sprintf(otmp2, " Detail0 %02x", packet->octets [payload_offset + 1]);
      strcat(otmp, otmp2);
    };
    break;
  default:
    if (ctx->verbosity > 3)
      fprintf(stdout, "Warning: unknown command (%x) in osdpdump_print_one_line\n", packet->command_response);
    break;
  };

  // print what we've decoded

  if (strlen(otmp) > 0)
    fprintf(stdout, "%s", otmp);

  fprintf(stdout, " CRC %02x%02x", packet->packet_check [0], packet->packet_check [1]);
  fprintf(stdout, "\n");

} /* osdpdump_print_one_line */


/*
  osdpdump_summary - create the summary text

  Output:
    fills in ctx->output_text e.g. so caller can print it.
*/
int 
  osdpdump_summary
    (OSDPDUMP_CONTEXT *ctx)

{ /* osdpdump_summary */

  int idx;
  char otmp [1024]; //maxstring


  printf("\nOSDPDUMP ACTIVITY SUMMARY\n");
  printf("=========================\n");
  sprintf(otmp, "%d. packets\n", ctx->detected_packets); strcat(ctx->output_text, otmp);
  sprintf(otmp, "Detected:\n"); strcat(ctx->output_text, otmp);
  for (idx=0; idx<255; idx++)
  {
    if (ctx->detected_commands [idx] > 0)
    {
      sprintf(otmp,
" %2x(%s) %d\n", idx, osdpdump_command_string(ctx, idx), ctx->detected_commands [idx]);
      strcat(ctx->output_text, otmp);
    };
  };
  strcat(ctx->output_text, "\n");

  sprintf(otmp, "Active PD's:"); strcat(ctx->output_text, otmp);
  for (idx=0; idx<OSDPDUMP_PD_MAX; idx++)
  {
    if (ctx->pd_ctx [idx].state EQUALS OSDPDUMP_PD_PRESENT)
    {
      sprintf(otmp, " %3d.(0x%02x)", idx, idx); strcat(ctx->output_text, otmp);
    };
  };
  sprintf(otmp, "%s", "\n"); strcat(ctx->output_text, otmp);
  sprintf(otmp, "%6d. octets dropped.\n", ctx->dropped_octets); strcat(ctx->output_text, otmp);
  return(0);

} /* osdpdump_summary */

