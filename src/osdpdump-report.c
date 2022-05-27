/*
  osdpdump-report.c - reporting functions for osdpdump

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
#include <osdpdump-decoding.h>
extern OSDPDUMP_TRACKING osdpdump_message_tracking [256];


/*
  osdpdump_print - dump a PDU as text line(s)

  Inputs:
    context
    context->print_format dictates text output

  OSDPDUMP_FMT_1LINE
  OSDPDUMP_FMT_2LINE
  OSDPDUMP_FMT_ANNOTATED
  OSDPDUMP_FMT_SUMMARY
*/
int
  osdpdump_print
    (OSDPDUMP_CONTEXT *ctx)

{ /* osdpdump_print */

  int i;
  OSDPDUMP_WORKING_PACKET *packet;


  packet = &(ctx->osdp_pdu);
  switch(ctx->print_format)
  {
  case OSDPDUMP_FMT_ANNOTATED:
    osdpdump_print_one_line(ctx, packet);
    if (strlen(ctx->output_text) > 0)
    {
      ctx->note_count ++;
      fprintf(stdout, "NOTE: %s", ctx->output_text);
      ctx->output_text [0] = 0;
    };
    osdpdump_print_hex(ctx);
    osdpdump_print_annotation(ctx, packet);
    break;

  case OSDPDUMP_FMT_SUMMARY:
    break;

  case OSDPDUMP_FMT_1LINE:
    osdpdump_print_one_line(ctx, packet);
    break;

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
  default:
    osdpdump_print_one_line(ctx, packet);
    break;
  };
  return(0);

} /* osdpdump_print */


void osdpdump_print_annotation
  (OSDPDUMP_CONTEXT *ctx,
  OSDPDUMP_WORKING_PACKET *packet)
{
  int count;
  int payload_offset = 6;


  switch(packet->command_response)
  {
  case OSDP_IEC_BIOREADR:
    {
      int i;

      fprintf(stdout, "BIOREAD Response-Octets are:");
      count = packet->octets [payload_offset + 4];
      count = count + (256 * packet->octets [payload_offset + 5]);
      for (i=0; i<count; i++)
      {
        fprintf(stdout, " %02x", packet->octets [6 + i + payload_offset]);
      };
      fprintf(stdout, "\n");
    };
    break;
  };
}


int osdpdump_print_hex
    (OSDPDUMP_CONTEXT *ctx)

{ /* osdpdump_print_hex */

  int i;
  OSDPDUMP_WORKING_PACKET *packet;


  packet = &(ctx->osdp_pdu);
  fprintf(stdout, "P:%06d Dump:", ctx->current_packet_number);
  for (i=0; i<packet->octet_length; i++)
    fprintf(stdout, " %02x", packet->octets [i]);
  fprintf(stdout, "\n");
  return(ST_OK);

} /* osdpdump_print_hex */


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
  unsigned int serial_number;
  int speed_returned;


  payload_offset = 6; // before secure channel

  fprintf(stdout, "P:%06d ", ctx->current_packet_number);
  fprintf(stdout, "t=%9s.%9s ", ctx->packet_seconds, ctx->packet_nanoseconds);
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
  case OSDP_IEC_ACK:
    break;
  case OSDP_IEC_CHLNG:
    if (!(ctx->osdp_pdu.completion_status & OSDPDUMP_COMPLETION_RSP)) // CHLNG
    {
      sprintf(otmp,
" RND: %02x%02x%02x%02x %02x%02x%02x%02x",
        packet->octets [payload_offset + 0], packet->octets [payload_offset + 1], packet->octets [payload_offset + 2], packet->octets [payload_offset + 3],
        packet->octets [payload_offset + 4], packet->octets [payload_offset + 5], packet->octets [payload_offset + 6], packet->octets [payload_offset + 7]);
    };
    if (ctx->osdp_pdu.completion_status & OSDPDUMP_COMPLETION_RSP) // CCRYPT
    {
      sprintf(otmp,
" RND: %02x%02x%02x%02x %02x%02x%02x%02x",
        packet->octets [payload_offset +  8], packet->octets [payload_offset +  9], packet->octets [payload_offset + 10], packet->octets [payload_offset + 11],
        packet->octets [payload_offset + 12], packet->octets [payload_offset + 13], packet->octets [payload_offset + 14], packet->octets [payload_offset + 15]);
    };
    break;
  case OSDP_IEC_COM:
      speed_returned = 0;
      speed_returned = speed_returned + packet->octets [payload_offset + 1];
      speed_returned = speed_returned + 0x100 * (packet->octets [payload_offset + 2]);
      speed_returned = speed_returned + 0x10000 * (packet->octets [payload_offset + 3]);
      speed_returned = speed_returned + 0x1000000 * (packet->octets [payload_offset + 4]);
      sprintf(otmp,
" NewAddr %02x NewSpeed %02x-%02x-%02x-%02x (%d.)",
        packet->octets [payload_offset + 0],
        packet->octets [payload_offset + 1], packet->octets [payload_offset + 2], packet->octets [payload_offset + 3], packet->octets [payload_offset + 4],
        speed_returned);
    break;
  case OSDP_IEC_FILETRANSFER:
    if (!(packet->completion_status & OSDPDUMP_COMPLETION_SCB))
    {
      sprintf(otmp,
" FtType %02X FtSizeTotal %02X %02X %02X %02X FtOffset %02X %02X %02X %02x FtFragment %02X %02X Data[0] %02X",
        packet->octets [payload_offset + 0],
        packet->octets [payload_offset + 1], packet->octets [payload_offset + 2],
        packet->octets [payload_offset + 3], packet->octets [payload_offset + 4],

        packet->octets [payload_offset + 5], packet->octets [payload_offset + 6],
        packet->octets [payload_offset + 7], packet->octets [payload_offset + 8],

        packet->octets [payload_offset + 9], packet->octets [payload_offset + 10],
        packet->octets [payload_offset + 11]);
    };
    break;
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
    sprintf(otmp, " Reason:%s", osdpdump_nak_reason(ctx, packet->octets [payload_offset + 0]));
    if (packet->payload_length > 1)
    {
      sprintf(otmp2, " Detail %02x", packet->octets [payload_offset + 1]);
      strcat(otmp, otmp2);
    };
    break;
  case OSDP_IEC_PDID:
    serial_number = 
      packet->octets [payload_offset + 5] +
      (packet->octets [payload_offset + 6] <<  8) +
      (packet->octets [payload_offset + 7] << 16) +
      (packet->octets [payload_offset + 8] << 24);

    sprintf(otmp, " OUI %02X-%02X-%02X Model %d. Version %d. Serial %d. FW %d.%d-%d",
      packet->octets [payload_offset + 0], packet->octets [payload_offset + 1],
      packet->octets [payload_offset + 2],
      packet->octets [payload_offset + 3], packet->octets [payload_offset + 4],
      serial_number,
      packet->octets [payload_offset + 9],
      packet->octets [payload_offset + 10],
      packet->octets [payload_offset + 11]);
    break;
  case OSDP_IEC_PIVDATAR:
    if (packet->completion_status EQUALS OSDPDUMP_COMPLETION_CMD)
      sprintf(otmp, " MFG...");
    else
    {
      sprintf(otmp, " PIVDATAR...");
    };
    break;
  case OSDP_IEC_POLL:
    break;
  default:
    if (ctx->verbosity > 3)
      fprintf(stdout, "Warning: unknown command (%x) in osdpdump_print_one_line\n", packet->command_response);
    break;
  };

  // print what we've decoded

  if (strlen(otmp) > 0)
    fprintf(stdout, "%s", otmp);

  if (packet->check_type != 0)
    fprintf(stdout, " CK  %02x", packet->packet_check [1]);
  else
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
  sprintf(otmp, "Notes: %d\n", ctx->note_count); strcat(ctx->output_text, otmp);
  sprintf(otmp, "%d. packets\n", ctx->detected_packets); strcat(ctx->output_text, otmp);
  sprintf(otmp, "Detected:\n"); strcat(ctx->output_text, otmp);
  for (idx=0; idx<255; idx++)
  {
    if (osdpdump_message_tracking [idx].count > 0)
    {
      sprintf(otmp,
" %2x(%s) %d\n", idx, osdpdump_command_string(ctx, idx), osdpdump_message_tracking [idx].count);
      strcat(ctx->output_text, otmp);
    };
  };
  strcat(ctx->output_text, "\n");

  sprintf(otmp, "Active PD's (by address):"); strcat(ctx->output_text, otmp);
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

