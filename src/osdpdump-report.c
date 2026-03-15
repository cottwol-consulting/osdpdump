/*
  osdpdump-report.c - reporting functions for osdpdump

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

#include <osdpdump.h>
#include <osdpdump-decoding.h>
#include <osdpdump-vendor-identification.h>
extern OSDPDUMP_TRACKING osdpdump_message_tracking [256];

#define PSIA_PKOC_MFGREP_CARD_PRESENT        (0xE0)
#define PSIA_PKOC_MFG_AUTH_REQUEST           (0xE1)
#define PSIA_PKOC_MFGREP_AUTH_RESPONSE       (0xE2)
#define PSIA_PKOC_MFG_NEXT_TRANSACTION       (0xE3)
#define PSIA_PKOC_MFGREP_TRANSACTION_REFRESH (0xE4)
#define PSIA_PKOC_MFGREP_READER_ERROR        (0xE5)

/*
  osdpdump_print - dump a PDU as a text line

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
  int status;


  status = ST_OK;
  packet = &(ctx->osdp_pdu);
  if (ctx->verbosity > 10)
    fprintf(stderr, "DEBUG: print format %d.\n", ctx->print_format);
  switch(ctx->print_format)
  {
  case OSDPDUMP_FMT_ANNOTATED:
    osdpdump_print_one_line(ctx, packet);
    if (strlen(ctx->output_text) > 0)
    {
      fprintf(stdout, "NOTE: %s\n", ctx->output_text);
      ctx->output_text [0] = 0;
    };
    osdpdump_print_hex(ctx);
    osdpdump_print_annotation(ctx, packet);
    break;

  case OSDPDUMP_FMT_APPEND:
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

  case OSDPDUMP_FMT_MAC:
    fprintf(stdout, "MAC: %02X%02X%02X%02X\n", packet->mac [0], packet->mac [1], packet->mac [2], packet->mac [3]);
    status = osdpdump_mac_stats(ctx, packet->mac);
    break;

  default:
    osdpdump_print_one_line(ctx, packet);
    break;
  };
  return(status);

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
  case OSDP_IEC_EXT_PDID:
    {
      int xid_frag_lth;
      xid_frag_lth = packet->octets [payload_offset + 4] + 256*packet->octets [payload_offset + 5];
      osdpdump_decode_extended_id(ctx, packet->octets + payload_offset + 6, xid_frag_lth);
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

  char color_temp1 [1024];
  char color_temp2 [1024];
  int offset;
  char otmp [8*1024]; //maxstring large
  char otmp2 [1024]; //maxstring
  int payload_offset;
  unsigned int serial_number;
  int speed_returned;
  char tstring [1024];


  payload_offset = osdpdump_command_offset(ctx, packet) + 1;

  fprintf(stdout, "P:%06d ", ctx->current_packet_number);
  fprintf(stdout, "t=%9s.%9s ", ctx->packet_seconds, ctx->packet_nanoseconds);
  if (!(ctx->osdp_pdu.completion_status & OSDPDUMP_COMPLETION_RSP)) // Command
  {
    fprintf(stdout, "C:");
    ctx->pd_ctx [packet->address].last_command_sequence = packet->sequence;
  }
  else
  {
    fprintf(stdout, "R:");
  };
  fprintf(stdout, "%s ", osdpdump_command_string(ctx, packet->command_response));
  fprintf(stdout, " A %2d.", packet->address);
  fprintf(stdout, " S%d", packet->sequence);
  fprintf(stdout, " L%04d", packet->octet_length);
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
  case OSDP_IEC_BUZ:
      sprintf(otmp,
" Buzzer: Rdr %d Tone Code %d OnTime %03d. OffTime %03d. Count %d.",
        packet->octets [payload_offset + 0], packet->octets [payload_offset + 1],
        packet->octets [payload_offset + 2], packet->octets [payload_offset + 3], packet->octets [payload_offset + 4]);
    break;
  case OSDP_IEC_CHLNG:
    if (!(ctx->osdp_pdu.completion_status & OSDPDUMP_COMPLETION_RSP)) // CHLNG
    {
      char *scbk_flavor;

      if (packet->octets [7] EQUALS 1)
        scbk_flavor = "Paired";
      else
        scbk_flavor = "Default";
      sprintf(otmp,
" RND: %02x%02x%02x%02x %02x%02x%02x%02x (%s)",
        packet->octets [payload_offset + 0], packet->octets [payload_offset + 1], packet->octets [payload_offset + 2], packet->octets [payload_offset + 3],
        packet->octets [payload_offset + 4], packet->octets [payload_offset + 5], packet->octets [payload_offset + 6], packet->octets [payload_offset + 7],
        scbk_flavor);
    };
    if (ctx->osdp_pdu.completion_status & OSDPDUMP_COMPLETION_RSP) // CCRYPT
    {
      sprintf(otmp,
" RND: %02x%02x%02x%02x %02x%02x%02x%02x",
        packet->octets [payload_offset +  8], packet->octets [payload_offset +  9], packet->octets [payload_offset + 10], packet->octets [payload_offset + 11],
        packet->octets [payload_offset + 12], packet->octets [payload_offset + 13], packet->octets [payload_offset + 14], packet->octets [payload_offset + 15]);

      {
        unsigned char rnd_b [8];
        unsigned long int rnd_b_int;

        memset(rnd_b, 0, sizeof(rnd_b));
        rnd_b_int = 0l;
        memcpy(rnd_b, packet->octets + payload_offset + 8, 8);
        rnd_b_int = *(unsigned long int *)rnd_b;
        if (rnd_b_int EQUALS 0)
        {
          sprintf(tstring, " - RND.B invalid\n");
          strcat(ctx->output_text, tstring);
          ctx->note_count ++;
        };
      };
    };
    break;
  case OSDP_IEC_CAP:
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
  case OSDP_IEC_EXT_PDID:
    {
      int xid_frag_lth;
      int xid_tot_lth;
      FILE *xidf;


      xid_tot_lth = packet->octets [payload_offset + 0] + 256*packet->octets [payload_offset + 1];
      xid_frag_lth = packet->octets [payload_offset + 4] + 256*packet->octets [payload_offset + 5];
      sprintf(otmp,
" Ext-PDID Total %04X Offset %04X Fraglen TLV(%04X octets): %02X %02X %02X %02X %02X %02X %02X %02X...",
        xid_tot_lth, packet->octets [payload_offset + 2] + 256*packet->octets [payload_offset + 3], xid_frag_lth,
        packet->octets [payload_offset + 6], packet->octets [payload_offset + 7],
        packet->octets [payload_offset + 8], packet->octets [payload_offset + 9],
        packet->octets [payload_offset + 10], packet->octets [payload_offset + 11],
        packet->octets [payload_offset + 12], packet->octets [payload_offset + 13]);

      fprintf(stderr, "Exporting Extended PDID Report to ext-pdid_response.bin\n");
      xidf = fopen("ext-pdid_response.bin", "w");
if (xid_frag_lth != xid_tot_lth)
  fprintf(stderr, "DEBUG: fix! only writes last fragment.\n");
      fwrite(packet->octets + payload_offset + 6, sizeof(packet->octets[0]), xid_frag_lth, xidf);
    };
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
  case OSDP_IEC_ID:
    sprintf(otmp, " ID-Blk %02x", packet->octets [payload_offset]);
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
  case OSDP_IEC_LED:
    offset = payload_offset;
    while (offset < packet->payload_length)
    {
      otmp [0] = 0;
      sprintf(otmp2, " Rdr %02X LED %02X",
        packet->octets [payload_offset + 0], packet->octets [payload_offset + 1]);
      strcpy(otmp, otmp2);
      strcpy(color_temp1, osdpdump_led_color(ctx, packet->octets [offset + 5]));
      strcpy(color_temp2, osdpdump_led_color(ctx, packet->octets [offset + 6]));
      sprintf(otmp2, " TEMP %s Ton %02X Toff %02X OnCol %s OffCol %s TmpTime %02X%02X",
        osdpdump_led_temp_command(ctx, packet->octets [offset + 2]),
        packet->octets [offset + 3], packet->octets [offset + 4],
        color_temp1, color_temp2,
        packet->octets [offset + 8], packet->octets [offset + 7]); // Temp Time is lo/hi
//        osdpdump_led_color(ctx, packet->octets [offset + 5]), osdpdump_led_color(ctx, packet->octets [offset + 6]),
      strcat(otmp, otmp2);
      sprintf(otmp2, " PERM %s Pon %02X Poff %02X POnCol %s POffCol %s",
        osdpdump_led_perm_command(ctx, packet->octets [offset +  9]),
        packet->octets [offset + 10], packet->octets [offset + 11],
        osdpdump_led_color(ctx, packet->octets [offset + 12]), osdpdump_led_color(ctx, packet->octets [offset + 13]));
      strcat(otmp, otmp2);
      offset = offset + 14;
    };
    break;
  case OSDP_IEC_MFGREP:
    {
      sprintf(otmp, " MFGREP...");

      // for PKOC specifically, interpret the MFGREP response

      if (0 EQUALS memcmp(packet->octets + payload_offset, OUI_PSIA, sizeof(OUI_PSIA))) // first 3 of mfgrep response are an OUI
      {
        switch(*(packet->octets + payload_offset + 3))
        {
        case PSIA_PKOC_MFGREP_AUTH_RESPONSE:
          sprintf(otmp, " PKOC Auth Response");
         break;
        case PSIA_PKOC_MFGREP_CARD_PRESENT:
          sprintf(otmp, " PKOC Card Present");
          break;
        case PSIA_PKOC_MFGREP_READER_ERROR:
          sprintf(otmp, " PKOC Reader Error");
          break;
        case PSIA_PKOC_MFGREP_TRANSACTION_REFRESH:
          sprintf(otmp, " PKOC Transaction Refresh");
          break;
        };
      };
    };
    break;
  case OSDP_IEC_NAK:
    if (packet->payload_length > 0)
    {
      sprintf(otmp, " Reason:%s", osdpdump_nak_reason(ctx, packet->octets [payload_offset + 0]));
      sprintf(otmp2, " Detail %02x", packet->octets [payload_offset + 1]);
      strcat(otmp, otmp2);
    };
    break;
  case OSDP_IEC_PDCAP:
    break;
  case OSDP_IEC_PDID:
    {
      char text [1024];
      char oui_name [1024];

    serial_number = 
      packet->octets [payload_offset + 5] +
      (packet->octets [payload_offset + 6] <<  8) +
      (packet->octets [payload_offset + 7] << 16) +
      (packet->octets [payload_offset + 8] << 24);

    text [0] = 0;
    strcpy(oui_name, oui_lookup(packet->octets [payload_offset + 0],
      packet->octets [payload_offset + 1], packet->octets [payload_offset + 2]));
    if (strlen(oui_name) > 0)
      sprintf(text, "(%s)", oui_name);

    sprintf(otmp, " OUI %02X-%02X-%02X%s Model %d. Version %d. Serial %d.(%02X%02X%02X%02X) FW %d.%d-%d",
      packet->octets [payload_offset + 0], packet->octets [payload_offset + 1],
      packet->octets [payload_offset + 2], text,
      packet->octets [payload_offset + 3], packet->octets [payload_offset + 4],
      serial_number,
      packet->octets [payload_offset + 5], packet->octets [payload_offset + 6], packet->octets [payload_offset + 7], packet->octets [payload_offset + 8],
      packet->octets [payload_offset + 9],
      packet->octets [payload_offset + 10],
      packet->octets [payload_offset + 11]);
    }
    break;
  case OSDP_IEC_PIVDATAR:
    if (packet->completion_status != OSDPDUMP_COMPLETION_CMD)
      sprintf(otmp, " PIVDATAR...");
    else
    {
      sprintf(otmp, " MFG OUI %02X-%02X-%02X Cmd %02x",
        packet->octets [payload_offset + 0], packet->octets [payload_offset + 1],
        packet->octets [payload_offset + 2], packet->octets [payload_offset + 3]);

      // yes the following will over-write otmp
      {
        // for PKOC specifically, interpret the MFG command

        if (0 EQUALS memcmp(packet->octets + payload_offset, OUI_PSIA, sizeof(OUI_PSIA))) // first 3 of mfgrep response are an OUI
        {
          switch(*(packet->octets + payload_offset + 3))
          {
          case PSIA_PKOC_MFG_AUTH_REQUEST:
            sprintf(otmp, " PKOC Auth Request");
            break;
          case PSIA_PKOC_MFG_NEXT_TRANSACTION:
            sprintf(otmp, " PKOC Next Transaction");
            break;
          };
        };
      };
    };
    break;
  case OSDP_IEC_POLL:
    if (packet->payload_length > 0)
    {
      sprintf(tstring, "%d. excess data", packet->payload_length);
      strcat(ctx->output_text, tstring);
      ctx->note_count ++;
    };
    break;
  case OSDP_IEC_RAW:
    {
      int count;
      int i;
      char octet [3];
      char raw_data [1024];

      // if it's encrypted we don't know the number of bits

      count = 0;
      raw_data [0] = 0;
      if (packet->completion_status & OSDPDUMP_COMPLETION_SCB)
        strcpy(raw_data, "(encrypted)");
      else
      {
        count = (packet->octets [payload_offset + 3])*256 + packet->octets [payload_offset + 2];
        for (i=0; i<(7+count)/8; i++)
        {
          sprintf(octet, "%02X", packet->octets [payload_offset + 4 + i]);
          strcat(raw_data, octet);
        };
      };
      sprintf(otmp, " RAW: Rdr %d. Fmt %d. Bits %d. Data %s",
        packet->octets [payload_offset + 0], packet->octets [payload_offset + 1], count, raw_data);
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

  if (packet->check_type != 0)
    fprintf(stdout, " CK  %02x", packet->packet_check [1]);
  else
    fprintf(stdout, " CRC %02x%02x", packet->packet_check [0], packet->packet_check [1]);
  if (ctx->print_format != OSDPDUMP_FMT_APPEND)
    fprintf(stdout, "\n");
  else
    fprintf(stdout, " ");

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
  sprintf(otmp, "%d. detected\n", ctx->detected_packets); strcat(ctx->output_text, otmp);
  sprintf(otmp, "%d. skipped\n", ctx->skipped_packets); strcat(ctx->output_text, otmp);
  sprintf(otmp, "Statistics:\n"); strcat(ctx->output_text, otmp);
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

