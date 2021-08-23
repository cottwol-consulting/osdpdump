/*
  osdpdump-report.c - reporting functions for osdpdump

  (C)2021 Smithee Solutions LLC
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
  case OSDPDUMP_FMT_2LINE:
    osdpdump_print_one_line(ctx, packet);
    fprintf(stdout, " Dump:");
    for (i=0; i<packet->octet_length; i++)
      fprintf(stdout, " %02x", packet->octets [i]);
    fprintf(stdout, "\n");
    break;
  case OSDPDUMP_FMT_1LINE:
    osdpdump_print_one_line(ctx, packet);
    break;
  default:
    fprintf(stdout, " C/R:%02x(%s)", packet->command_response, osdpdump_command_string(ctx, packet->command_response));
    fprintf(stdout, " A:%02x", packet->address);
    fprintf(stdout, " Check: %02x%02x", packet->packet_check [0], packet->packet_check [1]);
    fprintf(stdout, "\n");
    break;
  };
  return(0);

} /* osdpdump_print */


void
  osdpdump_print_one_line
    (OSDPDUMP_CONTEXT *ctx,
    OSDPDUMP_WORKING_PACKET *packet)

{ /* osdpdump_print_one_line */

  char otmp [8*1024]; //maxstring large
  int payload_offset;


  payload_offset = 6; // before secure channel

  fprintf(stdout, "P:%06d ", ctx->current_packet_number);
  fprintf(stdout, "%s ", osdpdump_command_string(ctx, packet->command_response));
  fprintf(stdout, " A %2d.", packet->address);
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
"FtAction %x FtDelay-LSB %02x FtDelay-MSB %02x FtStatusDetail-LSB %02x FtStatusDetail-MSB %02x FtUpdateMsgMax-LSB %2x FtUpdateMsgMax-MSB %2x",
        packet->octets [payload_offset + 0],
        packet->octets [payload_offset + 1], packet->octets [payload_offset + 2],
        packet->octets [payload_offset + 3], packet->octets [payload_offset + 4],
        packet->octets [payload_offset + 5], packet->octets [payload_offset + 6]);
    };
    break;
  default:
    if (ctx->verbosity > 3)
      fprintf(stdout, "Warning: unknown command (%x) in osdpdump_print_one_line\n", packet->command_response);
    break;
  };
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

