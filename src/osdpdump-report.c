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

  fprintf(stdout, "P:%06d ", ctx->current_packet_number);
  fprintf(stdout, "%s ", osdpdump_command_string(ctx, packet->command_response));
  fprintf(stdout, " A=%2d.", packet->address);
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

