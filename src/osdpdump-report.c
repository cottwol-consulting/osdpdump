#include <stdio.h>
#include <string.h>

#include <osdpdump.h>
#include <osdpdump-decoding.h>


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
  sprintf(otmp, "Detected:"); strcat(ctx->output_text, otmp);
  for (idx=0; idx<255; idx++)
  {
    if (ctx->detected_commands [idx] > 0)
    {
      sprintf(otmp, " %2x(%d.)", idx, ctx->detected_commands [idx]);
zzz
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

