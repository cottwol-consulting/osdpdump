/*
  osdpdump - read a byte stream and analyze/display the OSDP protocol contents

  "osdpdump --help" for instructions.

  (C)2026 Cottwol Consulting

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
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <getopt.h>

#include <jansson.h>


#include <osdpdump.h>
#include <osdpdump-version.h>
extern OSDPDUMP_TRACKING osdpdump_message_tracking [256];
typedef struct osdpdump_command_line_context
{
  int option;
} OSDPDUMP_COMMAND_LINE_CONTEXT;
#include <osdpdump-decoding.h>
FILE *f;
OSDPDUMP_COMMAND_LINE_CONTEXT osdpdump_command_line;
char last_input_line [8192];
struct option longopts [] = {
  {"analyze", optional_argument, &osdpdump_command_line.option, OSDPDUMP_OPT_ANALYZE},
  {"help", 0, &osdpdump_command_line.option, OSDPDUMP_OPT_HELP},
  {"format", required_argument, &osdpdump_command_line.option, OSDPDUMP_OPT_REPORT_FORMAT},
  {"pd-address", required_argument, &osdpdump_command_line.option, OSDPDUMP_OPT_ADDRESS},
  {"source", required_argument, &osdpdump_command_line.option, OSDPDUMP_OPT_SOURCE},
  {"time-format", required_argument, &osdpdump_command_line.option, OSDPDUMP_OPT_TIME_FORMAT},
  {"verbosity", required_argument, &osdpdump_command_line.option, OSDPDUMP_OPT_VERBOSITY},
  {"version", optional_argument, &osdpdump_command_line.option, OSDPDUMP_OPT_VERSION},
  {0, 0, 0, 0}};


int
  main
    (int argc,
    char * argv [])

{ /* main for osdpdump */

  OSDPDUMP_CONTEXT *ctx;
  int status;
  OSDPDUMP_CONTEXT osdp_dump_context;


  status = ST_OK;
  ctx = &osdp_dump_context;
  status = osdpdump_initialize(ctx, argc, argv);

  if (status EQUALS ST_OK)
  {
    switch(ctx->command)
    {
    case OSDPDUMP_CMD_HELP:
    default:
      fprintf(stdout, "osdpdump help.\n");
      fprintf(stdout,
"--analyze [=n] - set analysis level to n (0-9,default 1)\n");
      fprintf(stdout,
"--format=<n> - set report format.  1=1-line no dump; 2=1-line with dump, 3=annotate, 4=summary only\n");
      fprintf(stdout,
"--help - this message\n");
      fprintf(stdout,
"--pd-address=<n> - address (in decimal) of PD address to dump.\n");
      fprintf(stdout,
"--source=<file> - set dump filename to read.\n");
      fprintf(stdout,
"--time-format=<format> - set time to direct or delta (1).\n");
      fprintf(stdout,
"--verbosity=<n> - set message verbosity.  0=quiet, 3=normal, 9=debug.\n");
      break;

    case OSDPDUMP_CMD_DUMP:
      status = ST_OSDPDUMP_SOURCE_NOT_SUPPORTED;
      switch(ctx->input_source)
      {
      case OSDPDUMP_SOURCE_OSDPCAP:
        ctx->dump_file_handle = fopen(ctx->input_path, "r");
        if (ctx->dump_file_handle EQUALS NULL)
          status = ST_OSDPDUMP_BAD_INPUT_FILE;
        else
          status = ST_OK;
      };
      if (status EQUALS ST_OK)
      {
        status = osdpdump_digester(ctx);
        if (ctx->verbosity > 9)
          fprintf(stderr, "DEBUG: source is osdpcap %s\n", ctx->input_path);
        // regardless of what happened print the summary
        status = osdpdump_summary(ctx);
      };
      break;

    case OSDPDUMP_CMD_VERSION:
      // init code prints the version so we don't have to here.
      // printf("osdpdump %s\n", OSDPDUMP_VERSION);
      break;
    };
  };

  fprintf(stdout, "%s\n", ctx->output_text); ctx->output_text [0] = 0;

  if (status != ST_OK)
    fprintf(stderr, "osdpdump completed, status was %d. errno=%d.\n", status, errno);
  return(status);

} /* main for osdpdump */


/*
  osdpdump_command_offset - calculate where command starts

  Understand secure channel headers.

  Input:
    context
    packet we're decoding

  Output:
    integer offset
*/

int
  osdpdump_command_offset
    (OSDPDUMP_CONTEXT *ctx,
    OSDPDUMP_WORKING_PACKET *packet)

{ /* osdpdump_command_offset */

  int extra_offset;
  int returned_offset;


  extra_offset = 0;

  // SOM, address, length, ctl

  returned_offset = 1 + 1 + 2 + 1;
  if (packet->completion_status & OSDPDUMP_COMPLETION_SCB)
  {
    extra_offset = packet->octets [5];
  };

  return(returned_offset + extra_offset);

} /* osdpdump_command_offset */


/*
  osdpdump_digester - reads the input (file) and runs the processing framework
*/
int
  osdpdump_digester
    (OSDPDUMP_CONTEXT *ctx)

{ /* osdpdump_digester */

  int done;
  OSDPDUMP_INPUT input_value;
  OSDPDUMP_WORKING_PACKET *packet;
  int skip;
  int status;


  status = ST_OK;
  if (ctx->verbosity > 0)
    fprintf(stdout, "OSDP Dump (version %s) dumping file %s\n", OSDPDUMP_VERSION, ctx->input_path);
  memset(&input_value, 0, sizeof(input_value));
  packet = &(ctx->osdp_pdu);
  done = 0;
  while (!done)
  {
    // if there were notes there dump them now.  (likely from garbage packet)
    if (strlen(ctx->output_text) > 0)
    {
      printf("Note: %s",ctx->output_text);
      printf("Last input line: %s\n", last_input_line);
    };
    ctx->output_text [0] = 0;
    if (input_value.length EQUALS 0)
      status = osdpdump_read_input(ctx, &input_value);
    if (ctx->verbosity > 3)
      fprintf(stderr, "DEBUG: osdpdump_read_input %d.\n", status);
    if (status EQUALS ST_OK)
    {
      status = osdpdump_accumulate_input(ctx, &input_value);
if (ctx->verbosity > 9)
{
  int i;
  fprintf(stderr, "DEBUG: input bytes after osdpdump_accumulate_input (%d.)", input_value.length);
  for(i=0; i<input_value.length; i++)
    fprintf(stderr, " %02X", input_value.raw_bytes[i]);
  fprintf(stderr, "\n");
}
      if (status EQUALS ST_OSDPDUMP_PACKET)
      {
        if (ctx->verbosity > 3)
          fprintf(stderr, "DEBUG: whole packet detected\n");
        strcpy(ctx->previous_packet_seconds, ctx->packet_seconds);
        strcpy(ctx->previous_packet_nanoseconds, ctx->packet_nanoseconds);
        strcpy(ctx->packet_seconds, input_value.time_seconds);
        strcpy(ctx->packet_nanoseconds, input_value.time_nanoseconds);
        ctx->current_packet_number ++;
        ctx->detected_packets ++;
        {
          status = osdpdump_parse(ctx);
if (ctx->verbosity > 3)
  fprintf(stderr, "DEBUG: back from osdpdump_parse, status %d.\n", status);
          if (status EQUALS ST_OK)
            status = osdpdump_review_input(ctx);
          if (status EQUALS ST_OK)
          {
            skip = 0;
            if (ctx->specific_address_requested)
            {
              if (ctx->specific_address != packet->address)
              {
                skip = 1;
                ctx->skipped_packets ++;
              };
            };
            if (!skip)
            {
              status = osdpdump_print(ctx);
              if (strlen(ctx->output_text) > 0)
              {
                fprintf(stdout, "NOTES: %s", ctx->output_text); ctx->output_text [0] = 0;
              };

              // clear things out for the next packet
              memset(&input_value, 0, sizeof(input_value));

              ctx->pd_ctx [packet->address].last_command_response = ctx->osdp_pdu.command_response;
            };
          };
        };
      };
      fflush(stdout);  fflush(stderr);
      memset(packet, 0, sizeof(*packet));
    };
    if ((status != ST_OK) && (status != ST_OSDPDUMP_NEED_MORE_DATA))
      done = 1;
    fflush(stdout); fflush(stderr);
  };
  return(status);

} /* osdpdump_digester */


/*
  osdspdump_initialize - initalize values, process command line

  Inputs:
    context
    command line arguments

  Outputs:
    updated context
*/

int
  osdpdump_initialize
    (OSDPDUMP_CONTEXT *ctx,
    int argc,
    char *argv [])

{ /* osdpdump_initialize */

  int done;
  int i;
  int idx;
  char optstring [1024]; //maxstring
  int status;
  int status_opt;


  status = ST_OK;
  memset(ctx, 0, sizeof(*ctx));
  ctx->verbosity = 3;
  if (ctx->verbosity > 0)
    fprintf(stderr, "osdpdump %s\n", OSDPDUMP_VERSION);
  ctx->print_format = OSDPDUMP_FMT_1LINE;
  ctx->analysis = OSDPDUMP_ANA_STRICT;
  ctx->input_source = OSDPDUMP_SOURCE_OSDPCAP;
  strcpy(ctx->input_path, "./current.osdpcap");
  osdpdump_command_line.option = OSDPDUMP_OPT_HELP;
ctx->analysis_view = OSDPDUMP_ANA_PD;
ctx->output_report = 1;
ctx->output_analysis = 1;

  if (argc EQUALS 2)
  {
    ctx->command = OSDPDUMP_CMD_DUMP;
    strcpy(ctx->input_path, argv [1]);
  };

  // option switch processing

  done = 0;
  while (!done)
  {
    status_opt = getopt_long (argc, argv, optstring, longopts, NULL);
    if (status_opt EQUALS '?')
    {
      done = 1;
      status = ST_OSDPDUMP_UNKNOWN_ARGUMENT;
    };
    if (ctx->verbosity > 3)
    {
      if (status_opt > 0)
        fprintf(stderr, "option %c returned\n", status_opt);
    };
    if (ctx->verbosity > 9)
      fprintf(stderr, "getopt_long: %d\n", status_opt);
    if (status_opt EQUALS -1)
    {
      done = 1;
    };
    if (!done)
    {
      switch (osdpdump_command_line.option)
    {
    case OSDPDUMP_OPT_ADDRESS:
      sscanf(optarg, "%d", &i);
      ctx->specific_address = i;
      ctx->specific_address_requested = 1;
      break;
    case OSDPDUMP_OPT_ANALYZE:
      sscanf(optarg, "%d", &i);
      ctx->analysis = i;
      ctx->command = OSDPDUMP_CMD_DUMP;
      break;
    case OSDPDUMP_OPT_HELP:
      ctx->command = OSDPDUMP_CMD_HELP;
      break;
    case OSDPDUMP_OPT_REPORT_FORMAT:
      // 1,2,3,4,5 are allowed.  force it to 1 (1-liner) if out of range.
      ctx->print_format = 1;
      sscanf(optarg, "%d", &i);
      if ((i >= 1) && (i <= 6))
        ctx->print_format = i;
      ctx->command = OSDPDUMP_CMD_DUMP;
      break;
    case OSDPDUMP_OPT_SOURCE:
      strcpy(ctx->input_path, optarg);
      ctx->command = OSDPDUMP_CMD_DUMP;
      break;
    case OSDPDUMP_OPT_TIME_FORMAT:
      sscanf(optarg, "%d", &i);
      if (i != 0)
      ctx->time_format = 1;
      ctx->command = OSDPDUMP_CMD_DUMP;
      break;
    case OSDPDUMP_OPT_VERBOSITY:
      sscanf(optarg, "%d", &i);
      ctx->verbosity = i;
      ctx->command = OSDPDUMP_CMD_DUMP;
      break;
    case OSDPDUMP_OPT_VERSION:
      ctx->command = OSDPDUMP_CMD_VERSION;
      break;
    default:
      ctx->command = OSDPDUMP_CMD_HELP;
      break;
    };
    };
  };

  if (ctx->verbosity > 3)
  {
    fprintf(stderr, "osdpdump %s is in startup.\n", OSDPDUMP_VERSION);
  };

  for (idx=0; idx<OSDPDUMP_PD_MAX; idx++)
  {
    ctx->pd_ctx [idx].state = OSDPDUMP_PD_ABSENT;
  };

  // initialize MAC histogram

  status = osdpdump_mac_stats_init(ctx);

  osdpdump_init_tracking(ctx, osdpdump_message_tracking);

  return(status);

} /* osdpdump_initialize */


/*
  osdpdump_parse - given a OSDP packet decompose it into parts
*/
int
  osdpdump_parse
    (OSDPDUMP_CONTEXT *ctx)

{ /* osdpdump_parse */
 
  unsigned char control_octet;
  OSDPDUMP_WORKING_PACKET *packet;
  int status;


  status = ST_OK;
  packet = (OSDPDUMP_WORKING_PACKET *)&(ctx->osdp_pdu);
  packet->completion_status = 0;

  if (ctx->verbosity > 9)
    fprintf(stderr, "DEBUG: 419 payload length %03d.\n", packet->payload_length);
  packet->role = 0x80 & (packet->octets [1]);
  packet->address = 0x7F & (packet->octets [1]);
  packet->payload_length = packet->octet_length - 6; // less SOM addr len(2) ctrl c/r
  if (ctx->verbosity > 9)
    fprintf(stderr, "DEBUG: 422 payload length %03d.\n", packet->payload_length);
// sanity check address
  control_octet = packet->octets [4];
  if (control_octet & OSDP_IEC_CTL_CRC)
  {
    packet->payload_length = packet->payload_length - 2; // less CRC
    if (ctx->verbosity > 9)
      fprintf(stderr, "DEBUG: 429 payload length %03d.\n", packet->payload_length);
    packet->check_type = 0;
  }
  else
  {
    packet->payload_length = packet->payload_length - 1; // less Checksum
    packet->check_type = 1;
  };
  if (control_octet & OSDP_IEC_CTL_SCB)
  {
    // it had an SCB.  the payload is (SCP length) shorter.
    // the SCB length is always in the 6th octet (index 5)

    packet->completion_status = packet->completion_status | OSDPDUMP_COMPLETION_SCB;
    packet->payload_length = packet->payload_length - packet->octets [5]; // less SCB header
    packet->payload_length = packet->payload_length - 4; // less MAC
    if (ctx->verbosity > 9)
      fprintf(stderr, "DEBUG: 445 payload length %03d.\n", packet->payload_length);
  };
  packet->sequence = control_octet & 0x03;
  if ((status EQUALS ST_OK) && !(packet->role)) // do this for commands not responses
  {
    if (ctx->verbosity > 9)
      fprintf(stderr, "updating last seq to %d from %d ctl 0x%02x\n",
        packet->sequence, ctx->pd_ctx [packet->address].last_received_sequence,
        control_octet);
    ctx->pd_ctx [packet->address].last_received_sequence = packet->sequence;
  };

  // extract the command/response field and collect statistics

  packet->command_response = ctx->osdp_pdu.octets [osdpdump_command_offset(ctx, packet)];

  if (0x80 & packet->octets [1])
    packet->completion_status = packet->completion_status | OSDPDUMP_COMPLETION_RSP;
  else
    packet->completion_status = packet->completion_status | OSDPDUMP_COMPLETION_CMD;

  ctx->pd_ctx [packet->address].state = OSDPDUMP_PD_PRESENT;

  // detect SCB

  if (control_octet & OSDP_IEC_CTL_SCB)
  {
    // record SCS length and value

    packet->scs_length = ctx->osdp_pdu.octets [1+1+2+1];
    packet->scs_type = ctx->osdp_pdu.octets [1+1+2+1+1];

    // if this is a CHLNG note which SCBK it's for in the PD context.

    if ((packet->command_response EQUALS OSDP_IEC_CHLNG) ||
      (packet->command_response EQUALS OSDP_IEC_CCRYPT) ||
      (packet->command_response EQUALS OSDP_IEC_SCRYPT))
    {
      if (packet->octets [7] EQUALS 0) // 0 in 3rd octet of SCS header in osdp_CHLNG means SCBK-D
        packet->completion_status = packet->completion_status | OSDPDUMP_COMPLETION_SCBK_D;
    }

    if (packet->scs_type >0x14)
      memcpy(packet->mac, ctx->osdp_pdu.octets+packet->octet_length - 6, 4);
  };

/// checksum vs. crc and offset glitches

  packet->packet_check [0] = ctx->osdp_pdu.octets [ctx->osdp_pdu.octet_length-2];
  packet->packet_check [1] = ctx->osdp_pdu.octets [ctx->osdp_pdu.octet_length-1];
  packet = &(ctx->osdp_pdu);
  return(status);

} /* osdpdump_parse */


/*
  osdpdump_review_input - review the input so far and offer commentary
*/
int
  osdpdump_review_input
    (OSDPDUMP_CONTEXT *ctx)

{ /* osdpdump_review_input */

  unsigned short int calculated_crc;
  unsigned short int calculated_checksum;
  int expected_seq;
  int last_seq;
  OSDPDUMP_WORKING_PACKET *packet;
  int status;
  char tstring [1024];
  unsigned short int wire_checksum;
  unsigned short int wire_crc;


  status = ST_OK;
  if (ctx->verbosity > 9)
    printf("DEBUG: osdpdump_review_input\n");
  osdpdump_message_tracking [ctx->osdp_pdu.command_response].count ++;
  packet = &(ctx->osdp_pdu);

  if (ctx->osdp_pdu.command_response EQUALS ctx->pd_ctx [packet->address].last_command_response)
  {
    // assuming it's not a CCRYPT, which uses same command/response value as a CHLNG

    if ((ctx->osdp_pdu.role EQUALS 0x80) && (ctx->osdp_pdu.command_response EQUALS OSDP_IEC_CCRYPT))
    {
      if (ctx->verbosity > 3)
        fprintf(stderr, "CCRYPT/CHLNG dupe detected.\n");
    }
    else
    {
      sprintf(tstring, "  - Retry or skip\n");
      strcat(ctx->output_text, tstring);
      ctx->note_count ++;
      if (ctx->verbosity > 3)
        fprintf(stderr, "retry detector activated, now %d. notes.\n", ctx->note_count);
    };
  };

  if (!packet->check_type)
  {
    // check the CRC

    wire_crc = (packet->octets [packet->octet_length-1] << 8) + packet->octets [packet->octet_length-2];
    calculated_crc = fCrcBlk(packet->octets, packet->octet_length - 2);
    if (calculated_crc != wire_crc)
    {
      sprintf(tstring, "  - CRC is wrong (wire %04X, calc %04X.)\n", wire_crc, calculated_crc);
      strcat(ctx->output_text, tstring);
      ctx->note_count ++;
    };
  }
  else
  {
    // Checksum
    wire_checksum = packet->octets [packet->octet_length-1];
    calculated_checksum = checksum(packet->octets, packet->octet_length - 1);
    if (calculated_checksum != wire_checksum)
    {
      sprintf(tstring, "  - Checksum is wrong (wire %02X, calc %02X.)\n", wire_checksum, calculated_checksum);
      strcat(ctx->output_text, tstring);
      ctx->note_count ++;
    };
  };

  // make sure sequence numbers are consistent

  last_seq = ctx->pd_ctx [packet->address].last_received_sequence;
  if (packet->role) // Response
  {
    {
      expected_seq = last_seq ++;
      if (expected_seq == 4)
        expected_seq = 1;
      if (packet->sequence != expected_seq)
      {
        strcat(ctx->output_text, "  - sequence number not next in ACU sequence\n");
        ctx->note_count ++;
      };
    };
  };
  if (!(packet->role)) // Command
  {
    if (ctx->pd_ctx [packet->address].last_command_sequence EQUALS packet->sequence)
    {
      strcat(ctx->output_text, "  - Command retransmission\n");
      ctx->note_count ++;
    }
    else
    {
// TODO check this, it's in the ACU section why does it mention PD...
      if (packet->sequence != last_seq)
      {
        strcat(ctx->output_text, "  - PD is responding on unexpected sequence number\n");
        ctx->note_count ++;
      };
    };
  };

  // make sure SCS value in header is correct

  if (packet->scs_type != 0)
  {
    if ((osdpdump_message_tracking [packet->command_response].valid_SCB != packet->scs_type)
      && (osdpdump_message_tracking [packet->command_response].valid_r_SCB != packet->scs_type))
    {
      sprintf(tstring, "  - wrong SCS (should be %02x)\n", osdpdump_message_tracking [packet->command_response].valid_SCB);
      strcat(ctx->output_text, tstring);
      ctx->note_count ++;
    };
    if ((packet->command_response EQUALS OSDP_IEC_CHLNG) ||
      (packet->command_response EQUALS OSDP_IEC_CCRYPT) ||
      (packet->command_response EQUALS OSDP_IEC_SCRYPT) ||
      (packet->command_response EQUALS OSDP_IEC_RMAC_I))
    {
      if (packet->scs_length != 3)
      {
        sprintf(tstring, "  - SCS sub-header wrong length (%d not %d)\n", packet->scs_length, 3);
        strcat(ctx->output_text, tstring);
        ctx->note_count ++;
      };
    }
    else
    {
      // all others should have a 2-byte scs header

      if (packet->scs_length != 2)
      {
            sprintf(tstring, "  - SCS sub-header wrong length (%d not %d)\n", packet->scs_length, 2);
            strcat(ctx->output_text, tstring);
            ctx->note_count ++;
      };
    };
  };

  // make sure it has an appropriate payload

  if (ctx->verbosity > 9)
    fprintf(stderr, "DEBUG: tracking CR %02X payload %d.\n", ctx->osdp_pdu.command_response, osdpdump_message_tracking [ctx->osdp_pdu.command_response].payload);
  if ((osdpdump_message_tracking [ctx->osdp_pdu.command_response].payload EQUALS OSDPDUMP_TRACKING_NO_PAYLOAD) &&
    (packet->payload_length > 0))
  {
    sprintf(tstring, "  - Unexpected payload (%d. bytes) detected.\n", packet->payload_length);
    strcat(ctx->output_text, tstring);
    ctx->note_count ++;
  };

  return(status);

} /* osdpdump_review_input */

