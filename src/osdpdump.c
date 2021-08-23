/*
  osdpdump - read a byte stream and analyze/display the OSDP protocol contents

  (C)2021 Smithee Solutions LLC

  Usage:
    osdpdump [--switches]
      --source=file <osdpcap file> (default is current.osdpcap)
      --source=serial <serial device name>
      --analyze=[,strict,loose]
      --report
      --analysis
*/
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <getopt.h>

#include <jansson.h>


#include <osdpdump.h>
typedef struct osdpdump_command_line_context
{
  int option;
} OSDPDUMP_COMMAND_LINE_CONTEXT;
#include <osdpdump-decoding.h>
FILE *f;
OSDPDUMP_COMMAND_LINE_CONTEXT osdpdump_command_line;
struct option longopts [] = {
  {"analyze", optional_argument, &osdpdump_command_line.option, OSDPDUMP_OPT_ANALYZE},
  {"help", 0, &osdpdump_command_line.option, OSDPDUMP_OPT_HELP},
  {"format", required_argument, &osdpdump_command_line.option, OSDPDUMP_OPT_REPORT_FORMAT},
  {"source", required_argument, &osdpdump_command_line.option, OSDPDUMP_OPT_SOURCE},
  {"verbosity", required_argument, &osdpdump_command_line.option, OSDPDUMP_OPT_VERBOSITY},
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
"--format=<n> - set report format.  1=2-line with dump; 2=1-line, no dump\n");
      fprintf(stdout,
"--source=<file> - set dump filename to read.\n");
      fprintf(stdout,
"--verbosity=<n> - set message verbosity.  0=quiet, 3=normal, 9=debug.\n");
      fprintf(stdout,
"--help - this message\n");
      break;

    case OSDPDUMP_CMD_DUMP:
      switch(ctx->input_source)
      {
      case OSDPDUMP_SOURCE_OSDPCAP:
        ctx->dump_file_handle = fopen(ctx->input_path, "r");
        if (ctx->dump_file_handle EQUALS NULL)
          status = ST_OSDPDUMP_BAD_INPUT_FILE;
      };
      status = osdpdump_digester(ctx);
      if (ctx->verbosity > 9)
        fprintf(stderr, "DEBUG: source is osdpcap %s\n", ctx->input_path);
      // regardless of what happened print the summary
      status = osdpdump_summary(ctx);
      break;
    };
  };

  fprintf(stdout, "%s", ctx->output_text); ctx->output_text [0] = 0;

  if (status != ST_OK)
    fprintf(stderr, "osdpdump completed, status was %d. errno=%d.\n", status, errno);
  return(status);

} /* main for osdpdump */


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


int
  osdpdump_digester
    (OSDPDUMP_CONTEXT *ctx)

{ /* osdpdump_digester */

  int done;
  int input_exhausted;
  OSDPDUMP_INPUT input_value;
  OSDPDUMP_WORKING_PACKET *packet;
  int status;


  if (ctx->verbosity > 0)
    fprintf(stdout, "OSDP Dump of file %s\n", ctx->input_path);
  done = 0;
  while (!done)
  {
    status = osdpdump_read_input(ctx, &input_value);
    if (ctx->verbosity > 9)
      fprintf(stderr, "DEBUG: osdpdump_read_input %d.\n", status);
    if (status EQUALS ST_OK)
    {
      status = osdpdump_accumulate_input(ctx, &input_value);
      if (status EQUALS ST_OSDPDUMP_PACKET)
      {
        ctx->current_packet_number ++;
        ctx->detected_packets ++;
        input_exhausted = 0;
        {
          status = osdpdump_parse(ctx);
          if (status EQUALS ST_OK)
            status = osdpdump_review_input(ctx);
          if (status EQUALS ST_OK)
          {
            status = osdpdump_print(ctx);
            fprintf(stdout, "%s", ctx->output_text); ctx->output_text [0] = 0;
          };
        };
      };
      packet = &(ctx->osdp_pdu);
      memset(packet, 0, sizeof(*packet));
    };
    if ((status != ST_OK) && (status != ST_OSDPDUMP_NEED_MORE_DATA))
      done = 1;
    fflush(stdout); fflush(stderr);
  };
  return(status);

} /* osdpdump_digester */


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
  ctx->print_format = OSDPDUMP_FMT_2LINE;
  ctx->analysis = OSDPDUMP_ANA_STRICT;
  ctx->input_source = OSDPDUMP_SOURCE_OSDPCAP;
  strcpy(ctx->input_path, "./current.osdpcap");
  osdpdump_command_line.option = OSDPDUMP_OPT_HELP;
ctx->analysis_view = OSDPDUMP_ANA_PD;
ctx->output_report = 1;
ctx->output_analysis = 1;

  // option switch processing

  done = 0;
  while (!done)
  {
    status_opt = getopt_long (argc, argv, optstring, longopts, NULL);
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
    case OSDPDUMP_OPT_ANALYZE:
      sscanf(optarg, "%d", &i);
      ctx->analysis = i;
      ctx->command = OSDPDUMP_CMD_DUMP;
      break;
    case OSDPDUMP_OPT_HELP:
      ctx->command = OSDPDUMP_CMD_HELP;
      break;
    case OSDPDUMP_OPT_REPORT_FORMAT:
      sscanf(optarg, "%d", &i);
      ctx->print_format = i;
      ctx->command = OSDPDUMP_CMD_DUMP;
      break;
    case OSDPDUMP_OPT_SOURCE:
      strcpy(ctx->input_path, optarg);
      ctx->command = OSDPDUMP_CMD_DUMP;
      break;
    case OSDPDUMP_OPT_VERBOSITY:
      sscanf(optarg, "%d", &i);
      ctx->verbosity = i;
      ctx->command = OSDPDUMP_CMD_DUMP;
      break;
    default:
      ctx->command = OSDPDUMP_CMD_HELP;
      break;
    };
    };
  };

  if (ctx->verbosity > 3)
    fprintf(stderr, "osdpdump %s is in startup.\n", OSDPDUMP_VERSION);
  fprintf(stdout, "osdpdump %s \n", OSDPDUMP_VERSION);

  for (idx=0; idx<OSDPDUMP_PD_MAX; idx++)
  {
    ctx->pd_ctx [idx].state = OSDPDUMP_PD_ABSENT;
  };
  return(status);

} /* osdpdump_initialize */


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
  int process_octets;
  int status;
  unsigned char temp_bytes [2048]; //max


  // assume we used it or trashed it and need more.

  status = ST_OSDPDUMP_NEED_MORE_DATA;
  drop_octets = 0;
  process_octets = 0;
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
        if (ctx->verbosity > 9)
          fprintf(stderr, "DEBUG: have length (0x%x)\n", pdu_length);
        status = ST_OSDPDUMP_NEED_MORE_DATA;
      }
      else
      {
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
  return(status);

} /* osdpdump_packet_accumulate */


int
  osdpdump_parse
    (OSDPDUMP_CONTEXT *ctx)

{ /* osdpdump_parse */
 
  unsigned char control_octet;
  OSDPDUMP_WORKING_PACKET *packet;


  packet = &(ctx->osdp_pdu);
  packet->address = 0x7F & (packet->octets [1]);
  control_octet = packet->octets [4];
  if (control_octet & OSDP_IEC_CTL_SCB)
    packet->completion_status = packet->completion_status | OSDPDUMP_COMPLETION_SCB;

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
    // if this is a CHLNG note which SCBK it's for in the PD context.

    if (packet->command_response EQUALS OSDP_IEC_CHLNG)
    {
#if 0
zzz
      assuming there are 3 octets in the scs header
        use 3rd octet of scs header to identify SCBK or SCBK-D
        note that in the pd context
#endif
      if (packet->octets [7] EQUALS 0) // 0 in 3rd octet means SCBK-D
        packet->completion_status = packet->completion_status | OSDPDUMP_COMPLETION_SCBK_D;
    }
  };

  packet->packet_check [0] = ctx->osdp_pdu.octets [ctx->osdp_pdu.octet_length-2];
  packet->packet_check [1] = ctx->osdp_pdu.octets [ctx->osdp_pdu.octet_length-1];
  packet = &(ctx->osdp_pdu);
  return(0);

} /* osdpdump_parse */


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
char line [2*1024];


  status = ST_OK;
  switch(ctx->input_source)
  {
  case OSDPDUMP_SOURCE_OSDPCAP:
    input_value->input_string [0] = 0; // init string to empty
    status_io = fgets(line, sizeof(line), ctx->dump_file_handle);
    if (status_io != NULL)
    {
      if (ctx->verbosity > 9)
        fprintf(stderr, "line %s\n", line);
      strcpy(input_value->input_string, line);
      line_root = json_loads(input_value->input_string, 0, &status_json);
    }
    else
    {
status = -1;
    };
    if (status EQUALS ST_OK)
    {
      value = json_object_get(line_root, "data");
      if (json_is_string(value))
        strcpy(input_value->input_string, json_string_value(value));
      status = osdpdump_hex_to_raw_bytes(ctx, input_value->input_string, input_value->raw_bytes, &(input_value->length));
    };
    break;
  default:
    status = ST_OSDPDUMP_BAD_INPUT_FORMAT;
    break;
  };
  return(status);

} /* osdpdump_read_input */


/*
  osdpdump_review_input - review the input so far and offer commentary
*/
int
  osdpdump_review_input
    (OSDPDUMP_CONTEXT *ctx)

{ /* osdpdump_review_input */

  ctx->detected_commands [ctx->osdp_pdu.command_response] ++;
  if (ctx->verbosity > 9)
    printf("DEBUG: osdpdump_review_input\n");
  return(0);

} /* osdpdump_review_input */

