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

#include <jansson.h>


#include <osdpdump.h>
#include <osdpdump-decoding.h>
FILE *f;


int
  main
    (int argc,
    char * argv [])

{ /* main for osdpdump */

  OSDPDUMP_CONTEXT *ctx;
  int done;
  int input_exhausted;
  OSDPDUMP_INPUT input_value;
  OSDPDUMP_WORKING_PACKET *packet;
  int status;
  OSDPDUMP_CONTEXT osdp_dump_context;


  status = ST_OK;
  ctx = &osdp_dump_context;
  status = osdpdump_initialize(ctx, argc, argv);
  if (ctx->verbosity > 9)
    fprintf(stderr, "DEBUG: source is osdpcap %s\n", ctx->input_path);

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
        input_exhausted = 0;
//        while (!input_exhausted)
        {
          status = osdpdump_parse(ctx);
          if (status EQUALS ST_OK)
            status = osdpdump_review_input(ctx);
          if (status EQUALS ST_OK)
            status = osdpdump_print(ctx);
//          if (status != ST_OK) input_exhausted = 1;
//          if (status EQUALS ST_OK) status = osdpdump_accumulate_input(ctx, &input_value);
//          if (status != ST_OSDPDUMP_PACKET) { input_exhausted = 1; };
        };
      };
      packet = &(ctx->osdp_pdu);
      memset(packet, 0, sizeof(*packet));
    };
    if (status != ST_OK)
      done = 1;
    fflush(stdout); fflush(stderr);
  };

  // regardless of what happened print the summary
  status = osdpdump_summary(ctx);
  fprintf(stdout, "%s", ctx->output_text);

  if (status != ST_OK)
    fprintf(stderr, "osdpdump completed, status was %d. errno=%d.\n", status, errno);
  return(status);

} /* main for osdpdump */


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
  int expected_length;
  int idx;
//  unsigned char som;
//  int command_response;
//  unsigned char address;
//  unsigned char remainder [2048];
  int status;


  status = ST_OSDPDUMP_NEED_MORE_DATA;
  accumulated_message = &(ctx->accumulated_message);
  expected_length = 2; // SOM and address
  done = 1;
  idx = 0;

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


int
  osdpdump_command_offset
    (OSDPDUMP_CONTEXT *ctx,
    OSDPDUMP_WORKING_PACKET *packet)
{ /* osdpdump_command_offset */

  int returned_offset;


  // SOM, address, length, ctl

  returned_offset = 1 + 1 + 2 + 1;

  return(returned_offset);

} /* osdpdump_command_offset */


int
  osdpdump_initialize
    (OSDPDUMP_CONTEXT *ctx,
    int argc,
    char *argv [])

{ /* osdpdump_initialize */

  int idx;
  int status;


  status = ST_OK;
  memset(ctx, 0, sizeof(*ctx));
ctx->verbosity = 9;
  if (ctx->verbosity > 3)
    fprintf(stderr, "osdpdump %s is in startup.\n", OSDPDUMP_VERSION);
  fprintf(stdout, "osdpdump %s \n", OSDPDUMP_VERSION);
ctx->print_format = 2;
  ctx->input_source = OSDPDUMP_SOURCE_OSDPCAP;
  strcpy(ctx->input_path, "./current.osdpcap");
  if (argc > 1)
    strcpy(ctx->input_path, argv [1]);

  fprintf(stdout, "OSDP Dump of file %s\n", ctx->input_path);
  for (idx=0; idx<OSDPDUMP_PD_MAX; idx++)
  {
    ctx->pd_ctx [idx].state = OSDPDUMP_PD_ABSENT;
  };
  ctx->analysis_view = OSDPDUMP_ANA_PD;

//      --source=file <osdpcap file> (default is current.osdpcap)
//      --source=serial <serial device name>
//      --analyze=[,strict,loose]
//      --report
//      --analysis
  ctx->analysis = OSDPDUMP_ANA_STRICT;
  ctx->output_report = 1;
  ctx->output_analysis = 1;

  f = fopen(ctx->input_path, "r");

  switch(ctx->input_source)
  {
  case OSDPDUMP_SOURCE_OSDPCAP:
    ctx->dump_file_handle = fopen(ctx->input_path, "r");
    if (ctx->dump_file_handle EQUALS NULL)
      status = ST_OSDPDUMP_BAD_INPUT_FILE;
    break;
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
 
  OSDPDUMP_WORKING_PACKET *packet;


  packet = &(ctx->osdp_pdu);
  packet->address = 0x7F & (packet->octets [1]);

  if (0x80 & packet->octets [1])
    packet->completion_status = packet->completion_status | OSDPDUMP_COMPLETION_RSP;
  else
    packet->completion_status = packet->completion_status | OSDPDUMP_COMPLETION_CMD;

  ctx->pd_ctx [packet->address].state = OSDPDUMP_PD_PRESENT;
  packet->command_response = ctx->osdp_pdu.octets [osdpdump_command_offset(ctx, packet)];
  packet->packet_check [0] = ctx->osdp_pdu.octets [ctx->osdp_pdu.octet_length-2];
  packet->packet_check [1] = ctx->osdp_pdu.octets [ctx->osdp_pdu.octet_length-1];
  packet = &(ctx->osdp_pdu);
  return(0);

} /* osdpdump_parse */


int
  osdpdump_print
    (OSDPDUMP_CONTEXT *ctx)

{ /* osdpdump_print */

  int i;
  OSDPDUMP_WORKING_PACKET *packet;


  packet = &(ctx->osdp_pdu);
  switch(ctx->print_format)
  {
  case 2:
    fprintf(stdout, "%s ", osdpdump_command_string(ctx, packet->command_response));
    fprintf(stdout, " A=%2d.", packet->address);
    fprintf(stdout, " CRC %02x%02x", packet->packet_check [0], packet->packet_check [1]);
    fprintf(stdout, "\n");
    fprintf(stdout, " Dump:");
    for (i=0; i<packet->octet_length; i++)
      fprintf(stdout, " %02x", packet->octets [i]);
    fprintf(stdout, "\n");
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

  if (ctx->verbosity > 9)
    printf("DEBUG: osdpdump_review_input\n");
  return(0);

} /* osdpdump_review_input */


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
  printf("Active PD's:");
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

