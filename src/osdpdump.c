int verbosity=9;
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
  int status;
  OSDPDUMP_CONTEXT osdp_dump_context;


  status = ST_OK;
  ctx = &osdp_dump_context;
  status = osdpdump_initialize(ctx, argc, argv);

  done = 0;
  while (!done)
  {
    status = osdpdump_read_input(ctx, &input_value);
    if (status EQUALS ST_OK)
    {
      status = osdpdump_accumulate_input(ctx, &input_value);
      if (status EQUALS ST_OSDPDUMP_PACKET)
      {
        input_exhausted = 0;
        while (!input_exhausted)
        {
          status = osdpdump_parse(ctx);
          if (status EQUALS ST_OK)
            status = osdpdump_review_input(ctx);
          if (status EQUALS ST_OK)
            status = osdpdump_print(ctx);
          if (status != ST_OK)
            input_exhausted = 1;
          if (status EQUALS ST_OK)
            status = osdpdump_accumulate_input(ctx, &input_value);
          if (status != ST_OSDPDUMP_PACKET)
            input_exhausted = 1;
        };
      };
      if (status EQUALS ST_OSDPDUMP_NEED_MORE_DATA)
      {
fprintf(stderr, "DEBUG: need more data\n");
        status = ST_OK;
      };
    };
    if (status != ST_OK)
      done = 1;
    fflush(stdout); fflush(stderr);
  };
  if (status EQUALS ST_OK)
    status = osdpdump_summary(ctx);

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
//  int completion_status;
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
  osdpdump_initialize
    (OSDPDUMP_CONTEXT *ctx,
    int argc,
    char *argv [])

{ /* osdpdump_initialize */

  int idx;
  int status;


//??  status_io = fgets(line, sizeof(line), f);

  fprintf(stderr, "osdpdump %s is in startup.\n", OSDPDUMP_VERSION);
  status = ST_OK;
  memset(ctx, 0, sizeof(*ctx));
  ctx->input_source = OSDPDUMP_SOURCE_OSDPCAP;
  strcpy(ctx->input_path, "./current.osdpcap");
  if (argc > 1)
    strcpy(ctx->input_path, argv [1]);
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

fprintf(stderr, "DEBUG: parse command line\n");
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

#if 0
      ctx->osdp_pdu.command_response = 0x80 & input_value->raw_bytes [1];
      ctx->osdp_pdu.address = 0x7F & input_value->raw_bytes [1];
#endif

int osdpdump_packet_accumulate
  (OSDPDUMP_CONTEXT *ctx,
  OSDPDUMP_INPUT *input_bytes,
  OSDPDUMP_INPUT *pkt)

{ /* osdpdump_packet_accumulate */

  unsigned char current_byte;
  int drop_octets;
  OSDPDUMP_WORKING_PACKET *packet;
  int process_octets;
  int status;
  unsigned char temp_bytes [2048]; //max


  // assume we used it or trashed it and need more.

  status = ST_OSDPDUMP_NEED_MORE_DATA;
  drop_octets = 0;
  process_octets = 0;
  packet = &(ctx->osdp_pdu);

  if (input_bytes->length > 0)
  {
    // take first byte
    input_bytes->length --;
    current_byte = input_bytes->raw_bytes [0];
fprintf(stderr,"DEBUG: octet is %02x\n", current_byte);
    memset(temp_bytes, 0, sizeof(temp_bytes));
    memcpy(temp_bytes, input_bytes->raw_bytes+1, input_bytes->length);
    memcpy(input_bytes->raw_bytes, temp_bytes, input_bytes->length);
    input_bytes->raw_bytes [input_bytes->length] = 0x00;


    switch(packet->octet_length)
    {
    case 0:
      // we're looking for the SOM
      if (current_byte EQUALS OSDPDUMP_PDU_SOM)
      {
        packet->octets [packet->octet_length] = current_byte;
        packet->octet_length++;
fprintf(stderr, "DEBUG: SOM found.  check packet length %d\n", packet->octet_length);
        status = ST_OSDPDUMP_NEED_MORE_DATA;
      }
      else
      {
        drop_octets = 1;
      };
      break;
    case 1:
      // looking for first byte of length
      packet->octets [packet->octet_length] = current_byte;
      packet->octet_length++;
      status = ST_OSDPDUMP_NEED_MORE_DATA;
      break;
    case 2:
      // looking for second byte of length
      packet->octets [packet->octet_length] = current_byte;
      packet->octet_length++;
      status = ST_OSDPDUMP_NEED_MORE_DATA;
    };

zzz

zzz address is net then they two bytes

      packet->octets [packet->octet_length] = current_byte;
      packet->octet_length++;
      status = ST_OSDPDUMP_NEED_MORE_DATA;
    };

    // we have the alleged length.  make sure it's sane or dump
    // the whole thing.

    if ((packet->octet_length > 2) && (packet->octet_length < 4))
    {
      unsigned int pdu_length;
      pdu_length = (packet->octets [2] << 8) + packet->octets [1];
      if (pdu_length <= OSDPDUMP_PDU_MAX)
      {
fprintf(stderr, "DEBUG: have length (0x%x)\n", pdu_length);
        status = ST_OSDPDUMP_NEED_MORE_DATA;
      };
    }
    else
    {
      ctx->dropped_octets = ctx->dropped_octets + packet->octet_length;
      packet->octet_length = 0;
      status = ST_OSDPDUMP_NEED_MORE_DATA;
    };
  };
  if (drop_this_octet)
    ctx->dropped_octets ++;
  return(status);

} /* osdpdump_packet_accumulate */


int osdpdump_parse(OSDPDUMP_CONTEXT *ctx){printf("DEBUG: stub\n");return(0);}
int osdpdump_print(OSDPDUMP_CONTEXT *ctx){printf("DEBUG: stub\n");return(0);}


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
if (verbosity > 3)
  fprintf(stderr, "DEBUG: source is osdpcap %s\n", ctx->input_path);
    input_value->input_string [0] = 0; // init string to empty
    status_io = fgets(line, sizeof(line), ctx->dump_file_handle);
fprintf(stderr, "line %s\n", line);
    if (status_io != NULL)
    {
      strcpy(input_value->input_string, line);
      line_root = json_loads(input_value->input_string, 0, &status_json);
    };
    value = json_object_get(line_root, "data");
    if (json_is_string(value))
      strcpy(input_value->input_string, json_string_value(value));
    status = osdpdump_hex_to_raw_bytes(ctx, input_value->input_string, input_value->raw_bytes, &(input_value->length));
    break;
  default:
    status = ST_OSDPDUMP_BAD_INPUT_FORMAT;
    break;
  };
  return(status);

} /* osdpdump_read_input */


int osdpdump_review_input(OSDPDUMP_CONTEXT *ctx){printf("DEBUG: stub\n");return(0);}


int 
  osdpdump_summary
    (OSDPDUMP_CONTEXT *ctx)
{ /* osdpdump_summary */
  printf("DEBUG: stub\n");
  printf("%6d. octets dropped.\n", ctx->dropped_octets);
  return(0);

} /* osdpdump_summary */

