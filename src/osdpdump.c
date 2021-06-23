//zzz keep an accumulator buffer as well as the input queue.  input queue adds not replaces input

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
int zzzmain(int argc, char *argv []);
int osdpdump_accumulate_input(OSDPDUMP_CONTEXT *ctx, OSDPDUMP_INPUT *input_value);
int osdpdump_packet_accumulate(OSDPDUMP_INPUT *raw, OSDPDUMP_INPUT *accumulated_packet);


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
  status = zzzmain (argc, argv);
  ctx = &osdp_dump_context;
  status = osdpdump_initialize(ctx, argc, argv);

  done = 0;
  while (!done)
  {
#if 0
  get input
  add to working buffer
  pull from working buffer until SOM, return MORE
  pull from working buffer until whole packet, return MORE if not done
#endif
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
  if (input_value->length > 0)
    done = 0;
  if (!done)
  {
    while (!done)
    {
      status = osdpdump_packet_accumulate(input_value, accumulated_message);

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


  fprintf(stderr, "osdpdump %s is in startup.\n", OSDPDUMP_VERSION);
  status = ST_OK;
  memset(ctx, 0, sizeof(*ctx));
  ctx->input_source = OSDPDUMP_SOURCE_OSDPCAP;
  strcpy(ctx->input_path, "./current.osdpcap");
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

  switch(ctx->input_source)
  {
  case OSDPDUMP_SOURCE_OSDPCAP:
    ctx->dump_file_handle = fopen("current.osdpcap", "r");
//    ctx->dump_file_handle = fopen(ctx->input_path, "r");
    if (ctx->dump_file_handle EQUALS NULL)
      status = ST_OSDPDUMP_BAD_INPUT_FILE;
    break;
  };
  return(status);

} /* osdpdump_initialize */


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


int zzzmain (int argc, char *argv [])
{
  char line [1024];
  char *status_io;

  f = fopen("current.osdpcap", "r");
  status_io = fgets(line, sizeof(line), f);
  printf("line was %s\n", line);
  return(0);
}

 
zzz review
if not good packet start
eat first octet
drop
          ctx->dropped_octets ++;
status

if good packet start and not done
return need-more
        ctx->osdp_pdu.som = OSDP_SOM;

      ctx->osdp_pdu.command_response = 0x80 & input_value->raw_bytes [1];
      ctx->osdp_pdu.address = 0x7F & input_value->raw_bytes [1];

int osdpdump_packet_accumulate
  (OSDP_INPUT *input_bytes,
  OSDPDUMP_INPUT *pkt)
{
  unsigned char tmp_buffer [OSDPDUMP_BUFFER_MAX];

  // take first byte
          input_value->length --;
  // if whole update status else status is needs-more

  return(-1); }

