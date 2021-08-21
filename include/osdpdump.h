/*
  osdpdump.h - definitions for osdpdump

  (C)2021 Smithee Solutions LLC
*/

#define OSDPDUMP_VERSION "0.0.2-3"

#define EQUALS ==
#define ST_OK (0)
#define ST_OSDPDUMP_BAD_INPUT_FORMAT (-1)
#define ST_OSDPDUMP_BAD_INPUT_FILE   (-2)
#define ST_OSDPDUMP_PACKET           (-3)
#define ST_OSDPDUMP_MORE             (-4)
#define ST_OSDPDUMP_NEED_MORE_DATA   (-5)

#define OSDPDUMP_STRING     (1024)
#define OSDPDUMP_BUFFER_MAX (2048)

#define OSDPDUMP_SOURCE_OSDPCAP (1)
#define OSDPDUMP_SOURCE_SERIAL  (2)

#define OSDPDUMP_ANA_STRICT (2)

#define OSDPDUMP_PD_MAX (31)

#define OSDPDUMP_PD_ABSENT  (0)
#define OSDPDUMP_PD_PRESENT (1)

#define OSDPDUMP_ANA_PD  (1)
#define OSDPDUMP_ANA_ACU (2)

#define OSDPDUMP_PDU_MAX (1400) // tbd check
#define OSDPDUMP_PDU_SOM (0x53)

// values in the protocol

#define OSDP_SOM (0x53)

typedef struct osdpdump_input
{
  int length;
  unsigned char raw_bytes[OSDPDUMP_BUFFER_MAX];
  char input_string [OSDPDUMP_STRING*2];
} OSDPDUMP_INPUT;

typedef struct osdpdump_pd_context
{
  int state;
} OSDPDUMP_PD_CONTEXT;

#define OSDPDUMP_COMPLETION_SOM (0x0001)
typedef struct osdpdump_working_packet
{
  unsigned char octets [2048]; // max
  int octet_length;
  unsigned short int completion; // bitmask
  int completion_status;
  int command_response;
  unsigned char address;
  unsigned char packet_check [2];
  unsigned char remainder [2048];
} OSDPDUMP_WORKING_PACKET;

typedef struct osdpdump_context
{
  int verbosity;
  int analysis; // loose=0 normal=1 strict=2 3-255 rfu
  int input_source; // 1=file, 2=serial device
  int analysis_view; // 0=PD, 1=ACU, 2-255 RFU
  int output_report; // 1=yes
  int output_analysis; // 1=yes
  FILE *dump_file_handle;

  // statistics
  int dropped_octets;

  OSDPDUMP_WORKING_PACKET osdp_pdu;
  char input_path [OSDPDUMP_STRING];
  OSDPDUMP_PD_CONTEXT pd_ctx [OSDPDUMP_PD_MAX+1];
  OSDPDUMP_INPUT accumulated_message;
} OSDPDUMP_CONTEXT;

int osdpdump_accumulate_input(OSDPDUMP_CONTEXT *ctx, OSDPDUMP_INPUT *input_value);
int osdpdump_command_offset(OSDPDUMP_CONTEXT *ctx, OSDPDUMP_WORKING_PACKET *pkt);
int osdpdump_hex_to_raw_bytes(OSDPDUMP_CONTEXT *ctx, char *hex_string, unsigned char *raw_bytes, int *returned_length);
int osdpdump_initialize(OSDPDUMP_CONTEXT *ctx, int argc, char *argv []);
int osdpdump_packet_accumulate(OSDPDUMP_CONTEXT *ctx, OSDPDUMP_INPUT *raw, OSDPDUMP_INPUT *accumulated_packet);
int osdpdump_parse(OSDPDUMP_CONTEXT *ctx);
int osdpdump_print(OSDPDUMP_CONTEXT *ctx);
int osdpdump_read_input(OSDPDUMP_CONTEXT *ctx, OSDPDUMP_INPUT *input_value);
int osdpdump_review_input(OSDPDUMP_CONTEXT *ctx);
int osdpdump_summary(OSDPDUMP_CONTEXT *ctx);

