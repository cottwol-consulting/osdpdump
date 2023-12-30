/*
  osdpdump.h - definitions for osdpdump

  (C)2021-2023 Smithee Solutions LLC

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

#define EQUALS ==
#define ST_OK                            ( 0)
#define ST_OSDPDUMP_BAD_INPUT_FORMAT     (-1)
#define ST_OSDPDUMP_BAD_INPUT_FILE       (-2)
#define ST_OSDPDUMP_PACKET               (-3)
#define ST_OSDPDUMP_MORE                 (-4)
#define ST_OSDPDUMP_NEED_MORE_DATA       (-5)
#define ST_OSDPDUMP_SOURCE_NOT_SUPPORTED (-6)
#define ST_OSDPDUMP_FILE_READ_ERROR      (-7)
#define ST_OSDPDUMP_INPUT_ERROR_1        (-8)
#define ST_OSDPDUMP_INPUT_ERROR_2        (-9)
#define ST_OSDPDUMP_INPUT_ERROR_3        (-10)
#define ST_OSDPDUMP_LINE_TOO_LONG        (-11)

#define OSDPDUMP_BUFFER_MAX (8192)
#define OSDPDUMP_STRING     (3*OSDPDUMP_BUFFER_MAX)

#define OSDPDUMP_SOURCE_OSDPCAP (1)
#define OSDPDUMP_SOURCE_SERIAL  (2)

#define OSDPDUMP_ANA_STRICT (2)

#define OSDPDUMP_FMT_1LINE (0x01)     // 1-line, no hex, no comments
#define OSDPDUMP_FMT_2LINE (0x02)     // 1-line, hex
#define OSDPDUMP_FMT_ANNOTATED (0x03) // 2 lines plus commentary
#define OSDPDUMP_FMT_SUMMARY   (0x04) // just the summary
#define OSDPDUMP_FMT_MAC       (0x05) // output MAC only

#define OSDPDUMP_PD_MAX (31)

#define OSDPDUMP_PD_ABSENT  (0)
#define OSDPDUMP_PD_PRESENT (1)

#define OSDPDUMP_ANA_PD  (1)
#define OSDPDUMP_ANA_ACU (2)

#define OSDPDUMP_PDU_MAX (1440) // per SIA OSDP 2.2

#define OSDPDUMP_OPT_ANALYZE       (0x0000)
#define OSDPDUMP_OPT_HELP          (0x0001)
#define OSDPDUMP_OPT_REPORT_FORMAT (0x0002)
#define OSDPDUMP_OPT_SOURCE        (0x0003)
#define OSDPDUMP_OPT_VERBOSITY     (0x0004)
#define OSDPDUMP_OPT_VERSION       (0x0005)
#define OSDPDUMP_OPT_ADDRESS       (0x0006)

#define OSDPDUMP_CMD_DUMP (0x01)
#define OSDPDUMP_CMD_HELP (0x00)
#define OSDPDUMP_CMD_VERSION (0x02)

typedef struct osdpdump_input
{
  int length;
  unsigned char raw_bytes[OSDPDUMP_BUFFER_MAX];
  char input_string [8*OSDPDUMP_STRING];
  char time_seconds [1024];
  char time_nanoseconds [1024];
} OSDPDUMP_INPUT;

typedef struct osdpdump_pd_context
{
  int state;
  int last_received_sequence;
  unsigned char last_command_response;
  unsigned short int scs_status;
} OSDPDUMP_PD_CONTEXT;

#define OSDPDUMP_VALID (1)
#define OSDPDUMP_INVALID (0)

#define OSDPDUMP_TRACKING_NO_PAYLOAD (-1)

typedef struct opsdpdump_tracking
{
  int count;
  char *tag; // command and response
  char *r_tag; // response if different
  unsigned char valid_SCB;
  unsigned char valid_r_SCB;
  unsigned char valid_clear_always;
  int payload; // -1 prohibited, 0=unchecked, 1-14xx
} OSDPDUMP_TRACKING;

#define OSDPDUMP_COMPLETION_SOM    (0x0001)
#define OSDPDUMP_COMPLETION_SCB    (0x0002)
#define OSDPDUMP_COMPLETION_CMD    (0x8000)
#define OSDPDUMP_COMPLETION_RSP    (0x4000)
#define OSDPDUMP_COMPLETION_SCBK_D (0x0004)
typedef struct osdpdump_working_packet
{
  unsigned char octets [2048]; // max
  int octet_length;
  unsigned short int completion; // bitmask
  int completion_status;
  int role; // 0x80 for PD or 0x00 for ACU
  int command_response;
  int scs_type;
  int scs_length;
  int sequence;
  unsigned char address;
  unsigned char packet_check [2];
  int check_type; // 0=CRC 1=Checksum
  int payload_length;
  unsigned char mac [4];
//  unsigned char remainder [2048];
} OSDPDUMP_WORKING_PACKET;

typedef struct osdpdump_context
{
  int verbosity;
  int current_packet_number;
  int command; // command to the osdpdump program
//TODO sync these with command line switches and document
  int note_count;
  int analysis; // loose=0 normal=1 strict=2 3-255 rfu
  int input_source; // 1=file, 2=serial device
  int analysis_view; // 0=PD, 1=ACU, 2-255 RFU
  int output_report; // 1=yes
  int output_analysis; // 1=yes
  unsigned char specific_address;
  int specific_address_requested;
  int print_format;
  FILE *dump_file_handle;

  // statistics
  int dropped_octets;
  int detected_packets;
  int skipped_packets;

  OSDPDUMP_WORKING_PACKET osdp_pdu;
  char packet_seconds [1024];
  char packet_nanoseconds [1024];
  char input_path [OSDPDUMP_STRING];
  OSDPDUMP_PD_CONTEXT pd_ctx [OSDPDUMP_PD_MAX+1];
  unsigned long int histo_size;
  OSDPDUMP_INPUT accumulated_message;
  char output_text [16384]; //maxstring
} OSDPDUMP_CONTEXT;

unsigned char checksum(unsigned char *msg, int length);
int osdpdump_accumulate_input(OSDPDUMP_CONTEXT *ctx, OSDPDUMP_INPUT *input_value);
int osdpdump_command_offset(OSDPDUMP_CONTEXT *ctx, OSDPDUMP_WORKING_PACKET *pkt);
char *osdpdump_command_string(OSDPDUMP_CONTEXT *ctx, unsigned char command_response);
int osdpdump_digester(OSDPDUMP_CONTEXT *ctx);
int osdpdump_hex_to_raw_bytes(OSDPDUMP_CONTEXT *ctx, char *hex_string, unsigned char *raw_bytes, int *returned_length);
int osdpdump_initialize(OSDPDUMP_CONTEXT *ctx, int argc, char *argv []);
void osdpdump_init_tracking(OSDPDUMP_CONTEXT *ctx, OSDPDUMP_TRACKING osdpdump_message_tracking [256]);
int osdpdump_mac_stats(OSDPDUMP_CONTEXT *ctx, unsigned char *mac);
int osdpdump_mac_stats_init(OSDPDUMP_CONTEXT *ctx);
char *osdpdump_nak_reason(OSDPDUMP_CONTEXT *ctx, unsigned char nak_reason);
int osdpdump_packet_accumulate(OSDPDUMP_CONTEXT *ctx, OSDPDUMP_INPUT *raw, OSDPDUMP_INPUT *accumulated_packet);
int osdpdump_parse(OSDPDUMP_CONTEXT *ctx);
int osdpdump_print(OSDPDUMP_CONTEXT *ctx);
void osdpdump_print_annotation(OSDPDUMP_CONTEXT *ctx, OSDPDUMP_WORKING_PACKET *packet);
int osdpdump_print_hex(OSDPDUMP_CONTEXT *ctx);
void osdpdump_print_one_line(OSDPDUMP_CONTEXT *ctx, OSDPDUMP_WORKING_PACKET *packet);
int osdpdump_read_input(OSDPDUMP_CONTEXT *ctx, OSDPDUMP_INPUT *input_value);
int osdpdump_review_input(OSDPDUMP_CONTEXT *ctx);
char *osdpdump_strip_to_hexits(char *hex_string);
int osdpdump_summary(OSDPDUMP_CONTEXT *ctx);
unsigned short int fCrcBlk(unsigned char *pData, unsigned short int nLength);

