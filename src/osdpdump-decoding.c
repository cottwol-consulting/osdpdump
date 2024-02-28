/*
  osdpdump-decoding - decoding osdp packet into text

  (C)2021-2024 Smithee Solutions LLC

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
#include <stdio.h>
#include <string.h>

#include <osdpdump.h>
#include <osdpdump-decoding.h>
OSDPDUMP_TRACKING osdpdump_message_tracking [256];


/*
  osdpdump_command_string - return text string for a command/response

  Returns:
    character string, fixed size with trailing spaces
*/

char
  *osdpdump_command_string
    (OSDPDUMP_CONTEXT *ctx,
    unsigned char command_response)

{ /* osdpdump_command_string */

  int payload_offset;
  static char decoded [1024]; //maxstring


  payload_offset = ctx->osdp_pdu.payload_offset;
  if (payload_offset EQUALS 0) // not yet filled in
    payload_offset = 6; // cleartext

  if (osdpdump_message_tracking [command_response].tag)
  {
    strcpy(decoded, osdpdump_message_tracking [command_response].tag);
  }
  else
  {
    strcpy(decoded, "Unknown          ");
  };
  if (command_response EQUALS OSDP_IEC_CCRYPT)
  {
    if (ctx->osdp_pdu.completion_status & OSDPDUMP_COMPLETION_RSP)
    {
      strcpy(decoded, "osdp_CCRYPT      ");
    }
    else
    {
      strcpy(decoded, "osdp_CHLNG       ");
    };
  };
  if (command_response EQUALS OSDP_IEC_PIVDATAR)
  {
    if (ctx->osdp_pdu.completion_status & OSDPDUMP_COMPLETION_CMD)
    {
      strcpy(decoded, "osdp_MFG         ");
    }
    else
    {
      strcpy(decoded, "osdp_PIVDATAR    ");
    };
  };
  return(decoded);

} /* osdpdump_command_string */


void
  osdpdump_init_tracking
    (OSDPDUMP_CONTEXT *ctx,
    OSDPDUMP_TRACKING osdpdump_message_tracking [256])

{ /* osdpdump_init_tracking */

  memset(&(osdpdump_message_tracking [0]), 0, 256*sizeof(OSDPDUMP_TRACKING));

#define TRACK(cr,tagstring,scb,clear) \
  osdpdump_message_tracking [cr].tag = tagstring; \
  osdpdump_message_tracking [cr].valid_SCB = scb; \
  osdpdump_message_tracking [cr].valid_clear_always = clear;
#define TRACK_EX(cr,tagstring,scb,clear,available_payload) \
  osdpdump_message_tracking [cr].tag = tagstring; \
  osdpdump_message_tracking [cr].valid_SCB = scb; \
  osdpdump_message_tracking [cr].valid_clear_always = clear; \
  osdpdump_message_tracking [cr].payload = available_payload;

  TRACK(OSDP_IEC_ACK, "osdp_ACK         ", OSDP_SCS_16, OSDPDUMP_INVALID);
  osdpdump_message_tracking [OSDP_IEC_ACURXSIZE].tag = "osdp_ACURXSIZE   ";
  osdpdump_message_tracking [OSDP_IEC_ACURXSIZE].valid_SCB = OSDP_SCS_17;
  osdpdump_message_tracking [OSDP_IEC_ACURXSIZE].valid_clear_always = OSDPDUMP_INVALID;
  osdpdump_message_tracking [OSDP_IEC_BUSY].tag = "osdp_BUSY        ";
  osdpdump_message_tracking [OSDP_IEC_BUSY].valid_SCB = OSDP_SCS_15;
  osdpdump_message_tracking [OSDP_IEC_BUSY].valid_clear_always = OSDPDUMP_INVALID;
  osdpdump_message_tracking [OSDP_IEC_BUZ].tag = "osdp_BUZ         ";
  osdpdump_message_tracking [OSDP_IEC_BUZ].valid_SCB = OSDP_SCS_17;
  osdpdump_message_tracking [OSDP_IEC_BUZ].valid_clear_always = OSDPDUMP_INVALID;
  TRACK(OSDP_IEC_FILETRANSFER, "osdp_FILETRANSFER", OSDP_SCS_17, OSDPDUMP_VALID);
  TRACK(OSDP_IEC_BIOMATCH,     "osdp_BIOMATCH    ", OSDP_SCS_17, OSDPDUMP_INVALID);
  TRACK(OSDP_IEC_BIOMATCHR,    "osdp_BIOMATCHR   ", OSDP_SCS_18, OSDPDUMP_INVALID);
  TRACK(OSDP_IEC_BIOREAD,      "osdp_BIOREAD     ", OSDP_SCS_17, OSDPDUMP_INVALID);
  TRACK(OSDP_IEC_BIOREADR,     "osdp_BIOREADR    ", OSDP_SCS_18, OSDPDUMP_INVALID);
  TRACK(OSDP_IEC_CAP, "osdp_CAP         ", OSDP_SCS_17, OSDPDUMP_VALID);
  osdpdump_message_tracking [OSDP_IEC_CCRYPT].tag = "osdp_CHLNG       ";
  osdpdump_message_tracking [OSDP_IEC_CCRYPT].valid_SCB = OSDP_SCS_11;
  osdpdump_message_tracking [OSDP_IEC_CCRYPT].r_tag = "osdp_CCRYPT      ";
  osdpdump_message_tracking [OSDP_IEC_CCRYPT].valid_r_SCB = OSDP_SCS_12;
  osdpdump_message_tracking [OSDP_IEC_CCRYPT].valid_clear_always = OSDPDUMP_VALID;
  TRACK(OSDP_IEC_COM, "osdp_COM         ", OSDP_SCS_18, OSDPDUMP_VALID);
  TRACK(OSDP_IEC_COMSET, "osdp_COMSET      ", OSDP_SCS_17, OSDPDUMP_VALID);
  TRACK(OSDP_IEC_CRAUTH, "osdp_CRAUTH      ", OSDP_SCS_17, OSDPDUMP_INVALID);
  TRACK(OSDP_IEC_CRAUTHR, "osdp_CRAUTHR     ", OSDP_SCS_18, OSDPDUMP_INVALID);
  TRACK(OSDP_IEC_FILETRANSFER, "osdp_FILETRANSFER", OSDP_SCS_17, OSDPDUMP_VALID);
  TRACK(OSDP_IEC_FTSTAT, "osdp_FTSTAT      ", OSDP_SCS_18, OSDPDUMP_VALID);
  TRACK(OSDP_IEC_GENAUTH, "osdp_GENAUTH     ", OSDP_SCS_17, OSDPDUMP_INVALID);
  TRACK(OSDP_IEC_GENAUTHR, "osdp_GENAUTHR    ", OSDP_SCS_18, OSDPDUMP_INVALID);
  TRACK(OSDP_IEC_ID, "osdp_ID          ", OSDP_SCS_17, OSDPDUMP_VALID);
  TRACK(OSDP_IEC_ISTAT, "osdp_ISTAT       ", OSDP_SCS_15, OSDPDUMP_INVALID);
  TRACK(OSDP_IEC_ISTATR, "osdp_ISTATR      ", OSDP_SCS_18, OSDPDUMP_INVALID);
  TRACK(OSDP_IEC_KEEPACTIVE, "osdp_KEEPACTIVE  ", OSDP_SCS_17, OSDPDUMP_INVALID);
  TRACK(OSDP_IEC_KEYPAD, "osdp_KEYPAD      ", OSDP_SCS_18, OSDPDUMP_INVALID);
  TRACK(OSDP_IEC_KEYSET, "osdp_KEYSET      ", OSDP_SCS_17, OSDPDUMP_INVALID);
  TRACK(OSDP_IEC_LED, "osdp_LED         ", OSDP_SCS_17, OSDPDUMP_INVALID);
  TRACK(OSDP_IEC_LSTAT, "osdp_LSTAT       ", OSDP_SCS_15, OSDPDUMP_INVALID);
  TRACK(OSDP_IEC_LSTATR, "osdp_LSTATR      ", OSDP_SCS_18, OSDPDUMP_INVALID);
                         //TRACK(OSDP_IEC_MFG, "osdp_MFG         ", OSDP_SCS_17, OSDPDUMP_INVALID);
  osdpdump_message_tracking [OSDP_IEC_MFG].tag = "osdp_MFG         ";
  osdpdump_message_tracking [OSDP_IEC_MFG].valid_SCB = OSDP_SCS_17;
  osdpdump_message_tracking [OSDP_IEC_MFG].r_tag = "osdp_PIVDATAR    ";
  osdpdump_message_tracking [OSDP_IEC_MFG].valid_r_SCB = OSDP_SCS_18;
  osdpdump_message_tracking [OSDP_IEC_MFG].valid_clear_always = OSDPDUMP_INVALID;
  TRACK(OSDP_IEC_MFGERRR, "osdp_MFGERRR     ", OSDP_SCS_18, OSDPDUMP_INVALID);
  TRACK(OSDP_IEC_MFGREP,  "osdp_MFGREP      ", OSDP_SCS_18, OSDPDUMP_INVALID);
  TRACK(OSDP_IEC_NAK,     "osdp_NAK         ", OSDP_SCS_18, OSDPDUMP_INVALID);
  TRACK(OSDP_IEC_OSTAT,   "osdp_OSTAT       ", OSDP_SCS_15, OSDPDUMP_INVALID);
  TRACK(OSDP_IEC_OSTATR,  "osdp_OSTATR      ", OSDP_SCS_18, OSDPDUMP_INVALID);
  TRACK(OSDP_IEC_OUT,     "osdp_OUT         ", OSDP_SCS_17, OSDPDUMP_INVALID);
  TRACK(OSDP_IEC_PDCAP,   "osdp_PDCAP       ", OSDP_SCS_18, OSDPDUMP_VALID);
  TRACK(OSDP_IEC_PIVDATA, "osdp_PIVDATA     ", OSDP_SCS_17, OSDPDUMP_INVALID);
  //TRACK(OSDP_IEC_PIVDATAR,"osdp_PIVDATAR    ", OSDP_SCS_18, OSDPDUMP_INVALID);
  TRACK(OSDP_IEC_PDID,    "osdp_PDID        ", OSDP_SCS_18, OSDPDUMP_VALID);
  TRACK_EX(OSDP_IEC_POLL, "osdp_POLL        ", OSDP_SCS_15, OSDPDUMP_INVALID, OSDPDUMP_TRACKING_NO_PAYLOAD);
  TRACK(OSDP_IEC_RAW, "osdp_RAW         ", OSDP_SCS_18, OSDPDUMP_INVALID);
  TRACK(OSDP_IEC_RMAC_I, "osdp_RMAC_I      ", OSDP_SCS_14, OSDPDUMP_VALID);
  TRACK(OSDP_IEC_RSTAT, "osdp_RSTAT       ", OSDP_SCS_15, OSDPDUMP_INVALID);
  TRACK(OSDP_IEC_RSTATR, "osdp_RSTATR      ", OSDP_SCS_18, OSDPDUMP_INVALID);
  TRACK(OSDP_IEC_SCRYPT, "osdp_SCRYPT      ", OSDP_SCS_13, OSDPDUMP_VALID);
  TRACK(OSDP_IEC_TEXT, "osdp_TEXT        ", OSDP_SCS_17, OSDPDUMP_INVALID);

} /* osdpdump_init_tracking */


/*
  osdpdump_nak_reason - return text string for NAK reason code

  Returns:
    character string, fixed size with trailing spaces

  Note that if it is unknown this text string includes the hex value.
*/

char
  *osdpdump_nak_reason
    (OSDPDUMP_CONTEXT *ctx,
    unsigned char nak_reason)

{
  static char answer [1024];

  switch(nak_reason)
  {
  default:
    sprintf(answer, "Unknown(%02x) ", nak_reason);
    break;
  case OSDP_IEC_NAK_ENCRYPTION_REQUIRED:
    strcpy(answer, "Encryption Required");
    break;
  case OSDP_IEC_NAK_CMD_LENGTH_ERROR:
    strcpy(answer, "Command length error");
    break;
  case OSDP_IEC_NAK_SECURITY_UNAVAILABLE:
    strcpy(answer, "No SC Mode         ");
    break;
  case OSDP_IEC_NAK_SEQUENCE_ERROR:
    strcpy(answer, "Sequence Error     ");
    break;
  case OSDP_IEC_NAK_UNABLE_TO_PROCESS:
    strcpy(answer, "Cannot process     ");
    break;
  case OSDP_IEC_NAK_UNKNOWN_COMMAND:
    strcpy(answer, "Unknown command    ");
    break;
  };
  return(&(answer [0]));
}

