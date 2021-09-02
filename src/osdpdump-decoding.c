/*
  osdpdump-decoding - decoding osdp packet into text

  (C)2021 Smithee Solutions LLC

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

char
  *osdpdump_command_string
    (OSDPDUMP_CONTEXT *ctx,
    unsigned char command_response)

{ /* osdpdump_command_string */

  static char decoded [1024]; //maxstring


  switch(command_response)
  {
  default:
    strcpy(decoded, "Unknown          ");
    break;
  case OSDP_IEC_ACK:
    strcpy(decoded, "osdp_ACK         ");
    break;
  case OSDP_IEC_ACURXSIZE:
    strcpy(decoded, "osdp_ACURXSIZE   ");
    break;
  case OSDP_IEC_BUSY:
    strcpy(decoded, "osdp_BUSY        ");
    break;
  case OSDP_IEC_BUZ:
    strcpy(decoded, "osdp_BUZ         ");
    break;
  case OSDP_IEC_CAP:
    strcpy(decoded, "osdp_CAP         ");
    break;
  case OSDP_IEC_CCRYPT: // note CHLNG and CCRYPT are the same number
    if (ctx->osdp_pdu.completion_status & OSDPDUMP_COMPLETION_RSP)
    {
      strcpy(decoded, "osdp_CCRYPT      ");
    }
    else
    {
      strcpy(decoded, "osdp_CHLNG       ");
    };
    break;
  case OSDP_IEC_COM:
    strcpy(decoded, "osdp_COM         ");
    break;
  case OSDP_IEC_COMSET:
    strcpy(decoded, "osdp_COMSET      ");
    break;
  case OSDP_IEC_CRAUTH:
    strcpy(decoded, "osdp_CRAUTH      ");
    break;
  case OSDP_IEC_CRAUTHR:
    strcpy(decoded, "osdp_CRAUTHR     ");
    break;
  case OSDP_IEC_FILETRANSFER:
    strcpy(decoded, "osdp_FILETRANSFER");
    break;
  case OSDP_IEC_FTSTAT:
    strcpy(decoded, "osdp_FTSTAT      ");
    break;
  case OSDP_IEC_GENAUTH:
    strcpy(decoded, "osdp_GENAUTH     ");
    break;
  case OSDP_IEC_GENAUTHR:
    strcpy(decoded, "osdp_GENAUTHR    ");
    break;
  case OSDP_IEC_ID:
    strcpy(decoded, "osdp_ID          ");
    break;
  case OSDP_IEC_ISTAT:
    strcpy(decoded, "osdp_ISTAT       ");
    break;
  case OSDP_IEC_ISTATR:
    strcpy(decoded, "osdp_ISTATR      ");
    break;
  case OSDP_IEC_KEEPACTIVE:
    strcpy(decoded, "osdp_KEEPACTIVE  ");
    break;
  case OSDP_IEC_KEYPAD:
    strcpy(decoded, "osdp_KEYPAD      ");
    break;
  case OSDP_IEC_KEYSET:
    strcpy(decoded, "osdp_KEYSET      ");
    break;
  case OSDP_IEC_LED:
    strcpy(decoded, "osdp_LED         ");
    break;
  case OSDP_IEC_LSTAT:
    strcpy(decoded, "osdp_LSTAT       ");
    break;
  case OSDP_IEC_LSTATR:
    strcpy(decoded, "osdp_LSTATR      ");
    break;
  case OSDP_IEC_MFG:
    strcpy(decoded, "osdp_MFG         ");
    break;
  case OSDP_IEC_MFGERRR:
    strcpy(decoded, "osdp_MFGERRR     ");
    break;
  case OSDP_IEC_NAK:
    strcpy(decoded, "osdp_NAK         ");
    break;
  case OSDP_IEC_OSTAT:
    strcpy(decoded, "osdp_OSTAT       ");
    break;
  case OSDP_IEC_OSTATR:
    strcpy(decoded, "osdp_OSTATR      ");
    break;
  case OSDP_IEC_OUT:
    strcpy(decoded, "osdp_OUT         ");
    break;
  case OSDP_IEC_PDCAP:
    strcpy(decoded, "osdp_PDCAP       ");
    break;
  case OSDP_IEC_PDID:
    strcpy(decoded, "osdp_PDID        ");
    break;
  case OSDP_IEC_POLL:
    strcpy(decoded, "osdp_POLL        ");
    break;
  case OSDP_IEC_RAW:
    strcpy(decoded, "osdp_RAW         ");
    break;
  case OSDP_IEC_RMAC_I:
    strcpy(decoded, "osdp_RMAC_I      ");
    break;
  case OSDP_IEC_RSTAT:
    strcpy(decoded, "osdp_RSTAT       ");
    break;
  case OSDP_IEC_RSTATR:
    strcpy(decoded, "osdp_RSTATR      ");
    break;
  case OSDP_IEC_SCRYPT:
    strcpy(decoded, "osdp_SCRYPT      ");
    break;
  case OSDP_IEC_TEXT:
    strcpy(decoded, "osdp_TEXT        ");
    break;
  };
  return(decoded);

} /* osdpdump_command_string */

