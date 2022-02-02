/*
  osdpdump-decoding.h - values and strings for OSDP decoding

  (C)2021-2022 Smithee Solutions LLC

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
#define OSDP_IEC_SOM     (0x53)
#define OSDP_IEC_CTL_SCB (0x08) // bit in CTL for security control block(scb)
#define OSDP_IEC_CTL_CRC (0x04) // bit in CTL for crc/checksum
#define OSDP_SCS_11 (0x11)
#define OSDP_SCS_12 (0x12)
#define OSDP_SCS_13 (0x13)
#define OSDP_SCS_14 (0x14)
#define OSDP_SCS_15 (0x15)
#define OSDP_SCS_16 (0x16)
#define OSDP_SCS_17 (0x17)
#define OSDP_SCS_18 (0x18)

#define OSDP_IEC_ACK          (0x40)
#define OSDP_IEC_ACURXSIZE    (0x7b)
#define OSDP_IEC_BIOMATCH     (0x74)
#define OSDP_IEC_BIOMATCHR    (0x58)
#define OSDP_IEC_BIOREAD      (0x73)
#define OSDP_IEC_BIOREADR     (0x57)
#define OSDP_IEC_BUSY         (0x79)
#define OSDP_IEC_BUZ          (0x6A)
#define OSDP_IEC_CAP          (0x62)
#define OSDP_IEC_COM          (0x54)
#define OSDP_IEC_COMSET       (0x6E)
#define OSDP_IEC_CHLNG        (0x76)
#define OSDP_IEC_CCRYPT       (0x76)
#define OSDP_IEC_GENAUTH      (0xA4)
#define OSDP_IEC_CRAUTH       (0xA5)
#define OSDP_IEC_FILETRANSFER (0x7C)
#define OSDP_IEC_FTSTAT       (0x7A)
#define OSDP_IEC_ID           (0x61)
#define OSDP_IEC_ISTAT        (0x65)
#define OSDP_IEC_ISTATR       (0x49)
#define OSDP_IEC_KEEPACTIVE   (0xA7)
#define OSDP_IEC_KEYPAD       (0x53)
#define OSDP_IEC_KEYSET       (0x75)
#define OSDP_IEC_LED          (0x69)
#define OSDP_IEC_LSTAT        (0x64)
#define OSDP_IEC_LSTATR       (0x48)
#define OSDP_IEC_MFG          (0x80)
#define OSDP_IEC_MFGERRR      (0x84)
#define OSDP_IEC_MFGREP       (0x90)
#define OSDP_IEC_NAK          (0x41)
#define OSDP_IEC_OSTAT        (0x66)
#define OSDP_IEC_OSTATR       (0x4A)
#define OSDP_IEC_OUT          (0x68)
#define OSDP_IEC_PDCAP        (0x46)
#define OSDP_IEC_PDID         (0x45)
#define OSDP_IEC_POLL         (0x60)
#define OSDP_IEC_RAW          (0x50)
#define OSDP_IEC_RMAC_I       (0x78)
#define OSDP_IEC_RSTAT        (0x67)
#define OSDP_IEC_RSTATR       (0x4b)
#define OSDP_IEC_SCRYPT       (0x77)
#define OSDP_IEC_TEXT         (0x6b)
#define OSDP_IEC_GENAUTHR     (0x81)
#define OSDP_IEC_CRAUTHR      (0x82)

