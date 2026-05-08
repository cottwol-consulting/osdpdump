/*
  osdpdump-vendor-lookup.c - look up vendor name by OUI

  (C)2021-2026 Smithee Solutions LLC

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

#include <osdpdump.h>
#include <osdpdump-vendor-identification.h>


char *oui_lookup
  (unsigned char octet1,
  unsigned char octet2,
  unsigned char octet3)

{ /* oui_lookup */

  int done;
  int oui_index;
  unsigned char oui_in_question [3];
  static char text [1024];


  text [0] = 0;
  oui_in_question [0] = octet1;
  oui_in_question [1] = octet2;
  oui_in_question [2] = octet3;
  done = 0;
  oui_index = 0;
  while (!done)
  {
    if (!memcmp(oui_in_question, (oui_list+oui_index)->oui, sizeof(oui_list [0].oui)))
      strcpy(text, (oui_list+oui_index)->vendor_name);
    if (strlen(oui_list [oui_index].vendor_name) EQUALS 0)
      done = 1;
    else
      oui_index++;
  };
  return(text);

} /* oui_lookup */

