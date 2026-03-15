/*
  import-hex - convert hex dump protocol  to osdpcap file.

  Usage:

    import-hex <source-hex

  Input:
    reads text file of hex messages, one per line from standard input

  Output:
    outputs file import.osdpcap in current directory

  (C)2026 Smithee Solutions LLC

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


#include <osdpdump-version.h>
#define EQUALS ==

// one millisecond in nanoseconds.
#define MILLISECONDS (1000000)

int main
  (int argc,
  char *argv [])

{

  int done;
  unsigned long import_timeNano;
  unsigned long import_timeSec;
  char input_line [1024];
  FILE *osdpcap_file;
  char *status_gets;


  done = 0;
  import_timeSec = 0;
  import_timeNano = 0;
  osdpcap_file = fopen("import.osdpcap", "w");
  if (osdpcap_file EQUALS NULL)
    done = 1;

  while (!done)
  {
    status_gets = fgets(input_line, sizeof(input_line), stdin);
    if (status_gets EQUALS NULL)
      done = 1;
    if (!done)
    {
      // eat any trailing newline
      if (input_line [strlen(input_line)-1] EQUALS 0x0a)
        input_line [strlen(input_line)-1] = 0;
      // eat any trailing carriage return
      if (input_line [strlen(input_line)-1] EQUALS 0x0d)
        input_line [strlen(input_line)-1] = 0;

      if (strlen(input_line) > 0)
        fprintf(osdpcap_file,
"{\"timeSec\":\"%ld\",\"timeNano\":\"%ld\",\"data\":\"%s\",\"osdpTraceVersion\":\"1\",\"osdpSource\":\"import-hex %s\"}\n",
          import_timeSec, import_timeNano, input_line, OSDPDUMP_VERSION);

      // fake a timestamp
      import_timeNano = import_timeNano + 50*MILLISECONDS;
      if (import_timeNano > 1000*MILLISECONDS)
      {
        import_timeSec++;
        import_timeNano = import_timeNano - 1000*MILLISECONDS;
      };
    }
  }
  return(0);
}

