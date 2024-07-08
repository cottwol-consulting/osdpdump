/*
  convert-salea - convert from Salea 485 trace to osdpcap

  This takes an exported CSV file as standard input and converts
  it to OSDPCAP format on standard output.

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

#include <osdpdump-version.h>

#define EQUALS ==
#define ST_OK (0)
int verbosity;


int
  main
    (int argc,
    char *argv [])

{ /* main for convert-saleae */

  char buffer [1024];
  int done;
  FILE *input_file;
  int line_count;
  char my_buffer [1024];
  char octet_buffer [1024];
  int status;
  char *status_gets;
  char timestamp_string [1024];
  char *token;


  fprintf(stderr, "Convert Salea trace to OSDPCAP %s\n", OSDPDUMP_VERSION);
  fprintf(stderr, "Reading standard input, writing to standard output...\n");
  line_count = 0;
  verbosity = 3;
  input_file = stdin;

  // eat the first line
  status_gets = fgets(buffer, sizeof(buffer), input_file);
  if (status_gets != NULL)
    status = ST_OK;
  else
    status = -1;

  done = 0;
  while (!done)
  {
    // get a data line

    status_gets = fgets(buffer, sizeof(buffer), input_file);
    if (status_gets != NULL)
    {
      // eat the cr/lf at the end

      if (buffer [strlen(buffer)-1] EQUALS 0x0a)
        buffer [strlen(buffer)-1] = 0;
      if (buffer [strlen(buffer)-1] EQUALS 0x0d)
        buffer [strlen(buffer)-1] = 0;
      if (verbosity > 9)
        fprintf(stderr, "DEBUG: buffer was %s\n", buffer);

// 1              2      3                                   4         5
// "Async Serial","data",2024-07-06T21:54:02.105977600+00:00,0.0009895,0x53

      // pull time and data

      strcpy(timestamp_string, "-");
      strcpy(my_buffer, buffer);

      // fetch token 1
      token = strtok(my_buffer, ",");
      if (verbosity > 3)
        fprintf(stderr, "DEBUG: token 1 %s\n", token);

      // fetch token 2
      token = strtok(NULL, ",");
      if (verbosity > 3)
        fprintf(stderr, "DEBUG: token 2 %s\n", token);

      // fetch token 3.  this is the ISO8601 timestamp
      token = strtok(NULL, ",");
      strcpy(timestamp_string, token);
      if (verbosity > 3)
        fprintf(stderr, "DEBUG: token 3 %s\n", token);

      // fetch token 4
      token = strtok(NULL, ",");
      if (verbosity > 3)
        fprintf(stderr, "DEBUG: token 4 %s\n", token);

      // fetch token 5.  this is the data byte
      token = strtok(NULL, ",");
      if (verbosity > 3)
        fprintf(stderr, "DEBUG: token 5 %s\n", token);
      strcpy(octet_buffer, token);
      if (verbosity > 3)
        fprintf(stderr, "DEBUG: octet buffer %s\n", octet_buffer);
      if (strncmp(octet_buffer, "0x", 2) EQUALS 0)
        strncpy(octet_buffer, octet_buffer+2, 2);
      octet_buffer [2] = 0;
      if (verbosity > 9)
        fprintf(stderr, "DEBUG: octet buffer 1 %s", octet_buffer);
      if (0 EQUALS strcmp(octet_buffer, "53"))
      {
        if (line_count > 0)
          printf("\"}\n");
        line_count ++;

        // convert timestamp to timeSec/timeNano

// The ISO 8601 field looks like this:
// 2024-07-06T21:54:02.105977600+00:00
// 01234567890123456789012345678901234
// 00000000001111111111222222222233333
{
  char digits [1024];
  unsigned long long time_nanoseconds;
  unsigned long time_seconds;
  int value;
  unsigned long long value_long;

  memset(digits, 0, sizeof(digits));
  memcpy(digits, timestamp_string+11, 2);
  sscanf(digits, "%d", &value);
  time_seconds = 60*60*value; // add hours

  memset(digits, 0, sizeof(digits));
  memcpy(digits, timestamp_string+14, 2);
  sscanf(digits, "%d", &value);
  time_seconds = time_seconds + 60*value; // add minutes

  memset(digits, 0, sizeof(digits));
  memcpy(digits, timestamp_string+17, 2);
  sscanf(digits, "%d", &value);
  time_seconds = time_seconds + value; // add seconds

  memset(digits, 0, sizeof(digits));
  memcpy(digits, timestamp_string+20, 9);
  sscanf(digits, "%llu", &value_long);
  time_nanoseconds = value_long;

        // fprintf(stderr, "using timestamp string %s digits %s\n", timestamp_string, digits);
        printf("{ \"osdpSource\":\"convert-saleae\",\"timeSec\":\"%lu\",\"timeNano\":\"%09llu\",\"io\":\"trace\",\"data\":\"", time_seconds, time_nanoseconds);
};
        fflush(stdout);
      };
      printf(" %s", octet_buffer);
    }
    else
    {
      done = 1;
      printf("\"}\n");
    };
  };
  if (status != 0)
    fprintf(stderr, "complete, status was %d.\n", status);
  return(status);

} /* main for convert-saleae */

