/*
  convert-salea - convert from Salea 485 trace to osdpcap
*/
#include <stdio.h>
#include <string.h>
#define EQUALS ==
int verbosity;

#define VERSION "0.0.0-3"

int
  main
    (int argc,
    char *argv [])

{ /* main for convert-saleae-to-osdpcap */

  char buffer [1024];
  int done;
  int have_packet;
  FILE *input_file;
  char my_buffer [1024];
  int status;
  char *status_gets;
  char *token;


#if 0
skip the first line
comma as separator
get first token
get second token
get third token, save as time
get fourth token
get fifth token, save as data
"Async Serial [2]","data",0.02819616,0.000989576,0xFF,
#endif

  fprintf(stderr, "Convert Salea trace to OSDPCAP %s\n", VERSION);
  status = 0;
  have_packet = 0;
  verbosity = 9;
  input_file = stdin;
  printf("{ \"timeSec\":\"0\",\"timeNano\":\"0\",\"io\":\"trace\",\"data\":\"");
  done = 0;
  while (!done)
  {
    status_gets = fgets(buffer, sizeof(buffer), input_file);
    if (status_gets != NULL)
    {
      if (buffer [strlen(buffer)-1] EQUALS 0x0a)
        buffer [strlen(buffer)-1] = 0;
      if (buffer [strlen(buffer)-1] EQUALS 0x0d)
        buffer [strlen(buffer)-1] = 0;
if (verbosity > 9)
  fprintf(stderr, "DEBUG: buffer was %s\n", buffer);

      // pull time and data

      strcpy(my_buffer, buffer);
      token = strtok(my_buffer, ",");
fprintf(stderr, "DEBUG: token 1 %s\n", token);
      token = strtok(NULL, ",");
fprintf(stderr, "DEBUG: token 2 %s\n", token);
      if (strncmp(buffer, "0x", 2) EQUALS 0)
        strcpy(buffer, buffer+2);
if (verbosity > 9)
  fprintf(stderr, "DEBUG: buffer 1 %s", buffer);
      if (buffer [strlen(buffer)-1] == '\n')
        buffer [strlen(buffer)-1] = 0;
if (verbosity > 9)
  fprintf(stderr, "DEBUG: buffer 2 %s", buffer);
      if (0 EQUALS strcmp(buffer, "53"))
      {
//        if (have_packet)
          printf("\"}\n");
        printf("{ \"timeSec\":\"0\",\"timeNano\":\"0\",\"io\":\"trace\",\"data\":\"");
//{ "timeSec" : "1623638395", "timeNano" : "020800268", "io" : "trace", "data" : " 00 00 56 ef ff f7 3f 29 aa fe", "osdpTraceVersion":"1", "osdpSource":"libosdp-conformance 0.92-1" }
        have_packet = 1;
      };
      printf(" %s", buffer);
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

} /* main for convert-saleae-to-osdpcap */

