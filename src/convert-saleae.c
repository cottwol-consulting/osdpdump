/*
  convert-salea - convert from Salea 485 trace to osdpcap
*/
#include <stdio.h>
#include <string.h>
#define EQUALS ==
#define ST_OK (0)
int verbosity;

#define VERSION "0.0.0-4"

int
  main
    (int argc,
    char *argv [])

{ /* main for convert-saleae */

  char buffer [1024];
  int done;
  int have_packet;
  FILE *input_file;
  char my_buffer [1024];
  char octet_buffer [1024];
  int status;
  char *status_gets;
  char timestamp_string [1024];
  char *token;


  fprintf(stderr, "Convert Salea trace to OSDPCAP %s\n", VERSION);
  have_packet = 0;
  verbosity = 9;
  input_file = stdin;

  // eat the first line
  status_gets = fgets(buffer, sizeof(buffer), input_file);
  if (status_gets != NULL)
    status = ST_OK;
  else
    status = -1;

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
      token = strtok(NULL, ",");
fprintf(stderr, "DEBUG: token 3 %s\n", token);
      strcpy(timestamp_string, token);
      token = strtok(NULL, ",");
fprintf(stderr, "DEBUG: token 4 %s\n", token);
      token = strtok(NULL, ",");
fprintf(stderr, "DEBUG: token 5 %s\n", token);
      strcpy(octet_buffer, token);
fprintf(stderr, "DEBUG: octet buffer %s\n", octet_buffer);
      if (strncmp(octet_buffer, "0x", 2) EQUALS 0)
        strncpy(octet_buffer, octet_buffer+2, 2);
      octet_buffer [2] = 0;
if (verbosity > 9)
  fprintf(stderr, "DEBUG: octet buffer 1 %s", octet_buffer);
      if (0 EQUALS strcmp(octet_buffer, "53"))
      {
        char nano_digits [1024];
        int i;
        int time_sec;
//        if (have_packet)
          printf("\"}\n");

        // convert timestamp to timeSec/timeNano

        token = strtok(timestamp_string, ".");
        sscanf(token, "%d", &i);
        time_sec = i;
        token = strtok(NULL, ".");
        sscanf(token, "%d", &i);
        memset(nano_digits, 0, sizeof(nano_digits));
        memset(nano_digits, 0x30, 9);
        strcpy(nano_digits, token);
        nano_digits [strlen(nano_digits)] = 0x30;
        nano_digits [9] = 0;
        printf("{ \"timeSec\":\"%d\",\"timeNano\":\"%s\",\"io\":\"trace\",\"data\":\"", time_sec, nano_digits);
//{ "timeSec" : "1623638395", "timeNano" : "020800268", "io" : "trace", "data" : " 00 00 56 ef ff f7 3f 29 aa fe", "osdpTraceVersion":"1", "osdpSource":"libosdp-conformance 0.92-1" }
        fflush(stdout);
        have_packet = 1;
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

