/*
  blah

  (C)2021 Smithee Solutions LLC
*/

#include <stdio.h>
#include <string.h>


#include <osdpdump.h>


/*
  osdpdump_accumulate_input - use data received to build up a packet

  Input:
    raw value

  Output:
    updates accumulated packet in context
*/
int
  osdpdump_accumulate_input
    (OSDPDUMP_CONTEXT *ctx,
    OSDPDUMP_INPUT *input_value)

{ /* osdpdump_accumulate_input */

  OSDPDUMP_INPUT *accumulated_message;
  int done;
  int expected_length;
  int idx;
  int status;


  status = ST_OSDPDUMP_NEED_MORE_DATA;
  accumulated_message = &(ctx->accumulated_message);
  expected_length = 2; // SOM and address
  done = 1;
  idx = 0;

  // if there's something there, try to use it.

  if (input_value->length > 0)
    done = 0;
  {
    while (!done)
    {
      status = osdpdump_packet_accumulate(ctx, input_value, accumulated_message);

      if (status EQUALS ST_OSDPDUMP_PACKET)
        done = 1;

      if (!done)
      {
        if (input_value->length < 1)
          done = 1;
      };
    };
  };
  return(status);

} /* osdpdump_accumulate_input */

