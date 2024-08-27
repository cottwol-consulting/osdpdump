#include <string.h>

#define EQUALS ==

char *oui_lookup
  (unsigned char octet1,
  unsigned char octet2,
  unsigned char octet3)

{
  static char text [1024];

  text [0] = 0;
  if ((octet1 EQUALS 0xCA) && (octet2 EQUALS 0x44) && (octet3 EQUALS 0x6C))
    strcpy(text, "Cypress");
  return(text);
}

