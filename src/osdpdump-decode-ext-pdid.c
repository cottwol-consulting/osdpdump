
  unsigned char id_report [65536];
  int id_report_length;

  remainder = id_report_length;
  p = id_report;
  done = 0;
  while (!done)
  {
    // switch on tag
    switch(*p)
    {
    default:
      status = -1;
      break;
    case EXT_ID_MFG:
      memset(manufacturer, 0, sizeof(manufacturer));
      p++;
      length = (*p >> 8) + *(p+1);
      p = p + 2;
      memcpy(manufacturer, p, length);
      printf("\"manufacturer\":\"%s\",\n", manufacturer);
      break;
    };
    if (status != ST_OK)
      done = 1;
  };

