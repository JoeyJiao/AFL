#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int main()
{
  char buf[5];

  memset(buf, 0, 5);

  if (!read(0, buf, 5))
    printf("read error\n");

  if (buf[0] == 'c')
    if (buf[1] == 'r')
      if (buf[2] == 'a')
        if (buf[3] == 's')
          if (buf[4] == 'h')
            abort();

  return 0;
}
