
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

extern void afl_client_start(void);

int main()
{
  afl_client_start();
  struct sockaddr_un addr;
  int sfd;
  char buf[1024];

  memset(buf, 0, sizeof(buf));

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, "aflsocket", sizeof(addr.sun_path));

  if ((sfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
    perror("socket create failed");
    exit(EXIT_FAILURE);
  }

  int addrlen = sizeof(addr);
RECONNECT:
  if (connect(sfd, (struct sockaddr*)&addr, addrlen) < 0) {
    usleep(1000);
    goto RECONNECT;
  }

  if (!read(0, buf, sizeof(buf)))
    perror("read error");

  if (send(sfd, buf, sizeof(buf), 0) < 0) {
    perror("send error");
    close(sfd);
    exit(EXIT_FAILURE);
  }

  close(sfd);

  return 0;
}
