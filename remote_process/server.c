
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

int main()
{
  struct sockaddr_un addr;
  int sfd;
  int sock;

  char buf[1024] = {0};

  unlink("aflsocket");
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, "aflsocket", sizeof(addr.sun_path));

  if ((sfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
    perror("socket create failed");
    exit(EXIT_FAILURE);
  }

  unsigned int addrlen = sizeof(addr);
  if (bind(sfd, (struct sockaddr*)&addr, addrlen) < 0) {
    perror("socket bind failed");
    exit(EXIT_FAILURE);
  }

  if (listen(sfd, 1) < 0) {
    perror("socket listen failed");
    exit(EXIT_FAILURE);
  }

  if ((sock=accept(sfd, (struct sockaddr*)&addr, &addrlen)) < 0) {
    perror("socket accept failed");
    exit(EXIT_FAILURE);
  }

  int size = read(sock, buf, sizeof(buf));
  if (!size) {
    exit(EXIT_FAILURE);
  }

  printf("is_server: buf=%s\n", buf);
  if (buf[0] == 'c')
    if (buf[1] == 'r')
      if (buf[2] == 'a')
        if (buf[3] == 's')
          if (buf[4] == 'h')
            abort();

  close(sock);
  close(sfd);

  return 0;
}
