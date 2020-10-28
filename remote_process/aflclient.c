#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <signal.h>
#include "../android-ashmem.h"

#define MAP_SIZE_POW2 16
#define MAP_SIZE (1 << MAP_SIZE_POW2)

#define SHM_ENV_VAR         "__AFL_SHM_ID"

typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;

static s32 shm_id = -1;
static s32 server_pid = -1;
static s32 client_pid = -1;
char* tmpdir;

u8  __afl_area_initial[MAP_SIZE];
u8* __afl_area_ptr = __afl_area_initial;
u8* trace_bits = __afl_area_initial;

int fd_fifo_ctl;
int fd_fifo_st;

void handle_sig(int sig) {

  _exit(sig);
}

void setup_signal_handlers(void) {
  struct sigaction sa;

  sa.sa_handler = NULL;
  sa.sa_flags = SA_RESTART;
  sa.sa_sigaction = NULL;

  sigemptyset(&sa.sa_mask);
  sa.sa_handler = handle_sig;

  sigaction(SIGTERM, &sa, NULL);
  sigaction(SIGKILL, &sa, NULL);
}

/* SHM setup. */

void __afl_map_shm(void) {

  char *id_str = getenv(SHM_ENV_VAR);

  /* If we're running under AFL, attach to the appropriate region, replacing the
     early-stage __afl_area_initial region that is needed to allow some really
     hacky .init code to work correctly in projects such as OpenSSL. */

  if (id_str) {

    shm_id = atoi(id_str);

    __afl_area_ptr = shmat(shm_id, NULL, 0);

    /* Whooooops. */

    if (__afl_area_ptr == (void *)-1) _exit(1);

    /* Write something into the bitmap so that even with low AFL_INST_RATIO,
       our parent doesn't give up on us. */

    __afl_area_ptr[0] = 1;

  }

}

void __afl_start_client(void) {
  tmpdir = getenv("TMPDIR");
  if (!tmpdir) tmpdir = "/tmp";

  char fifo_ctl[1024];
  char fifo_st[1024];
  snprintf(fifo_ctl, sizeof(fifo_ctl), "%s/fifo_ctl", tmpdir);
  snprintf(fifo_st, sizeof(fifo_st), "%s/fifo_st", tmpdir);

  if (access(fifo_ctl, F_OK) != 0) {
    if (mkfifo(fifo_ctl, 0666) < 0) _exit(1);
  }

  if (access(fifo_st, F_OK) != 0) _exit(1);

  if ((fd_fifo_st=open(fifo_st, O_RDONLY)) < 0) _exit(1);
  if ((fd_fifo_ctl=open(fifo_ctl, O_WRONLY)) < 0) _exit(1);

  if (write(fd_fifo_ctl, &shm_id, 4) != 4) {
    _exit(1);
  }

  client_pid = getpid();
  if (write(fd_fifo_ctl, &client_pid, 4) != 4) exit(1);
 
  if (read(fd_fifo_st, &server_pid, 4) != 4) exit(1);
}

void afl_client_exit(void);

__attribute__((constructor(5)))
void afl_client_init(void) {
  static u8 init_done;

  atexit(afl_client_exit);
  setup_signal_handlers();

  if (!init_done) {

    __afl_map_shm();
    __afl_start_client();
    init_done = 1;
  }
}

void afl_client_exit(void) {

  u8 tmp[4];

  if (read(fd_fifo_st, &tmp, 4) != 4) _exit(1);

#ifdef __ANDROID__
  if (write(fd_fifo_ctl, &tmp, 4) != 4) _exit(1);

  char *id_str = getenv(SHM_ENV_VAR);
  if (id_str) {
    if (read(fd_fifo_st, __afl_area_ptr, MAP_SIZE) != MAP_SIZE) _exit(1);
  }
#endif
  
  close(fd_fifo_st);
  close(fd_fifo_ctl);
  
  _exit(0);
}
