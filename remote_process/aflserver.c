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
#include <dlfcn.h>
#include "../android-ashmem.h"

typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;


#define MAP_SIZE_POW2 16
#define MAP_SIZE (1 << MAP_SIZE_POW2)

#define SHM_ENV_VAR         "__AFL_SHM_ID"
#define AFL_FIFO_SUFFIX     "AFL_FIFO_SUFFIX"
#define MAX_ALLOC           0x40000000

#define SAYF(x...)    printf(x)

#define PFATAL(x...) do { \
    fflush(stdout); \
    SAYF("\n[-]  SYSTEM ERROR : " x); \
    SAYF("\n    Stop location : %s(), %s:%u\n", \
         __FUNCTION__, __FILE__, __LINE__); \
    SAYF("       OS message : %s\n", strerror(errno)); \
    _exit(1); \
  } while (0)

typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;

static s32 shm_id = -1;
static s32 server_pid = -1,
           client_pid = -1;
static u8* trace_bits;
char* tmpdir;
static char fifo_ctl[1024];
static char fifo_st[1024];
int fd_fifo_ctl;
int fd_fifo_st;

#define ALLOC_MAGIC_C1  0xFF00FF00 /* Used head (dword)  */
#define ALLOC_MAGIC_F   0xFE00FE00 /* Freed head (dword) */
#define ALLOC_MAGIC_C2  0xF0       /* Used tail (byte)   */

#define ALLOC_C1(_ptr)  (((u32*)(_ptr))[-2])
#define ALLOC_S(_ptr)   (((u32*)(_ptr))[-1])
#define ALLOC_C2(_ptr)  (((u8*)(_ptr))[ALLOC_S(_ptr)])

#define ALLOC_OFF_HEAD  8
#define ALLOC_OFF_TOTAL (ALLOC_OFF_HEAD + 1)

#define ABORT(x...) do { \
    SAYF("\n[-] PROGRAM ABORT : " x); \
    SAYF("\n    Stop location : %s(), %s:%u\n\n", \
         __FUNCTION__, __FILE__, __LINE__); \
    abort(); \
  } while (0)

#define FATAL(x...) do { \
    SAYF("\n[-] PROGRAM ABORT : " x); \
    SAYF("\n         Location : %s(), %s:%u\n\n", \
         __FUNCTION__, __FILE__, __LINE__); \
    _exit(1); \
  } while (0)

#define CHECK_PTR(_p) do { \
    if (_p) { \
      if (ALLOC_C1(_p) ^ ALLOC_MAGIC_C1) {\
        if (ALLOC_C1(_p) == ALLOC_MAGIC_F) \
          ABORT("Use after free."); \
        else ABORT("Corrupted head alloc canary."); \
      } \
      if (ALLOC_C2(_p) ^ ALLOC_MAGIC_C2) \
        ABORT("Corrupted tail alloc canary."); \
    } \
  } while (0)

#define ALLOC_CHECK_SIZE(_s) do { \
    if ((_s) > MAX_ALLOC) \
      ABORT("Bad alloc request: %u bytes", (_s)); \
  } while (0)

#define ALLOC_CHECK_RESULT(_r, _s) do { \
    if (!(_r)) \
      ABORT("Out of memory: can't allocate %u bytes", (_s)); \
  } while (0)

static inline void* DFL_ck_alloc_nozero(u32 size) {

  void* ret;

  if (!size) return NULL;

  ALLOC_CHECK_SIZE(size);
  ret = malloc(size + ALLOC_OFF_TOTAL);
  ALLOC_CHECK_RESULT(ret, size);

  ret += ALLOC_OFF_HEAD;

  ALLOC_C1(ret) = ALLOC_MAGIC_C1;
  ALLOC_S(ret)  = size;
  ALLOC_C2(ret) = ALLOC_MAGIC_C2;

  return ret;

}

static inline void* DFL_ck_alloc(u32 size) {

  void* mem;

  if (!size) return NULL;
  mem = DFL_ck_alloc_nozero(size);

  return memset(mem, 0, size);

}

#define ck_alloc          DFL_ck_alloc
#define ck_free           DFL_ck_free

static inline void DFL_ck_free(void* mem) {

  if (!mem) return;

  CHECK_PTR(mem);

#ifdef DEBUG_BUILD

  /* Catch pointer issues sooner. */
  memset(mem, 0xFF, ALLOC_S(mem));

#endif /* DEBUG_BUILD */

  ALLOC_C1(mem) = ALLOC_MAGIC_F;

  free(mem - ALLOC_OFF_HEAD);

}

#define alloc_printf(_str...) ({ \
    u8* _tmp; \
    s32 _len = snprintf(NULL, 0, _str); \
    if (_len < 0) FATAL("Whoa, snprintf() fails?!"); \
    _tmp = ck_alloc(_len + 1); \
    snprintf((char*)_tmp, _len + 1, _str); \
    _tmp; \
  })

void setup_shm(void) {
  char* shm_str;

  if (shm_id != -1) {
#ifdef __ANDROID__
    shm_id = shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600);
#endif

    shm_str = (char*)alloc_printf("%d", shm_id);
    if (!getenv("AFL_DUMB_MODE")) setenv(SHM_ENV_VAR, shm_str, 1);

    ck_free(shm_str);

    trace_bits = shmat(shm_id, NULL, 0);

    if (trace_bits == (void*)-1) PFATAL("shmat() failed");
  } 
}

void handle_sig(int sig) {
  if (sig == 6 || sig == 8) {
    if (client_pid != -1)
      kill(client_pid, sig);
  }
}

void setup_signal_handlers(void) {
  struct sigaction sa;

  sa.sa_handler = NULL;
  sa.sa_flags = SA_RESTART;
  sa.sa_sigaction = NULL;

  sigemptyset(&sa.sa_mask);
  sa.sa_handler = handle_sig;

  sigaction(SIGABRT, &sa, NULL);
  sigaction(SIGFPE, &sa, NULL);
  sigaction(SIGALRM, &sa, NULL);
}

__attribute__((constructor))
void setup_afl_server() {

  setup_signal_handlers();

  tmpdir = getenv("TMPDIR");
  if (!tmpdir) tmpdir = "/tmp";

  char *fifo_suffix = getenv(AFL_FIFO_SUFFIX);
  if (fifo_suffix) {
    snprintf(fifo_ctl, sizeof(fifo_ctl), "%s/fifo_ctl_%s", tmpdir, fifo_suffix);
    snprintf(fifo_st, sizeof(fifo_st), "%s/fifo_st_%s", tmpdir, fifo_suffix);
  } else {
    snprintf(fifo_ctl, sizeof(fifo_ctl), "%s/fifo_ctl", tmpdir);
    snprintf(fifo_st, sizeof(fifo_st), "%s/fifo_st", tmpdir);
  }

  if (access(fifo_st, F_OK) != 0) {
    if (mkfifo(fifo_st, 0666) < 0) _exit(1);
  }

  if ((fd_fifo_st=open(fifo_st, O_WRONLY)) < 0) _exit(1);
  if ((fd_fifo_ctl=open(fifo_ctl, O_RDONLY)) < 0) _exit(1);

  if (read(fd_fifo_ctl, &shm_id, 4) != 4) _exit(1);

  setup_shm();
}

int __afl_remote_loop(void) {
  static u8 first_pass = 1;
  static u8 loop_end = 0;

LOOP_BEGIN:
  if (!loop_end) {

    if (!first_pass) {
      if ((fd_fifo_st=open(fifo_st, O_WRONLY)) < 0) _exit(1);
      if ((fd_fifo_ctl=open(fifo_ctl, O_RDONLY)) < 0) _exit(1);
  
      if (read(fd_fifo_ctl, &shm_id, 4) != 4) goto error;
    }

    first_pass = 0;

    if (read(fd_fifo_ctl, &client_pid, 4) != 4) goto error;
  
    server_pid = getpid();
    if (write(fd_fifo_st, &server_pid, 4) != 4) goto error;

    loop_end = 1;

  } else {

    u8 tmp[4];

    if (write(fd_fifo_st, &tmp, 4) != 4) goto error;
  
#ifdef __ANDROID__
    if (read(fd_fifo_ctl, &tmp, 4) != 4) goto error;
  
    if (shm_id != -1) {
      if (write(fd_fifo_st, trace_bits, MAP_SIZE) != MAP_SIZE) goto error;
    }
#endif

    close(fd_fifo_ctl);
    close(fd_fifo_st);

    loop_end = 0;
    goto LOOP_BEGIN;
  }

  return 1;

error:
  close(fd_fifo_ctl);
  close(fd_fifo_st);

  loop_end = 0;
  goto LOOP_BEGIN;
}
