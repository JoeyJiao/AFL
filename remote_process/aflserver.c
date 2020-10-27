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


#define MAP_SIZE_POW2 16
#define MAP_SIZE (1 << MAP_SIZE_POW2)

#define SHM_ENV_VAR         "__AFL_SHM_ID"
#define MAX_ALLOC           0x40000000

#define SAYF(x...)    printf(x)

#define PFATAL(x...) do { \
    fflush(stdout); \
    SAYF("\n[-]  SYSTEM ERROR : " x); \
    SAYF("\n    Stop location : %s(), %s:%u\n", \
         __FUNCTION__, __FILE__, __LINE__); \
    SAYF("       OS message : %s\n", strerror(errno)); \
    exit(1); \
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
static int status;

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
    exit(1); \
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
  } else {
    _exit(1);
  }

  trace_bits = shmat(shm_id, NULL, 0);

  if (trace_bits == (void*)-1) PFATAL("shmat() failed");
}

int fd_fifo_ctl;
int fd_fifo_st;

void handle_sig(int sig) {
  if (sig == 6 || sig == 8) {
    if (client_pid != -1)
      kill(client_pid, sig);
  }

  exit(sig);
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

void afl_server_exit(void);

__attribute__((constructor))
void setup_afl_server() {
  atexit(afl_server_exit);

  setup_signal_handlers();

  tmpdir = getenv("TMPDIR");
  if (!tmpdir) tmpdir = "/tmp";

  snprintf(fifo_ctl, sizeof(fifo_ctl), "%s/fifo_ctl", tmpdir);
  snprintf(fifo_st, sizeof(fifo_st), "%s/fifo_st", tmpdir);

  if (access(fifo_st, F_OK) != 0) {
    if (mkfifo(fifo_st, 0666) < 0) exit(1);
  }

  if ((fd_fifo_st=open(fifo_st, O_WRONLY)) < 0) exit(1);

  if ((fd_fifo_ctl=open(fifo_ctl, O_RDONLY)) < 0) exit(1);

  if (read(fd_fifo_ctl, &client_pid, 4) != 4) exit(1);

  server_pid = getpid();
  if (write(fd_fifo_st, &server_pid, 4) != 4) exit(1);

  if (read(fd_fifo_ctl, &shm_id, 4) != 4) _exit(1);

  setup_shm();
}

void afl_server_exit(void) {
  u8 tmp[4];

  if (write(fd_fifo_st, &status, 4) != 4) _exit(1);

#ifdef __ANDROID__
  if (read(fd_fifo_ctl, &tmp, 4) != 4) _exit(1);

  if (write(fd_fifo_st, trace_bits, MAP_SIZE) != MAP_SIZE) _exit(1);
#endif

  close(fd_fifo_st);
  close(fd_fifo_ctl);

  _exit(status);
}

/* LD_PRELOAD override that causes normal process termination to instead result
 * in abnormal process termination through a raised SIGABRT signal via abort(3)
 * (even if SIGABRT is ignored, or is caught by a handler that returns).
 * 
 * Loosely based on libminijailpreload.c by Chromium OS authors: 
 * https://android.googlesource.com/platform/external/minijail/+/master/libminijailpreload.c
 */

/* The address of the real main is stored here for fake_main to access */
static int (*real_main) (int, char **, char **);

/* Fake main(), spliced in before the real call to main() in __libc_start_main */
static int fake_main(int argc, char **argv, char **envp)
{	
	/* Register abort(3) as an atexit(3) handler to be called at normal
	 * process termination */
	atexit(afl_server_exit);

	/* Finally call the real main function */
	status = real_main(argc, argv, envp);
	return status;
}

/* LD_PRELOAD override of __libc_start_main.
 *
 * The objective is to splice fake_main above to be executed instead of the
 * program main function. We cannot use LD_PRELOAD to override main directly as
 * LD_PRELOAD can only be used to override functions in dynamically linked
 * shared libraries whose addresses are determined via the Procedure
 * Linkage Table (PLT). However, main's location is not determined via the PLT,
 * but is statically linked to the executable entry routine at __start which
 * pushes main's address onto the stack, then invokes libc's startup routine,
 * which obtains main's address from the stack. 
 * 
 * Instead, we use LD_PRELOAD to override libc's startup routine,
 * __libc_start_main, which is normally responsible for calling main. We can't
 * just run our setup code *here* because the real __libc_start_main is
 * responsible for setting up the C runtime environment, so we can't rely on
 * standard library functions such as malloc(3) or atexit(3) being available
 * yet. 
 */
int __libc_start_main(int (*main) (int, char **, char **),
		      int argc, char **ubp_av, void (*init) (void),
		      void (*fini) (void), void (*rtld_fini) (void),
		      void (*stack_end))
{
	void *libc_handle, *sym;
	/* This type punning is unfortunately necessary in C99 as casting
	 * directly from void* to function pointers is left undefined in C99.
	 * Strictly speaking, the conversion via union is still undefined
	 * behaviour in C99 (C99 Section 6.2.6.1):
	 * 
	 *  "When a value is stored in a member of an object of union type, the
	 *  bytes of the object representation that do not correspond to that
	 *  member but do correspond to other members take unspecified values,
	 *  but the value of the union object shall not thereby become a trap
	 *  representation."
	 * 
	 * However, this conversion is valid in GCC, and dlsym() also in effect
	 * mandates these conversions to be valid in POSIX system C compilers.
	 * 
	 * C11 explicitly allows this conversion (C11 Section 6.5.2.3): 
	 *  
	 *  "If the member used to read the contents of a union object is not
	 *  the same as the member last used to store a value in the object, the
	 *  appropriate part of the object representation of the value is
	 *  reinterpreted as an object representation in the new type as
	 *  described in 6.2.6 (a process sometimes called ‘‘type punning’’).
	 *  This might be a trap representation.
	 * 
	 * Some compilers allow direct conversion between pointers to an object
	 * or void to a pointer to a function and vice versa. C11's annex “J.5.7
	 * Function pointer casts lists this as a common extension:
	 * 
	 *   "1 A pointer to an object or to void may be cast to a pointer to a
	 *   function, allowing data to be invoked as a function (6.5.4).
         * 
	 *   2 A pointer to a function may be cast to a pointer to an object or
	 *   to void, allowing a function to be inspected or modified (for
	 *   example, by a debugger) (6.5.4)."
	 */
	union {
		int (*fn) (int (*main) (int, char **, char **), int argc,
			   char **ubp_av, void (*init) (void),
			   void (*fini) (void), void (*rtld_fini) (void),
			   void (*stack_end));
		void *sym;
	} real_libc_start_main;


	/* Obtain handle to libc shared library. The object should already be
	 * resident in the programs memory space, hence we can attempt to open
	 * it without loading the shared object. If this fails, we are most
	 * likely dealing with another version of libc.so */
#ifdef __ANDROID__
	libc_handle = dlopen("libc.so", RTLD_NOLOAD | RTLD_NOW);
#else
	libc_handle = dlopen("libc.so.6", RTLD_NOLOAD | RTLD_NOW);
#endif

	if (!libc_handle) {
#ifdef __ANDROID__
		fprintf(stderr, "can't open handle to libc.so: %s\n",
#else
		fprintf(stderr, "can't open handle to libc.so.6: %s\n",
#endif
			dlerror());
		/* We dare not use abort() here because it would run atexit(3)
		 * handlers and try to flush stdio. */
		_exit(EXIT_FAILURE);
	}
	
	/* Our LD_PRELOAD will overwrite the real __libc_start_main, so we have
	 * to look up the real one from libc and invoke it with a pointer to the
	 * fake main we'd like to run before the real main function. */
	sym = dlsym(libc_handle, "__libc_start_main");
	if (!sym) {
		fprintf(stderr, "can't find __libc_start_main():%s\n",
			dlerror());
		_exit(EXIT_FAILURE);
	}

	real_libc_start_main.sym = sym;
	real_main = main;
	
	/* Close our handle to dynamically loaded libc. Since the libc object
	 * was already loaded previously, this only decrements the reference
	 * count to the shared object. Hence, we can be confident that the
	 * symbol to the read __libc_start_main remains valid even after we
	 * close our handle. In order to strictly adhere to the API, we could
	 * defer closing the handle to our spliced-in fake main before it call
	 * the real main function. */
	if(dlclose(libc_handle)) {
#ifdef __ANDROID__
		fprintf(stderr, "can't close handle to libc.so: %s\n",
#else
		fprintf(stderr, "can't close handle to libc.so.6: %s\n",
#endif
			dlerror());

		_exit(EXIT_FAILURE);
	}

	/* Note that we swap fake_main in for main - fake_main should call
	 * real_main after its setup is done. */
	return real_libc_start_main.fn(fake_main, argc, ubp_av, init, fini,
				       rtld_fini, stack_end);
}
