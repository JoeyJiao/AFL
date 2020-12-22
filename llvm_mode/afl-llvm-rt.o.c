/*
  Copyright 2015 Google LLC All rights reserved.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

/*
   american fuzzy lop - LLVM instrumentation bootstrap
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   LLVM integration design comes from Laszlo Szekeres.

   This code is the rewrite of afl-as.h's main_payload.
*/

#include "../android-ashmem.h"
#include "../config.h"
#include "../types.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>

#define AFL_SOCK_SUFFIX     "AFL_SOCK_SUFFIX"
#define AFL_DEBUG           "AFL_DEBUG"
#define AFL_NO_REMOTE       "AFL_NO_REMOTE"
#define AFL_REMOTE_SKIP_COUNT    "AFL_REMOTE_SKIP_COUNT"

/* This is a somewhat ugly hack for the experimental 'trace-pc-guard' mode.
   Basically, we need to make sure that the forkserver is initialized after
   the LLVM-generated runtime initialization pass, not before. */

#ifdef USE_TRACE_PC
#  define CONST_PRIO 5
#else
#  define CONST_PRIO 0
#endif /* ^USE_TRACE_PC */


/* Globals needed by the injected instrumentation. The __afl_area_initial region
   is used for instrumentation output before __afl_map_shm() has a chance to run.
   It will end up as .comm, so it shouldn't be too wasteful. */

u8  __afl_area_initial[MAP_SIZE];
u8* __afl_area_ptr = __afl_area_initial;

__thread u32 __afl_prev_loc;

static s32 shm_id = -1;
static s32 server_pid = -1,
           client_pid = -1;
char* tmpdir;
static u8 first_pass = 1;
static u8 loop_continue = 0;
static u8 __afl_loop_flag = 0;
static char afl_debug = 0;
static struct sockaddr_un addr;
static char sock_str[1024];
static int sock_fd;
static int afl_sock_fd;
static unsigned int afl_remote_skip_count = 0;
static unsigned int loop_count = 0;

/* Running in persistent mode? */

static u8 is_persistent;


/* SHM setup. */

void __afl_map_shm(void) {

  u8 *id_str = getenv(SHM_ENV_VAR);

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


/* Fork server logic. */

static void __afl_start_forkserver(void) {

  static u8 tmp[4];
  s32 child_pid;

  u8  child_stopped = 0;

  /* Phone home and tell the parent that we're OK. If parent isn't there,
     assume we're not running in forkserver mode and just execute program. */

  if (write(FORKSRV_FD + 1, tmp, 4) != 4) return;

  while (1) {

    u32 was_killed;
    int status;

    /* Wait for parent by reading from the pipe. Abort if read fails. */

    if (read(FORKSRV_FD, &was_killed, 4) != 4) _exit(1);

    /* If we stopped the child in persistent mode, but there was a race
       condition and afl-fuzz already issued SIGKILL, write off the old
       process. */

    if (child_stopped && was_killed) {
      child_stopped = 0;
      if (waitpid(child_pid, &status, 0) < 0) _exit(1);
    }

    if (!child_stopped) {

      /* Once woken up, create a clone of our process. */

      child_pid = fork();
      if (child_pid < 0) _exit(1);

      /* In child process: close fds, resume execution. */

      if (!child_pid) {

        close(FORKSRV_FD);
        close(FORKSRV_FD + 1);
        return;
  
      }

    } else {

      /* Special handling for persistent mode: if the child is alive but
         currently stopped, simply restart it with SIGCONT. */

      kill(child_pid, SIGCONT);
      child_stopped = 0;

    }

    /* In parent process: write PID to pipe, then wait for child. */

    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) _exit(1);

    if (waitpid(child_pid, &status, is_persistent ? WUNTRACED : 0) < 0)
      _exit(1);

    /* In persistent mode, the child stops itself with SIGSTOP to indicate
       a successful run. In this case, we want to wake it up without forking
       again. */

    if (WIFSTOPPED(status)) child_stopped = 1;

    /* Relay wait status to pipe, then loop back. */

    if (write(FORKSRV_FD + 1, &status, 4) != 4) _exit(1);

  }

}


/* A simplified persistent mode handler, used as explained in README.llvm. */

int __afl_persistent_loop(unsigned int max_cnt) {

  static u8  first_pass = 1;
  static u32 cycle_cnt;

  if (first_pass) {

    /* Make sure that every iteration of __AFL_LOOP() starts with a clean slate.
       On subsequent calls, the parent will take care of that, but on the first
       iteration, it's our job to erase any trace of whatever happened
       before the loop. */

    if (is_persistent) {

      memset(__afl_area_ptr, 0, MAP_SIZE);
      __afl_area_ptr[0] = 1;
      __afl_prev_loc = 0;
    }

    cycle_cnt  = max_cnt;
    first_pass = 0;
    return 1;

  }

  if (is_persistent) {

    if (--cycle_cnt) {

      raise(SIGSTOP);

      __afl_area_ptr[0] = 1;
      __afl_prev_loc = 0;

      return 1;

    } else {

      /* When exiting __AFL_LOOP(), make sure that the subsequent code that
         follows the loop is not traced. We do that by pivoting back to the
         dummy output region. */

      __afl_area_ptr = __afl_area_initial;

    }

  }

  return 0;

}


/* This one can be called from user code when deferred forkserver mode
    is enabled. */

void __afl_manual_init(void) {

  static u8 init_done;

  if (!init_done) {

    __afl_map_shm();
    __afl_start_forkserver();
    init_done = 1;

  }

}


/* Proper initialization routine. */

__attribute__((constructor(CONST_PRIO))) void __afl_auto_init(void) {

  is_persistent = !!getenv(PERSIST_ENV_VAR);

  if (getenv(DEFER_ENV_VAR)) return;

  __afl_manual_init();

}


/* The following stuff deals with supporting -fsanitize-coverage=trace-pc-guard.
   It remains non-operational in the traditional, plugin-backed LLVM mode.
   For more info about 'trace-pc-guard', see README.llvm.

   The first function (__sanitizer_cov_trace_pc_guard) is called back on every
   edge (as opposed to every basic block). */

void __sanitizer_cov_trace_pc_guard(uint32_t* guard) {
  __afl_area_ptr[*guard]++;
}


/* Init callback. Populates instrumentation IDs. Note that we're using
   ID of 0 as a special value to indicate non-instrumented bits. That may
   still touch the bitmap, but in a fairly harmless way. */

void __sanitizer_cov_trace_pc_guard_init(uint32_t* start, uint32_t* stop) {

  u32 inst_ratio = 100;
  u8* x;

  if (start == stop || *start) return;

  x = getenv("AFL_INST_RATIO");
  if (x) inst_ratio = atoi(x);

  if (!inst_ratio || inst_ratio > 100) {
    fprintf(stderr, "[-] ERROR: Invalid AFL_INST_RATIO (must be 1-100).\n");
    abort();
  }

  /* Make sure that the first element in the range is always set - we use that
     to avoid duplicate calls (which can happen as an artifact of the underlying
     implementation in LLVM). */

  *(start++) = R(MAP_SIZE - 1) + 1;

  while (start < stop) {

    if (R(100) < inst_ratio) *start = R(MAP_SIZE - 1) + 1;
    else *start = 0;

    start++;

  }

}

void setup_shm(void) {
  char shm_str[11];

  if (shm_id != -1) {
#ifdef __ANDROID__
    shm_id = shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600);
#endif

    snprintf(shm_str, sizeof(shm_str), "%d", shm_id);
    if (!getenv("AFL_DUMB_MODE")) setenv(SHM_ENV_VAR, shm_str, 1);

    __afl_map_shm();
  } else if (afl_debug && shm_id == -1) {
    shm_id = shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600);

    snprintf(shm_str, sizeof(shm_str), "%d", shm_id);
    if (!getenv("AFL_DUMB_MODE")) setenv(SHM_ENV_VAR, shm_str, 1);

    __afl_map_shm();
  }
}

void handle_sig(int sig) {
  if (client_pid != -1) {
    // send trace_bits to client in case crash 
    if (afl_debug) dprintf(2, "handle sig %d\n", sig);
    if (getenv(AFL_NO_REMOTE)) return;

    u8 tmp[4];

    memset(tmp, 0, 4);
    if (recv(afl_sock_fd, &tmp, 4, MSG_WAITALL) != 4) goto error;

#ifdef __ANDROID__
    if (shm_id != -1) {
      if (send(afl_sock_fd, __afl_area_ptr, MAP_SIZE, 0) != MAP_SIZE) goto error;
    }
#endif

error:
    close(afl_sock_fd);
    close(sock_fd);

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
  sigaction(SIGSEGV, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);
  sigaction(SIGKILL, &sa, NULL);
  signal(SIGPIPE, SIG_IGN);
}

__attribute__((constructor))
void setup_afl_server() {
  if (getenv(AFL_DEBUG)) afl_debug = 1;
  if (getenv(AFL_NO_REMOTE)) return;
  if (getenv(AFL_REMOTE_SKIP_COUNT)) afl_remote_skip_count = (unsigned int)atol(getenv(AFL_REMOTE_SKIP_COUNT));

  setup_signal_handlers();

  tmpdir = getenv("TMPDIR");
  if (!tmpdir) tmpdir = "/tmp";

  char *sock_suffix = getenv(AFL_SOCK_SUFFIX);
  if (sock_suffix)
    snprintf(sock_str, sizeof(sock_str), "%s/afl_sock_%s", tmpdir, sock_suffix);
  else
    snprintf(sock_str, sizeof(sock_str), "%s/afl_sock", tmpdir);

  unlink(sock_str);
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, sock_str, sizeof(addr.sun_path));

  if ((sock_fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
    perror("socket create failed");
    _exit(EXIT_FAILURE);
  }

  unsigned int addrlen = sizeof(addr);
  if (bind(sock_fd, (struct sockaddr*)&addr, addrlen) < 0) {
    perror("socket bind failed");
    close(sock_fd);
    _exit(EXIT_FAILURE);
  }

  if (listen(sock_fd, 8) < 0) {
    perror("socket listen failed");
    close(sock_fd);
    _exit(EXIT_FAILURE);
  }
}

int afl_remote_loop_start(void) {
  if (afl_debug) printf("afl_remote_loop_start\n");
  if (getenv(AFL_NO_REMOTE)) return 0;

  if (loop_count < afl_remote_skip_count) return 0;
  if (loop_continue) {
    if (afl_debug) printf("afl_remote_loop_continue\n");
    loop_continue = 0;
    return 0;
  }

  unsigned int addrlen = sizeof(addr);
LOOP:
  if ((afl_sock_fd=accept(sock_fd, (struct sockaddr*)&addr, &addrlen)) < 0) {
    perror("socket accept failed");
    setup_afl_server();
    goto LOOP;
  }

  if (recv(afl_sock_fd, &shm_id, 4, MSG_WAITALL) != 4) goto error;

  if (first_pass) setup_shm();

  first_pass = 0;

  server_pid = getpid();
  if (send(afl_sock_fd, &server_pid, 4, 0) != 4) goto error;

  if (recv(afl_sock_fd, &client_pid, 4, MSG_WAITALL) != 4) goto error;

  return 0;

error:
  close(afl_sock_fd);
  close(sock_fd);
  return 1;
}

int afl_remote_loop_next(void) {
  if (afl_debug) printf("afl_remote_loop_next\n");
  if (getenv(AFL_NO_REMOTE)) return 0;
  if (loop_count < afl_remote_skip_count) {
    loop_count++;
    return 0;
  }

  u8 tmp[4];

  memset(tmp, 0, 4);
  if (recv(afl_sock_fd, &tmp, 4, MSG_WAITALL) != 4) goto error;

  if (!memcmp(tmp, "CONT", 4)) {
    loop_continue = 1;
    return 0;
  }

#ifdef __ANDROID__
  if (shm_id != -1) {
    if (send(afl_sock_fd, __afl_area_ptr, MAP_SIZE, 0) != MAP_SIZE) goto error;
  }
#endif

  close(afl_sock_fd);
  return 0;

error:
  close(afl_sock_fd);
  close(sock_fd);
  return 1;
}

int afl_remote_loop(void) {
  if (getenv(AFL_NO_REMOTE)) return 1;

LOOP_BEGIN:
  if (!__afl_loop_flag) {

    if(afl_remote_loop_start()) goto error;
    __afl_loop_flag = 1;

  } else {

    if (afl_remote_loop_next()) goto error;
    __afl_loop_flag = 0;
    goto LOOP_BEGIN;

  }

  return 1;

error:
  __afl_loop_flag = 0;
  goto LOOP_BEGIN;
}

void afl_remote_set_loop_continue(int flag) {
  loop_continue = flag;
}
