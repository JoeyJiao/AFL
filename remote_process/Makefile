CC := clang
CFLAGS := -g -O0 -fPIC -fno-omit-frame-pointer -Wall
ifneq ($(ENABLE_ASAN),)
CFLAGS += -fsanitize=address
endif

ifneq ($(AFL_DEBUG),)
export AFL_NO_UI := 1
export AFL_SHOW_STDIO := 1
endif

export LD_LIBRARY_PATH := .:$(LD_LIBRARY_PATH)

all: clean
	AFL_TRACE_PC=1 AFL_CC=$(CC) afl-clang-fast $(CFLAGS) -o remote_server server.c
	$(CC) $(CFLAGS) -shared aflclient.c -o libaflclient.so
	$(CC) $(CFLAGS) -L . -laflclient client.c -o remote_client
	AFL_TRACE_PC=1 AFL_CC=clang afl-clang-fast $(CFLAGS) -o crash crash.c

clean:
	rm -rf *.so remote_server remote_client crash

runserver:
	while true; do timeout 60s ./remote_server; done

fuzz:
	if [ -d output ]; then AFL_NO_FORKSRV=1 AFL_SKIP_BIN_CHECK=1 afl-fuzz -i - -o output -m none -x words.dict -- ./remote_client; else AFL_NO_FORKSRV=1 AFL_SKIP_BIN_CHECK=1 afl-fuzz -i input -o output -m none -x words.dict -- ./remote_client; fi

gdb:
	if [ -d output ]; then AFL_NO_FORKSRV=1 AFL_SKIP_BIN_CHECK=1 gdb -x gdbinit -q --args afl-fuzz -i - -o output -m none -x words.dict -- ./remote_client; else AFL_NO_FORKSRV=1 AFL_SKIP_BIN_CHECK=1 gdb -x gdbinit -q --args afl-fuzz -i input -o output -m none -x words.dict -- ./remote_client; fi

runcrash:
	if [ -d output_crash ]; then AFL_NO_FORKSRV=1 AFL_SKIP_BIN_CHECK=1 afl-fuzz -i - -o output_crash -m none -x words.dict -- ./crash; else AFL_NO_FORKSRV=1 AFL_SKIP_BIN_CHECK=1 afl-fuzz -i input -o output_crash -m none -x words.dict -- ./crash; fi
