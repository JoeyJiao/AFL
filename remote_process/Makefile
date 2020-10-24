CFLAGS := -g -O0 -fPIC -fno-omit-frame-pointer -Wall
ifneq ($(ENABLE_ASAN),)
CFLAGS += -fsanitize=address
endif

ifneq ($(AFL_DEBUG),)
export AFL_NO_UI := 1
export AFL_SHOW_STDIO := 1
endif

all: clean
	clang aflserver.c -shared $(CFLAGS) -o libaflserver.so
	aarch64-linux-gnu-gcc aflserver.c -shared $(CFLAGS) -o libaflserver.aarch64.so
	AFL_TRACE_PC=1 AFL_CC=clang afl-clang-fast $(CFLAGS) -o server server.c
	clang $(CFLAGS) -shared aflclient.c -o libaflclient.so
	clang $(CFLAGS) -L . -laflclient client.c -o client
	AFL_TRACE_PC=1 AFL_CC=clang afl-clang-fast $(CFLAGS) -o crash crash.c

clean:
	rm -rf *.so server client crash

runserver:
	while true; do LD_PRELOAD=./libaflserver.so ./server; done

client:
	echo hi | ./client

fuzz:
	if [ -d output ]; then AFL_NO_FORKSRV=1 AFL_SKIP_BIN_CHECK=1 afl-fuzz -i - -o output -m none -x words.dict -- ./client; else AFL_NO_FORKSRV=1 AFL_SKIP_BIN_CHECK=1 afl-fuzz -i input -o output -m none -x words.dict -- ./client; fi	

gdb:
	if [ -d output ]; then AFL_NO_FORKSRV=1 AFL_SKIP_BIN_CHECK=1 gdb -x gdbinit -q --args afl-fuzz -i - -o output -m none -x words.dict -- ./client; else AFL_NO_FORKSRV=1 AFL_SKIP_BIN_CHECK=1 gdb -x gdbinit -q --args afl-fuzz -i input -o output -m none -x words.dict -- ./client; fi	

runcrash:
	if [ -d output_crash ]; then AFL_NO_FORKSRV=1 AFL_SKIP_BIN_CHECK=1 afl-fuzz -i - -o output_crash -m none -x words.dict -- ./crash; else AFL_NO_FORKSRV=1 AFL_SKIP_BIN_CHECK=1 afl-fuzz -i input -o output_crash -m none -x words.dict -- ./crash; fi
