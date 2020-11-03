# AFL remote process fuzzing

The feature is to fuzz remote process (normally a server), so the client code which communicates with the server will not be instrumented.

# How to use
As client hasn't been instrumented, so AFL_SKIP_BIN_CHECK=1 is needed; also as client runs pretty fast, to simplify the design, forkserver is disabled by AFL_NO_FORKSRV=1.

Another note on server is that server will exit when crash is found, so a shell while loop is needed to restart the server.

AFL_SOCK_SUFFIX can be set for each afl-fuzz instance with different name in order to support multi afl-fuzz instances. The env variable is not needed if only one afl-fuzz instance launched.

Modify server code is needed to replace while(1) like loop to while(__afl_remote_loop()). Inside the __afl_remote_loop funtion, it will communicate with client before the loop cycle start and after the loop cycle end.

In some server implementation, while loop needs to be executed once before starting to proceed client request, so AFL_REMOTE_SKIP_COUNT=1 can be used.
And if the while loop needs to execute twice for each client connection, which might means client send two IPC messages, then afl_client_continue() is needed between these two IPC messages.

Add "extern int afl_remote_loop(void);" in server code is also needed.
In case afl_remote_loop cannot be used, it also provides two separate functions afl_remote_loop_start() and afl_remote_loop_next() to indicate client entry and client exit.

## Host
```
make
make runserver &
make fuzz
```

## Android
The target server needs to dependent on libaflserver.so during build.

```
adb shell
export TMPDIR=/data/local/tmp
export LD_LIBRARY_PATH=.
while true; do ./aflserver; done &
AFL_NO_FORKSRV=1 AFL_SKIP_BIN_CHECK=1 afl-fuzz -i input -o output -m none -- ./aflclient
```
