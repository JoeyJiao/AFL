# AFL remote process fuzzing

The feature is to fuzz remote process (normally a server), so the client code which communicates with the server will not be instrumented.

# How to use
As client hasn't been instrumented, so AFL_SKIP_BIN_CHECK=1 is needed; also as client runs pretty fast, to simplify the design, forkserver is disabled by AFL_NO_FORKSRV=1.

Another note on server is that server will exit when crash is found, so a shell while loop is needed to restart the server.

AFL_FIFO_SUFFIX can be set for each afl-fuzz instance with different name in order to support multi afl-fuzz instances. The env variable is not needed if only one afl-fuzz instance launched.

Modify server code is needed to replace while(1) like loop to while(__afl_remote_loop()). Inside the __afl_remote_loop funtion, it will communicate with client before the loop cycle start and after the loop cycle end.
Add "extern int __afl_remote_loop(void);" in server code is also needed.

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
