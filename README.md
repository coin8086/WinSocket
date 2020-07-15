# Run Test

## Before You Run
You need a certificate for the server. The Subject Name of the certificate must be "localhost", and the certificate must be stored in the "My" store of the system's certificate store, in the "Local Machine". The certificate can be self issued but must not be expired.

## Simple Server and Client
Start echo server and write what received to stdout, which is redirected to file `svr-output` since client may send binary data.

```
SimpleSocketServer.exe -t 1>svr-output
```

Start client to send `file-to-send` to server, and write what server sent back to stdout, which is redirected to file `cli-output`.

```
SimpleSocketClient.exe localhost -t 1>cli-output <file-to-send
```

In the end, `svr-output`, `cli-output` and `file-to-send` should be identical.

When option `-t` is present on command line, TLS is enabled on socket. Remove the option to send and receive without TLS.

## IOCP Server
Start iocp server with TLS by

```
IocpServer.exe -t
```

or without TLS

```
IocpServer.exe
```

Then you can use the simple client to interact with it as mentioned above, like

```
SimpleSocketClient.exe localhost -t 1>cli-output <file-to-send
```

You can also try to script multiple clients interacting with an IOCP server at the same time, to validate the server's concurrency. Here's an example in Cygwin:

```bash
for i in {1..5} ; do ./SimpleSocketClient.exe localhost -t 1>test-$i <file-to-send & done
```
