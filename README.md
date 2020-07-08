# Run Test

Before you run, you need a certificate for the server. The Subject Name of the certificate must be "localhost", and the certificate must be stored in the "My" store of the system's certificate store, in the "Local Machine". The certificate can be self issued but must not be expired.

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
