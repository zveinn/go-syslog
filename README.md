# syslog

A Go package for building syslog messages. Hand it a message struct, get bytes back. Pick the RFC, wrap for TCP if you want, write to the network.

## Supported RFCs

* RFC 3164 (BSD syslog)
* RFC 5424 (modern syslog)
* RFC 6587 (TCP framing, octet counting and non transparent)

## Examples

Basic format:

```go
b, err := syslog.FormatRFC5424(&syslog.Message{
    Facility: syslog.FacUser,
    Severity: syslog.SevInfo,
    Hostname: "host",
    AppName:  "app",
    Message:  "hello",
})
```

Append into a reused buffer. After the buffer has grown to fit your largest message there are no further allocations:

```go
buf := make([]byte, 0, 512)
for _, m := range messages {
    buf = buf[:0]
    buf, _ = syslog.AppendRFC5424(buf, m)
    conn.Write(buf)
}
```

Wrap with RFC 6587 octet counting for TCP:

```go
f := syslog.NewFrameRFC6587()
f.AddLog(msg1)
f.AddLog(msg2)
conn.Write(f.Bytes())
```

## Performance

```
BenchmarkAppendRFC3164     74 ns/op      0 B/op    0 allocs/op
BenchmarkAppendRFC5424    281 ns/op      0 B/op    0 allocs/op
BenchmarkFormatRFC3164    111 ns/op    112 B/op    1 allocs/op
```

Ryzen 7 7840HS, Go 1.26.
