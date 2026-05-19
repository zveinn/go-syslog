# syslog

This is a package to format syslog messages based on standard RFCs.

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

Or use the non transparent variant. Pick a trailer byte (LF is the default per the RFC). Your messages must not contain that byte:

```go
f := syslog.NewFrameRFC6587NonTransparent('\n')
f.AddLog(msg1)
f.AddLog(msg2)
conn.Write(f.Bytes())
```

## Performance

```
BenchmarkNewPriority                              1.3 ns/op     0 B/op  0 allocs/op
BenchmarkPriority_Facility                        0.4 ns/op     0 B/op  0 allocs/op
BenchmarkPriority_Severity                        0.4 ns/op     0 B/op  0 allocs/op
BenchmarkAppendRFC3164                             74 ns/op     0 B/op  0 allocs/op
BenchmarkAppendRFC5424                            285 ns/op     0 B/op  0 allocs/op
BenchmarkFormatRFC3164                            109 ns/op   112 B/op  1 allocs/op
BenchmarkFormatRFC5424                            375 ns/op   224 B/op  1 allocs/op
BenchmarkNewFrameRFC6587                           18 ns/op    24 B/op  1 allocs/op
BenchmarkFrameRFC6587_AddLog                      8.9 ns/op     0 B/op  0 allocs/op
BenchmarkFrameRFC6587_Size                        0.4 ns/op     0 B/op  0 allocs/op
BenchmarkFrameRFC6587_Bytes                       0.8 ns/op     0 B/op  0 allocs/op
BenchmarkFrameRFC6587_Reset                       0.5 ns/op     0 B/op  0 allocs/op
BenchmarkNewFrameRFC6587NonTransparent             20 ns/op    32 B/op  1 allocs/op
BenchmarkFrameRFC6587NonTransparent_AddLog        7.7 ns/op     0 B/op  0 allocs/op
BenchmarkFrameRFC6587NonTransparent_Size          0.4 ns/op     0 B/op  0 allocs/op
BenchmarkFrameRFC6587NonTransparent_Bytes         0.9 ns/op     0 B/op  0 allocs/op
BenchmarkFrameRFC6587NonTransparent_Reset         0.6 ns/op     0 B/op  0 allocs/op
```
