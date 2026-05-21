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

Format and frame in one call. The framer formats directly into its own buffer so the caller does not need a scratch slice:

```go
f := syslog.NewFrameRFC6587()
for _, m := range messages {
    if err := f.AddLogRFC5424(m); err != nil {
        // m had a validation error; f's buffer is left unchanged
        continue
    }
}
conn.Write(f.Bytes())
```

The same methods exist on `FrameRFC6587NonTransparent`, and there are `AddLogRFC3164` variants on both framers.

## Performance

```
BenchmarkNewPriority                                  0.47 ns/op     0 B/op  0 allocs/op
BenchmarkPriority_Facility                            0.54 ns/op     0 B/op  0 allocs/op
BenchmarkPriority_Severity                            0.55 ns/op     0 B/op  0 allocs/op
BenchmarkAppendRFC3164                                  93 ns/op     0 B/op  0 allocs/op
BenchmarkAppendRFC5424                                 337 ns/op     0 B/op  0 allocs/op
BenchmarkFormatRFC3164                                 133 ns/op   112 B/op  1 allocs/op
BenchmarkFormatRFC5424                                 437 ns/op   224 B/op  1 allocs/op
BenchmarkNewFrameRFC6587                                21 ns/op    24 B/op  1 allocs/op
BenchmarkFrameRFC6587_AddLog                          11.2 ns/op     0 B/op  0 allocs/op
BenchmarkFrameRFC6587_Size                            0.55 ns/op     0 B/op  0 allocs/op
BenchmarkFrameRFC6587_Bytes                            1.1 ns/op     0 B/op  0 allocs/op
BenchmarkFrameRFC6587_Reset                           0.82 ns/op     0 B/op  0 allocs/op
BenchmarkNewFrameRFC6587NonTransparent                  22 ns/op    32 B/op  1 allocs/op
BenchmarkFrameRFC6587NonTransparent_AddLog             9.9 ns/op     0 B/op  0 allocs/op
BenchmarkFrameRFC6587NonTransparent_Size              0.54 ns/op     0 B/op  0 allocs/op
BenchmarkFrameRFC6587NonTransparent_Bytes              1.1 ns/op     0 B/op  0 allocs/op
BenchmarkFrameRFC6587NonTransparent_Reset             0.54 ns/op     0 B/op  0 allocs/op
```

Format-and-frame pipelines, end-to-end (one append into a reused buffer, then framing). The `Pipeline*` rows are the two-step `AppendRFC*` + `AddLog` pattern; the `AddLogRFC*` rows are the direct in-place methods. Both write the same wire bytes:

```
BenchmarkPipelineRFC3164_Octet                         108 ns/op     0 B/op  0 allocs/op
BenchmarkFrameRFC6587_AddLogRFC3164                    106 ns/op     0 B/op  0 allocs/op
BenchmarkPipelineRFC3164_NonTransp                     103 ns/op     0 B/op  0 allocs/op
BenchmarkFrameRFC6587NonTransparent_AddLogRFC3164      102 ns/op     0 B/op  0 allocs/op
BenchmarkPipelineRFC5424_Octet                         193 ns/op     0 B/op  0 allocs/op
BenchmarkFrameRFC6587_AddLogRFC5424                    192 ns/op     0 B/op  0 allocs/op
BenchmarkPipelineRFC5424_NonTransp                     201 ns/op     0 B/op  0 allocs/op
BenchmarkFrameRFC6587NonTransparent_AddLogRFC5424      189 ns/op     0 B/op  0 allocs/op
```

The direct methods are within noise of the two-step pattern for octet counting and a few percent faster for non transparent framing. The bigger win is ergonomic: callers do not need to own a scratch buffer.
