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

Validate a message without formatting it. Useful for input forms, API request validation, or anywhere you want to check a `Message` before committing to encoding it:

```go
if err := syslog.ValidateMessageRFC5424(m); err != nil {
    return fmt.Errorf("invalid syslog message: %w", err)
}
```

There are per-field validators too (`ValidateHostnameRFC5424`, `ValidateAppNameRFC3164`, `ValidateSDID`, ...) and an RFC 3164 variant `ValidateMessageRFC3164`.

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

Or pass a whole slice. On the first validation error the call stops and returns an error naming the index; messages already framed before that point stay in the buffer:

```go
f := syslog.NewFrameRFC6587()
if err := f.AddLogsRFC5424(messages); err != nil {
    log.Printf("partial batch: %v", err)
}
conn.Write(f.Bytes())
```

The same methods exist on `FrameRFC6587NonTransparent`, and there are `AddLogRFC3164` / `AddLogsRFC3164` variants on both framers.

## Performance

```
$ go test -bench=. -benchmem -run='^$' -benchtime=3s -count=1 ./...
goos: linux
goarch: amd64
pkg: github.com/zveinn/go-syslog
cpu: AMD Ryzen 7 7840HS w/ Radeon 780M Graphics
BenchmarkNewPriority-16                                         1000000000               0.6608 ns/op          0 B/op          0 allocs/op
BenchmarkPriority_Facility-16                                   1000000000               0.5409 ns/op          0 B/op          0 allocs/op
BenchmarkPriority_Severity-16                                   1000000000               0.5395 ns/op          0 B/op          0 allocs/op
BenchmarkAppendRFC3164-16                                       37581124                94.48 ns/op            0 B/op          0 allocs/op
BenchmarkAppendRFC5424-16                                       10086043               353.7 ns/op             0 B/op          0 allocs/op
BenchmarkFormatRFC3164-16                                       25484018               156.1 ns/op           112 B/op          1 allocs/op
BenchmarkFormatRFC5424-16                                        6193645               505.0 ns/op           224 B/op          1 allocs/op
BenchmarkNewFrameRFC6587-16                                     100000000               33.93 ns/op           24 B/op          1 allocs/op
BenchmarkFrameRFC6587_AddLog-16                                 267571840               11.87 ns/op     6994.14 MB/s           0 B/op          0 allocs/op
BenchmarkFrameRFC6587_Size-16                                   1000000000               0.5413 ns/op          0 B/op          0 allocs/op
BenchmarkFrameRFC6587_Bytes-16                                  1000000000               1.067 ns/op           0 B/op          0 allocs/op
BenchmarkFrameRFC6587_Reset-16                                  1000000000               0.8100 ns/op          0 B/op          0 allocs/op
BenchmarkNewFrameRFC6587NonTransparent-16                       100000000               34.74 ns/op           32 B/op          1 allocs/op
BenchmarkFrameRFC6587NonTransparent_AddLog-16                   295441210               10.59 ns/op     7837.12 MB/s           0 B/op          0 allocs/op
BenchmarkFrameRFC6587NonTransparent_Size-16                     1000000000               0.5455 ns/op          0 B/op          0 allocs/op
BenchmarkFrameRFC6587NonTransparent_Bytes-16                    1000000000               1.074 ns/op           0 B/op          0 allocs/op
BenchmarkFrameRFC6587NonTransparent_Reset-16                    1000000000               0.6210 ns/op          0 B/op          0 allocs/op
BenchmarkPipelineRFC5424_Octet-16                               17588158               203.7 ns/op             0 B/op          0 allocs/op
BenchmarkPipelineRFC3164_Octet-16                               32542057               108.5 ns/op             0 B/op          0 allocs/op
BenchmarkFrameRFC6587_AddLogRFC3164-16                          33090034               107.7 ns/op             0 B/op          0 allocs/op
BenchmarkPipelineRFC3164_NonTransp-16                           33545490               104.4 ns/op             0 B/op          0 allocs/op
BenchmarkFrameRFC6587NonTransparent_AddLogRFC3164-16            35060760               101.7 ns/op             0 B/op          0 allocs/op
BenchmarkFrameRFC6587_AddLogRFC5424-16                          17885848               199.2 ns/op             0 B/op          0 allocs/op
BenchmarkPipelineRFC5424_NonTransp-16                           18416469               194.2 ns/op             0 B/op          0 allocs/op
BenchmarkFrameRFC6587NonTransparent_AddLogRFC5424-16            18571788               192.0 ns/op             0 B/op          0 allocs/op
BenchmarkValidateHostnameRFC3164-16                             152204276               23.74 ns/op            0 B/op          0 allocs/op
BenchmarkValidateProcIDRFC3164-16                               100000000               33.31 ns/op            0 B/op          0 allocs/op
BenchmarkValidateAppNameRFC3164-16                              666640089                5.425 ns/op           0 B/op          0 allocs/op
BenchmarkValidateHostnameRFC5424-16                             258467637               13.94 ns/op            0 B/op          0 allocs/op
BenchmarkValidateAppNameRFC5424-16                              433289787                8.315 ns/op           0 B/op          0 allocs/op
BenchmarkValidateProcIDRFC5424-16                               835405143                4.293 ns/op           0 B/op          0 allocs/op
BenchmarkValidateMsgIDRFC5424-16                                789726434                4.554 ns/op           0 B/op          0 allocs/op
BenchmarkValidateSDID-16                                        176882556               20.38 ns/op            0 B/op          0 allocs/op
BenchmarkValidateStructuredData-16                              35011795               107.0 ns/op             0 B/op          0 allocs/op
BenchmarkValidateMessageRFC3164-16                              233203078               15.72 ns/op            0 B/op          0 allocs/op
BenchmarkValidateMessageRFC5424-16                              27455179               133.4 ns/op             0 B/op          0 allocs/op
BenchmarkFrameRFC6587_AddLogsRFC5424-16                           182808             19792 ns/op              28 B/op          0 allocs/op
BenchmarkFrameRFC6587NonTransparent_AddLogsRFC5424-16             186752             19240 ns/op              28 B/op          0 allocs/op
```
