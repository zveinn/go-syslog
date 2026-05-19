// Command load drives an extensive syslog corpus against a target server.
// It exercises every (RFC × transport × TCP-framing) combination plus an
// explicit corner-case suite for boundary conditions called out in the
// RFCs (NILVALUE, max-length fields, packet size limits, escape chars,
// UTF-8 BOM, multiple SD-ELEMENTs, etc.).
//
// For each message sent it appends one line to -expect of the form
//
//	[imudp|imtcp] <wire bytes>
//
// so an external verifier can diff what the server received against what
// was sent, byte-for-byte.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"os"
	"runtime"
	"runtime/pprof"
	"strings"
	"time"

	syslog "github.com/zveinn/go-syslog"
)

const bulkPerCategory = 8000

func main() {
	udpAddr := flag.String("udp", "127.0.0.1:5514", "UDP target host:port")
	tcpAddr := flag.String("tcp", "127.0.0.1:5514", "TCP target host:port")
	expect := flag.String("expect", "expected.txt", "path to write expected lines")
	cpuProf := flag.String("cpuprofile", "", "write CPU profile to file")
	memProf := flag.String("memprofile", "", "write allocs profile to file")
	flag.Parse()

	if *cpuProf != "" {
		f, err := os.Create(*cpuProf)
		if err != nil {
			log.Fatalf("create cpu profile: %v", err)
		}
		defer f.Close()
		if err := pprof.StartCPUProfile(f); err != nil {
			log.Fatalf("start cpu profile: %v", err)
		}
		defer pprof.StopCPUProfile()
	}

	var msStart runtime.MemStats
	runtime.ReadMemStats(&msStart)
	tStart := time.Now()

	expectRaw, err := os.Create(*expect)
	if err != nil {
		log.Fatalf("create expect file: %v", err)
	}
	defer expectRaw.Close()
	expectF := bufio.NewWriterSize(expectRaw, 1<<20)
	defer expectF.Flush()

	udp, err := net.Dial("udp", *udpAddr)
	if err != nil {
		log.Fatalf("dial udp: %v", err)
	}
	defer udp.Close()

	// Two TCP connections so octet-counting and non-transparent framing
	// can be exercised independently — rsyslog autodetects per-connection.
	tcpOctet, err := net.Dial("tcp", *tcpAddr)
	if err != nil {
		log.Fatalf("dial tcp/octet: %v", err)
	}
	defer tcpOctet.Close()
	tcpNT, err := net.Dial("tcp", *tcpAddr)
	if err != nil {
		log.Fatalf("dial tcp/nontransp: %v", err)
	}
	defer tcpNT.Close()

	var (
		nUDP3164, nUDP5424                 int
		nTCPOctet3164, nTCPOctet5424       int
		nTCPNonTransp3164, nTCPNonTransp5424 int
	)

	// ---- UDP ------------------------------------------------------------
	nUDP3164 = sendUDPBatch(udp, expectF, "3164-udp",
		corners3164("3164-udp"),
		bulk3164(bulkPerCategory, "3164-udp"),
		syslog.AppendRFC3164)

	nUDP5424 = sendUDPBatch(udp, expectF, "5424-udp",
		corners5424("5424-udp"),
		bulk5424(bulkPerCategory, "5424-udp"),
		syslog.AppendRFC5424)

	// ---- TCP via RFC 6587 §3.4.1 octet-counting -------------------------
	nTCPOctet3164 = sendTCPOctet(tcpOctet, expectF,
		corners3164("3164-tcp-octet"),
		bulk3164(bulkPerCategory, "3164-tcp-octet"),
		syslog.AppendRFC3164)

	nTCPOctet5424 = sendTCPOctet(tcpOctet, expectF,
		corners5424("5424-tcp-octet"),
		bulk5424(bulkPerCategory, "5424-tcp-octet"),
		syslog.AppendRFC5424)

	// ---- TCP via RFC 6587 §3.4.2 non-transparent (LF) -------------------
	nTCPNonTransp3164 = sendTCPNonTransp(tcpNT, expectF,
		corners3164("3164-tcp-nt"),
		bulk3164(bulkPerCategory, "3164-tcp-nt"),
		syslog.AppendRFC3164)

	nTCPNonTransp5424 = sendTCPNonTransp(tcpNT, expectF,
		corners5424("5424-tcp-nt"),
		bulk5424(bulkPerCategory, "5424-tcp-nt"),
		syslog.AppendRFC5424)

	total := nUDP3164 + nUDP5424 + nTCPOctet3164 + nTCPOctet5424 + nTCPNonTransp3164 + nTCPNonTransp5424
	log.Printf(
		"sent: 3164/UDP=%d  5424/UDP=%d  3164/TCP-octet=%d  5424/TCP-octet=%d  3164/TCP-nt=%d  5424/TCP-nt=%d  total=%d",
		nUDP3164, nUDP5424,
		nTCPOctet3164, nTCPOctet5424,
		nTCPNonTransp3164, nTCPNonTransp5424,
		total,
	)

	if err := expectF.Flush(); err != nil {
		log.Fatalf("flush expect: %v", err)
	}

	var msEnd runtime.MemStats
	runtime.ReadMemStats(&msEnd)
	elapsed := time.Since(tStart)
	allocObjects := msEnd.Mallocs - msStart.Mallocs
	allocBytes := msEnd.TotalAlloc - msStart.TotalAlloc
	gcCycles := msEnd.NumGC - msStart.NumGC

	log.Printf(
		"memory: alloc-objects=%s alloc-bytes=%s heap-inuse=%s sys=%s gc=%d elapsed=%s "+
			"(%.2f allocs/msg, %.0f B/msg)",
		fmtCount(allocObjects), fmtBytes(allocBytes),
		fmtBytes(msEnd.HeapInuse), fmtBytes(msEnd.Sys),
		gcCycles, elapsed,
		float64(allocObjects)/float64(total),
		float64(allocBytes)/float64(total),
	)

	if *memProf != "" {
		runtime.GC()
		f, err := os.Create(*memProf)
		if err != nil {
			log.Fatalf("create mem profile: %v", err)
		}
		defer f.Close()
		// "allocs" profile = every alloc since start (independent of GC),
		// which is what we want for hotspot hunting.
		if err := pprof.Lookup("allocs").WriteTo(f, 0); err != nil {
			log.Fatalf("write mem profile: %v", err)
		}
	}
}

func fmtBytes(n uint64) string {
	const k = 1024
	switch {
	case n >= k*k*k:
		return fmt.Sprintf("%.2f GiB", float64(n)/float64(k*k*k))
	case n >= k*k:
		return fmt.Sprintf("%.2f MiB", float64(n)/float64(k*k))
	case n >= k:
		return fmt.Sprintf("%.2f KiB", float64(n)/float64(k))
	}
	return fmt.Sprintf("%d B", n)
}

func fmtCount(n uint64) string {
	switch {
	case n >= 1_000_000:
		return fmt.Sprintf("%.2fM", float64(n)/1_000_000)
	case n >= 1_000:
		return fmt.Sprintf("%.2fk", float64(n)/1_000)
	}
	return fmt.Sprintf("%d", n)
}

// -----------------------------------------------------------------------------
// senders
// -----------------------------------------------------------------------------

// appender is the AppendRFC3164 / AppendRFC5424 signature. Using it (instead
// of FormatRFC*) lets each sender keep a single growable buffer and reuse it
// across messages, eliminating one allocation per message.
type appender func(dst []byte, m *syslog.Message) ([]byte, error)

// forEach iterates corners and bulk in sequence without allocating a
// combined slice (which is what `append(corners, bulk...)` would do).
func forEach(corners, bulk []*syslog.Message, fn func(int, *syslog.Message)) {
	i := 0
	for _, m := range corners {
		fn(i, m)
		i++
	}
	for _, m := range bulk {
		fn(i, m)
		i++
	}
}

func sendUDPBatch(c net.Conn, expect *bufio.Writer, label string,
	corners, bulk []*syslog.Message, app appender) int {

	sent := 0
	var buf []byte
	forEach(corners, bulk, func(i int, m *syslog.Message) {
		buf = buf[:0]
		var err error
		buf, err = app(buf, m)
		if err != nil {
			log.Fatalf("%s seq=%d format: %v", label, i, err)
		}
		if _, err := c.Write(buf); err != nil {
			log.Fatalf("%s seq=%d write: %v", label, i, err)
		}
		// Direct bufio writes avoid fmt.Fprintf's interface boxing.
		_, _ = expect.WriteString("[imudp] ")
		_, _ = expect.Write(buf)
		_ = expect.WriteByte('\n')
		sent++
		// Light pacing so the kernel UDP recv buffer doesn't fill while
		// rsyslog is still draining the previous burst.
		if sent%200 == 0 {
			time.Sleep(time.Millisecond)
		}
	})
	return sent
}

func sendTCPOctet(c net.Conn, expect *bufio.Writer,
	corners, bulk []*syslog.Message, app appender) int {

	sent := 0
	var buf []byte
	frame := syslog.NewFrameRFC6587()
	const flushEvery = 1000
	forEach(corners, bulk, func(i int, m *syslog.Message) {
		buf = buf[:0]
		var err error
		buf, err = app(buf, m)
		if err != nil {
			log.Fatalf("tcp/octet seq=%d format: %v", i, err)
		}
		if err := frame.AddLog(buf); err != nil {
			log.Fatalf("tcp/octet seq=%d frame: %v", i, err)
		}
		_, _ = expect.WriteString("[imtcp] ")
		_, _ = expect.Write(buf)
		_ = expect.WriteByte('\n')
		sent++
		if sent%flushEvery == 0 {
			if err := writeAll(c, frame.Bytes()); err != nil {
				log.Fatalf("tcp/octet flush: %v", err)
			}
			frame.Reset()
		}
	})
	if frame.Size() > 0 {
		if err := writeAll(c, frame.Bytes()); err != nil {
			log.Fatalf("tcp/octet final flush: %v", err)
		}
	}
	return sent
}

func sendTCPNonTransp(c net.Conn, expect *bufio.Writer,
	corners, bulk []*syslog.Message, app appender) int {

	sent := 0
	var buf []byte
	frame := syslog.NewFrameRFC6587NonTransparent('\n')
	const flushEvery = 1000
	forEach(corners, bulk, func(i int, m *syslog.Message) {
		buf = buf[:0]
		var err error
		buf, err = app(buf, m)
		if err != nil {
			log.Fatalf("tcp/nt seq=%d format: %v", i, err)
		}
		if err := frame.AddLog(buf); err != nil {
			log.Fatalf("tcp/nt seq=%d frame: %v", i, err)
		}
		_, _ = expect.WriteString("[imtcp] ")
		_, _ = expect.Write(buf)
		_ = expect.WriteByte('\n')
		sent++
		if sent%flushEvery == 0 {
			if err := writeAll(c, frame.Bytes()); err != nil {
				log.Fatalf("tcp/nt flush: %v", err)
			}
			frame.Reset()
		}
	})
	if frame.Size() > 0 {
		if err := writeAll(c, frame.Bytes()); err != nil {
			log.Fatalf("tcp/nt final flush: %v", err)
		}
	}
	return sent
}

func writeAll(c net.Conn, b []byte) error {
	n, err := c.Write(b)
	if err != nil {
		return err
	}
	if n != len(b) {
		return fmt.Errorf("short write %d/%d", n, len(b))
	}
	return nil
}

// -----------------------------------------------------------------------------
// RFC 3164 corner cases
// -----------------------------------------------------------------------------

func corners3164(tag string) []*syslog.Message {
	ts := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	withTS := func(m *syslog.Message, t time.Time) *syslog.Message {
		m.Timestamp = t
		return m
	}
	// Each message embeds the category tag plus a corner label, guaranteeing
	// uniqueness across categories and across the bulk space.
	mk := func(label string, m *syslog.Message) *syslog.Message {
		m.Timestamp = ts
		m.Message = fmt.Sprintf("corner=%s cat=%s 3164", label, tag)
		return m
	}

	out := []*syslog.Message{
		// PRI = 0 (Facility 0, Severity 0).
		mk("pri0", &syslog.Message{
			Facility: syslog.FacKern, Severity: syslog.SevEmerg,
			Hostname: "h", AppName: "a",
		}),
		// PRI = 191 (Facility 23, Severity 7).
		mk("pri191", &syslog.Message{
			Facility: syslog.FacLocal7, Severity: syslog.SevDebug,
			Hostname: "h", AppName: "a",
		}),
		// TAG exactly 32 chars (the §4.1.3 ceiling).
		mk("tag32", &syslog.Message{
			Facility: syslog.FacUser, Severity: syslog.SevInfo,
			Hostname: "h", AppName: strings.Repeat("a", 32),
		}),
		// Single-character TAG.
		mk("tag1", &syslog.Message{
			Facility: syslog.FacUser, Severity: syslog.SevInfo,
			Hostname: "h", AppName: "x",
		}),
		// IPv4 hostname (§4.1.2 allows hostname, IPv4, or IPv6).
		mk("ipv4host", &syslog.Message{
			Facility: syslog.FacUser, Severity: syslog.SevInfo,
			Hostname: "192.0.2.5", AppName: "app",
		}),
		// FQDN hostname.
		mk("fqdn", &syslog.Message{
			Facility: syslog.FacUser, Severity: syslog.SevInfo,
			Hostname: "host.subdomain.example.com", AppName: "app",
		}),
		// No ProcID → "TAG: MSG" (no [PID]).
		mk("noprocid", &syslog.Message{
			Facility: syslog.FacUser, Severity: syslog.SevInfo,
			Hostname: "h", AppName: "app",
		}),
		// Long numeric ProcID.
		mk("longpid", &syslog.Message{
			Facility: syslog.FacUser, Severity: syslog.SevInfo,
			Hostname: "h", AppName: "app", ProcID: "987654321",
		}),
		// ProcID with non-numeric characters (allowed: anything but []/ws).
		mk("namedpid", &syslog.Message{
			Facility: syslog.FacUser, Severity: syslog.SevInfo,
			Hostname: "h", AppName: "app", ProcID: "worker-3",
		}),
		// Body close to (but under) the §4.1 1024-byte packet limit.
		mk("nearmax", &syslog.Message{
			Facility: syslog.FacUser, Severity: syslog.SevInfo,
			Hostname: "h", AppName: "app",
		}),
		// Day 1 (single-digit, exercises space-pad in TIMESTAMP).
		withTS(mk("day1", &syslog.Message{
			Facility: syslog.FacUser, Severity: syslog.SevInfo,
			Hostname: "h", AppName: "app",
		}), time.Date(2026, time.July, 1, 8, 9, 10, 0, time.UTC)),
		// Day 31 (double-digit).
		withTS(mk("day31", &syslog.Message{
			Facility: syslog.FacUser, Severity: syslog.SevInfo,
			Hostname: "h", AppName: "app",
		}), time.Date(2026, time.July, 31, 23, 59, 59, 0, time.UTC)),
	}
	// Replace "nearmax" body with a real near-limit payload now that all
	// other fields are settled. Header overhead is ~50 bytes, so 950 bytes
	// of body stays under the 1024-octet ceiling.
	for _, m := range out {
		if strings.HasPrefix(m.Message, "corner=nearmax") {
			m.Message = "corner=nearmax cat=" + tag + " 3164 " + strings.Repeat("X", 900)
			break
		}
	}
	return out
}

// -----------------------------------------------------------------------------
// RFC 5424 corner cases
// -----------------------------------------------------------------------------

func corners5424(tag string) []*syslog.Message {
	ts := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	mk := func(label string, m *syslog.Message) *syslog.Message {
		if m.Timestamp.IsZero() {
			m.Timestamp = ts
		}
		if m.Message == "" {
			m.Message = fmt.Sprintf("corner=%s cat=%s 5424", label, tag)
		}
		return m
	}

	// Note: "x" is used as MSGID for cases that exercise the message body so
	// each corner stays distinguishable in the dump.
	return []*syslog.Message{
		// All headers NILVALUE → wire form "- - - - -".
		mk("allnil", &syslog.Message{
			Facility: syslog.FacUser, Severity: syslog.SevInfo,
			Message: "corner=allnil cat=" + tag + " 5424",
		}),
		// HOSTNAME = NILVALUE only.
		mk("nilhost", &syslog.Message{
			Facility: syslog.FacUser, Severity: syslog.SevInfo,
			AppName: "app", ProcID: "1", MsgID: "ID",
			Message: "corner=nilhost cat=" + tag + " 5424",
		}),
		// HOSTNAME at the 255-octet ceiling (§6.2.4).
		mk("hostmax", &syslog.Message{
			Facility: syslog.FacUser, Severity: syslog.SevInfo,
			Hostname: strings.Repeat("h", 255), AppName: "app",
		}),
		// APP-NAME at the 48-octet ceiling (§6.2.5).
		mk("appmax", &syslog.Message{
			Facility: syslog.FacUser, Severity: syslog.SevInfo,
			Hostname: "h", AppName: strings.Repeat("a", 48),
		}),
		// PROCID at the 128-octet ceiling (§6.2.6).
		mk("procmax", &syslog.Message{
			Facility: syslog.FacUser, Severity: syslog.SevInfo,
			Hostname: "h", AppName: "app", ProcID: strings.Repeat("p", 128),
		}),
		// MSGID at the 32-octet ceiling (§6.2.7).
		mk("msgidmax", &syslog.Message{
			Facility: syslog.FacUser, Severity: syslog.SevInfo,
			Hostname: "h", AppName: "app", MsgID: strings.Repeat("m", 32),
		}),
		// PRI = 0.
		mk("pri0", &syslog.Message{
			Facility: syslog.FacKern, Severity: syslog.SevEmerg,
			Hostname: "h", AppName: "app",
		}),
		// PRI = 191.
		mk("pri191", &syslog.Message{
			Facility: syslog.FacLocal7, Severity: syslog.SevDebug,
			Hostname: "h", AppName: "app",
		}),
		// Negative TZ offset.
		mk("tzneg", &syslog.Message{
			Facility: syslog.FacUser, Severity: syslog.SevInfo,
			Timestamp: time.Date(2026, 3, 15, 9, 0, 0, 0,
				time.FixedZone("pst", -8*3600)),
			Hostname: "h", AppName: "app",
		}),
		// Maximum positive TZ offset (+14:00 per RFC 3339).
		mk("tzplus14", &syslog.Message{
			Facility: syslog.FacUser, Severity: syslog.SevInfo,
			Timestamp: time.Date(2026, 3, 15, 9, 0, 0, 0,
				time.FixedZone("kir", 14*3600)),
			Hostname: "h", AppName: "app",
		}),
		// 6-digit fractional seconds (the §6.2.3.2 ceiling).
		mk("frac6", &syslog.Message{
			Facility: syslog.FacUser, Severity: syslog.SevInfo,
			Timestamp: time.Date(2026, 6, 15, 12, 0, 0, 123456000, time.UTC),
			Hostname: "h", AppName: "app",
		}),
		// SD-ELEMENT with zero params (just "[id]").
		mk("sdnoparams", &syslog.Message{
			Facility: syslog.FacUser, Severity: syslog.SevInfo,
			Hostname: "h", AppName: "app",
			StructuredData: []syslog.SDElement{{ID: "empty@32473"}},
		}),
		// All three escape-required chars (", \, ]) in one PARAM-VALUE.
		mk("sdescapes", &syslog.Message{
			Facility: syslog.FacUser, Severity: syslog.SevInfo,
			Hostname: "h", AppName: "app",
			StructuredData: []syslog.SDElement{{
				ID:     "escape@32473",
				Params: []syslog.SDParam{{Name: "all", Value: `q"b\s]e`}},
			}},
		}),
		// Three SD-ELEMENTs, varied param counts.
		mk("sdmulti", &syslog.Message{
			Facility: syslog.FacUser, Severity: syslog.SevInfo,
			Hostname: "h", AppName: "app",
			StructuredData: []syslog.SDElement{
				{ID: "first@32473"},
				{ID: "second@32473", Params: []syslog.SDParam{{Name: "k", Value: "v"}}},
				{ID: "third@32473", Params: []syslog.SDParam{
					{Name: "a", Value: "1"},
					{Name: "b", Value: "2"},
					{Name: "c", Value: "3"},
				}},
			},
		}),
		// MSG with UTF-8 BOM (§6.4 — required when MSG is UTF-8).
		mk("bom", &syslog.Message{
			Facility: syslog.FacUser, Severity: syslog.SevInfo,
			Hostname: "h", AppName: "app",
			Message: "\xef\xbb\xbfcorner=bom cat=" + tag + " 5424 ütf-8",
		}),
		// Empty MSG (legal — the SP MSG is optional per §6).
		mk("emptymsg", &syslog.Message{
			Facility: syslog.FacUser, Severity: syslog.SevInfo,
			Hostname: "h", AppName: "app", MsgID: "EMPTYMSG-" + tag,
			Message: "",
		}),
	}
}

// -----------------------------------------------------------------------------
// Body shapes
//
// Real-world syslog payloads carry highly varied content: Go's log/slog
// emits both TextHandler ("key=value") and JSONHandler output; many apps
// emit logfmt; some pass through raw bytes. Each body generator is keyed
// off seq so re-runs are bit-identical, which keeps the byte-exact diff
// in run.sh meaningful.
//
// The shapes here intentionally exercise:
//   - embedded JSON braces, quotes, colons (look like RFC 5424 SD syntax
//     but appear inside MSG, where they have no special meaning)
//   - backslashes (only special inside SD PARAM-VALUE)
//   - UTF-8 multi-byte runs (must be valid UTF-8; see also BOM variant)
//   - random printable ASCII (full 32..126 except newline)
//   - tabs in MSG (legal — only LF/NUL are practically problematic)
//
// LF is deliberately avoided so the same bodies can travel over RFC 6587
// non-transparent framing without violating that protocol's trailer rule.
// -----------------------------------------------------------------------------

func slogTextBody(seq int, transport string) string {
	return fmt.Sprintf(
		`time=2026-05-19T13:00:00Z level=INFO source=auth/login.go:42 msg="login ok" `+
			`seq=%d cat=%s user="alice bob" client_ip=192.0.2.7 latency_ms=12 trace_id=abc123`,
		seq, transport)
}

func slogJSONBody(seq int, transport string) string {
	return fmt.Sprintf(
		`{"time":"2026-05-19T13:00:00Z","level":"INFO","msg":"login ok",`+
			`"seq":%d,"cat":%q,"user":"alice bob","client_ip":"192.0.2.7",`+
			`"latency_ms":12,"trace_id":"abc123","attrs":{"role":"admin","tier":"gold"}}`,
		seq, transport)
}

func logfmtBody(seq int, transport string) string {
	return fmt.Sprintf(
		`ts=2026-05-19T13:00:00Z lvl=info evt=http_request seq=%d cat=%s `+
			`method=GET path=/api/v1/users status=200 dur=42ms ua="curl/8.0"`,
		seq, transport)
}

func nestedJSONBody(seq int, transport string) string {
	return fmt.Sprintf(
		`{"event":"order_placed","seq":%d,"cat":%q,`+
			`"order":{"id":"ord_%d","items":[{"sku":"AB-1","qty":2},{"sku":"CD-2","qty":1}],`+
			`"total_cents":4299},"customer":{"id":"cus_%d","email":"a@example.com"}}`,
		seq, transport, seq, seq*7)
}

// randomASCIIBody produces a deterministic printable-ASCII payload (32..126,
// LF excluded) of variable length.
func randomASCIIBody(seq int, transport string) string {
	r := rand.New(rand.NewPCG(uint64(seq), 0xA5A5A5A5A5A5A5A5))
	n := 60 + r.IntN(180) // 60..239 chars
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.IntN(95) + 32) // 32..126
	}
	return fmt.Sprintf("seq=%d cat=%s rnd=%s", seq, transport, b)
}

// randomUTF8Body mixes ASCII, Latin-1 supplement, Cyrillic, hiragana, and
// CJK so we put non-trivial multi-byte UTF-8 on the wire.
func randomUTF8Body(seq int, transport string) string {
	r := rand.New(rand.NewPCG(uint64(seq), 0x5A5A5A5A5A5A5A5A))
	runes := 25 + r.IntN(60) // 25..84 runes
	var b strings.Builder
	for range runes {
		var c rune
		switch r.IntN(5) {
		case 0:
			c = rune(r.IntN(94) + 33) // printable ASCII (excl. SP)
		case 1:
			c = rune(r.IntN(0x1E0) + 0xA1) // Latin-1 supp + Latin extended
		case 2:
			c = rune(r.IntN(0x60) + 0x0400) // Cyrillic
		case 3:
			c = rune(r.IntN(0x60) + 0x3041) // Hiragana
		case 4:
			c = rune(r.IntN(0x100) + 0x4E00) // CJK unified ideographs
		}
		b.WriteRune(c)
	}
	return fmt.Sprintf("seq=%d cat=%s utf8=%s", seq, transport, b.String())
}

func tabAndSymbolsBody(seq int, transport string) string {
	return fmt.Sprintf(
		"seq=%d\tcat=%s\tlevel=warn\tmsg=\"value with !@#$%%^&*()_+-={}[]|;:'<>,.?/~`\"",
		seq, transport)
}

// -----------------------------------------------------------------------------
// Bulk generators
// -----------------------------------------------------------------------------

// hostnames3164 lists hostname shapes valid under RFC 3164's
// no-whitespace / printable-ASCII rule.
var hostnames3164 = []string{
	"host",
	"webserver-01",
	"db.example.com",
	"node.region.cloud.example.net",
	"192.0.2.5",
	"10.20.30.40",
}

var tags3164 = []string{
	"a", "sshd", "kernel", "nginx", "myapp01", "longappname123",
	strings.Repeat("a", 32), // max length
}

var procIDs3164 = []string{"", "1", "12345", "999999", "worker-3", "main"}

func bulk3164(n int, transport string) []*syslog.Message {
	out := make([]*syslog.Message, 0, n)
	for seq := range n {
		fac := syslog.Facility(seq % 24)
		sev := syslog.Severity((seq / 24) % 8)
		month := time.Month((seq%12)+1)
		day := (seq % 28) + 1
		ts := time.Date(2026, month, day,
			seq%24, (seq*7)%60, (seq*13)%60, 0, time.UTC)

		host := hostnames3164[seq%len(hostnames3164)]
		tag := tags3164[seq%len(tags3164)]
		pid := procIDs3164[seq%len(procIDs3164)]

		// 12 body shapes including slog/json/logfmt/random/UTF-8/tabs.
		// All variants kept under ~600 bytes so 3164's 1024-byte packet
		// limit holds even with max-length TAG (32) and longest hostname.
		var body string
		switch seq % 12 {
		case 0:
			body = fmt.Sprintf("seq=%d cat=%s 3164 short", seq, transport)
		case 1:
			body = fmt.Sprintf("seq=%d cat=%s 3164 sym !@#$%%^&*()_+-=.,/?", seq, transport)
		case 2:
			body = fmt.Sprintf("seq=%d cat=%s 3164 long %s", seq, transport,
				strings.Repeat("abcdef ", 50))
		case 3:
			body = fmt.Sprintf("seq=%d cat=%s 3164 nums 0123456789", seq, transport)
		case 4:
			body = slogTextBody(seq, transport)
		case 5:
			body = slogJSONBody(seq, transport)
		case 6:
			body = logfmtBody(seq, transport)
		case 7:
			body = nestedJSONBody(seq, transport)
		case 8:
			body = randomASCIIBody(seq, transport)
		case 9:
			body = randomUTF8Body(seq, transport)
		case 10:
			body = tabAndSymbolsBody(seq, transport)
		default:
			body = fmt.Sprintf("seq=%d cat=%s 3164 v=%d", seq, transport, seq%7)
		}

		out = append(out, &syslog.Message{
			Facility:  fac,
			Severity:  sev,
			Timestamp: ts,
			Hostname:  host,
			AppName:   tag,
			ProcID:    pid,
			Message:   body,
		})
	}
	return out
}

var tzCycle = []*time.Location{
	time.UTC,
	time.FixedZone("east", 5*3600+30*60),
	time.FixedZone("pst", -8*3600),
	time.FixedZone("jst", 9*3600),
	time.FixedZone("nzdt", 13*3600),
}

func bulk5424(n int, transport string) []*syslog.Message {
	out := make([]*syslog.Message, 0, n)
	for seq := range n {
		fac := syslog.Facility(seq % 24)
		sev := syslog.Severity((seq / 24) % 8)

		base := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
		ts := base.Add(time.Duration(seq) * time.Minute)
		switch seq % 5 {
		case 0:
			// no fractional
		case 1:
			ts = ts.Add(123 * time.Millisecond)
		case 2:
			ts = ts.Add(123456 * time.Microsecond)
		case 3:
			ts = ts.Add(1 * time.Microsecond)
		case 4:
			// move into a non-UTC zone
		}
		ts = ts.In(tzCycle[seq%len(tzCycle)])

		// Hostname / AppName / ProcID / MsgID rotated to include NILVALUEs
		// and max-length values.
		host := fmt.Sprintf("host%04d.example.com", seq)
		switch seq % 17 {
		case 0:
			host = ""
		case 1:
			host = strings.Repeat("h", 255) // boundary
		}

		app := "app"
		switch seq % 13 {
		case 0:
			app = ""
		case 1:
			app = strings.Repeat("a", 48)
		case 2:
			app = "longappname"
		}

		procID := fmt.Sprintf("%d", 1000+seq)
		switch seq % 11 {
		case 0:
			procID = ""
		case 1:
			procID = strings.Repeat("p", 128)
		}

		msgID := fmt.Sprintf("MID%05d", seq)
		switch seq % 19 {
		case 0:
			msgID = ""
		case 1:
			msgID = strings.Repeat("m", 32)
		}

		var sd []syslog.SDElement
		switch seq % 7 {
		case 0:
			// no SD
		case 1:
			sd = []syslog.SDElement{{
				ID:     "test@32473",
				Params: []syslog.SDParam{{Name: "seq", Value: fmt.Sprintf("%d", seq)}},
			}}
		case 2:
			sd = []syslog.SDElement{{
				ID: "test@32473",
				Params: []syslog.SDParam{
					{Name: "seq", Value: fmt.Sprintf("%d", seq)},
					{Name: "transport", Value: transport},
					{Name: "esc", Value: `q="x" b=] s=\`},
				},
			}}
		case 3:
			sd = []syslog.SDElement{
				{ID: "first@32473", Params: []syslog.SDParam{{Name: "a", Value: fmt.Sprintf("%d", seq)}}},
				{ID: "second@32473", Params: []syslog.SDParam{
					{Name: "b", Value: transport},
					{Name: "c", Value: "value with ü"}, // valid UTF-8
				}},
			}
		case 4:
			sd = []syslog.SDElement{{ID: "noparams@32473"}}
		case 5:
			sd = []syslog.SDElement{{
				ID: fmt.Sprintf("k%d@32473", seq%1000),
				Params: []syslog.SDParam{
					{Name: "x", Value: ""}, // empty PARAM-VALUE is allowed
				},
			}}
		case 6:
			sd = []syslog.SDElement{{
				ID: "big@32473",
				Params: []syslog.SDParam{
					{Name: "p1", Value: "v1"},
					{Name: "p2", Value: "v2"},
					{Name: "p3", Value: "v3"},
					{Name: "p4", Value: "v4"},
					{Name: "p5", Value: "v5"},
				},
			}}
		}

		// 13 body shapes. RFC 5424 MSG-ANY accepts any bytes, but LF is
		// avoided so the same payloads can travel over RFC 6587 non-
		// transparent framing. The "binary" variant exercises high bytes
		// + control chars (still no LF/NUL).
		var body string
		switch seq % 13 {
		case 0:
			body = ""
		case 1:
			body = fmt.Sprintf("seq=%d cat=%s 5424 short", seq, transport)
		case 2:
			body = fmt.Sprintf("seq=%d cat=%s 5424 long %s", seq, transport,
				strings.Repeat("xyz ", 100))
		case 3:
			body = fmt.Sprintf("\xef\xbb\xbfseq=%d cat=%s 5424 BOM ütf", seq, transport)
		case 4:
			body = slogTextBody(seq, transport)
		case 5:
			body = slogJSONBody(seq, transport)
		case 6:
			body = logfmtBody(seq, transport)
		case 7:
			body = nestedJSONBody(seq, transport)
		case 8:
			body = randomASCIIBody(seq, transport)
		case 9:
			body = randomUTF8Body(seq, transport)
		case 10:
			body = tabAndSymbolsBody(seq, transport)
		case 11:
			// MSG-UTF8: BOM + UTF-8 multibyte. Explicitly testing §6.4.
			body = "\xef\xbb\xbf" + randomUTF8Body(seq, transport)
		default:
			body = fmt.Sprintf("seq=%d cat=%s 5424 v=%d", seq, transport, seq%7)
		}

		out = append(out, &syslog.Message{
			Facility:       fac,
			Severity:       sev,
			Timestamp:      ts,
			Hostname:       host,
			AppName:        app,
			ProcID:         procID,
			MsgID:          msgID,
			StructuredData: sd,
			Message:        body,
		})
	}
	return out
}
