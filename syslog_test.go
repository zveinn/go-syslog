package syslog

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"
)

// -----------------------------------------------------------------------------
// RFC 3164
// -----------------------------------------------------------------------------

func TestFormatRFC3164_SpecExample(t *testing.T) {
	// RFC 3164 §5.4 example (with our facility=20/severity=5 → PRI 165).
	ts := time.Date(2026, time.October, 11, 22, 14, 15, 0, time.UTC)
	m := &Message{
		Facility:  FacLocal4,
		Severity:  SevNotice,
		Timestamp: ts,
		Hostname:  "mymachine",
		AppName:   "su",
		Message:   "'su root' failed for lonvick on /dev/pts/8",
	}
	got, err := FormatRFC3164(m)
	if err != nil {
		t.Fatalf("FormatRFC3164: %v", err)
	}
	want := "<165>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8"
	if string(got) != want {
		t.Errorf("\n got: %q\nwant: %q", got, want)
	}
}

func TestFormatRFC3164_DayPadding(t *testing.T) {
	// §4.1.2: day < 10 → "Mmm _d" with two spaces between month and day.
	ts := time.Date(2026, time.January, 3, 1, 2, 3, 0, time.UTC)
	m := &Message{
		Facility:  FacUser,
		Severity:  SevInfo,
		Timestamp: ts,
		Hostname:  "h",
		AppName:   "app",
		Message:   "hi",
	}
	got, _ := FormatRFC3164(m)
	if !bytes.Contains(got, []byte("Jan  3 01:02:03")) {
		t.Errorf("expected space-padded day, got %q", got)
	}
}

func TestFormatRFC3164_WithProcID(t *testing.T) {
	ts := time.Date(2026, time.March, 5, 12, 0, 0, 0, time.UTC)
	m := &Message{
		Facility:  FacDaemon,
		Severity:  SevErr,
		Timestamp: ts,
		Hostname:  "host1",
		AppName:   "myapp",
		ProcID:    "1234",
		Message:   "boom",
	}
	got, _ := FormatRFC3164(m)
	if !bytes.Contains(got, []byte("myapp[1234]: boom")) {
		t.Errorf("expected TAG[PID]: form, got %q", got)
	}
}

func TestFormatRFC3164_RejectsBadInput(t *testing.T) {
	good := func() *Message {
		return &Message{
			Facility: FacUser, Severity: SevInfo,
			Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			Hostname:  "h", AppName: "app", Message: "x",
		}
	}
	cases := []struct {
		name string
		mut  func(m *Message)
	}{
		{"nil", func(m *Message) { *m = Message{} }},
		{"empty hostname", func(m *Message) { m.Hostname = "" }},
		{"space in hostname", func(m *Message) { m.Hostname = "a b" }},
		{"empty tag", func(m *Message) { m.AppName = "" }},
		{"non-alphanumeric tag :", func(m *Message) { m.AppName = "a:b" }},
		{"non-alphanumeric tag -", func(m *Message) { m.AppName = "a-b" }},
		{"non-alphanumeric tag _", func(m *Message) { m.AppName = "a_b" }},
		{"tag > 32 chars", func(m *Message) { m.AppName = strings.Repeat("a", 33) }},
		{"procid with ]", func(m *Message) { m.ProcID = "1]2" }},
		{"procid with [", func(m *Message) { m.ProcID = "1[2" }},
		{"procid with space", func(m *Message) { m.ProcID = "1 2" }},
		{"facility out of range", func(m *Message) { m.Facility = 24 }},
		{"severity out of range", func(m *Message) { m.Severity = 8 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := good()
			tc.mut(m)
			if tc.name == "nil" {
				if _, err := FormatRFC3164(nil); err == nil {
					t.Error("want error")
				}
				return
			}
			if _, err := FormatRFC3164(m); err == nil {
				t.Errorf("want error, got nil")
			}
		})
	}
}

func TestFormatRFC3164_AcceptsAlphanumericTag(t *testing.T) {
	m := &Message{
		Facility: FacUser, Severity: SevInfo,
		Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Hostname:  "h", AppName: "App1Tag", Message: "x",
	}
	if _, err := FormatRFC3164(m); err != nil {
		t.Errorf("alphanumeric tag rejected: %v", err)
	}
}

func TestFormatRFC3164_NoLeadingZeroInPRI(t *testing.T) {
	// PRI of 0 → "<0>", not "<00>". §4.1.1.
	m := &Message{
		Facility: FacKern, Severity: SevEmerg,
		Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Hostname:  "h", AppName: "app", Message: "x",
	}
	got, _ := FormatRFC3164(m)
	if !bytes.HasPrefix(got, []byte("<0>")) {
		t.Errorf("want PRI <0>, got %q", got)
	}
}

// -----------------------------------------------------------------------------
// RFC 5424
// -----------------------------------------------------------------------------

func TestFormatRFC5424_SpecExample1(t *testing.T) {
	// RFC 5424 §6.5 example 1 (sans BOM, since we keep MSG as MSG-ANY).
	ts := time.Date(2026, time.October, 11, 22, 14, 15, 3000000, time.UTC)
	m := &Message{
		Facility:  FacLocal4,
		Severity:  SevNotice,
		Timestamp: ts,
		Hostname:  "mymachine.example.com",
		AppName:   "su",
		MsgID:     "ID47",
		Message:   "'su root' failed for lonvick",
	}
	got, err := FormatRFC5424(m)
	if err != nil {
		t.Fatalf("FormatRFC5424: %v", err)
	}
	want := "<165>1 2026-10-11T22:14:15.003Z mymachine.example.com su - ID47 - 'su root' failed for lonvick"
	if string(got) != want {
		t.Errorf("\n got: %q\nwant: %q", got, want)
	}
}

func TestFormatRFC5424_SpecExample2(t *testing.T) {
	// RFC 5424 §6.5 example 2: structured data only, no MSG.
	ts := time.Date(2026, time.October, 11, 22, 14, 15, 0, time.UTC)
	m := &Message{
		Facility:  FacLocal4,
		Severity:  SevNotice,
		Timestamp: ts,
		Hostname:  "mymachine.example.com",
		AppName:   "evntslog",
		MsgID:     "ID47",
		StructuredData: []SDElement{{
			ID: "exampleSDID@32473",
			Params: []SDParam{
				{Name: "iut", Value: "3"},
				{Name: "eventSource", Value: "Application"},
				{Name: "eventID", Value: "1011"},
			},
		}},
	}
	got, err := FormatRFC5424(m)
	if err != nil {
		t.Fatalf("FormatRFC5424: %v", err)
	}
	want := `<165>1 2026-10-11T22:14:15Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"]`
	if string(got) != want {
		t.Errorf("\n got: %q\nwant: %q", got, want)
	}
}

func TestFormatRFC5424_TimestampMaxSixDigits(t *testing.T) {
	// §6.2.3.2: TIME-SECFRAC = "." 1*6DIGIT. Sub-µs precision must be
	// truncated, not emitted as 9 digits.
	ts := time.Date(2026, 1, 1, 0, 0, 0, 123456789, time.UTC)
	got, err := FormatRFC5424(&Message{
		Facility: FacUser, Severity: SevInfo, Timestamp: ts,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(got, []byte("2026-01-01T00:00:00.123456Z")) {
		t.Errorf("want 6-digit fractional, got %q", got)
	}
	if bytes.Contains(got, []byte(".123456789")) {
		t.Errorf("got >6 fractional digits: %q", got)
	}
}

func TestFormatRFC5424_TimestampZeroFractional(t *testing.T) {
	// §6.2.3.1: if no sub-second precision, MUST NOT generate TIME-SECFRAC.
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	got, _ := FormatRFC5424(&Message{Facility: FacUser, Severity: SevInfo, Timestamp: ts})
	if bytes.Contains(got, []byte(".")) {
		t.Errorf("zero fractional should omit dot, got %q", got)
	}
}

func TestFormatRFC5424_TimestampOffset(t *testing.T) {
	// §6.2.3.3: TIME-NUMOFFSET = ("+"/"-") TIME-HOUR ":" TIME-MINUTE.
	loc := time.FixedZone("east", 5*3600+30*60)
	ts := time.Date(2026, 1, 1, 12, 0, 0, 0, loc)
	got, _ := FormatRFC5424(&Message{Facility: FacUser, Severity: SevInfo, Timestamp: ts})
	if !bytes.Contains(got, []byte("+05:30")) {
		t.Errorf("want +05:30 offset, got %q", got)
	}
}

func TestFormatRFC5424_EscapesSDValue(t *testing.T) {
	// §6.3.3: only ", \, ] are escaped.
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	m := &Message{
		Facility: FacUser, Severity: SevInfo, Timestamp: ts,
		StructuredData: []SDElement{{
			ID:     "id@1",
			Params: []SDParam{{Name: "k", Value: `a"b\c]d`}},
		}},
	}
	got, err := FormatRFC5424(m)
	if err != nil {
		t.Fatalf("FormatRFC5424: %v", err)
	}
	if !bytes.Contains(got, []byte(`k="a\"b\\c\]d"`)) {
		t.Errorf("expected escaped value, got %q", got)
	}
	// And no other char should be escaped:
	m2 := &Message{
		Facility: FacUser, Severity: SevInfo, Timestamp: ts,
		StructuredData: []SDElement{{
			ID:     "id@1",
			Params: []SDParam{{Name: "k", Value: "a/b=c"}},
		}},
	}
	got2, _ := FormatRFC5424(m2)
	if !bytes.Contains(got2, []byte(`k="a/b=c"`)) {
		t.Errorf("non-special chars must not be escaped, got %q", got2)
	}
}

func TestFormatRFC5424_NilValueHeaders(t *testing.T) {
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	got, err := FormatRFC5424(&Message{Facility: FacUser, Severity: SevInfo, Timestamp: ts})
	if err != nil {
		t.Fatal(err)
	}
	want := "<14>1 2026-01-01T00:00:00Z - - - - -"
	if string(got) != want {
		t.Errorf("\n got: %q\nwant: %q", got, want)
	}
}

func TestFormatRFC5424_RejectsBadInput(t *testing.T) {
	good := func() *Message {
		return &Message{
			Facility: FacUser, Severity: SevInfo,
			Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			Hostname:  "h", AppName: "a",
		}
	}
	cases := []struct {
		name string
		mut  func(m *Message)
	}{
		{"hostname too long", func(m *Message) { m.Hostname = strings.Repeat("a", 256) }},
		{"appname too long", func(m *Message) { m.AppName = strings.Repeat("a", 49) }},
		{"procid too long", func(m *Message) { m.ProcID = strings.Repeat("a", 129) }},
		{"msgid too long", func(m *Message) { m.MsgID = strings.Repeat("a", 33) }},
		{"hostname has space", func(m *Message) { m.Hostname = "a b" }},
		{"hostname has tab", func(m *Message) { m.Hostname = "a\tb" }},
		{"hostname has DEL", func(m *Message) { m.Hostname = "a\x7fb" }},
		{"hostname has high byte", func(m *Message) { m.Hostname = "a\x80b" }},
		{"bad SD-ID", func(m *Message) {
			m.StructuredData = []SDElement{{ID: "bad id"}}
		}},
		{"SD-ID with ]", func(m *Message) {
			m.StructuredData = []SDElement{{ID: "a]b"}}
		}},
		{"SD-ID @ with empty name", func(m *Message) {
			m.StructuredData = []SDElement{{ID: "@32473"}}
		}},
		{"SD-ID @ with empty number", func(m *Message) {
			m.StructuredData = []SDElement{{ID: "name@"}}
		}},
		{"SD-ID @ with space in name", func(m *Message) {
			m.StructuredData = []SDElement{{ID: "bad name@1"}}
		}},
		{"SD-ID @ with space in number", func(m *Message) {
			m.StructuredData = []SDElement{{ID: "n@bad 1"}}
		}},
		{"SD-ID with multiple @", func(m *Message) {
			m.StructuredData = []SDElement{{ID: "a@b@1"}}
		}},
		{"duplicate SD-ID", func(m *Message) {
			m.StructuredData = []SDElement{{ID: "x@1"}, {ID: "x@1"}}
		}},
		{"duplicate PARAM-NAME", func(m *Message) {
			m.StructuredData = []SDElement{{
				ID: "x@1",
				Params: []SDParam{
					{Name: "k", Value: "a"},
					{Name: "k", Value: "b"},
				},
			}}
		}},
		{"PARAM-NAME with =", func(m *Message) {
			m.StructuredData = []SDElement{{
				ID:     "x@1",
				Params: []SDParam{{Name: "n=", Value: "v"}},
			}}
		}},
		{"invalid UTF-8 in PARAM-VALUE", func(m *Message) {
			m.StructuredData = []SDElement{{
				ID:     "x@1",
				Params: []SDParam{{Name: "k", Value: "\xff\xfe"}},
			}}
		}},
		{"facility out of range", func(m *Message) { m.Facility = 24 }},
		{"severity out of range", func(m *Message) { m.Severity = 8 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := good()
			tc.mut(m)
			if _, err := FormatRFC5424(m); err == nil {
				t.Error("want error, got nil")
			}
		})
	}
	if _, err := FormatRFC5424(nil); err == nil {
		t.Error("want error for nil message")
	}
}

func TestFormatRFC5424_TimestampUnder32Chars(t *testing.T) {
	// §6.2.3.4: TIMESTAMP MUST NOT exceed 32 chars. With 6-digit fractional
	// + ±HH:MM offset that is 32 chars exactly.
	loc := time.FixedZone("z", 5*3600+30*60)
	ts := time.Date(2026, 12, 31, 23, 59, 59, 999999000, loc)
	got, _ := FormatRFC5424(&Message{Facility: FacUser, Severity: SevInfo, Timestamp: ts})
	// header starts "<14>1 " then TIMESTAMP then " ".
	body := bytes.TrimPrefix(got, []byte("<14>1 "))
	sp := bytes.IndexByte(body, ' ')
	if sp == -1 || sp > 32 {
		t.Errorf("timestamp length %d > 32: %q", sp, got)
	}
}

// -----------------------------------------------------------------------------
// Priority
// -----------------------------------------------------------------------------

func TestPriority(t *testing.T) {
	p, err := NewPriority(FacLocal4, SevNotice)
	if err != nil {
		t.Fatal(err)
	}
	if p != 165 {
		t.Errorf("priority = %d, want 165", p)
	}
	if p.Facility() != FacLocal4 {
		t.Errorf("Facility() = %d, want %d", p.Facility(), FacLocal4)
	}
	if p.Severity() != SevNotice {
		t.Errorf("Severity() = %d, want %d", p.Severity(), SevNotice)
	}
	if _, err := NewPriority(24, 0); err == nil {
		t.Error("expected error for facility 24")
	}
	if _, err := NewPriority(0, 8); err == nil {
		t.Error("expected error for severity 8")
	}
}

// -----------------------------------------------------------------------------
// RFC 6587
// -----------------------------------------------------------------------------

func TestFrameRFC6587_OctetCounting(t *testing.T) {
	// §3.4.1: SYSLOG-FRAME = MSG-LEN SP SYSLOG-MSG; MSG-LEN is octet count.
	f := NewFrameRFC6587()
	if f.Size() != 0 {
		t.Errorf("empty Size() = %d, want 0", f.Size())
	}
	if err := f.AddLog([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := f.AddLog([]byte("world!")); err != nil {
		t.Fatal(err)
	}
	want := "5 hello6 world!"
	if string(f.Bytes()) != want {
		t.Errorf("Bytes() = %q, want %q", f.Bytes(), want)
	}
	if f.Size() != len(want) {
		t.Errorf("Size() = %d, want %d", f.Size(), len(want))
	}
}

func TestFrameRFC6587_RejectsEmpty(t *testing.T) {
	// §3.4.1: MSG-LEN must be a non-empty positive integer.
	f := NewFrameRFC6587()
	if err := f.AddLog(nil); err == nil {
		t.Error("expected error for nil log")
	}
	if err := f.AddLog([]byte{}); err == nil {
		t.Error("expected error for empty log")
	}
}

func TestFrameRFC6587_NoLeadingZeros(t *testing.T) {
	// §3.4.1: leading zeros in MSG-LEN make frames malformed.
	f := NewFrameRFC6587()
	_ = f.AddLog([]byte("a"))
	if got := string(f.Bytes()); strings.HasPrefix(got, "0") {
		t.Errorf("MSG-LEN must not start with 0: %q", got)
	}
}

func TestFrameRFC6587_BinarySafe(t *testing.T) {
	// §3.4.1: arbitrary OCTET values allowed in SYSLOG-MSG.
	f := NewFrameRFC6587()
	payload := []byte{0x00, 0x01, 0xff, ' ', 'a'}
	if err := f.AddLog(payload); err != nil {
		t.Fatal(err)
	}
	want := append([]byte("5 "), payload...)
	if !bytes.Equal(f.Bytes(), want) {
		t.Errorf("Bytes() = %q, want %q", f.Bytes(), want)
	}
}

func TestFrameRFC6587_Reset(t *testing.T) {
	f := NewFrameRFC6587()
	_ = f.AddLog([]byte("abc"))
	f.Reset()
	if f.Size() != 0 {
		t.Errorf("after Reset Size() = %d, want 0", f.Size())
	}
	_ = f.AddLog([]byte("xy"))
	if string(f.Bytes()) != "2 xy" {
		t.Errorf("after Reset+AddLog Bytes() = %q, want %q", f.Bytes(), "2 xy")
	}
}

func TestFrameRFC6587NonTransparent_LFTrailer(t *testing.T) {
	// §3.4.2: default trailer is LF.
	f := NewFrameRFC6587NonTransparent('\n')
	if err := f.AddLog([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := f.AddLog([]byte("world!")); err != nil {
		t.Fatal(err)
	}
	want := "hello\nworld!\n"
	if string(f.Bytes()) != want {
		t.Errorf("Bytes() = %q, want %q", f.Bytes(), want)
	}
	if f.Size() != len(want) {
		t.Errorf("Size() = %d, want %d", f.Size(), len(want))
	}
}

func TestFrameRFC6587NonTransparent_CustomTrailer(t *testing.T) {
	// §3.4.2 permits a non-LF trailer by mutual agreement; NUL is common.
	f := NewFrameRFC6587NonTransparent(0x00)
	_ = f.AddLog([]byte("a"))
	_ = f.AddLog([]byte("bb"))
	want := []byte{'a', 0, 'b', 'b', 0}
	if !bytes.Equal(f.Bytes(), want) {
		t.Errorf("Bytes() = %v, want %v", f.Bytes(), want)
	}
}

func TestFrameRFC6587NonTransparent_RejectsTrailerInMessage(t *testing.T) {
	// A message containing the trailer byte is ambiguous to any receiver.
	f := NewFrameRFC6587NonTransparent('\n')
	if err := f.AddLog([]byte("two\nlines")); err == nil {
		t.Error("want error for embedded trailer")
	}
}

func TestFrameRFC6587NonTransparent_RejectsEmpty(t *testing.T) {
	f := NewFrameRFC6587NonTransparent('\n')
	if err := f.AddLog(nil); err == nil {
		t.Error("want error for nil log")
	}
	if err := f.AddLog([]byte{}); err == nil {
		t.Error("want error for empty log")
	}
}

func TestFrameRFC6587NonTransparent_Reset(t *testing.T) {
	f := NewFrameRFC6587NonTransparent('\n')
	_ = f.AddLog([]byte("abc"))
	f.Reset()
	if f.Size() != 0 {
		t.Errorf("after Reset Size() = %d, want 0", f.Size())
	}
	_ = f.AddLog([]byte("xy"))
	if string(f.Bytes()) != "xy\n" {
		t.Errorf("after Reset+AddLog Bytes() = %q, want %q", f.Bytes(), "xy\n")
	}
}

// -----------------------------------------------------------------------------
// Direct framer methods (AddLogRFC3164 / AddLogRFC5424)
// -----------------------------------------------------------------------------

// addLogRFCDirectCases pins each direct method's output byte-for-byte against
// the two-step AppendRFC* + AddLog path. Any divergence indicates a framing
// bug, not just a perf regression.
func TestFrameRFC6587_AddLogRFCDirect_MatchesTwoStep(t *testing.T) {
	cases := []struct {
		name string
		app  func(dst []byte, m *Message) ([]byte, error)
		add  func(f *FrameRFC6587, m *Message) error
		msg  *Message
	}{
		{"3164/basic", AppendRFC3164,
			func(f *FrameRFC6587, m *Message) error { return f.AddLogRFC3164(m) },
			basicMessage3164()},
		{"5424/basic", AppendRFC5424,
			func(f *FrameRFC6587, m *Message) error { return f.AddLogRFC5424(m) },
			basicMessage5424()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			twoStep := NewFrameRFC6587()
			buf, err := tc.app(nil, tc.msg)
			if err != nil {
				t.Fatalf("Append: %v", err)
			}
			if err := twoStep.AddLog(buf); err != nil {
				t.Fatalf("AddLog: %v", err)
			}
			direct := NewFrameRFC6587()
			if err := tc.add(direct, tc.msg); err != nil {
				t.Fatalf("AddLogRFC*: %v", err)
			}
			if !bytes.Equal(direct.Bytes(), twoStep.Bytes()) {
				t.Errorf("framed bytes differ:\n  direct:   %q\n  two-step: %q",
					direct.Bytes(), twoStep.Bytes())
			}
		})
	}
}

func TestFrameRFC6587NonTransparent_AddLogRFCDirect_MatchesTwoStep(t *testing.T) {
	cases := []struct {
		name string
		app  func(dst []byte, m *Message) ([]byte, error)
		add  func(f *FrameRFC6587NonTransparent, m *Message) error
		msg  *Message
	}{
		{"3164/basic", AppendRFC3164,
			func(f *FrameRFC6587NonTransparent, m *Message) error { return f.AddLogRFC3164(m) },
			basicMessage3164()},
		{"5424/basic", AppendRFC5424,
			func(f *FrameRFC6587NonTransparent, m *Message) error { return f.AddLogRFC5424(m) },
			basicMessage5424()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			twoStep := NewFrameRFC6587NonTransparent('\n')
			buf, err := tc.app(nil, tc.msg)
			if err != nil {
				t.Fatalf("Append: %v", err)
			}
			if err := twoStep.AddLog(buf); err != nil {
				t.Fatalf("AddLog: %v", err)
			}
			direct := NewFrameRFC6587NonTransparent('\n')
			if err := tc.add(direct, tc.msg); err != nil {
				t.Fatalf("AddLogRFC*: %v", err)
			}
			if !bytes.Equal(direct.Bytes(), twoStep.Bytes()) {
				t.Errorf("framed bytes differ:\n  direct:   %q\n  two-step: %q",
					direct.Bytes(), twoStep.Bytes())
			}
		})
	}
}

// TestFrameRFC6587_AddLogRFC5424_DigitBoundaries checks the in-place memmove
// + decimal-width logic at every decimal-width boundary. Body length is
// padded so the framed message lands at sizes that cross digit boundaries.
func TestFrameRFC6587_AddLogRFC5424_DigitBoundaries(t *testing.T) {
	// Measure header overhead by formatting with an empty body, then build
	// bodies that put total length at each boundary.
	headerBuf, err := AppendRFC5424(nil, basicMessage5424())
	if err != nil {
		t.Fatal(err)
	}
	headerLen := len(headerBuf) - len("hi") // strip the default "hi" body

	for _, target := range []int{9, 10, 99, 100, 999, 1000, 9999, 10000} {
		t.Run(fmt.Sprintf("len=%d", target), func(t *testing.T) {
			bodyLen := target - headerLen
			if bodyLen < 1 {
				t.Skipf("header already %d ≥ target %d", headerLen, target)
			}
			m := basicMessage5424()
			m.Message = strings.Repeat("x", bodyLen)

			direct := NewFrameRFC6587()
			if err := direct.AddLogRFC5424(m); err != nil {
				t.Fatal(err)
			}
			twoStep := NewFrameRFC6587()
			buf, _ := AppendRFC5424(nil, m)
			_ = twoStep.AddLog(buf)
			if !bytes.Equal(direct.Bytes(), twoStep.Bytes()) {
				t.Errorf("at target=%d (msgLen=%d):\n  direct:   %q\n  two-step: %q",
					target, len(buf), direct.Bytes(), twoStep.Bytes())
			}
		})
	}
}

func TestFrameRFC6587_AddLogRFCDirect_RevertsOnError(t *testing.T) {
	f := NewFrameRFC6587()
	if err := f.AddLogRFC5424(basicMessage5424()); err != nil {
		t.Fatal(err)
	}
	snapshot := append([]byte(nil), f.Bytes()...)

	// Bad message: facility out of range.
	bad := basicMessage5424()
	bad.Facility = 99
	if err := f.AddLogRFC5424(bad); err == nil {
		t.Fatal("expected error")
	}
	if !bytes.Equal(f.Bytes(), snapshot) {
		t.Errorf("buffer mutated on error:\n  before: %q\n  after:  %q", snapshot, f.Bytes())
	}

	// Bad message: RFC 3164 with non-alphanumeric TAG.
	bad3164 := basicMessage3164()
	bad3164.AppName = "bad-tag"
	if err := f.AddLogRFC3164(bad3164); err == nil {
		t.Fatal("expected error")
	}
	if !bytes.Equal(f.Bytes(), snapshot) {
		t.Errorf("buffer mutated on 3164 error:\n  before: %q\n  after:  %q", snapshot, f.Bytes())
	}
}

func TestFrameRFC6587NonTransparent_AddLogRFCDirect_RevertsOnError(t *testing.T) {
	f := NewFrameRFC6587NonTransparent('\n')
	if err := f.AddLogRFC5424(basicMessage5424()); err != nil {
		t.Fatal(err)
	}
	snapshot := append([]byte(nil), f.Bytes()...)

	bad := basicMessage5424()
	bad.Severity = 99
	if err := f.AddLogRFC5424(bad); err == nil {
		t.Fatal("expected error")
	}
	if !bytes.Equal(f.Bytes(), snapshot) {
		t.Errorf("buffer mutated on error:\n  before: %q\n  after:  %q", snapshot, f.Bytes())
	}

	// Trailer-in-message must also revert.
	trailerInMsg := basicMessage5424()
	trailerInMsg.Message = "first\nsecond" // contains LF trailer
	if err := f.AddLogRFC5424(trailerInMsg); err == nil {
		t.Fatal("expected trailer-byte error")
	}
	if !bytes.Equal(f.Bytes(), snapshot) {
		t.Errorf("buffer mutated on trailer-in-msg:\n  before: %q\n  after:  %q",
			snapshot, f.Bytes())
	}
}

func TestFrameRFC6587_AddLogRFCDirect_MixedRFCs(t *testing.T) {
	// Both RFCs into a single frame, interleaved with raw AddLog. Verify
	// total bytes match the explicit two-step construction.
	m3164 := basicMessage3164()
	m5424 := basicMessage5424()

	direct := NewFrameRFC6587()
	if err := direct.AddLogRFC3164(m3164); err != nil {
		t.Fatal(err)
	}
	if err := direct.AddLogRFC5424(m5424); err != nil {
		t.Fatal(err)
	}
	if err := direct.AddLog([]byte("raw")); err != nil {
		t.Fatal(err)
	}

	twoStep := NewFrameRFC6587()
	b1, _ := AppendRFC3164(nil, m3164)
	_ = twoStep.AddLog(b1)
	b2, _ := AppendRFC5424(nil, m5424)
	_ = twoStep.AddLog(b2)
	_ = twoStep.AddLog([]byte("raw"))

	if !bytes.Equal(direct.Bytes(), twoStep.Bytes()) {
		t.Errorf("mixed bytes differ:\n  direct:   %q\n  two-step: %q",
			direct.Bytes(), twoStep.Bytes())
	}
}

func TestFrameRFC6587_NilReceiver_DirectMethods(t *testing.T) {
	var f *FrameRFC6587
	if err := f.AddLogRFC3164(basicMessage3164()); err == nil {
		t.Error("nil receiver should error")
	}
	if err := f.AddLogRFC5424(basicMessage5424()); err == nil {
		t.Error("nil receiver should error")
	}
}

func TestFrameRFC6587NonTransparent_NilReceiver_DirectMethods(t *testing.T) {
	var f *FrameRFC6587NonTransparent
	if err := f.AddLogRFC3164(basicMessage3164()); err == nil {
		t.Error("nil receiver should error")
	}
	if err := f.AddLogRFC5424(basicMessage5424()); err == nil {
		t.Error("nil receiver should error")
	}
}

// AddLogsRFC* (batch): equivalence vs. a loop of AddLogRFC*.
func TestFrameRFC6587_AddLogsRFC5424_MatchesLoop(t *testing.T) {
	msgs := []*Message{basicMessage5424(), basicMessage5424(), basicMessage5424()}
	for i, m := range msgs {
		m.MsgID = fmt.Sprintf("ID%02d", i)
	}

	batch := NewFrameRFC6587()
	if err := batch.AddLogsRFC5424(msgs); err != nil {
		t.Fatal(err)
	}
	loop := NewFrameRFC6587()
	for _, m := range msgs {
		if err := loop.AddLogRFC5424(m); err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(batch.Bytes(), loop.Bytes()) {
		t.Errorf("batch vs loop differ:\n  batch: %q\n  loop:  %q", batch.Bytes(), loop.Bytes())
	}
}

func TestFrameRFC6587NonTransparent_AddLogsRFC3164_MatchesLoop(t *testing.T) {
	msgs := []*Message{basicMessage3164(), basicMessage3164(), basicMessage3164()}
	for i, m := range msgs {
		m.ProcID = fmt.Sprintf("%d", i)
	}

	batch := NewFrameRFC6587NonTransparent('\n')
	if err := batch.AddLogsRFC3164(msgs); err != nil {
		t.Fatal(err)
	}
	loop := NewFrameRFC6587NonTransparent('\n')
	for _, m := range msgs {
		if err := loop.AddLogRFC3164(m); err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(batch.Bytes(), loop.Bytes()) {
		t.Errorf("batch vs loop differ:\n  batch: %q\n  loop:  %q", batch.Bytes(), loop.Bytes())
	}
}

// AddLogsRFC* (batch): mid-batch error stops at the bad message, keeps
// pre-failure messages in f.buf, and the returned error names the index.
func TestFrameRFC6587_AddLogsRFC5424_StopsAtBadMessage(t *testing.T) {
	good := basicMessage5424()
	bad := basicMessage5424()
	bad.Severity = 99 // out of range
	msgs := []*Message{good, good, bad, good}

	f := NewFrameRFC6587()
	err := f.AddLogsRFC5424(msgs)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "msg 2") {
		t.Errorf("error should name index 2: %v", err)
	}

	// f.buf must hold exactly the two good messages framed.
	expect := NewFrameRFC6587()
	_ = expect.AddLogRFC5424(good)
	_ = expect.AddLogRFC5424(good)
	if !bytes.Equal(f.Bytes(), expect.Bytes()) {
		t.Errorf("partial batch state wrong:\n  got:  %q\n  want: %q", f.Bytes(), expect.Bytes())
	}
}

// AddLogsRFC* (batch): empty and nil slices are no-ops, not errors.
func TestFrameRFC6587_AddLogsRFC5424_EmptyAndNil(t *testing.T) {
	f := NewFrameRFC6587()
	if err := f.AddLogsRFC5424(nil); err != nil {
		t.Errorf("nil slice: %v", err)
	}
	if err := f.AddLogsRFC5424([]*Message{}); err != nil {
		t.Errorf("empty slice: %v", err)
	}
	if f.Size() != 0 {
		t.Errorf("buffer unexpectedly populated: %q", f.Bytes())
	}
}

// AddLogsRFC* (batch): nil receiver must error even on an empty slice.
func TestFrameRFC6587_AddLogsRFC5424_NilReceiver(t *testing.T) {
	var f *FrameRFC6587
	if err := f.AddLogsRFC5424(nil); err == nil {
		t.Error("nil receiver should error")
	}
	var fnt *FrameRFC6587NonTransparent
	if err := fnt.AddLogsRFC3164(nil); err == nil {
		t.Error("nil receiver should error")
	}
}

// -----------------------------------------------------------------------------
// Complex / freeform message bodies
//
// RFC 5424 §6.4 defines MSG-ANY as *OCTET, so any bytes are legal in MSG as
// long as the stream doesn't start with the BOM (which would imply MSG-UTF8).
// RFC 3164 §4.1.3 only "RECOMMENDS" printable ASCII in MSG. The library
// therefore passes MSG through verbatim and these tests pin that contract.
// -----------------------------------------------------------------------------

func TestFormatRFC5424_PreservesArbitraryBody(t *testing.T) {
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		body string
	}{
		{"slog/text", `time=2026-05-19T13:00:00Z level=INFO msg="hello world" user=alice latency=12ms`},
		{"slog/json", `{"time":"2026-05-19T13:00:00Z","level":"INFO","msg":"hello","user":"alice","latency_ms":12}`},
		{"logfmt", `ts=2026-05-19T13:00:00Z lvl=info evt=req path=/v1/users status=200 dur=42ms`},
		{"json-nested", `{"req":{"id":"abc","headers":{"x-trace":"t1"}},"resp":{"code":200,"body":null}}`},
		{"quotes-and-backslashes", `path="C:\Users\alice\file.txt" note="he said \"hi\""`},
		{"utf8-with-bom", "\xef\xbb\xbf日本語のメッセージ — éàü"},
		{"utf8-no-bom", "résumé — naïve façade — €100"},
		{"binary-bytes-mid-body", "header\x01\x02\x03tail"},
		{"tabs-and-symbols", "col1\tcol2\tcol3\t!@#$%^&*()"},
		{"empty-after-strip-equivalent", `{"k":""}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := FormatRFC5424(&Message{
				Facility: FacUser, Severity: SevInfo, Timestamp: ts,
				Hostname: "h", AppName: "app",
				Message: tc.body,
			})
			if err != nil {
				t.Fatalf("FormatRFC5424: %v", err)
			}
			// MSG must appear verbatim at the tail, preceded by SP.
			suffix := " " + tc.body
			if !bytes.HasSuffix(got, []byte(suffix)) {
				t.Errorf("body not preserved verbatim:\n  got: %q\n want suffix: %q", got, suffix)
			}
		})
	}
}

func TestFormatRFC3164_PreservesArbitraryBody(t *testing.T) {
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		body string
	}{
		{"slog/text", `time=2026-05-19T13:00:00Z level=INFO msg="hello" user=alice`},
		{"slog/json", `{"level":"INFO","msg":"hello","user":"alice"}`},
		{"logfmt", `ts=2026-05-19T13:00:00Z lvl=info path=/v1 status=200`},
		{"utf8", "résumé — café"},
		{"json-with-colon", `{"url":"https://example.com:8080/path"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := FormatRFC3164(&Message{
				Facility: FacUser, Severity: SevInfo, Timestamp: ts,
				Hostname: "h", AppName: "app",
				Message: tc.body,
			})
			if err != nil {
				t.Fatalf("FormatRFC3164: %v", err)
			}
			suffix := ": " + tc.body
			if !bytes.HasSuffix(got, []byte(suffix)) {
				t.Errorf("body not preserved verbatim:\n  got: %q\n want suffix: %q", got, suffix)
			}
		})
	}
}

func TestFormatRFC5424_AcceptsBinaryMSG(t *testing.T) {
	// MSG-ANY is *OCTET. Even NUL, LF, etc. are spec-legal here (subject to
	// receiver behaviour). Library must not reject.
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	body := string([]byte{0x00, 0x01, 0x02, 'a', 0x7f, 0x80, 0xff, 0x0a, 'b'})
	got, err := FormatRFC5424(&Message{
		Facility: FacUser, Severity: SevInfo, Timestamp: ts,
		Hostname: "h", AppName: "app",
		Message: body,
	})
	if err != nil {
		t.Fatalf("FormatRFC5424: %v", err)
	}
	if !bytes.HasSuffix(got, []byte(" "+body)) {
		t.Errorf("binary body not preserved verbatim")
	}
}

func TestFrameRFC6587NonTransparent_RejectsLFInJSONBody(t *testing.T) {
	// Pretty-printed JSON contains LF, which is the default RFC 6587 §3.4.2
	// trailer. The framer must refuse to silently corrupt the wire.
	prettyJSON := []byte("{\n  \"key\": \"value\"\n}")
	f := NewFrameRFC6587NonTransparent('\n')
	if err := f.AddLog(prettyJSON); err == nil {
		t.Error("want error: pretty-printed JSON would corrupt LF framing")
	}
	// Single-line JSON is fine.
	if err := f.AddLog([]byte(`{"key":"value"}`)); err != nil {
		t.Errorf("compact JSON should be accepted: %v", err)
	}
}

func TestFrameRFC6587_AcceptsArbitraryBytesIncludingLF(t *testing.T) {
	// Octet-counting framing is binary-safe — LF in the payload is fine
	// because MSG-LEN tells the receiver exactly where the message ends.
	f := NewFrameRFC6587()
	body := "line1\nline2\nline3"
	if err := f.AddLog([]byte(body)); err != nil {
		t.Fatalf("octet-counted framing should accept LF: %v", err)
	}
	want := fmt.Sprintf("%d %s", len(body), body)
	if string(f.Bytes()) != want {
		t.Errorf("Bytes() = %q, want %q", f.Bytes(), want)
	}
}

// -----------------------------------------------------------------------------
// Append API contract
//
// These pin down what the Append* functions promise — caller-buffer prefix
// preservation, no-modification on validation errors, dst truncation on the
// post-write 3164 size check, Format equivalence, and natural concatenation
// when the same buffer is passed to back-to-back Append calls.
// -----------------------------------------------------------------------------

func basicMessage3164() *Message {
	return &Message{
		Facility:  FacUser,
		Severity:  SevInfo,
		Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Hostname:  "h",
		AppName:   "app",
		Message:   "hi",
	}
}

func basicMessage5424() *Message {
	return &Message{
		Facility:  FacUser,
		Severity:  SevInfo,
		Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Hostname:  "h",
		AppName:   "app",
		Message:   "hi",
	}
}

func TestAppendRFC3164_PreservesPrefix(t *testing.T) {
	dst := []byte("KEEP-")
	out, err := AppendRFC3164(dst, basicMessage3164())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(out, []byte("KEEP-<14>")) {
		t.Errorf("prefix lost or corrupted: %q", out)
	}
}

func TestAppendRFC5424_PreservesPrefix(t *testing.T) {
	dst := []byte("KEEP-")
	out, err := AppendRFC5424(dst, basicMessage5424())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(out, []byte("KEEP-<14>1 ")) {
		t.Errorf("prefix lost or corrupted: %q", out)
	}
}

func TestAppendRFC3164_DstUnchangedOnValidationError(t *testing.T) {
	dst := []byte("UNCHANGED")
	out, err := AppendRFC3164(dst, &Message{Hostname: ""})
	if err == nil {
		t.Fatal("want error")
	}
	if string(out) != "UNCHANGED" {
		t.Errorf("dst was modified: %q", out)
	}
}

func TestAppendRFC5424_DstUnchangedOnValidationError(t *testing.T) {
	dst := []byte("UNCHANGED")
	out, err := AppendRFC5424(dst, &Message{
		Facility: FacUser, Severity: SevInfo,
		Hostname: strings.Repeat("a", 256), // over 255-octet limit
	})
	if err == nil {
		t.Fatal("want error")
	}
	if string(out) != "UNCHANGED" {
		t.Errorf("dst was modified: %q", out)
	}
}

func TestFormatEqualsAppendNil_RFC3164(t *testing.T) {
	m := basicMessage3164()
	want, err := FormatRFC3164(m)
	if err != nil {
		t.Fatal(err)
	}
	got, err := AppendRFC3164(nil, m)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("Format != Append(nil): %q vs %q", want, got)
	}
}

func TestFormatEqualsAppendNil_RFC5424(t *testing.T) {
	m := basicMessage5424()
	m.StructuredData = []SDElement{{
		ID: "x@1", Params: []SDParam{{Name: "k", Value: `v"`}},
	}}
	want, err := FormatRFC5424(m)
	if err != nil {
		t.Fatal(err)
	}
	got, err := AppendRFC5424(nil, m)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("Format != Append(nil): %q vs %q", want, got)
	}
}

func TestAppendRFC3164_Concatenation(t *testing.T) {
	// Calling Append twice with the same buffer must produce the two
	// messages concatenated. There is no separator — that's the framer's
	// job (RFC 6587).
	m1 := basicMessage3164()
	m1.Message = "first"
	m2 := basicMessage3164()
	m2.Message = "second"
	buf := make([]byte, 0, 256)
	buf, _ = AppendRFC3164(buf, m1)
	mid := len(buf)
	buf, _ = AppendRFC3164(buf, m2)
	if !bytes.HasSuffix(buf[:mid], []byte(": first")) {
		t.Errorf("first message corrupted: %q", buf[:mid])
	}
	if !bytes.HasSuffix(buf, []byte(": second")) {
		t.Errorf("second message corrupted: %q", buf[mid:])
	}
}

// -----------------------------------------------------------------------------
// Boundary precision
// -----------------------------------------------------------------------------

func TestPriorityBoundaries(t *testing.T) {
	if p, err := NewPriority(FacKern, SevEmerg); err != nil || p != 0 {
		t.Errorf("NewPriority(0,0) = (%d, %v), want (0, nil)", p, err)
	}
	if p, err := NewPriority(FacLocal7, SevDebug); err != nil || p != 191 {
		t.Errorf("NewPriority(23,7) = (%d, %v), want (191, nil)", p, err)
	}
}

func TestRFC3164_TagLengthBoundary(t *testing.T) {
	m := basicMessage3164()
	m.AppName = strings.Repeat("a", 32) // exact limit
	if _, err := FormatRFC3164(m); err != nil {
		t.Errorf("TAG=32 should be accepted: %v", err)
	}
	m.AppName = strings.Repeat("a", 33)
	if _, err := FormatRFC3164(m); err == nil {
		t.Error("TAG=33 should be rejected")
	}
}

func TestRFC3164_NoPacketSizeLimit(t *testing.T) {
	// RFC 3164 §4.1's 1024-octet cap is UDP-specific and not enforced by
	// the formatter — callers using TCP (RFC 6587) or TLS (RFC 5425) are
	// not subject to it. UDP senders must check len(result) ≤ 1024 themselves.
	m := basicMessage3164()
	m.Message = strings.Repeat("x", 8192)
	out, err := FormatRFC3164(m)
	if err != nil {
		t.Fatalf("oversized message should be accepted: %v", err)
	}
	if len(out) <= 1024 {
		t.Errorf("expected packet > 1024 octets, got %d", len(out))
	}
}

func TestRFC5424_FieldLengthBoundaries(t *testing.T) {
	type field struct {
		name  string
		limit int
		set   func(*Message, string)
	}
	fields := []field{
		{"HOSTNAME", 255, func(m *Message, s string) { m.Hostname = s }},
		{"APP-NAME", 48, func(m *Message, s string) { m.AppName = s }},
		{"PROCID", 128, func(m *Message, s string) { m.ProcID = s }},
		{"MSGID", 32, func(m *Message, s string) { m.MsgID = s }},
	}
	for _, f := range fields {
		t.Run(f.name+"/at-limit", func(t *testing.T) {
			m := basicMessage5424()
			f.set(m, strings.Repeat("a", f.limit))
			if _, err := FormatRFC5424(m); err != nil {
				t.Errorf("%s=%d should be accepted: %v", f.name, f.limit, err)
			}
		})
		t.Run(f.name+"/over-limit", func(t *testing.T) {
			m := basicMessage5424()
			f.set(m, strings.Repeat("a", f.limit+1))
			if _, err := FormatRFC5424(m); err == nil {
				t.Errorf("%s=%d should be rejected", f.name, f.limit+1)
			}
		})
	}
}

func TestRFC5424_SDNameLengthBoundaries(t *testing.T) {
	t.Run("SD-ID/at-limit", func(t *testing.T) {
		m := basicMessage5424()
		m.StructuredData = []SDElement{{ID: strings.Repeat("a", 32)}}
		if _, err := FormatRFC5424(m); err != nil {
			t.Errorf("SD-ID=32 should be accepted: %v", err)
		}
	})
	t.Run("SD-ID/over-limit", func(t *testing.T) {
		m := basicMessage5424()
		m.StructuredData = []SDElement{{ID: strings.Repeat("a", 33)}}
		if _, err := FormatRFC5424(m); err == nil {
			t.Error("SD-ID=33 should be rejected")
		}
	})
	t.Run("PARAM-NAME/at-limit", func(t *testing.T) {
		m := basicMessage5424()
		m.StructuredData = []SDElement{{
			ID: "x@1",
			Params: []SDParam{{Name: strings.Repeat("p", 32), Value: "v"}},
		}}
		if _, err := FormatRFC5424(m); err != nil {
			t.Errorf("PARAM-NAME=32 should be accepted: %v", err)
		}
	})
	t.Run("PARAM-NAME/over-limit", func(t *testing.T) {
		m := basicMessage5424()
		m.StructuredData = []SDElement{{
			ID: "x@1",
			Params: []SDParam{{Name: strings.Repeat("p", 33), Value: "v"}},
		}}
		if _, err := FormatRFC5424(m); err == nil {
			t.Error("PARAM-NAME=33 should be rejected")
		}
	})
	t.Run("SD-ID/empty", func(t *testing.T) {
		m := basicMessage5424()
		m.StructuredData = []SDElement{{ID: ""}}
		if _, err := FormatRFC5424(m); err == nil {
			t.Error("empty SD-ID should be rejected")
		}
	})
	t.Run("PARAM-NAME/empty", func(t *testing.T) {
		m := basicMessage5424()
		m.StructuredData = []SDElement{{
			ID:     "x@1",
			Params: []SDParam{{Name: "", Value: "v"}},
		}}
		if _, err := FormatRFC5424(m); err == nil {
			t.Error("empty PARAM-NAME should be rejected")
		}
	})
}

// -----------------------------------------------------------------------------
// Coverage gaps from the RFC reading
// -----------------------------------------------------------------------------

func TestRFC3164_AllMonthsAbbreviation(t *testing.T) {
	// §4.1.2 fixes the three-letter month abbreviations exactly.
	wants := []string{"Jan", "Feb", "Mar", "Apr", "May", "Jun",
		"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}
	for i, want := range wants {
		month := time.Month(i + 1)
		ts := time.Date(2026, month, 15, 12, 0, 0, 0, time.UTC)
		got, err := FormatRFC3164(&Message{
			Facility: FacUser, Severity: SevInfo, Timestamp: ts,
			Hostname: "h", AppName: "app", Message: "x",
		})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(got, []byte(want+" 15")) {
			t.Errorf("month=%s: got %q, want abbrev %q", month, got, want)
		}
	}
}

func TestRFC3164_HostnameRejectsNonPrintable(t *testing.T) {
	for _, c := range []byte{0x00, 0x1f, 0x7f, 0x80, 0xff} {
		m := basicMessage3164()
		m.Hostname = "a" + string(c) + "b"
		if _, err := FormatRFC3164(m); err == nil {
			t.Errorf("non-printable byte %#x in hostname should be rejected", c)
		}
	}
}

func TestRFC3164_EmptyMessageBody(t *testing.T) {
	// Empty Message is allowed; output ends in "TAG: " (trailing SP).
	m := basicMessage3164()
	m.Message = ""
	got, err := FormatRFC3164(m)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(got, []byte("app: ")) {
		t.Errorf("expected trailing 'app: ', got %q", got)
	}
}

func TestRFC3164_ZeroTimestampUsesNow(t *testing.T) {
	// With Timestamp unset, time.Now() is used. We can't pin the exact
	// value, but the current month abbreviation must appear.
	got, err := FormatRFC3164(&Message{
		Facility: FacUser, Severity: SevInfo,
		Hostname: "h", AppName: "app", Message: "x",
	})
	if err != nil {
		t.Fatal(err)
	}
	mon := time.Now().Month().String()[:3]
	if !bytes.Contains(got, []byte(mon)) {
		t.Errorf("output should include current month %q, got %q", mon, got)
	}
}

func TestRFC5424_ZeroTimestampUsesNow(t *testing.T) {
	got, err := FormatRFC5424(&Message{
		Facility: FacUser, Severity: SevInfo,
		Hostname: "h", AppName: "app",
	})
	if err != nil {
		t.Fatal(err)
	}
	year := fmt.Sprintf("%d", time.Now().UTC().Year())
	if !bytes.Contains(got, []byte(year)) {
		t.Errorf("output should include current year %q, got %q", year, got)
	}
}

func TestRFC5424_NegativeTimezone(t *testing.T) {
	loc := time.FixedZone("pst", -8*3600)
	ts := time.Date(2026, 3, 15, 12, 0, 0, 0, loc)
	got, err := FormatRFC5424(&Message{
		Facility: FacUser, Severity: SevInfo, Timestamp: ts,
		Hostname: "h", AppName: "app",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(got, []byte("-08:00")) {
		t.Errorf("expected -08:00 offset, got %q", got)
	}
}

func TestRFC5424_EmptyPARAMVALUE(t *testing.T) {
	// PARAM-VALUE = UTF-8-STRING = *OCTET; empty is allowed and emits k="".
	m := basicMessage5424()
	m.StructuredData = []SDElement{{
		ID:     "x@1",
		Params: []SDParam{{Name: "k", Value: ""}},
	}}
	got, err := FormatRFC5424(m)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(got, []byte(`k=""`)) {
		t.Errorf("expected k=\"\" in output, got %q", got)
	}
}

func TestRFC5424_SameParamNameAcrossElements(t *testing.T) {
	// §6.3.2: PARAM-NAME unique only *within* an SD-ELEMENT.
	m := basicMessage5424()
	m.StructuredData = []SDElement{
		{ID: "a@1", Params: []SDParam{{Name: "k", Value: "1"}}},
		{ID: "b@1", Params: []SDParam{{Name: "k", Value: "2"}}},
	}
	if _, err := FormatRFC5424(m); err != nil {
		t.Errorf("same PARAM-NAME across elements should be allowed: %v", err)
	}
}

func TestRFC5424_SDElementZeroParams(t *testing.T) {
	// §6.3: SD-ELEMENT = "[" SD-ID *(SP SD-PARAM) "]" — zero params is legal.
	m := basicMessage5424()
	m.StructuredData = []SDElement{{ID: "noparams@1"}}
	got, err := FormatRFC5424(m)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(got, []byte("[noparams@1]")) {
		t.Errorf("expected bare [noparams@1], got %q", got)
	}
}

// -----------------------------------------------------------------------------
// Frame edge cases (nil receiver, alternative trailers)
// -----------------------------------------------------------------------------

func TestFrameRFC6587_NilReceiver(t *testing.T) {
	var f *FrameRFC6587
	if err := f.AddLog([]byte("x")); err == nil {
		t.Error("nil-receiver AddLog should error")
	}
	if got := f.Size(); got != 0 {
		t.Errorf("nil-receiver Size() = %d, want 0", got)
	}
	if got := f.Bytes(); got != nil {
		t.Errorf("nil-receiver Bytes() = %v, want nil", got)
	}
	f.Reset() // must not panic
}

func TestFrameRFC6587NonTransparent_NilReceiver(t *testing.T) {
	var f *FrameRFC6587NonTransparent
	if err := f.AddLog([]byte("x")); err == nil {
		t.Error("nil-receiver AddLog should error")
	}
	if got := f.Size(); got != 0 {
		t.Errorf("nil-receiver Size() = %d, want 0", got)
	}
	if got := f.Bytes(); got != nil {
		t.Errorf("nil-receiver Bytes() = %v, want nil", got)
	}
	f.Reset() // must not panic
}

func TestFrameRFC6587NonTransparent_VariousTrailers(t *testing.T) {
	// §3.4.2: any agreed byte may be the trailer.
	cases := []struct {
		name    string
		trailer byte
	}{
		{"LF", '\n'},
		{"NUL", 0x00},
		{"CR", '\r'},
		{"TAB", '\t'},
		{"DEL", 0x7f},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := NewFrameRFC6587NonTransparent(tc.trailer)
			if err := f.AddLog([]byte("hello")); err != nil {
				t.Fatal(err)
			}
			if err := f.AddLog([]byte("world")); err != nil {
				t.Fatal(err)
			}
			want := []byte{'h', 'e', 'l', 'l', 'o', tc.trailer,
				'w', 'o', 'r', 'l', 'd', tc.trailer}
			if !bytes.Equal(f.Bytes(), want) {
				t.Errorf("Bytes() = %v, want %v", f.Bytes(), want)
			}
			// A message that contains the trailer must be rejected even for
			// non-LF trailers.
			if err := f.AddLog([]byte{'a', tc.trailer, 'b'}); err == nil {
				t.Errorf("trailer byte %#x inside message should be rejected", tc.trailer)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// Fuzz: random bodies must never crash or produce invalid PRI / length
// -----------------------------------------------------------------------------

func FuzzAppendRFC5424(f *testing.F) {
	// Seed with the spec-example body shape and a few oddities.
	f.Add(uint8(20), uint8(5), "host.example.com", "app", "1234", "ID47",
		`hello world`)
	f.Add(uint8(0), uint8(0), "h", "a", "", "", "")
	f.Add(uint8(23), uint8(7), strings.Repeat("a", 255), strings.Repeat("a", 48),
		strings.Repeat("p", 128), strings.Repeat("m", 32),
		"\xef\xbb\xbfunicode")
	f.Fuzz(func(t *testing.T, fac, sev uint8, host, app, proc, mid, body string) {
		buf := make([]byte, 0, 1024)
		m := &Message{
			Facility:  Facility(fac),
			Severity:  Severity(sev),
			Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			Hostname:  host, AppName: app, ProcID: proc, MsgID: mid,
			Message: body,
		}
		// Either it errors cleanly or the result starts with "<PRI>1 ".
		out, err := AppendRFC5424(buf, m)
		if err != nil {
			if len(out) != 0 {
				t.Fatalf("error path must not extend dst: len=%d, err=%v", len(out), err)
			}
			return
		}
		if len(out) < 5 || out[0] != '<' {
			t.Fatalf("output missing PRI: %q", out)
		}
		// PRI digits followed by '>' then '1' then SP.
		gt := bytes.IndexByte(out, '>')
		if gt < 2 || gt > 4 {
			t.Fatalf("malformed PRI delimiter: %q", out)
		}
		if string(out[gt:gt+3]) != ">1 " {
			t.Fatalf("expected '>1 ' after PRI, got %q", out[gt:gt+3])
		}
	})
}

// -----------------------------------------------------------------------------
// Benchmarks
//
// One per exported function / method. The Append* family is zero-alloc with
// a reused buffer; the Format* convenience wrappers cost one allocation (the
// returned slice). Frame AddLog is zero-alloc in steady state once the
// internal buffer has grown; the rest of the Frame surface (Size, Bytes,
// Reset) is essentially free.
// -----------------------------------------------------------------------------

func BenchmarkNewPriority(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		if _, err := NewPriority(FacLocal4, SevNotice); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPriority_Facility(b *testing.B) {
	p := Priority(165)
	var sink Facility
	b.ReportAllocs()
	for b.Loop() {
		sink = p.Facility()
	}
	_ = sink
}

func BenchmarkPriority_Severity(b *testing.B) {
	p := Priority(165)
	var sink Severity
	b.ReportAllocs()
	for b.Loop() {
		sink = p.Severity()
	}
	_ = sink
}

func BenchmarkAppendRFC3164(b *testing.B) {
	m := &Message{
		Facility:  FacLocal4,
		Severity:  SevNotice,
		Timestamp: time.Date(2026, time.October, 11, 22, 14, 15, 0, time.UTC),
		Hostname:  "mymachine.example.com",
		AppName:   "myapp",
		ProcID:    "1234",
		Message:   "user login succeeded for alice from 192.0.2.7",
	}
	buf := make([]byte, 0, 256)
	b.ReportAllocs()
	for b.Loop() {
		buf = buf[:0]
		var err error
		buf, err = AppendRFC3164(buf, m)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAppendRFC5424(b *testing.B) {
	m := &Message{
		Facility:  FacLocal4,
		Severity:  SevNotice,
		Timestamp: time.Date(2026, time.October, 11, 22, 14, 15, 3000000, time.UTC),
		Hostname:  "mymachine.example.com",
		AppName:   "myapp",
		ProcID:    "1234",
		MsgID:     "ID47",
		StructuredData: []SDElement{{
			ID: "exampleSDID@32473",
			Params: []SDParam{
				{Name: "iut", Value: "3"},
				{Name: "eventSource", Value: "Application"},
				{Name: "eventID", Value: "1011"},
			},
		}},
		Message: "user login succeeded for alice from 192.0.2.7",
	}
	buf := make([]byte, 0, 512)
	b.ReportAllocs()
	for b.Loop() {
		buf = buf[:0]
		var err error
		buf, err = AppendRFC5424(buf, m)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFormatRFC3164(b *testing.B) {
	// The convenience wrapper (= AppendRFC3164(nil, m)) does allocate.
	m := &Message{
		Facility:  FacLocal4,
		Severity:  SevNotice,
		Timestamp: time.Date(2026, time.October, 11, 22, 14, 15, 0, time.UTC),
		Hostname:  "mymachine.example.com",
		AppName:   "myapp",
		ProcID:    "1234",
		Message:   "user login succeeded for alice from 192.0.2.7",
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := FormatRFC3164(m); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFormatRFC5424(b *testing.B) {
	m := &Message{
		Facility:  FacLocal4,
		Severity:  SevNotice,
		Timestamp: time.Date(2026, time.October, 11, 22, 14, 15, 3000000, time.UTC),
		Hostname:  "mymachine.example.com",
		AppName:   "myapp",
		ProcID:    "1234",
		MsgID:     "ID47",
		StructuredData: []SDElement{{
			ID: "exampleSDID@32473",
			Params: []SDParam{
				{Name: "iut", Value: "3"},
				{Name: "eventSource", Value: "Application"},
				{Name: "eventID", Value: "1011"},
			},
		}},
		Message: "user login succeeded for alice from 192.0.2.7",
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := FormatRFC5424(m); err != nil {
			b.Fatal(err)
		}
	}
}

// benchMsg is a realistically-shaped formatted RFC 5424 message; used to
// drive the framing benchmarks below.
var benchMsg = []byte(
	`<165>1 2026-10-11T22:14:15.003Z mymachine.example.com myapp 1234 ID47 - hello world`,
)

// newFrameSink forces the constructor's result to escape so the bench
// reflects a heap allocation, which is what a real caller incurs.
var (
	newFrameSink   *FrameRFC6587
	newFrameNTSink *FrameRFC6587NonTransparent
)

func BenchmarkNewFrameRFC6587(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		newFrameSink = NewFrameRFC6587()
	}
}

func BenchmarkFrameRFC6587_AddLog(b *testing.B) {
	// Measure steady-state AddLog cost. The frame grows once at the start
	// then we Reset every ~1 MiB so the bench reflects per-message work,
	// not append-grow amortisation.
	f := NewFrameRFC6587()
	b.ReportAllocs()
	b.SetBytes(int64(len(benchMsg)))
	for b.Loop() {
		if err := f.AddLog(benchMsg); err != nil {
			b.Fatal(err)
		}
		if f.Size() > 1<<20 {
			f.Reset()
		}
	}
}

func BenchmarkFrameRFC6587_Size(b *testing.B) {
	f := NewFrameRFC6587()
	_ = f.AddLog(benchMsg)
	var sink int
	b.ReportAllocs()
	for b.Loop() {
		sink = f.Size()
	}
	_ = sink
}

func BenchmarkFrameRFC6587_Bytes(b *testing.B) {
	f := NewFrameRFC6587()
	_ = f.AddLog(benchMsg)
	var sink []byte
	b.ReportAllocs()
	for b.Loop() {
		sink = f.Bytes()
	}
	_ = sink
}

func BenchmarkFrameRFC6587_Reset(b *testing.B) {
	f := NewFrameRFC6587()
	_ = f.AddLog(benchMsg) // populate once so Reset has something to do on the first call
	b.ReportAllocs()
	for b.Loop() {
		f.Reset()
	}
}

func BenchmarkNewFrameRFC6587NonTransparent(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		newFrameNTSink = NewFrameRFC6587NonTransparent('\n')
	}
}

func BenchmarkFrameRFC6587NonTransparent_AddLog(b *testing.B) {
	f := NewFrameRFC6587NonTransparent('\n')
	b.ReportAllocs()
	b.SetBytes(int64(len(benchMsg)))
	for b.Loop() {
		if err := f.AddLog(benchMsg); err != nil {
			b.Fatal(err)
		}
		if f.Size() > 1<<20 {
			f.Reset()
		}
	}
}

func BenchmarkFrameRFC6587NonTransparent_Size(b *testing.B) {
	f := NewFrameRFC6587NonTransparent('\n')
	_ = f.AddLog(benchMsg)
	var sink int
	b.ReportAllocs()
	for b.Loop() {
		sink = f.Size()
	}
	_ = sink
}

func BenchmarkFrameRFC6587NonTransparent_Bytes(b *testing.B) {
	f := NewFrameRFC6587NonTransparent('\n')
	_ = f.AddLog(benchMsg)
	var sink []byte
	b.ReportAllocs()
	for b.Loop() {
		sink = f.Bytes()
	}
	_ = sink
}

func BenchmarkFrameRFC6587NonTransparent_Reset(b *testing.B) {
	f := NewFrameRFC6587NonTransparent('\n')
	_ = f.AddLog(benchMsg)
	b.ReportAllocs()
	for b.Loop() {
		f.Reset()
	}
}

// BenchmarkPipelineRFC5424_Octet measures a realistic hot path: append one
// 5424 message into a reused buffer, then add it to an octet-counted frame.
func BenchmarkPipelineRFC5424_Octet(b *testing.B) {
	m := &Message{
		Facility:  FacLocal4,
		Severity:  SevNotice,
		Timestamp: time.Date(2026, time.October, 11, 22, 14, 15, 3000000, time.UTC),
		Hostname:  "mymachine.example.com",
		AppName:   "myapp",
		ProcID:    "1234",
		MsgID:     "ID47",
		Message:   "user login succeeded for alice from 192.0.2.7",
	}
	buf := make([]byte, 0, 256)
	f := NewFrameRFC6587()
	b.ReportAllocs()
	for b.Loop() {
		buf = buf[:0]
		var err error
		buf, err = AppendRFC5424(buf, m)
		if err != nil {
			b.Fatal(err)
		}
		if err := f.AddLog(buf); err != nil {
			b.Fatal(err)
		}
		if f.Size() > 1<<20 {
			f.Reset()
		}
	}
}

func BenchmarkPipelineRFC3164_Octet(b *testing.B) {
	m := &Message{
		Facility:  FacLocal4,
		Severity:  SevNotice,
		Timestamp: time.Date(2026, time.October, 11, 22, 14, 15, 0, time.UTC),
		Hostname:  "mymachine.example.com",
		AppName:   "myapp",
		ProcID:    "1234",
		Message:   "user login succeeded for alice from 192.0.2.7",
	}
	buf := make([]byte, 0, 256)
	f := NewFrameRFC6587()
	b.ReportAllocs()
	for b.Loop() {
		buf = buf[:0]
		var err error
		buf, err = AppendRFC3164(buf, m)
		if err != nil {
			b.Fatal(err)
		}
		if err := f.AddLog(buf); err != nil {
			b.Fatal(err)
		}
		if f.Size() > 1<<20 {
			f.Reset()
		}
	}
}

func BenchmarkFrameRFC6587_AddLogRFC3164(b *testing.B) {
	m := &Message{
		Facility:  FacLocal4,
		Severity:  SevNotice,
		Timestamp: time.Date(2026, time.October, 11, 22, 14, 15, 0, time.UTC),
		Hostname:  "mymachine.example.com",
		AppName:   "myapp",
		ProcID:    "1234",
		Message:   "user login succeeded for alice from 192.0.2.7",
	}
	f := NewFrameRFC6587()
	b.ReportAllocs()
	for b.Loop() {
		if err := f.AddLogRFC3164(m); err != nil {
			b.Fatal(err)
		}
		if f.Size() > 1<<20 {
			f.Reset()
		}
	}
}

func BenchmarkPipelineRFC3164_NonTransp(b *testing.B) {
	m := &Message{
		Facility:  FacLocal4,
		Severity:  SevNotice,
		Timestamp: time.Date(2026, time.October, 11, 22, 14, 15, 0, time.UTC),
		Hostname:  "mymachine.example.com",
		AppName:   "myapp",
		ProcID:    "1234",
		Message:   "user login succeeded for alice from 192.0.2.7",
	}
	buf := make([]byte, 0, 256)
	f := NewFrameRFC6587NonTransparent('\n')
	b.ReportAllocs()
	for b.Loop() {
		buf = buf[:0]
		var err error
		buf, err = AppendRFC3164(buf, m)
		if err != nil {
			b.Fatal(err)
		}
		if err := f.AddLog(buf); err != nil {
			b.Fatal(err)
		}
		if f.Size() > 1<<20 {
			f.Reset()
		}
	}
}

func BenchmarkFrameRFC6587NonTransparent_AddLogRFC3164(b *testing.B) {
	m := &Message{
		Facility:  FacLocal4,
		Severity:  SevNotice,
		Timestamp: time.Date(2026, time.October, 11, 22, 14, 15, 0, time.UTC),
		Hostname:  "mymachine.example.com",
		AppName:   "myapp",
		ProcID:    "1234",
		Message:   "user login succeeded for alice from 192.0.2.7",
	}
	f := NewFrameRFC6587NonTransparent('\n')
	b.ReportAllocs()
	for b.Loop() {
		if err := f.AddLogRFC3164(m); err != nil {
			b.Fatal(err)
		}
		if f.Size() > 1<<20 {
			f.Reset()
		}
	}
}

// BenchmarkFrameRFC6587_AddLogRFC5424 measures the direct in-place path
// (no caller-side scratch buffer) for octet-counted framing. Compare
// against BenchmarkPipelineRFC5424_Octet.
func BenchmarkFrameRFC6587_AddLogRFC5424(b *testing.B) {
	m := &Message{
		Facility:  FacLocal4,
		Severity:  SevNotice,
		Timestamp: time.Date(2026, time.October, 11, 22, 14, 15, 3000000, time.UTC),
		Hostname:  "mymachine.example.com",
		AppName:   "myapp",
		ProcID:    "1234",
		MsgID:     "ID47",
		Message:   "user login succeeded for alice from 192.0.2.7",
	}
	f := NewFrameRFC6587()
	b.ReportAllocs()
	for b.Loop() {
		if err := f.AddLogRFC5424(m); err != nil {
			b.Fatal(err)
		}
		if f.Size() > 1<<20 {
			f.Reset()
		}
	}
}

// BenchmarkPipelineRFC5424_NonTransp is the non-transparent counterpart of
// BenchmarkPipelineRFC5424_Octet.
func BenchmarkPipelineRFC5424_NonTransp(b *testing.B) {
	m := &Message{
		Facility:  FacLocal4,
		Severity:  SevNotice,
		Timestamp: time.Date(2026, time.October, 11, 22, 14, 15, 3000000, time.UTC),
		Hostname:  "mymachine.example.com",
		AppName:   "myapp",
		ProcID:    "1234",
		MsgID:     "ID47",
		Message:   "user login succeeded for alice from 192.0.2.7",
	}
	buf := make([]byte, 0, 256)
	f := NewFrameRFC6587NonTransparent('\n')
	b.ReportAllocs()
	for b.Loop() {
		buf = buf[:0]
		var err error
		buf, err = AppendRFC5424(buf, m)
		if err != nil {
			b.Fatal(err)
		}
		if err := f.AddLog(buf); err != nil {
			b.Fatal(err)
		}
		if f.Size() > 1<<20 {
			f.Reset()
		}
	}
}

func BenchmarkFrameRFC6587NonTransparent_AddLogRFC5424(b *testing.B) {
	m := &Message{
		Facility:  FacLocal4,
		Severity:  SevNotice,
		Timestamp: time.Date(2026, time.October, 11, 22, 14, 15, 3000000, time.UTC),
		Hostname:  "mymachine.example.com",
		AppName:   "myapp",
		ProcID:    "1234",
		MsgID:     "ID47",
		Message:   "user login succeeded for alice from 192.0.2.7",
	}
	f := NewFrameRFC6587NonTransparent('\n')
	b.ReportAllocs()
	for b.Loop() {
		if err := f.AddLogRFC5424(m); err != nil {
			b.Fatal(err)
		}
		if f.Size() > 1<<20 {
			f.Reset()
		}
	}
}

// BenchmarkFrameRFC6587_AddLogsRFC5424 frames a slice of 100 messages in
// one call. Reported as ns/op per batch; divide by 100 for per-message.
func BenchmarkFrameRFC6587_AddLogsRFC5424(b *testing.B) {
	const N = 100
	m := &Message{
		Facility:  FacLocal4,
		Severity:  SevNotice,
		Timestamp: time.Date(2026, time.October, 11, 22, 14, 15, 3000000, time.UTC),
		Hostname:  "mymachine.example.com",
		AppName:   "myapp",
		ProcID:    "1234",
		MsgID:     "ID47",
		Message:   "user login succeeded for alice from 192.0.2.7",
	}
	msgs := make([]*Message, N)
	for i := range msgs {
		msgs[i] = m
	}
	f := NewFrameRFC6587()
	b.ReportAllocs()
	for b.Loop() {
		if err := f.AddLogsRFC5424(msgs); err != nil {
			b.Fatal(err)
		}
		if f.Size() > 1<<20 {
			f.Reset()
		}
	}
}

func BenchmarkFrameRFC6587NonTransparent_AddLogsRFC5424(b *testing.B) {
	const N = 100
	m := &Message{
		Facility:  FacLocal4,
		Severity:  SevNotice,
		Timestamp: time.Date(2026, time.October, 11, 22, 14, 15, 3000000, time.UTC),
		Hostname:  "mymachine.example.com",
		AppName:   "myapp",
		ProcID:    "1234",
		MsgID:     "ID47",
		Message:   "user login succeeded for alice from 192.0.2.7",
	}
	msgs := make([]*Message, N)
	for i := range msgs {
		msgs[i] = m
	}
	f := NewFrameRFC6587NonTransparent('\n')
	b.ReportAllocs()
	for b.Loop() {
		if err := f.AddLogsRFC5424(msgs); err != nil {
			b.Fatal(err)
		}
		if f.Size() > 1<<20 {
			f.Reset()
		}
	}
}

// -----------------------------------------------------------------------------
// End-to-end
// -----------------------------------------------------------------------------

func TestEndToEnd(t *testing.T) {
	ts := time.Date(2026, time.May, 19, 10, 0, 0, 0, time.UTC)
	msg, err := FormatRFC5424(&Message{
		Facility:  FacLocal0,
		Severity:  SevInfo,
		Timestamp: ts,
		Hostname:  "host",
		AppName:   "app",
		Message:   "hello",
	})
	if err != nil {
		t.Fatal(err)
	}
	f := NewFrameRFC6587()
	if err := f.AddLog(msg); err != nil {
		t.Fatal(err)
	}
	// 5424 message is 48 bytes; framed it is "48 " + msg.
	want := "48 <134>1 2026-05-19T10:00:00Z host app - - - hello"
	if string(f.Bytes()) != want {
		t.Errorf("\n got: %q\nwant: %q", f.Bytes(), want)
	}
}
