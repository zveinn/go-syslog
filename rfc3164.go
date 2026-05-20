package syslog

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// rfc3164TagMax is the MUST-NOT-EXCEED TAG length from RFC 3164 §4.1.3.
const rfc3164TagMax = 32

// FormatRFC3164 builds an RFC 3164 (BSD syslog) message from m. It is
// equivalent to AppendRFC3164 with a single-use buffer. Callers in a hot
// path should prefer AppendRFC3164 with a reused buffer to avoid per-call
// allocation.
//
// RFC 3164 §4.1's 1024-octet packet limit is UDP-specific (the whole RFC
// is scoped to UDP transport). It is not enforced here; callers sending
// over UDP must check len(result) ≤ 1024 themselves. TCP (RFC 6587) and
// TLS (RFC 5425) transports have no such limit.
func FormatRFC3164(m *Message) ([]byte, error) {
	// Pre-size the buffer so AppendRFC3164 doesn't need to grow it. Header
	// (PRI + timestamp + " HOSTNAME TAG[PID]: ") is bounded; 32 bytes of
	// slack absorbs day-padding and any small variance.
	cap := 32
	if m != nil {
		cap += len(m.Hostname) + len(m.AppName) + len(m.ProcID) + len(m.Message)
	}
	return AppendRFC3164(make([]byte, 0, cap), m)
}

// AppendRFC3164 appends an RFC 3164 (BSD syslog) message to dst and returns
// the extended slice. On error, dst is returned with its original length
// (the underlying buffer may have been partially written; only bytes within
// the returned len are valid).
//
// The wire format is:
//
//	<PRI>Mmm _d hh:mm:ss HOSTNAME TAG[PID]: MSG
//
// See FormatRFC3164's doc for the per-field RFC constraints; AppendRFC3164
// enforces the same rules.
func AppendRFC3164(dst []byte, m *Message) ([]byte, error) {
	if m == nil {
		return dst, fmt.Errorf("syslog: nil message")
	}
	pri, err := NewPriority(m.Facility, m.Severity)
	if err != nil {
		return dst, err
	}

	if m.Hostname == "" {
		return dst, fmt.Errorf("syslog: RFC 3164 hostname is required")
	}
	if strings.ContainsAny(m.Hostname, " \t\n\r") {
		return dst, fmt.Errorf("syslog: RFC 3164 hostname must not contain whitespace")
	}
	for i := 0; i < len(m.Hostname); i++ {
		if c := m.Hostname[i]; c < 33 || c > 126 {
			return dst, fmt.Errorf("syslog: RFC 3164 hostname contains non-printable byte %#x", c)
		}
	}

	if m.AppName == "" {
		return dst, fmt.Errorf("syslog: RFC 3164 TAG (AppName) is required")
	}
	if len(m.AppName) > rfc3164TagMax {
		return dst, fmt.Errorf("syslog: RFC 3164 TAG exceeds %d octets", rfc3164TagMax)
	}
	for i := 0; i < len(m.AppName); i++ {
		if c := m.AppName[i]; !isAlphaNum(c) {
			return dst, fmt.Errorf("syslog: RFC 3164 TAG must be alphanumeric (got %q)", c)
		}
	}

	if strings.ContainsAny(m.ProcID, "][ \t\n\r") {
		return dst, fmt.Errorf("syslog: RFC 3164 ProcID must not contain ']', '[', or whitespace")
	}

	ts := m.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}

	dst = append(dst, '<')
	dst = strconv.AppendUint(dst, uint64(pri), 10)
	dst = append(dst, '>')

	// "Mmm _d hh:mm:ss" — Month.String is always English (Go stdlib), so the
	// first three chars are RFC 3164's required abbreviation.
	dst = append(dst, ts.Month().String()[:3]...)
	dst = append(dst, ' ')

	// Day: space-padded to two characters per §4.1.2.
	day := ts.Day()
	if day < 10 {
		dst = append(dst, ' ', '0'+byte(day))
	} else {
		dst = append(dst, '0'+byte(day/10), '0'+byte(day%10))
	}
	dst = append(dst, ' ')

	// hh:mm:ss, all zero-padded to two digits.
	h, mn, s := ts.Hour(), ts.Minute(), ts.Second()
	dst = append(dst,
		'0'+byte(h/10), '0'+byte(h%10), ':',
		'0'+byte(mn/10), '0'+byte(mn%10), ':',
		'0'+byte(s/10), '0'+byte(s%10), ' ',
	)

	dst = append(dst, m.Hostname...)
	dst = append(dst, ' ')
	dst = append(dst, m.AppName...)
	if m.ProcID != "" {
		dst = append(dst, '[')
		dst = append(dst, m.ProcID...)
		dst = append(dst, ']')
	}
	dst = append(dst, ':', ' ')
	dst = append(dst, m.Message...)

	return dst, nil
}

func isAlphaNum(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
}
