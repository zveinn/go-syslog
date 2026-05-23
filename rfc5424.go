package syslog

import (
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const rfc5424Version = 1

// rfc5424TimeFormat enforces TIME-SECFRAC = "." 1*6DIGIT (§6.2.3.2). Go
// RFC3339Nano (".999999999") emits up to 9 fractional digits, which is out
// of spec; this format truncates to microseconds and drops the dot when the
// fractional part is zero.
const rfc5424TimeFormat = "2006-01-02T15:04:05.999999Z07:00"

// FormatRFC5424 builds an RFC 5424 syslog message from m. It is equivalent
// to AppendRFC5424 with a single-use buffer. Callers in a hot path should
// prefer AppendRFC5424 with a reused buffer to avoid per-call allocation.
func FormatRFC5424(m *Message) ([]byte, error) {
	// Pre-size to avoid grow-realloc cycles. Header is bounded; SD width
	// is estimated below.
	cap := 64
	if m != nil {
		cap += len(m.Hostname) + len(m.AppName) + len(m.ProcID) + len(m.MsgID) + len(m.Message)
		for _, e := range m.StructuredData {
			cap += 2 + len(e.ID) // [ + id + ]
			for _, p := range e.Params {
				cap += 4 + len(p.Name) + len(p.Value) // SP name="value"
			}
		}
	}
	return AppendRFC5424(make([]byte, 0, cap), m)
}

// AppendRFC5424 appends an RFC 5424 syslog message to dst and returns the
// extended slice. On error, dst is returned with its original length (any
// validation that runs after writes start is staged so dst can be reverted).
//
// The wire format is:
//
//	<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA [SP MSG]
//
// See FormatRFC5424's doc for the per-field RFC constraints; AppendRFC5424
// enforces the same rules.
func AppendRFC5424(dst []byte, m *Message) ([]byte, error) {
	if m == nil {
		return dst, fmt.Errorf("syslog: nil message")
	}
	pri, err := NewPriority(m.Facility, m.Severity)
	if err != nil {
		return dst, err
	}

	ts := m.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}

	host, err := nilOrPrintUSASCII("HOSTNAME", m.Hostname, 255)
	if err != nil {
		return dst, err
	}
	app, err := nilOrPrintUSASCII("APP-NAME", m.AppName, 48)
	if err != nil {
		return dst, err
	}
	proc, err := nilOrPrintUSASCII("PROCID", m.ProcID, 128)
	if err != nil {
		return dst, err
	}
	msgid, err := nilOrPrintUSASCII("MSGID", m.MsgID, 32)
	if err != nil {
		return dst, err
	}

	// Validate SD up front so we don't partially emit on error.
	if err := validateSDList(m.StructuredData); err != nil {
		return dst, err
	}

	dst = append(dst, '<')
	dst = strconv.AppendUint(dst, uint64(pri), 10)
	dst = append(dst, '>')
	dst = strconv.AppendInt(dst, int64(rfc5424Version), 10)
	dst = append(dst, ' ')
	dst = ts.AppendFormat(dst, rfc5424TimeFormat)
	dst = append(dst, ' ')
	dst = append(dst, host...)
	dst = append(dst, ' ')
	dst = append(dst, app...)
	dst = append(dst, ' ')
	dst = append(dst, proc...)
	dst = append(dst, ' ')
	dst = append(dst, msgid...)
	dst = append(dst, ' ')
	dst = appendSD(dst, m.StructuredData)
	if m.Message != "" {
		dst = append(dst, ' ')
		dst = append(dst, m.Message...)
	}
	return dst, nil
}

// ValidateHostnameRFC5424 reports whether s is a valid RFC 5424 §6.2.4
// HOSTNAME: either empty (NILVALUE "-" on the wire) or 1-255
// PRINTUSASCII octets.
func ValidateHostnameRFC5424(s string) error {
	_, err := nilOrPrintUSASCII("HOSTNAME", s, 255)
	return err
}

// ValidateAppNameRFC5424 reports whether s is a valid RFC 5424 §6.2.5
// APP-NAME: either empty (encoded as NILVALUE "-" on the wire) or 1-48
// PRINTUSASCII octets (%d33-126). Hyphens, dots, underscores etc. are
// allowed — only HTAB/SPACE and bytes outside [33,126] are rejected.
func ValidateAppNameRFC5424(s string) error {
	_, err := nilOrPrintUSASCII("APP-NAME", s, 48)
	return err
}

// ValidateProcIDRFC5424 reports whether s is a valid RFC 5424 §6.2.6
// PROCID: either empty (NILVALUE) or 1-128 PRINTUSASCII octets.
func ValidateProcIDRFC5424(s string) error {
	_, err := nilOrPrintUSASCII("PROCID", s, 128)
	return err
}

// ValidateMsgIDRFC5424 reports whether s is a valid RFC 5424 §6.2.7
// MSGID: either empty (NILVALUE) or 1-32 PRINTUSASCII octets.
func ValidateMsgIDRFC5424(s string) error {
	_, err := nilOrPrintUSASCII("MSGID", s, 32)
	return err
}

// ValidateSDID reports whether s is a valid RFC 5424 §6.3.2 SD-ID:
// 1-32 SD-NAME octets (PRINTUSASCII excluding '=', SP, ']', '"').
func ValidateSDID(s string) error {
	return validateSDName(s, "SD-ID")
}

// ValidateParamName reports whether s is a valid RFC 5424 §6.3.3
// PARAM-NAME. Same rules as SD-ID: 1-32 SD-NAME octets.
func ValidateParamName(s string) error {
	return validateSDName(s, "PARAM-NAME")
}

// ValidateStructuredData reports whether sd as a whole is a valid RFC
// 5424 STRUCTURED-DATA list: every SD-ID and every PARAM-NAME passes
// the SD-NAME rule, SD-IDs are unique within the list, PARAM-NAMEs are
// unique within their element, and every PARAM-VALUE is valid UTF-8.
// An empty or nil slice is valid (encoded as NILVALUE on the wire).
func ValidateStructuredData(sd []SDElement) error {
	return validateSDList(sd)
}

// nilOrPrintUSASCII returns "-" for empty fields, otherwise enforces that
// the value is 1*nnnPRINTUSASCII (%d33-126).
func nilOrPrintUSASCII(field, s string, max int) (string, error) {
	if s == "" {
		return "-", nil
	}
	if len(s) > max {
		return "", fmt.Errorf("syslog: %s exceeds %d octets", field, max)
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 33 || c > 126 {
			return "", fmt.Errorf("syslog: %s contains non-PRINTUSASCII byte %#x", field, c)
		}
	}
	return s, nil
}

// validateSDList verifies the structural rules from RFC 5424 §6.3 without
// emitting any bytes. Maps for duplicate detection are only allocated when
// they're actually needed (more than one element / param).
func validateSDList(elems []SDElement) error {
	if len(elems) == 0 {
		return nil
	}
	var seenIDs map[string]struct{}
	if len(elems) > 1 {
		seenIDs = make(map[string]struct{}, len(elems))
	}
	for _, e := range elems {
		if err := validateSDID(e.ID); err != nil {
			return err
		}
		if seenIDs != nil {
			if _, dup := seenIDs[e.ID]; dup {
				return fmt.Errorf("syslog: duplicate SD-ID %q", e.ID)
			}
			seenIDs[e.ID] = struct{}{}
		}
		var seenParams map[string]struct{}
		if len(e.Params) > 1 {
			seenParams = make(map[string]struct{}, len(e.Params))
		}
		for _, p := range e.Params {
			if err := validateSDName(p.Name, "PARAM-NAME"); err != nil {
				return err
			}
			if seenParams != nil {
				if _, dup := seenParams[p.Name]; dup {
					return fmt.Errorf("syslog: duplicate PARAM-NAME %q in SD-ID %q", p.Name, e.ID)
				}
				seenParams[p.Name] = struct{}{}
			}
			if !utf8.ValidString(p.Value) {
				return fmt.Errorf("syslog: PARAM-VALUE for %q is not valid UTF-8", p.Name)
			}
		}
	}
	return nil
}

// appendSD emits structured-data (the value already validated). It assumes
// validateSDList ran successfully.
func appendSD(dst []byte, elems []SDElement) []byte {
	if len(elems) == 0 {
		return append(dst, '-')
	}
	for _, e := range elems {
		dst = append(dst, '[')
		dst = append(dst, e.ID...)
		for _, p := range e.Params {
			dst = append(dst, ' ')
			dst = append(dst, p.Name...)
			dst = append(dst, '=', '"')
			dst = appendEscapedSDValue(dst, p.Value)
			dst = append(dst, '"')
		}
		dst = append(dst, ']')
	}
	return dst
}

// validateSDName enforces the SD-NAME rules from RFC 5424 §6.3.3: 1*32
// PRINTUSASCII excluding '=' (61), SP (32), ']' (93), '"' (34).
func validateSDName(name, kind string) error {
	if name == "" {
		return fmt.Errorf("syslog: %s must not be empty", kind)
	}
	if len(name) > 32 {
		return fmt.Errorf("syslog: %s exceeds 32 octets", kind)
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c < 33 || c > 126 || c == '=' || c == ']' || c == '"' {
			return fmt.Errorf("syslog: %s contains invalid character %#x", kind, c)
		}
	}
	return nil
}

// validateSDID enforces RFC 5424 §6.3.2 SD-ID format. If the ID contains
// '@' it is a private enterprise ID; both the name part and the enterprise
// number must each conform to SD-NAME rules. IANA-registered IDs (no '@')
// are validated as a plain SD-NAME.
func validateSDID(id string) error {
	if idx := strings.IndexByte(id, '@'); idx >= 0 {
		if strings.IndexByte(id[idx+1:], '@') >= 0 {
			return fmt.Errorf("syslog: SD-ID contains multiple '@' signs")
		}
		if len(id) > 32 {
			return fmt.Errorf("syslog: SD-ID exceeds 32 octets")
		}
		if err := validateSDName(id[:idx], "SD-ID (name part)"); err != nil {
			return err
		}
		if err := validateSDName(id[idx+1:], "SD-ID (enterprise number)"); err != nil {
			return err
		}
		return nil
	}
	return validateSDName(id, "SD-ID")
}

// sdEscapeLUT[c] != 0 iff c must be escaped per RFC 5424 §6.3.3.
var sdEscapeLUT = func() (t [256]byte) {
	t['\\'] = 1
	t['"'] = 1
	t[']'] = 1
	return
}()

// appendEscapedSDValue escapes the three RFC 5424 §6.3.3 special chars
// (\, ", ]) and appends the result to dst.
//
// For values ≥64 octets, a single ContainsAny scan to confirm cleanliness
// followed by a bulk append beats the byte loop. Below that threshold the
// loop is cheap enough that the scan is pure overhead — benchmark-driven.
func appendEscapedSDValue(dst []byte, v string) []byte {
	if len(v) >= 64 && !strings.ContainsAny(v, `\"]`) {
		return append(dst, v...)
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if sdEscapeLUT[c] != 0 {
			dst = append(dst, '\\')
		}
		dst = append(dst, c)
	}
	return dst
}
