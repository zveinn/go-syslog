package syslog

import (
	"bytes"
	"fmt"
	"strconv"
)

// FrameRFC6587 accumulates syslog messages using RFC 6587 §3.4.1 octet-
// counting framing. Each frame is encoded as "LENGTH SP MSG" where LENGTH
// is the ASCII decimal byte-length of MSG. FrameRFC6587 is not safe for
// concurrent use.
type FrameRFC6587 struct {
	buf []byte
}

// NewFrameRFC6587 returns an empty frame buffer.
func NewFrameRFC6587() *FrameRFC6587 {
	return &FrameRFC6587{}
}

// AddLog appends one octet-counted frame containing log to the buffer. It
// returns an error if log is empty.
func (f *FrameRFC6587) AddLog(log []byte) error {
	if f == nil {
		return fmt.Errorf("syslog: nil FrameRFC6587")
	}
	if len(log) == 0 {
		return fmt.Errorf("syslog: empty log")
	}
	f.buf = strconv.AppendInt(f.buf, int64(len(log)), 10)
	f.buf = append(f.buf, ' ')
	f.buf = append(f.buf, log...)
	return nil
}

// Size returns the total number of bytes currently buffered.
func (f *FrameRFC6587) Size() int {
	if f == nil {
		return 0
	}
	return len(f.buf)
}

// Bytes returns the accumulated framed bytes. The returned slice aliases the
// internal buffer; callers must copy it if they intend to retain it across
// further AddLog calls.
func (f *FrameRFC6587) Bytes() []byte {
	if f == nil {
		return nil
	}
	return f.buf
}

// Reset clears the buffer for reuse without releasing its capacity.
func (f *FrameRFC6587) Reset() {
	if f == nil {
		return
	}
	f.buf = f.buf[:0]
}

// AddLogRFC3164 formats m as RFC 3164 directly into f's buffer and prepends
// the octet-count framing in place. Equivalent to AppendRFC3164 followed by
// AddLog but skips the caller-side scratch buffer.
func (f *FrameRFC6587) AddLogRFC3164(m *Message) error {
	if f == nil {
		return fmt.Errorf("syslog: nil FrameRFC6587")
	}
	start := len(f.buf)
	var err error
	f.buf, err = AppendRFC3164(f.buf, m)
	if err != nil {
		f.buf = f.buf[:start]
		return err
	}
	return f.framePrefix(start)
}

// AddLogRFC5424 formats m as RFC 5424 directly into f's buffer and prepends
// the octet-count framing in place. Equivalent to AppendRFC5424 followed by
// AddLog but skips the caller-side scratch buffer.
func (f *FrameRFC6587) AddLogRFC5424(m *Message) error {
	if f == nil {
		return fmt.Errorf("syslog: nil FrameRFC6587")
	}
	start := len(f.buf)
	var err error
	f.buf, err = AppendRFC5424(f.buf, m)
	if err != nil {
		f.buf = f.buf[:start]
		return err
	}
	return f.framePrefix(start)
}

// framePrefix inserts "LEN SP" at offset start, where the message bytes
// already occupy f.buf[start:]. It shifts those bytes right via an
// overlapping copy and writes the decimal length + space in the freed slot.
// f.buf is left at its pre-call state on error.
func (f *FrameRFC6587) framePrefix(start int) error {
	msgLen := len(f.buf) - start
	if msgLen == 0 {
		f.buf = f.buf[:start]
		return fmt.Errorf("syslog: empty log")
	}
	digits := decimalWidth(msgLen)
	prefixLen := digits + 1
	// Grow by prefixLen. The pad bytes will be overwritten; the array
	// literal doubles as a single-shot append for the slice growth.
	var pad [10]byte
	f.buf = append(f.buf, pad[:prefixLen]...)
	// Overlapping copy = memmove. Shifts the message bytes right by prefixLen.
	copy(f.buf[start+prefixLen:], f.buf[start:start+msgLen])
	n := msgLen
	for i := digits - 1; i >= 0; i-- {
		f.buf[start+i] = '0' + byte(n%10)
		n /= 10
	}
	f.buf[start+digits] = ' '
	return nil
}

// decimalWidth returns the number of base-10 digits needed to represent n.
// n must be positive; behaviour is unspecified otherwise.
func decimalWidth(n int) int {
	switch {
	case n < 10:
		return 1
	case n < 100:
		return 2
	case n < 1_000:
		return 3
	case n < 10_000:
		return 4
	case n < 100_000:
		return 5
	case n < 1_000_000:
		return 6
	case n < 10_000_000:
		return 7
	case n < 100_000_000:
		return 8
	}
	return 9
}

// FrameRFC6587NonTransparent accumulates syslog messages using RFC 6587
// §3.4.2 non-transparent framing: each message is followed by a single
// trailer byte. The RFC default and most widely supported choice is LF
// (0x0A); pass '\n' for that. The message itself MUST NOT contain the
// trailer byte, otherwise a receiver cannot determine where the message
// ends. Not safe for concurrent use.
type FrameRFC6587NonTransparent struct {
	buf     []byte
	trailer byte
}

// NewFrameRFC6587NonTransparent returns a frame buffer that delimits each
// message with the given trailer byte. RFC 6587 §3.4.2 names LF as the
// default; pass '\n' for that or e.g. 0 for NUL.
func NewFrameRFC6587NonTransparent(trailer byte) *FrameRFC6587NonTransparent {
	return &FrameRFC6587NonTransparent{trailer: trailer}
}

// AddLog appends one message followed by the trailer byte. Returns an
// error if log is empty or if log contains the trailer byte (which would
// be ambiguous on the wire).
func (f *FrameRFC6587NonTransparent) AddLog(log []byte) error {
	if f == nil {
		return fmt.Errorf("syslog: nil FrameRFC6587NonTransparent")
	}
	if len(log) == 0 {
		return fmt.Errorf("syslog: empty log")
	}
	if bytes.IndexByte(log, f.trailer) >= 0 {
		return fmt.Errorf("syslog: log contains trailer byte %#x", f.trailer)
	}
	f.buf = append(f.buf, log...)
	f.buf = append(f.buf, f.trailer)
	return nil
}

// Size returns the total number of bytes currently buffered.
func (f *FrameRFC6587NonTransparent) Size() int {
	if f == nil {
		return 0
	}
	return len(f.buf)
}

// Bytes returns the accumulated framed bytes. The returned slice aliases
// the internal buffer; copy it if it must survive further AddLog calls.
func (f *FrameRFC6587NonTransparent) Bytes() []byte {
	if f == nil {
		return nil
	}
	return f.buf
}

// Reset clears the buffer for reuse without releasing its capacity.
func (f *FrameRFC6587NonTransparent) Reset() {
	if f == nil {
		return
	}
	f.buf = f.buf[:0]
}

// AddLogRFC3164 formats m as RFC 3164 directly into f's buffer and appends
// the trailer in place. Equivalent to AppendRFC3164 followed by AddLog but
// skips the caller-side scratch buffer.
func (f *FrameRFC6587NonTransparent) AddLogRFC3164(m *Message) error {
	if f == nil {
		return fmt.Errorf("syslog: nil FrameRFC6587NonTransparent")
	}
	start := len(f.buf)
	var err error
	f.buf, err = AppendRFC3164(f.buf, m)
	if err != nil {
		f.buf = f.buf[:start]
		return err
	}
	return f.frameTrailer(start)
}

// AddLogRFC5424 formats m as RFC 5424 directly into f's buffer and appends
// the trailer in place. Equivalent to AppendRFC5424 followed by AddLog but
// skips the caller-side scratch buffer.
func (f *FrameRFC6587NonTransparent) AddLogRFC5424(m *Message) error {
	if f == nil {
		return fmt.Errorf("syslog: nil FrameRFC6587NonTransparent")
	}
	start := len(f.buf)
	var err error
	f.buf, err = AppendRFC5424(f.buf, m)
	if err != nil {
		f.buf = f.buf[:start]
		return err
	}
	return f.frameTrailer(start)
}

// frameTrailer validates the just-appended message at f.buf[start:] doesn't
// contain the trailer byte, then appends it. f.buf is reverted on error.
func (f *FrameRFC6587NonTransparent) frameTrailer(start int) error {
	if len(f.buf) == start {
		return fmt.Errorf("syslog: empty log")
	}
	if bytes.IndexByte(f.buf[start:], f.trailer) >= 0 {
		f.buf = f.buf[:start]
		return fmt.Errorf("syslog: log contains trailer byte %#x", f.trailer)
	}
	f.buf = append(f.buf, f.trailer)
	return nil
}
