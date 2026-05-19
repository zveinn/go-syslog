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
