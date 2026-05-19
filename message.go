package syslog

import "time"

// Message holds the fields used to build a syslog message in either RFC 3164
// or RFC 5424 format. Not every field is meaningful in both formats; see the
// Format functions for details.
type Message struct {
	Facility  Facility
	Severity  Severity
	Timestamp time.Time

	// Hostname is the source host. For RFC 3164 it should not contain spaces.
	Hostname string

	// AppName is the application name (RFC 5424) or TAG (RFC 3164). For RFC
	// 3164 this is the program name; ProcID is appended in brackets if set.
	AppName string

	// ProcID is the process ID (RFC 5424) or the PID appended to TAG (RFC
	// 3164). May be empty.
	ProcID string

	// MsgID is the RFC 5424 MSGID. Ignored by RFC 3164.
	MsgID string

	// StructuredData is the RFC 5424 STRUCTURED-DATA. Ignored by RFC 3164.
	StructuredData []SDElement

	// Message is the free-form message text.
	Message string
}

// SDElement is a single RFC 5424 STRUCTURED-DATA element.
type SDElement struct {
	ID     string
	Params []SDParam
}

// SDParam is a single name=value parameter inside an SDElement.
type SDParam struct {
	Name  string
	Value string
}
