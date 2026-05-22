package syslog

import "fmt"

// ValidateMessageRFC3164 reports whether m would format successfully as
// an RFC 3164 message. Runs every per-field validator (Priority,
// Hostname, AppName, ProcID) without producing wire bytes. Equivalent
// to calling AppendRFC3164 and discarding the output, but allocation-
// free and slightly faster.
func ValidateMessageRFC3164(m *Message) error {
	if m == nil {
		return fmt.Errorf("syslog: nil message")
	}
	if _, err := NewPriority(m.Facility, m.Severity); err != nil {
		return err
	}
	if err := ValidateHostnameRFC3164(m.Hostname); err != nil {
		return err
	}
	if err := ValidateAppNameRFC3164(m.AppName); err != nil {
		return err
	}
	if err := ValidateProcIDRFC3164(m.ProcID); err != nil {
		return err
	}
	return nil
}

// ValidateMessageRFC5424 reports whether m would format successfully as
// an RFC 5424 message. Runs every per-field validator (Priority,
// Hostname, AppName, ProcID, MsgID, StructuredData) without producing
// wire bytes.
func ValidateMessageRFC5424(m *Message) error {
	if m == nil {
		return fmt.Errorf("syslog: nil message")
	}
	if _, err := NewPriority(m.Facility, m.Severity); err != nil {
		return err
	}
	if err := ValidateHostnameRFC5424(m.Hostname); err != nil {
		return err
	}
	if err := ValidateAppNameRFC5424(m.AppName); err != nil {
		return err
	}
	if err := ValidateProcIDRFC5424(m.ProcID); err != nil {
		return err
	}
	if err := ValidateMsgIDRFC5424(m.MsgID); err != nil {
		return err
	}
	if err := ValidateStructuredData(m.StructuredData); err != nil {
		return err
	}
	return nil
}
