package syslog

import "errors"

var (
	errFacilityOutOfRange = errors.New("syslog: facility out of range (0-23)")
	errSeverityOutOfRange = errors.New("syslog: severity out of range (0-7)")
)

// Facility is the syslog facility code (0-23).
type Facility uint8

const (
	FacKern Facility = iota
	FacUser
	FacMail
	FacDaemon
	FacAuth
	FacSyslog
	FacLPR
	FacNews
	FacUUCP
	FacCron
	FacAuthPriv
	FacFTP
	FacNTP
	FacAudit
	FacAlert
	FacClock
	FacLocal0
	FacLocal1
	FacLocal2
	FacLocal3
	FacLocal4
	FacLocal5
	FacLocal6
	FacLocal7
)

// Severity is the syslog severity code (0-7).
type Severity uint8

const (
	SevEmerg Severity = iota
	SevAlert
	SevCrit
	SevErr
	SevWarning
	SevNotice
	SevInfo
	SevDebug
)

// Priority encodes a facility and severity as PRI = facility*8 + severity.
type Priority uint8

// NewPriority returns a valid Priority from facility and severity. It returns
// an error if either argument is outside its valid range.
func NewPriority(f Facility, s Severity) (Priority, error) {
	if f > 23 {
		return 0, errFacilityOutOfRange
	}
	if s > 7 {
		return 0, errSeverityOutOfRange
	}
	return Priority(uint8(f)*8 + uint8(s)), nil
}

// Facility returns the facility part of the priority.
func (p Priority) Facility() Facility { return Facility(p / 8) }

// Severity returns the severity part of the priority.
func (p Priority) Severity() Severity { return Severity(p % 8) }
