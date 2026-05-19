// One off RFC 5424 formatting. FormatRFC5424 returns a fresh []byte each
// call. Use this when you only need a message or two, or when ergonomics
// matter more than allocation count.
package main

import (
	"fmt"
	"log"
	"time"

	syslog "github.com/zveinn/go-syslog"
)

func main() {
	msg, err := syslog.FormatRFC5424(&syslog.Message{
		Facility:  syslog.FacUser,
		Severity:  syslog.SevInfo,
		Timestamp: time.Now().UTC(),
		Hostname:  "myhost.example.com",
		AppName:   "demo",
		ProcID:    "1234",
		MsgID:     "DEMO01",
		Message:   "one shot format",
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", msg)
}
