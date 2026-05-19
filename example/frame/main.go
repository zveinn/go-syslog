// RFC 6587 framing for sending syslog over TCP. Two flavours: octet
// counting (the recommended one) and non transparent (LF terminated).
package main

import (
	"fmt"
	"log"
	"time"

	syslog "github.com/zveinn/go-syslog"
)

func main() {
	ts := time.Now().UTC()

	// Build a few RFC 5424 messages to frame.
	var msgs [][]byte
	for _, body := range []string{"alpha", "beta", "gamma"} {
		b, err := syslog.FormatRFC5424(&syslog.Message{
			Facility:  syslog.FacLocal0,
			Severity:  syslog.SevInfo,
			Timestamp: ts,
			Hostname:  "myhost.example.com",
			AppName:   "demo",
			Message:   body,
		})
		if err != nil {
			log.Fatal(err)
		}
		msgs = append(msgs, b)
	}

	// Octet counting: each frame is "<LEN> <MSG>". Binary safe.
	octet := syslog.NewFrameRFC6587()
	for _, m := range msgs {
		if err := octet.AddLog(m); err != nil {
			log.Fatal(err)
		}
	}
	fmt.Printf("octet counting (%d bytes):\n%s\n\n", octet.Size(), octet.Bytes())

	// Non transparent: each message is followed by a trailer byte. LF is
	// the RFC default; messages must not contain that byte.
	nt := syslog.NewFrameRFC6587NonTransparent('\n')
	for _, m := range msgs {
		if err := nt.AddLog(m); err != nil {
			log.Fatal(err)
		}
	}
	fmt.Printf("non transparent (%d bytes):\n%s", nt.Size(), nt.Bytes())

	// In real use, write the frame bytes to your TCP connection:
	//   conn.Write(octet.Bytes())
}
