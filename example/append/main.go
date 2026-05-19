// Appending into a reused buffer. After the buffer has grown to fit your
// largest expected message there are zero further allocations. Use this
// when you're emitting many messages in a tight loop.
package main

import (
	"fmt"
	"log"
	"time"

	syslog "github.com/zveinn/go-syslog"
)

func main() {
	bodies := []string{"first event", "second event", "third event"}

	buf := make([]byte, 0, 512)
	for i, body := range bodies {
		buf = buf[:0] // reuse the underlying array, drop length
		var err error
		buf, err = syslog.AppendRFC5424(buf, &syslog.Message{
			Facility:  syslog.FacLocal0,
			Severity:  syslog.SevInfo,
			Timestamp: time.Now().UTC(),
			Hostname:  "myhost.example.com",
			AppName:   "demo",
			ProcID:    "1234",
			MsgID:     fmt.Sprintf("EVT%03d", i),
			Message:   body,
		})
		if err != nil {
			log.Fatal(err)
		}
		// buf now holds one syslog message. In real use you would
		// conn.Write(buf) and move on.
		fmt.Printf("%s\n", buf)
	}
}
