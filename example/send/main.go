// Command send transmits one RFC 3164 UDP message, one RFC 5424 UDP message,
// and a batch of RFC 5424 messages framed with RFC 6587 octet-counting over
// TCP, against a syslog server reachable at -addr (default 127.0.0.1:5514).
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"time"

	syslog "github.com/zveinn/go-syslog"
)

func main() {
	udpAddr := flag.String("udp", "127.0.0.1:5514", "syslog UDP target")
	tcpAddr := flag.String("tcp", "127.0.0.1:5514", "syslog TCP target")
	flag.Parse()

	ts := time.Date(2026, time.May, 19, 10, 30, 0, 123000000, time.UTC)

	send3164UDP(*udpAddr, ts)
	send5424UDP(*udpAddr, ts)
	send5424TCP6587(*tcpAddr, ts)
}

func send3164UDP(addr string, ts time.Time) {
	msg, err := syslog.FormatRFC3164(&syslog.Message{
		Facility:  syslog.FacLocal4,
		Severity:  syslog.SevNotice,
		Timestamp: ts,
		Hostname:  "demo-host",
		AppName:   "demoapp",
		ProcID:    "1234",
		Message:   "RFC3164-UDP hello from go-syslog",
	})
	if err != nil {
		log.Fatalf("FormatRFC3164: %v", err)
	}
	mustWriteUDP(addr, msg)
	fmt.Printf("RFC3164/UDP  → %s  (%d bytes)\n%s\n\n", addr, len(msg), msg)
}

func send5424UDP(addr string, ts time.Time) {
	msg, err := syslog.FormatRFC5424(&syslog.Message{
		Facility:  syslog.FacLocal4,
		Severity:  syslog.SevInfo,
		Timestamp: ts,
		Hostname:  "demo-host.example.com",
		AppName:   "demoapp",
		ProcID:    "1234",
		MsgID:     "DEMO01",
		StructuredData: []syslog.SDElement{{
			ID: "demo@32473",
			Params: []syslog.SDParam{
				{Name: "transport", Value: "udp"},
				{Name: "note", Value: `quotes " and ] need escaping`},
			},
		}},
		Message: "RFC5424-UDP hello from go-syslog",
	})
	if err != nil {
		log.Fatalf("FormatRFC5424: %v", err)
	}
	mustWriteUDP(addr, msg)
	fmt.Printf("RFC5424/UDP  → %s  (%d bytes)\n%s\n\n", addr, len(msg), msg)
}

func send5424TCP6587(addr string, ts time.Time) {
	frame := syslog.NewFrameRFC6587()
	for i, txt := range []string{
		"RFC5424-TCP first message",
		"RFC5424-TCP second message",
		"RFC5424-TCP third message",
	} {
		msg, err := syslog.FormatRFC5424(&syslog.Message{
			Facility:  syslog.FacLocal4,
			Severity:  syslog.SevInfo,
			Timestamp: ts.Add(time.Duration(i) * time.Second),
			Hostname:  "demo-host.example.com",
			AppName:   "demoapp",
			ProcID:    "1234",
			MsgID:     fmt.Sprintf("BATCH%02d", i+1),
			Message:   txt,
		})
		if err != nil {
			log.Fatalf("FormatRFC5424: %v", err)
		}
		if err := frame.AddLog(msg); err != nil {
			log.Fatalf("AddLog: %v", err)
		}
	}
	mustWriteTCP(addr, frame.Bytes())
	fmt.Printf("RFC5424+6587/TCP → %s  (%d bytes framed)\n%s\n",
		addr, frame.Size(), frame.Bytes())
}

func mustWriteUDP(addr string, msg []byte) {
	c, err := net.Dial("udp", addr)
	if err != nil {
		log.Fatalf("dial udp: %v", err)
	}
	defer c.Close()
	if _, err := c.Write(msg); err != nil {
		log.Fatalf("udp write: %v", err)
	}
}

func mustWriteTCP(addr string, msg []byte) {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		log.Fatalf("dial tcp: %v", err)
	}
	defer c.Close()
	if _, err := c.Write(msg); err != nil {
		log.Fatalf("tcp write: %v", err)
	}
}
