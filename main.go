package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"time"
)

func getIPAddr(host string) (net.IP, error) {
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}

	for _, ip := range ips {
		if ip.To4() != nil {
			return ip.To4(), nil
		}
	}

	return nil, errors.New("IP address not found")
}

type Type uint8

const (
	ECHO_REPLY Type = 0
	ECHO       Type = 8
)

type EchoMessage struct {
	Type     Type
	Code     uint8
	Checksum uint16
	ID       uint16
	Seq      uint16
	Data     []byte
}

func (m *EchoMessage) Marshal() []byte {
	b := make([]byte, 8+len(m.Data))
	b[0] = byte(m.Type)
	b[1] = byte(m.Code)
	b[2] = 0
	b[3] = 0
	binary.BigEndian.PutUint16(b[4:6], m.ID)
	binary.BigEndian.PutUint16(b[6:8], m.Seq)
	copy(b[8:], m.Data)
	cs := checksum(b)
	b[2] = byte(cs >> 8)
	b[3] = byte(cs)
	return b
}

func ParseEchoMessageWithIPv4Header(b []byte) (*EchoMessage, error) {
	// IHL * 4 bytes
	hlen := int(b[0]&0x0f) << 2
	// Total Length does not count Header Length on OSX?
	// tlen := int(binary.LittleEndian.Uint16(b[2:4])) + hlen
	b = b[hlen:]
	m := &EchoMessage{
		Type:     Type(b[0]),
		Code:     uint8(b[1]),
		Checksum: uint16(binary.BigEndian.Uint16(b[2:4])),
		ID:       uint16(binary.BigEndian.Uint16(b[4:6])),
		Seq:      uint16(binary.BigEndian.Uint16(b[6:8])),
	}
	m.Data = make([]byte, len(b)-8)
	copy(m.Data, b[8:])
	return m, nil
}

// Compute Internet Checksum
// See http://tools.ietf.org/html/rfc1071#section-4.1
func checksum(b []byte) uint16 {
	count := len(b)
	sum := uint32(0)
	for i := 0; i < count-1; i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if count&1 != 0 {
		sum += uint32(b[count-1]) << 8
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^(uint16(sum))
}

func pinger(conn net.Conn, id uint16, sigc chan os.Signal, c chan int) {
	nt := 0
	seq := uint16(0)
	t := time.NewTicker(1 * time.Second)
	done := false
	for !done {
		select {
		case <-sigc:
			done = true
		case <-t.C:
			tb, err := time.Now().MarshalBinary()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Time.MarshalBinary:", err)
				os.Exit(1)
			}
			m := EchoMessage{
				Type: ECHO,
				Code: 0,
				ID:   id,
				Seq:  seq,
				Data: tb,
			}
			seq += 1
			mb := m.Marshal()
			_, err = conn.Write(mb)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Write:", err)
				os.Exit(1)
			}
			nt += 1
		}
	}
	t.Stop()
	c <- nt
}

func PrintStats(rtts []time.Duration, nt int) {
	if nt == 0 {
		return
	}
	var max time.Duration = 0
	var min time.Duration = 1000000000
	var sum time.Duration = 0
	for _, rtt := range rtts {
		sum += rtt
		if rtt > max {
			max = rtt
		}
		if rtt < min {
			min = rtt
		}
	}
	nr := len(rtts)
	loss := 100 * (nt - nr) / nt
	fmt.Println("\n----", os.Args[1], "ping statistics  -----")
	fmt.Println(nt, "packets transmitted,", nr, "packets received,", loss, "% packet loss")
	avg := time.Duration(int(sum.Nanoseconds()) / len(rtts))
	fmt.Println("min/max/avg = ", min, "/", max, "/", avg)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "arg error")
		os.Exit(1)
	}
	host := os.Args[1]

	ip, err := getIPAddr(host)
	if err != nil {
		fmt.Fprintf(os.Stderr, "getIPAddr")
		os.Exit(1)
	}

	conn, err := net.Dial("ip4:1", ip.String())
	if err != nil {
		fmt.Fprintf(os.Stderr, "net.Dial", err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Println("PING", os.Args[1], "(", ip, ")")
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt)
	c := make(chan int, 1)

	id := uint16(os.Getpid() & 0xffff)
	go pinger(conn, id, sigc, c)

	var rtts []time.Duration
	nt := 0
	done := false
	for !done {
		select {
		case nt = <-c:
			done = true
			break
		default:
			rb := make([]byte, 100)
			conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, err := conn.Read(rb)
			if err != nil {
				// FIXME
				continue
			}
			received_at := time.Now()

			rm, err := ParseEchoMessageWithIPv4Header(rb[:n])

			if rm.Type == ECHO_REPLY && rm.ID == id {
				sent_at := time.Time{}
				err = sent_at.UnmarshalBinary(rm.Data)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Time.UnmarshalBinary:", err)
				}
				rtt := received_at.Sub(sent_at)
				rtts = append(rtts, rtt)
				fmt.Println("seq =", rm.Seq, "time =", rtt)
			}
		}
	}
	PrintStats(rtts, nt)
}
