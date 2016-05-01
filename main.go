package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
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

	id := uint16(os.Getpid() & 0xffff)
	now, err := time.Now().MarshalBinary()
	if err != nil {
		fmt.Errorf("Time.MarshalBinary:", err)
		os.Exit(1)
	}
	m := EchoMessage{
		Type: ECHO,
		Code: 0,
		ID:   id,
		Seq:  0,
		Data: now,
	}
	mb := m.Marshal()
	rb := make([]byte, 100)
	_, err = conn.Write(mb)
	if err != nil {
		fmt.Errorf("Write:", err)
		os.Exit(1)
	}

	n, err := conn.Read(rb)
	received_at := time.Now()

	rm, err := ParseEchoMessageWithIPv4Header(rb[:n])

	if rm.Type == ECHO_REPLY && rm.ID == id {
		sent_at := time.Time{}
		err = sent_at.UnmarshalBinary(rm.Data)
		if err != nil {
			fmt.Errorf("Time.UnmarshalBinary:", err)
		}
		rtt := received_at.Sub(sent_at)
		fmt.Println(rtt)
	}
}
