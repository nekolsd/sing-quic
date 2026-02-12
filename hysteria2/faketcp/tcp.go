package faketcp

import (
	"encoding/binary"
	"errors"
	"net"
)

const (
	tcpHeaderMinLen = 20

	// TCP flags
	FlagFIN = 0x01
	FlagSYN = 0x02
	FlagRST = 0x04
	FlagPSH = 0x08
	FlagACK = 0x10
	FlagURG = 0x20
)

// TCPHeader represents a minimal TCP header (no options).
type TCPHeader struct {
	SrcPort  uint16
	DstPort  uint16
	Seq      uint32
	Ack      uint32
	Flags    uint8
	Window   uint16
	Checksum uint16
	Urgent   uint16
}

// DecodeTCPHeader parses a TCP header from raw bytes (starting at the TCP header).
// It returns the header and the payload slice.
func DecodeTCPHeader(data []byte) (*TCPHeader, []byte, error) {
	if len(data) < tcpHeaderMinLen {
		return nil, nil, errors.New("packet too short for TCP header")
	}

	h := &TCPHeader{
		SrcPort:  binary.BigEndian.Uint16(data[0:2]),
		DstPort:  binary.BigEndian.Uint16(data[2:4]),
		Seq:      binary.BigEndian.Uint32(data[4:8]),
		Ack:      binary.BigEndian.Uint32(data[8:12]),
		Flags:    data[13],
		Window:   binary.BigEndian.Uint16(data[14:16]),
		Checksum: binary.BigEndian.Uint16(data[16:18]),
		Urgent:   binary.BigEndian.Uint16(data[18:20]),
	}

	// Data offset is the upper 4 bits of byte 12, in 32-bit words
	dataOffset := int(data[12]>>4) * 4
	if dataOffset < tcpHeaderMinLen {
		return nil, nil, errors.New("invalid TCP data offset")
	}
	if dataOffset > len(data) {
		return nil, nil, errors.New("TCP data offset exceeds packet length")
	}

	return h, data[dataOffset:], nil
}

// EncodeTCPPacket builds a raw TCP segment (header + payload) with correct checksum.
// srcIP and dstIP are used for the pseudo-header checksum calculation.
func EncodeTCPPacket(h *TCPHeader, payload []byte, srcIP, dstIP net.IP) []byte {
	totalLen := tcpHeaderMinLen + len(payload)
	buf := make([]byte, totalLen)

	// Encode the TCP header
	binary.BigEndian.PutUint16(buf[0:2], h.SrcPort)
	binary.BigEndian.PutUint16(buf[2:4], h.DstPort)
	binary.BigEndian.PutUint32(buf[4:8], h.Seq)
	binary.BigEndian.PutUint32(buf[8:12], h.Ack)
	// Data offset = 5 (20 bytes / 4), shifted left 4 bits
	buf[12] = 5 << 4
	buf[13] = h.Flags
	binary.BigEndian.PutUint16(buf[14:16], h.Window)
	// Checksum and Urgent pointer left as 0 for now
	binary.BigEndian.PutUint16(buf[18:20], h.Urgent)

	// Copy payload
	if len(payload) > 0 {
		copy(buf[tcpHeaderMinLen:], payload)
	}

	// Calculate checksum with pseudo-header
	binary.BigEndian.PutUint16(buf[16:18], tcpChecksum(buf, srcIP, dstIP))

	return buf
}

// tcpChecksum calculates the TCP checksum including the pseudo-header.
// tcpSegment is the full TCP segment (header + payload).
func tcpChecksum(tcpSegment []byte, srcIP, dstIP net.IP) uint16 {
	// Normalize IPs to 4 or 16 bytes
	src4 := srcIP.To4()
	dst4 := dstIP.To4()

	var pseudoHeader []byte
	if src4 != nil && dst4 != nil {
		// IPv4 pseudo-header: src(4) + dst(4) + zero(1) + proto(1) + tcpLen(2) = 12 bytes
		pseudoHeader = make([]byte, 12)
		copy(pseudoHeader[0:4], src4)
		copy(pseudoHeader[4:8], dst4)
		pseudoHeader[8] = 0
		pseudoHeader[9] = 6 // TCP protocol number
		binary.BigEndian.PutUint16(pseudoHeader[10:12], uint16(len(tcpSegment)))
	} else {
		// IPv6 pseudo-header: src(16) + dst(16) + tcpLen(4) + zero(3) + nextHeader(1) = 40 bytes
		src16 := srcIP.To16()
		dst16 := dstIP.To16()
		pseudoHeader = make([]byte, 40)
		copy(pseudoHeader[0:16], src16)
		copy(pseudoHeader[16:32], dst16)
		binary.BigEndian.PutUint32(pseudoHeader[32:36], uint32(len(tcpSegment)))
		pseudoHeader[39] = 6 // TCP protocol number
	}

	// Sum pseudo-header
	sum := checksumAccumulate(pseudoHeader)
	// Sum TCP segment
	sum += checksumAccumulate(tcpSegment)

	// Fold 32-bit sum to 16 bits
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}

	return ^uint16(sum)
}

// checksumAccumulate sums all 16-bit words in data, returning a 32-bit accumulator.
func checksumAccumulate(data []byte) uint32 {
	var sum uint32
	length := len(data)
	i := 0
	for i < length-1 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
		i += 2
	}
	// If odd length, pad with zero byte
	if i < length {
		sum += uint32(data[i]) << 8
	}
	return sum
}
