package network

import (
	"fmt"
	"strings"
)

const (
	TCP                     = 1
	UDP                     = 2
	TCP_STRING              = "TCP"
	UDP_STRING              = "UDP"
	PROTOCOL_UNKNOWN_STRING = "UNKOWN"
)

func byte2IPv4(addrBytes [4]byte) string {
	var s []string
	for _, b := range addrBytes {
		s = append(s, fmt.Sprintf("%d", b))
	}
	return strings.Join(s, ".")
}

func byte2IPv6(addrBytes [16]byte) string {
	var s []string
	var t string
	for i, b := range addrBytes {
		t = t + fmt.Sprintf("%02x", b)
		if i%2 == 1 {
			s = append(s, t)
			t = ""
		}
	}
	return strings.Join(s, ":")
}

func comm2string(commBytes [16]byte) string {
	var s string
	for _, b := range commBytes {
		if b != 0x00 {
			s += string(b)
		}
	}
	return s
}

func nodename2string(bytes [65]byte) string {
	var s string
	for _, b := range bytes {
		if b != 0x00 {
			s += string(b)
		}
	}
	return s
}

func sockTypeToProtocolName(sockType uint8) string {
	// https://elixir.bootlin.com/linux/latest/source/include/linux/net.h#L61
	switch sockType {
	case TCP:
		return TCP_STRING
	case UDP:
		return UDP_STRING
	default:
		return PROTOCOL_UNKNOWN_STRING
	}
}
