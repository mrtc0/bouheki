package network

import (
	"github.com/stretchr/testify/assert"
	"net"
	"reflect"
	"testing"
)

func Test_parseCIDR_parse(t *testing.T) {
	cidr := "192.168.1.1/24"
	actual, _ := parseCIDR(cidr)
	if reflect.TypeOf(actual).String() == "net.IPNet" {
		t.Errorf("got: %#v\nwant: net.IPNet", actual)
	}
}

func Test_parseCIDR_error(t *testing.T) {
	cidr := "192.168.1.1"
	_, actual := parseCIDR(cidr)
	if actual == nil {
		t.Errorf("got: %#v\nwant: error", actual)
	}
}

func Test_ipToKey_ipNetToKey(t *testing.T) {
	ip := net.IPv4(192, 168, 1, 1)
	ipnet, err := parseCIDR("192.168.1.1/32")
	assert.Nil(t, err)
	assert.Equal(t, ipToKey(ip), ipNetToKey(*ipnet))
}
