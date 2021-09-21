package network

import (
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
