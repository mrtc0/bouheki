package network

import (
	"net"
	"reflect"
	"testing"

	"github.com/mrtc0/bouheki/pkg/config"
	"github.com/stretchr/testify/assert"
)

type SpyDNSResolver struct{}

func (r *SpyDNSResolver) Resolve(host string) ([]net.IP, error) {
	return []net.IP{
		net.IPv4(192, 168, 1, 1),
		net.IPv4(10, 0, 1, 1),
	}, nil
}

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

func Test_updateDNSCache_noNeedUpdate(t *testing.T) {
	ipAddr1 := IPAddress{address: net.ParseIP("10.0.1.1")}
	ipAddr1.ipAddressToBPFMapKey()
	ipAddr2 := IPAddress{address: net.ParseIP("192.168.1.1")}
	ipAddr2.ipAddressToBPFMapKey()

	tests := []struct {
		name            string
		caches          []DomainCache
		deniedAddressed []IPAddress
	}{
		{
			name: "If the IP address does not change, there is no need to update it.",
			caches: []DomainCache{
				{key: ipAddr1.key, mapName: DENIED_V4_CIDR_LIST_MAP_NAME},
				{key: ipAddr2.key, mapName: DENIED_V4_CIDR_LIST_MAP_NAME},
			},
			deniedAddressed: []IPAddress{
				{address: net.ParseIP("10.0.1.1")},
				{address: net.ParseIP("192.168.1.1")},
			},
		},
	}

	config := config.DefaultConfig()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for i, ipaddr := range test.deniedAddressed {
				test.deniedAddressed[i].key = ipaddr.ipAddressToBPFMapKey()
			}

			mgr := createManager(config)

			assert.Equal(t, nil, mgr.updateDNSCache(test.caches, test.deniedAddressed))
		})
	}
}

func Test_updateDNSCache_needUpdate(t *testing.T) {
	ipAddr1 := IPAddress{address: net.ParseIP("10.0.1.1")}
	ipAddr1.ipAddressToBPFMapKey()
	ipAddr2 := IPAddress{address: net.ParseIP("192.168.1.1")}
	ipAddr2.ipAddressToBPFMapKey()
	ipAddr3 := IPAddress{address: net.ParseIP("172.25.1.1")}
	ipAddr3.ipAddressToBPFMapKey()

	tests := []struct {
		name            string
		caches          []DomainCache
		deniedAddressed []IPAddress
	}{
		{
			name: "Remove the IP address from the map, as it will need to be updated if the IP address changes.",
			caches: []DomainCache{
				{key: ipAddr1.key, mapName: DENIED_V4_CIDR_LIST_MAP_NAME},
				{key: ipAddr2.key, mapName: DENIED_V4_CIDR_LIST_MAP_NAME},
			},
			deniedAddressed: []IPAddress{
				{address: net.ParseIP("10.0.1.1")},
				{address: net.ParseIP("172.25.1.1")},
			},
		},
	}

	testConfig := config.DefaultConfig()
	testConfig.Network.CIDR = config.CIDRConfig{Deny: []string{"10.0.1.1/32", "192.168.1.1/32"}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for i, ipaddr := range test.deniedAddressed {
				test.deniedAddressed[i].key = ipaddr.ipAddressToBPFMapKey()
			}

			mgr := createManager(testConfig)

			assert.Equal(t, nil, mgr.updateDNSCache(test.caches, test.deniedAddressed))

			bpfmap, err := mgr.mod.GetMap(DENIED_V4_CIDR_LIST_MAP_NAME)
			if err != nil {
				t.Errorf("cannot open BPF Map: %s", err)
			}

			_, err = bpfmap.GetValue(ipAddr2.key, 1)
			assert.NotEqual(t, nil, err)

			_, err = bpfmap.GetValue(ipAddr1.key, 1)
			assert.Equal(t, nil, err)
		})
	}
}

func Test_findOldCache(t *testing.T) {
	ipAddr1 := IPAddress{address: net.ParseIP("10.0.1.1")}
	ipAddr1.ipAddressToBPFMapKey()
	ipAddr2 := IPAddress{address: net.ParseIP("192.168.1.1")}
	ipAddr2.ipAddressToBPFMapKey()
	ipAddr3 := IPAddress{address: net.ParseIP("172.25.1.1")}
	ipAddr3.ipAddressToBPFMapKey()

	tests := []struct {
		name            string
		caches          []DomainCache
		deniedAddressed []IPAddress
		expected        []DomainCache
	}{
		{
			name: "If the IP address does not change, there is no need to update it.",
			caches: []DomainCache{
				{key: ipAddr1.key, mapName: DENIED_V4_CIDR_LIST_MAP_NAME},
				{key: ipAddr2.key, mapName: DENIED_V4_CIDR_LIST_MAP_NAME},
			},
			deniedAddressed: []IPAddress{
				{address: net.ParseIP("10.0.1.1")},
				{address: net.ParseIP("192.168.1.1")},
			},
			expected: []DomainCache{},
		},
		{
			name: "If the IP address changes, it need to be update.",
			caches: []DomainCache{
				{key: ipAddr1.key, mapName: DENIED_V4_CIDR_LIST_MAP_NAME},
				{key: ipAddr3.key, mapName: DENIED_V4_CIDR_LIST_MAP_NAME},
			},
			deniedAddressed: []IPAddress{
				{address: net.ParseIP("10.0.1.1")},
				{address: net.ParseIP("192.168.1.1")},
			},
			expected: []DomainCache{{key: ipAddr3.key, mapName: DENIED_V4_CIDR_LIST_MAP_NAME}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for i, ipaddr := range test.deniedAddressed {
				test.deniedAddressed[i].key = ipaddr.ipAddressToBPFMapKey()
			}

			assert.Equal(t, test.expected, findOldCache(test.caches, test.deniedAddressed))
		})
	}
}

func Test_ipAddressToBPFMapKey(t *testing.T) {
	tests := []struct {
		name      string
		ipAddress IPAddress
		expected  []byte
	}{
		{
			name:      "IPv4",
			ipAddress: IPAddress{address: net.ParseIP("10.0.1.1")},
			expected:  []byte{0x20, 0x0, 0x0, 0x0, 0xa, 0x0, 0x1, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		},
		{
			name:      "IPv6",
			ipAddress: IPAddress{address: net.ParseIP("2001:3984:3989::3")},
			expected:  []byte{0x80, 0x0, 0x0, 0x0, 0x20, 0x1, 0x39, 0x84, 0x39, 0x89, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x3},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, test.ipAddress.ipAddressToBPFMapKey())
		})
	}
}

func Test_domainNameToBPFMapKey(t *testing.T) {
	tests := []struct {
		name       string
		domainName string
		expected   []IPAddress
	}{
		{
			name:       "example.com",
			domainName: "example.com",
			expected: []IPAddress{
				{
					address: []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 0xc0, 0xa8, 0x1, 0x1},
					key:     []byte{0x20, 0x0, 0x0, 0x0, 0xc0, 0xa8, 0x1, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
				},
				{
					address: []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 0xa, 0x0, 0x1, 0x1},
					key:     []byte{0x20, 0x0, 0x0, 0x0, 0xa, 0x0, 0x1, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			addrs, err := domainNameToBPFMapKey(test.domainName, &SpyDNSResolver{})
			if err != nil {
				t.Errorf("domanNameToBPFMapKey return error: %#v", err)
			}
			assert.Equal(t, test.expected, addrs)
		})
	}
}
