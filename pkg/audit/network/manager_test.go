package network

import (
	"net"
	"testing"
	"unsafe"

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

func Test_cidrToBPFMapKey(t *testing.T) {
	tests := []struct {
		name     string
		cidr     string
		expected IPAddress
	}{
		{
			name: "Parsing the CIDR and returning IPAddress{}",
			cidr: "192.168.1.1/24",
			expected: IPAddress{
				address:  net.IP{0xc0, 0xa8, 0x1, 0x0},
				cidrMask: net.IPMask{0xff, 0xff, 0xff, 0x0},
				key:      []byte{0x18, 0x0, 0x0, 0x0, 0xc0, 0xa8, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ipaddr, _ := cidrToBPFMapKey(test.cidr)
			assert.Equal(t, test.expected, ipaddr)
		})
	}
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

			mgr := createManager(config, &DefaultResolver{})

			assert.Equal(t, nil, mgr.updateDNSCache(test.caches, test.deniedAddressed))
		})
	}
}

func Test_updateDNSCache_needUpdate(t *testing.T) {
	cidr1 := "10.0.1.1/32"
	cidr2 := "192.168.1.1/32"
	cidr3 := "172.25.1.1/32"

	ipAddr1, _ := cidrToBPFMapKey(cidr1)
	ipAddr2, _ := cidrToBPFMapKey(cidr2)
	ipAddr3, _ := cidrToBPFMapKey(cidr3)

	tests := []struct {
		name         string
		caches       []DomainCache
		newAddresses []IPAddress
	}{
		{
			name: "Remove the IP address from the map, as it will need to be updated if the IP address changes.",
			caches: []DomainCache{
				{key: ipAddr1.key, mapName: DENIED_V4_CIDR_LIST_MAP_NAME},
				{key: ipAddr2.key, mapName: DENIED_V4_CIDR_LIST_MAP_NAME},
			},
			newAddresses: []IPAddress{
				ipAddr1,
				ipAddr3,
			},
		},
	}

	testConfig := config.DefaultConfig()
	testConfig.Network.CIDR = config.CIDRConfig{Deny: []string{cidr1, cidr2}}
	mgr := createManager(testConfig, &DefaultResolver{})

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, nil, mgr.updateDNSCache(test.caches, test.newAddresses))

			bpfmap, err := mgr.mod.GetMap(DENIED_V4_CIDR_LIST_MAP_NAME)
			if err != nil {
				t.Errorf("cannot open BPF Map: %s", err)
			}

			// After name resolution, the ipAddr2 address was not included, so it should have been removed.
			_, err = bpfmap.GetValue(unsafe.Pointer(&ipAddr2.key[0]))
			assert.NotEqual(t, nil, err)

			// The ipAddr1 has not changed, so the map is still available.
			_, err = bpfmap.GetValue(unsafe.Pointer(&ipAddr1.key[0]))
			assert.Equal(t, nil, err)
		})
	}
}

func Test_findOldCache(t *testing.T) {
	cidr1 := "10.0.1.1/32"
	cidr2 := "192.168.1.1/32"
	cidr3 := "172.25.1.1/32"

	ipAddr1, _ := cidrToBPFMapKey(cidr1)
	ipAddr2, _ := cidrToBPFMapKey(cidr2)
	ipAddr3, _ := cidrToBPFMapKey(cidr3)

	tests := []struct {
		name         string
		caches       []DomainCache
		newAddresses []IPAddress
		expected     []DomainCache
	}{
		{
			name: "The IP address has not changed, there is no cache to be deleted.",
			caches: []DomainCache{
				{key: ipAddr1.key, mapName: DENIED_V4_CIDR_LIST_MAP_NAME},
				{key: ipAddr2.key, mapName: DENIED_V4_CIDR_LIST_MAP_NAME},
			},
			newAddresses: []IPAddress{
				ipAddr1,
				ipAddr2,
			},
			expected: []DomainCache{},
		},
		{
			name: "The address of ipAddr2 is not included, it should be removed from the cache.",
			caches: []DomainCache{
				{key: ipAddr1.key, mapName: DENIED_V4_CIDR_LIST_MAP_NAME},
				{key: ipAddr2.key, mapName: DENIED_V4_CIDR_LIST_MAP_NAME},
			},
			newAddresses: []IPAddress{
				ipAddr1,
				ipAddr3,
			},
			expected: []DomainCache{{key: ipAddr2.key, mapName: DENIED_V4_CIDR_LIST_MAP_NAME}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, findOldCache(test.caches, test.newAddresses))
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
			name: "IPv4",
			ipAddress: IPAddress{
				address:  net.IP{0xc0, 0xa8, 0x1, 0x1},       // 192.168.1.1
				cidrMask: net.IPMask{0xff, 0xff, 0xff, 0xff}, // /32
			},
			expected: []byte{0x20, 0x0, 0x0, 0x0, 0xc0, 0xa8, 0x1, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		},
		{
			name: "IPv6",
			ipAddress: IPAddress{
				address:  net.IP{0x20, 0x1, 0x39, 0x84, 0x39, 0x89, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x3},                // 2001:3984:3989::3
				cidrMask: net.IPMask{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // /128
			},
			expected: []byte{0x80, 0x0, 0x0, 0x0, 0x20, 0x1, 0x39, 0x84, 0x39, 0x89, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x3},
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
					address:  []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 0xc0, 0xa8, 0x1, 0x1},
					cidrMask: net.IPMask{0xff, 0xff, 0xff, 0xff},
					key:      []byte{0x20, 0x0, 0x0, 0x0, 0xc0, 0xa8, 0x1, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
				},
				{
					address:  []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 0xa, 0x0, 0x1, 0x1},
					cidrMask: net.IPMask{0xff, 0xff, 0xff, 0xff},
					key:      []byte{0x20, 0x0, 0x0, 0x0, 0xa, 0x0, 0x1, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
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

func loadFixtureConfig(path string) *config.Config {
	conf, err := config.NewConfig(path)
	if err != nil {
		panic(err)
	}
	return conf
}

func createManager(conf *config.Config, dnsResolver DNSResolver) Manager {
	mod, err := setupBPFProgram()
	if err != nil {
		panic(err)
	}

	mgr := Manager{
		mod:         mod,
		config:      conf,
		cache:       make(map[string][]DomainCache),
		dnsResolver: dnsResolver,
	}

	err = mgr.SetConfigToMap()
	if err != nil {
		panic(err)
	}

	return mgr
}
