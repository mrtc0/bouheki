package network

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/mrtc0/bouheki/pkg/config"
	"github.com/stretchr/testify/assert"
)

type SpyDNSResolver struct {
	config  *dns.ClientConfig
	client  *dns.Client
	message *dns.Msg
}

func (r *SpyDNSResolver) Resolve(host string, recordType uint16) (DNSAnswer, error) {
	answers := DNSAnswer{Domain: host}
	answers.Addresses = []net.IP{
		net.IPv4(192, 168, 1, 1),
		net.IPv4(10, 0, 1, 1),
	}
	answers.TTL = 1234

	return answers, nil
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
		addresses  []net.IP
		expected   []IPAddress
	}{
		{
			name:       "example.com",
			domainName: "example.com",
			addresses: []net.IP{
				{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 0xc0, 0xa8, 0x1, 0x1},
				{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 0xa, 0x0, 0x1, 0x1},
			},
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
			addrs, err := domainNameToBPFMapKey(test.domainName, test.addresses)
			if err != nil {
				t.Errorf("domanNameToBPFMapKey return error: %#v", err)
			}
			assert.Equal(t, test.expected, addrs)
		})
	}
}

func newSpyDNSResolver() SpyDNSResolver {
	dnsConfig, _ := dns.ClientConfigFromFile("/etc/resolv.conf")
	resolver := SpyDNSResolver{
		config:  dnsConfig,
		client:  new(dns.Client),
		message: new(dns.Msg),
	}

	return resolver
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
		dnsResolver: dnsResolver,
	}

	err = mgr.SetConfigToMap()
	if err != nil {
		panic(err)
	}

	return mgr
}
