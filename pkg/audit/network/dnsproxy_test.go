package network

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func Test_resolveConfFromClientConfig(t *testing.T) {
	tests := []struct {
		name      string
		expect    []byte
		dnsConfig *dns.ClientConfig
	}{
		{
			name: "with servers and search",
			expect: []byte(`# This file managed by bouheki. Do not edit.
nameserver 10.0.1.1
search .

options edns0 trust-ad`),
			dnsConfig: &dns.ClientConfig{Servers: []string{"10.0.1.1"}, Search: []string{"."}},
		},
		{
			name: "with servers",
			expect: []byte(`# This file managed by bouheki. Do not edit.
nameserver 10.0.1.1

options edns0 trust-ad`),
			dnsConfig: &dns.ClientConfig{Servers: []string{"10.0.1.1"}, Search: []string{}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			content, err := resolvConfFromClientConfig(test.dnsConfig)
			if err != nil {
				t.Fatalf("%s", err)
			}
			assert.Equal(t, test.expect, content)
		})
	}
}
