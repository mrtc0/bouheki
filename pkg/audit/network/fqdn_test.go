package network

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_domainNameToFqdn(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		expect string
	}{
		{
			name:   "example.com -> example.com.",
			domain: "example.com",
			expect: "example.com.",
		},
		{
			name:   "example.com. -> example.com.",
			domain: "example.com.",
			expect: "example.com.",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expect, domainNameToFqdn(test.domain))
		})
	}
}
