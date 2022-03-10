package helpers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNodenameToString(t *testing.T) {
	tests := []struct {
		name   string
		input  [65]byte
		expect string
	}{
		{
			name:   "Hexadecimal string to be string (ubuntu)",
			input:  [65]byte{0x75, 0x62, 0x75, 0x6e, 0x74, 0x75, 0x00, 0x00, 0x00},
			expect: "ubuntu",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, NodenameToString(test.input), test.expect)
		})
	}
}

func TestCommToString(t *testing.T) {
	tests := []struct {
		name   string
		input  [16]byte
		expect string
	}{
		{
			name:   "Hexadecimal string to be string (curl)",
			input:  [16]byte{0x63, 0x75, 0x72, 0x6c, 0x00, 0x00, 0x00},
			expect: "curl",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, CommToString(test.input), test.expect)
		})
	}
}
