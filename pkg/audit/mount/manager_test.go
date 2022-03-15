package mount

import (
	"bytes"
	"testing"
	"unsafe"

	"github.com/mrtc0/bouheki/pkg/config"
	"github.com/stretchr/testify/assert"
)

func Test_SetConfigMap(t *testing.T) {
	tests := []struct {
		name              string
		deniedSourcePaths []string
		expected          []byte
	}{
		{
			name:              "test",
			deniedSourcePaths: []string{"/var/run/docker.sock"},
			expected:          []byte{0x2f, 0x76, 0x61, 0x72, 0x2f, 0x72, 0x75, 0x6e, 0x2f, 0x64, 0x6f, 0x63, 0x6b, 0x65, 0x72, 0x2e, 0x73, 0x6f, 0x63, 0x6b},
		},
	}

	config := config.DefaultConfig()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config.RestrictedMountConfig.DenySourcePath = test.deniedSourcePaths
			mgr := createManager(config)
			defer mgr.mod.Close()

			deniedMap, err := mgr.mod.GetMap(MOUNT_DENIED_SOURCE_LIST)
			if err != nil {
				t.Fatalf("Failed open eBPF map for %s, err: %s", MOUNT_DENIED_SOURCE_LIST, err)
			}

			key := uint8(0)
			actual, err := deniedMap.GetValue(unsafe.Pointer(&key))
			if err != nil {
				t.Fatalf("Failed to get value from eBPF map %s, err: %s", MOUNT_DENIED_SOURCE_LIST, err)
			}

			padding := bytes.Repeat([]byte{0x00}, PATH_MAX-len(test.expected))
			expected := append(test.expected, padding...)
			assert.Equal(t, expected, actual)
		})
	}
}

func createManager(conf *config.Config) Manager {
	mod, err := setupBPFProgram()
	if err != nil {
		panic(err)
	}

	mgr := Manager{
		mod:    mod,
		config: conf,
	}

	err = mgr.SetConfigToMap()
	if err != nil {
		panic(err)
	}

	return mgr
}
