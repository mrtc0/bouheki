package fileaccess

import (
	"bytes"
	"testing"

	"github.com/mrtc0/bouheki/pkg/config"
	"github.com/stretchr/testify/assert"
)

func Test_Start(t *testing.T) {
	t.Run("expect to be initialize perf buffer", func(t *testing.T) {
		config := config.DefaultConfig()
		mgr := createManager(config)

		eventChannel := make(chan []byte)
		actual := mgr.Start(eventChannel)
		assert.Equal(t, nil, actual)
	})
}

func Test_Attach(t *testing.T) {
	t.Run("expect to be attach BPF Program", func(t *testing.T) {
		config := config.DefaultConfig()
		mgr := createManager(config)

		actual := mgr.Attach()
		assert.Equal(t, nil, actual)
	})
}

func Test_SetConfigMap_AllowedFiles(t *testing.T) {
	tests := []struct {
		name         string
		allowedFiles []string
		deniedFiles  []string
		expected     []byte
	}{
		{
			name:         "test",
			allowedFiles: []string{"/"},
			deniedFiles:  []string{"/etc/passwd"},
			expected:     []byte{0x2f},
		},
	}

	config := config.DefaultConfig()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config.RestrictedFileAccess.Allow = test.allowedFiles
			config.RestrictedFileAccess.Deny = test.deniedFiles
			mgr := createManager(config)

			err := mgr.SetConfigToMap()
			assert.Equal(t, nil, err)

			map_allowed_files, err := mgr.mod.GetMap(ALLOWED_FILES_MAP_NAME)
			if err != nil {
				t.Fatalf("Failed open eBPF map for %s, err: %s", ALLOWED_FILES_MAP_NAME, err)
			}

			actual, err := map_allowed_files.GetValue(uint8(0), PATH_MAX)
			if err != nil {
				t.Fatalf("Faild to get value from eBPF map %s, err: %s", ALLOWED_FILES_MAP_NAME, err)
			}

			padding := bytes.Repeat([]byte{0x00}, PATH_MAX-len(test.allowedFiles))
			expected := append(test.expected, padding...)
			assert.Equal(t, expected, actual)
		})
	}
}

func Test_SetConfigMap_DeniedFiles(t *testing.T) {
	tests := []struct {
		name         string
		allowedFiles []string
		deniedFiles  []string
		expected     []byte
	}{
		{
			name:         "test",
			allowedFiles: []string{"/"},
			deniedFiles:  []string{"/etc/passwd"},
			expected:     []byte{0x2f, 0x65, 0x74, 0x63, 0x2f, 0x70, 0x61, 0x73, 0x73, 0x77, 0x64},
		},
	}

	config := config.DefaultConfig()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config.RestrictedFileAccess.Allow = test.allowedFiles
			config.RestrictedFileAccess.Deny = test.deniedFiles
			mgr := createManager(config)

			err := mgr.SetConfigToMap()
			assert.Equal(t, nil, err)

			map_denied_files, err := mgr.mod.GetMap(DENIED_FILES_MAP_NAME)
			if err != nil {
				t.Fatalf("Failed open eBPF map for %s, err: %s", DENIED_FILES_MAP_NAME, err)
			}

			actual, err := map_denied_files.GetValue(uint8(0), PATH_MAX)
			if err != nil {
				t.Fatalf("Faild to get value from eBPF map %s, err: %s", DENIED_FILES_MAP_NAME, err)
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

	return mgr
}
