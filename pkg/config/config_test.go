package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsOnlyContainer(t *testing.T) {
	config := DefaultConfig()

	t.Run("For network", func(t *testing.T) {
		t.Run("When target is container, should be return true", func(t *testing.T) {
			config.Network.Target = "container"
			assert.Equal(t, config.IsOnlyContainer("network"), true)
		})

		t.Run("When target is host, should be return false", func(t *testing.T) {
			config.Network.Target = "host"
			assert.Equal(t, config.IsOnlyContainer("network"), false)
		})
	})

	t.Run("For fileaccess", func(t *testing.T) {
		t.Run("When target is container, should be return true", func(t *testing.T) {
			config.RestrictedFileAccess.Target = "container"
			assert.Equal(t, config.IsOnlyContainer("fileaccess"), true)
		})

		t.Run("When target is host, should be return false", func(t *testing.T) {
			config.RestrictedFileAccess.Target = "host"
			assert.Equal(t, config.IsOnlyContainer("fileaccess"), false)
		})
	})
}
func TestIsRestrictedMode(t *testing.T) {
	config := DefaultConfig()

	t.Run("For network", func(t *testing.T) {
		t.Run("When mode is block, should be return true", func(t *testing.T) {
			config.Network.Mode = "block"
			assert.Equal(t, config.IsRestrictedMode("network"), true)
		})

		t.Run("When mode is monitor, should be return false", func(t *testing.T) {
			config.Network.Mode = "monitor"
			assert.Equal(t, config.IsRestrictedMode("network"), false)
		})
	})

	t.Run("For fileaccess", func(t *testing.T) {
		t.Run("When mode is block, should be return true", func(t *testing.T) {
			config.RestrictedFileAccess.Mode = "block"
			assert.Equal(t, config.IsRestrictedMode("fileaccess"), true)
		})

		t.Run("When mode is monitor, should be return false", func(t *testing.T) {
			config.RestrictedFileAccess.Mode = "monitor"
			assert.Equal(t, config.IsRestrictedMode("fileaccess"), false)
		})
	})
}
