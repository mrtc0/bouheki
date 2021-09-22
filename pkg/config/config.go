package config

import (
	"os"

	"gopkg.in/yaml.v2"
)

type NetworkConfig struct {
	Mode    string        `yaml:"mode"`
	Target  string        `yaml:"target"`
	Command CommandConfig `yaml:"command"`
	CIDR    CIDRConfig    `yaml:"cidr"`
	UID     UIDConfig     `yaml:"uid"`
}

type CIDRConfig struct {
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
}

type CommandConfig struct {
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
}

type UIDConfig struct {
	Allow []uint `yaml:"allow"`
	Deny  []uint `yaml:"deny"`
}

type LogConfig struct {
	Format  string `yaml:"format"`
	Output  string `yaml:"output"`
	MaxSize int    `yaml:"max_size"`
	MaxAge  int    `yaml:"max_age"`
}

type Config struct {
	Network NetworkConfig
	Log     LogConfig
}

func defaultConfig() *Config {
	return &Config{
		Network: NetworkConfig{
			Mode:    "monitor",
			Target:  "host",
			Command: CommandConfig{Allow: []string{}, Deny: []string{}},
			CIDR:    CIDRConfig{Allow: []string{"0.0.0.0/0"}, Deny: []string{}},
			UID:     UIDConfig{Allow: []uint{}, Deny: []uint{}},
		},
		Log: LogConfig{
			Format: "json",
			Output: "stdout",
		},
	}
}

func NewConfig(configPath string) (*Config, error) {
	file, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	d := yaml.NewDecoder(file)

	config := defaultConfig()
	if err := d.Decode(&config); err != nil {
		return nil, err
	}

	return config, nil
}

func (c *Config) IsRestricted() bool {
	if c.Network.Mode == "block" {
		return true
	} else {
		return false
	}
}

func (c *Config) IsOnlyContainer() bool {
	if c.Network.Target == "container" {
		return true
	} else {
		return false
	}
}
