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
	Domain  DomainConfig  `yaml:"domain"`
	UID     UIDConfig     `yaml:"uid"`
	GID     GIDConfig     `yaml:"gid"`
}

type RestrictedFileAccess struct {
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
}

type DomainConfig struct {
	Allow    []string `yaml:"allow"`
	Deny     []string `yaml:"deny"`
	Interval uint     `yaml:"interval"`
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

type GIDConfig struct {
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
	Network              NetworkConfig
	RestrictedFileAccess `yaml:"files"`
	Log                  LogConfig
}

func DefaultConfig() *Config {
	return &Config{
		Network: NetworkConfig{
			Mode:    "monitor",
			Target:  "host",
			Command: CommandConfig{Allow: []string{}, Deny: []string{}},
			CIDR:    CIDRConfig{Allow: []string{"0.0.0.0/0", "::/0"}, Deny: []string{}},
			Domain:  DomainConfig{Allow: []string{}, Deny: []string{}, Interval: 5},
			UID:     UIDConfig{Allow: []uint{}, Deny: []uint{}},
			GID:     GIDConfig{Allow: []uint{}, Deny: []uint{}},
		},
		RestrictedFileAccess: RestrictedFileAccess{
			Allow: []string{"/"},
			Deny:  []string{},
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

	config := DefaultConfig()
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
