package config

import (
	"os"

	"gopkg.in/yaml.v2"
)

type Config struct {
	Network struct {
		Mode           string   `yaml:"mode"`
		Target         string   `yaml:"target"`
		AllowedCommand []string `yaml:"allowed_command"`
		Allow          []string `yaml:"allow"`
		Deny           []string `yaml:"deny"`
	}
}

func NewConfig(configPath string) (*Config, error) {
	file, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	d := yaml.NewDecoder(file)

	config := &Config{}
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
