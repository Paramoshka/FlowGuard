package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Allow          []string         `yaml:"allow"`
	Deny           []string         `yaml:"deny"`
	Forwarding     []ForwardingRule `yaml:"forwarding"`
	DDoSProtection DDoSConfig       `yaml:"ddos_protection"`
	Interface      string           `yaml:"iface"`
}

type ForwardingRule struct {
	SourceIP        string `yaml:"source_ip"`
	DestinationPort string `yaml:"destiantion_port"`
	ForwardIP       string `yaml:"forward_ip"`
	ForwardPort     string `yaml:"forward_port"`
}

type DDoSConfig struct {
	MaxRequestsPerSecond int `yaml:"max_requests_per_second"`
}

func LoadConfig(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	cfg := new(Config)
	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}
