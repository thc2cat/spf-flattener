package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config holds the application configuration loaded from a YAML file.
type Config struct {
	// ConcurrencyLimit for parallel DNS lookups.
	ConcurrencyLimit int `yaml:"concurrencyLimit"`
	// MaxLookups is an optional limit for DNS lookups, typically 10 for SPF.
	MaxLookups int `yaml:"maxLookups"`
	// PriorityEntries contains a list of domains or CIDRs that should be prioritized.
	PriorityEntries []string `yaml:"priorityEntries"`
	// TargetDomain is the domain that we are targeting for the lookups.
	TargetDomain string `yaml:"targetDomain"`
}

// LoadConfig reads and unmarshals the configuration from the specified YAML file path.
func LoadConfig(filePath string) (*Config, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		// Log the error if the file cannot be read (e.g., does not exist or permission denied)
		return nil, fmt.Errorf("failed to read config file %s: %w", filePath, err)
	}

	var cfg Config
	err = yaml.Unmarshal(data, &cfg)
	if err != nil {
		// Log the error if the YAML content is invalid
		return nil, fmt.Errorf("failed to unmarshal config file %s: %w", filePath, err)
	}

	// Apply sensible defaults if values are missing or invalid
	if cfg.MaxLookups == 0 {
		cfg.MaxLookups = 10 // Default SPF lookup limit
	}
	if cfg.ConcurrencyLimit == 0 {
		cfg.ConcurrencyLimit = 4 // Default concurrency limit
	}

	return &cfg, nil
}
