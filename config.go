package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	defaultDBName  = "db.asc"
	configFileName = "config"
	configDir      = ".config/arruin"
)

type Config struct {
	Recipients []string // GPG key IDs or fingerprints
	DBPath     string   // path to encrypted secrets file
}

func configPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("could not determine home directory: %w", err)
	}
	return filepath.Join(home, configDir, configFileName), nil
}

// LoadConfig reads ~/.config/arruin/config. Missing file is not an error.
func LoadConfig() (*Config, error) {
	path, err := configPath()
	if err != nil {
		return nil, err
	}

	cfg := &Config{}

	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return cfg, nil
	}
	if err != nil {
		return nil, fmt.Errorf("opening config: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch key {
		case "recipient":
			cfg.Recipients = append(cfg.Recipients, value)
		case "db":
			cfg.DBPath = value
		}
	}
	return cfg, scanner.Err()
}

// SaveConfig writes the config to ~/.config/arruin/config.
func SaveConfig(cfg *Config) error {
	path, err := configPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("creating config dir: %w", err)
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("writing config: %w", err)
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for _, r := range cfg.Recipients {
		fmt.Fprintf(w, "recipient = %s\n", r)
	}
	if cfg.DBPath != "" {
		fmt.Fprintf(w, "db = %s\n", cfg.DBPath)
	}
	return w.Flush()
}

// DBPath returns the resolved path to the encrypted secrets file, preferring
// an explicit flag value, then config, then defaulting to ./db.asc.
func (c *Config) ResolvedDBPath(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if c.DBPath != "" {
		return c.DBPath
	}
	return defaultDBName
}
