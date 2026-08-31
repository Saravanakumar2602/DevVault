package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const (
	DirName           = ".devvault"
	DBFileName        = "devvault.db"
	ConfigFileName    = "config.json"
	LocalProjectFile  = ".devvault.json"
	DefaultProfile    = "default"
	DefaultFileMode   = 0600
	DefaultDirMode    = 0700
)

// AppConfig represents global user options stored in ~/.devvault/config.json.
type AppConfig struct {
	ActiveProfile string `json:"active_profile"`
	DBPath        string `json:"db_path,omitempty"`
}

// LocalProjectConfig represents directory-level project configuration in .devvault.json.
type LocalProjectConfig struct {
	Profile string `json:"profile"`
}

// GetDevVaultDir returns the absolute path to ~/.devvault directory.
func GetDevVaultDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("unable to locate user home directory: %w", err)
	}
	dir := filepath.Join(home, DirName)
	if err := os.MkdirAll(dir, DefaultDirMode); err != nil {
		return "", fmt.Errorf("failed to create devvault configuration directory: %w", err)
	}
	return dir, nil
}

// GetDBPath returns the full path to the SQLite database file.
func GetDBPath() (string, error) {
	dir, err := GetDevVaultDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, DBFileName), nil
}

// GetConfigPath returns the full path to config.json.
func GetConfigPath() (string, error) {
	dir, err := GetDevVaultDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, ConfigFileName), nil
}

// LoadConfig reads the global app configuration.
func LoadConfig() (*AppConfig, error) {
	configPath, err := GetConfigPath()
	if err != nil {
		return nil, err
	}

	cfg := &AppConfig{
		ActiveProfile: DefaultProfile,
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return cfg, nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read configuration file: %w", err)
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		return cfg, nil // Fallback to defaults on parse error
	}

	if cfg.ActiveProfile == "" {
		cfg.ActiveProfile = DefaultProfile
	}

	return cfg, nil
}

// SaveConfig writes the global app configuration.
func SaveConfig(cfg *AppConfig) error {
	configPath, err := GetConfigPath()
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode configuration: %w", err)
	}

	return os.WriteFile(configPath, data, DefaultFileMode)
}

// ResolveActiveProfile determines the active profile based on CLI flag, local directory file, global config, or default.
func ResolveActiveProfile(cliFlag string) string {
	if cliFlag != "" {
		return cliFlag
	}

	// Check local project file (.devvault.json in CWD)
	if cwd, err := os.Getwd(); err == nil {
		localPath := filepath.Join(cwd, LocalProjectFile)
		if data, err := os.ReadFile(localPath); err == nil {
			var localCfg LocalProjectConfig
			if err := json.Unmarshal(data, &localCfg); err == nil && localCfg.Profile != "" {
				return localCfg.Profile
			}
		}
	}

	// Check global config
	cfg, err := LoadConfig()
	if err == nil && cfg.ActiveProfile != "" {
		return cfg.ActiveProfile
	}

	return DefaultProfile
}
