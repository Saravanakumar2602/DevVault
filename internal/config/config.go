package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const (
	AppName          = "devvault"
	DBFileName       = "devvault.db"
	ConfigFileName   = "config.json"
	LocalProjectFile = ".devvault.json"
	DefaultProfile   = "default"
	DefaultFileMode  = 0600
	DefaultDirMode   = 0700
)

// AppConfig represents global user configuration settings.
type AppConfig struct {
	ActiveProfile string `json:"active_profile"`
	DBPath        string `json:"db_path,omitempty"`
}

// LocalProjectConfig represents directory-level project configuration in .devvault.json.
type LocalProjectConfig struct {
	Profile string `json:"profile"`
}

// GetConfigDir returns the OS-specific user config/data directory.
// On Windows: %APPDATA%\devvault
// On macOS: ~/Library/Application Support/devvault
// On Linux/Unix: ~/.config/devvault (or $XDG_CONFIG_HOME/devvault)
func GetConfigDir() (string, error) {
	baseDir, err := os.UserConfigDir()
	if err != nil {
		home, homeErr := os.UserHomeDir()
		if homeErr != nil {
			return "", fmt.Errorf("unable to determine user configuration directory: %w", err)
		}
		baseDir = filepath.Join(home, ".config")
	}

	appDir := filepath.Join(baseDir, AppName)
	if err := os.MkdirAll(appDir, DefaultDirMode); err != nil {
		return "", fmt.Errorf("failed to create config directory '%s': %w", appDir, err)
	}

	return appDir, nil
}

// GetDBPath returns the full path to the SQLite database file.
func GetDBPath() (string, error) {
	dir, err := GetConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, DBFileName), nil
}

// GetConfigPath returns the full path to config.json.
func GetConfigPath() (string, error) {
	dir, err := GetConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, ConfigFileName), nil
}

// LoadConfig reads the global application configuration.
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
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		return cfg, nil // Fallback to default if invalid JSON
	}

	if cfg.ActiveProfile == "" {
		cfg.ActiveProfile = DefaultProfile
	}

	return cfg, nil
}

// SaveConfig writes the global application configuration.
func SaveConfig(cfg *AppConfig) error {
	configPath, err := GetConfigPath()
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
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
