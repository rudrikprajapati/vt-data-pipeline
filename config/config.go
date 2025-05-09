package config

import (
	"errors"
	"os"
)

type Config struct {
	Database struct {
		URL string
	}
	Server struct {
		Port string
	}
	VirusTotal struct {
		APIKey string
	}
}

func LoadConfig() (*Config, error) {
	cfg := &Config{}

	if dbURL := os.Getenv("DB_URL"); dbURL != "" {
		cfg.Database.URL = dbURL
	} else {
		return nil, errors.New("DB_URL is not set")
	}

	if port := os.Getenv("PORT"); port != "" {
		cfg.Server.Port = port
	} else {
		// default port
		cfg.Server.Port = "8080"
	}

	if apiKey := os.Getenv("VT_API_KEY"); apiKey != "" {
		cfg.VirusTotal.APIKey = apiKey
	} else {
		return nil, errors.New("VT_API_KEY is not set")
	}

	return cfg, nil
}

func GetVTAPIKey() string {
	return os.Getenv("VT_API_KEY")
}
