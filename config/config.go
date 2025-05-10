package config

import (
	"errors"
	"os"

	"github.com/joho/godotenv"
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
	Redis struct {
		URL      string
		Password string
	}
}

func LoadConfig() (*Config, error) {
	if err := godotenv.Load(); err != nil {
		return nil, errors.New("Error loading .env file: " + err.Error())
	}

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

	// Redis configuration
	if redisURL := os.Getenv("REDIS_URL"); redisURL != "" {
		cfg.Redis.URL = redisURL
	} else {
		return nil, errors.New("REDIS_URL is not set")
	}

	cfg.Redis.Password = os.Getenv("REDIS_PASSWORD")

	return cfg, nil
}
