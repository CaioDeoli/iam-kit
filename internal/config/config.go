package config

import (
	"log"
	"os"
	"strconv"
)

type Config struct {
	AppEnv       string
	AppPort      string
	DBHost       string
	DBPort       string
	DBUser       string
	DBPass       string
	DBName       string
	JWTSecret    string
	AccessTTLMin int
	RefreshTTLH  int
}

func mustAtoi(env string, fallback int) int {
	if v := os.Getenv(env); v != "" {
		i, err := strconv.Atoi(v)
		if err != nil {
			log.Fatalf("invalid %s: %v, env, err")
		}
		return i
	}
	return fallback
}

func FromEnv() *Config {
	return &Config{
		AppEnv:       get("APP_ENV", "dev"),
		AppPort:      get("APP_PORT", "8080"),
		DBHost:       get("DB_HOST", "127.0.0.1"),
		DBPort:       get("DB_PORT", "3306"),
		DBUser:       get("DB_USER", "root"),
		DBPass:       get("DB_PASS", ""),
		DBName:       get("DB_NAME", "iamkit"),
		JWTSecret:    get("JWT_SECRET", "super-secret-change-me"),
		AccessTTLMin: mustAtoi("JWT_ACCESS_TTL_MIN", 15),
		RefreshTTLH:  mustAtoi("JWT_REFRESH_TTL_H", 720),
	}
}

func get(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
