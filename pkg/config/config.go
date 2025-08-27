package config

import (
	"os"
	"strconv"
	"time"
	
	"github.com/sirupsen/logrus"
)

// Config holds application configuration
type Config struct {
	Server    ServerConfig    `json:"server"`
	Database  DatabaseConfig  `json:"database"`
	APIs      APIConfig       `json:"apis"`
	Cache     CacheConfig     `json:"cache"`
	Logging   LoggingConfig   `json:"logging"`
	Security  SecurityConfig  `json:"security"`
	Analysis  AnalysisConfig  `json:"analysis"`
}

// ServerConfig holds server configuration
type ServerConfig struct {
	Host         string        `json:"host"`
	Port         int           `json:"port"`
	ReadTimeout  time.Duration `json:"read_timeout"`
	WriteTimeout time.Duration `json:"write_timeout"`
	IdleTimeout  time.Duration `json:"idle_timeout"`
	EnableCORS   bool          `json:"enable_cors"`
	EnableTLS    bool          `json:"enable_tls"`
	TLSCertFile  string        `json:"tls_cert_file"`
	TLSKeyFile   string        `json:"tls_key_file"`
}

// DatabaseConfig holds database configuration
type DatabaseConfig struct {
	Type         string        `json:"type"`
	Host         string        `json:"host"`
	Port         int           `json:"port"`
	Database     string        `json:"database"`
	Username     string        `json:"username"`
	Password     string        `json:"password"`
	SSLMode      string        `json:"ssl_mode"`
	MaxOpenConns int           `json:"max_open_conns"`
	MaxIdleConns int           `json:"max_idle_conns"`
	ConnMaxLifetime time.Duration `json:"conn_max_lifetime"`
}

// APIConfig holds external API configuration
type APIConfig struct {
	SimilarWebAPIKey   string        `json:"similarweb_api_key"`
	LinkedInAPIKey     string        `json:"linkedin_api_key"`
	CrunchbaseAPIKey   string        `json:"crunchbase_api_key"`
	TwitterAPIKey      string        `json:"twitter_api_key"`
	TwitterAPISecret   string        `json:"twitter_api_secret"`
	InstagramAPIKey    string        `json:"instagram_api_key"`
	DefaultTimeout     time.Duration `json:"default_timeout"`
	MaxRetries         int           `json:"max_retries"`
	RetryDelay         time.Duration `json:"retry_delay"`
}

// CacheConfig holds cache configuration
type CacheConfig struct {
	Type       string        `json:"type"`
	Host       string        `json:"host"`
	Port       int           `json:"port"`
	Password   string        `json:"password"`
	Database   int           `json:"database"`
	TTL        time.Duration `json:"ttl"`
	MaxRetries int           `json:"max_retries"`
}

// LoggingConfig holds logging configuration
type LoggingConfig struct {
	Level      string `json:"level"`
	Format     string `json:"format"`
	Output     string `json:"output"`
	Filename   string `json:"filename"`
	MaxSize    int    `json:"max_size"`
	MaxAge     int    `json:"max_age"`
	MaxBackups int    `json:"max_backups"`
	Compress   bool   `json:"compress"`
}

// SecurityConfig holds security configuration
type SecurityConfig struct {
	EnableRateLimit    bool          `json:"enable_rate_limit"`
	RateLimit          int           `json:"rate_limit"`
	RateLimitWindow    time.Duration `json:"rate_limit_window"`
	EnableAPIKey       bool          `json:"enable_api_key"`
	APIKeys            []string      `json:"api_keys"`
	EnableJWT          bool          `json:"enable_jwt"`
	JWTSecret          string        `json:"jwt_secret"`
	JWTExpiry          time.Duration `json:"jwt_expiry"`
	TrustedProxies     []string      `json:"trusted_proxies"`
}

// AnalysisConfig holds analysis configuration
type AnalysisConfig struct {
	MaxConcurrentAnalyses int           `json:"max_concurrent_analyses"`
	AnalysisTimeout       time.Duration `json:"analysis_timeout"`
	RetryAttempts         int           `json:"retry_attempts"`
	EnableCaching         bool          `json:"enable_caching"`
	CacheTTL              time.Duration `json:"cache_ttl"`
	UserAgent             string        `json:"user_agent"`
	MaxPageSize           int64         `json:"max_page_size"`
	FollowRedirects       bool          `json:"follow_redirects"`
	MaxRedirects          int           `json:"max_redirects"`
}

// New creates a new configuration with default values
func New() *Config {
	return &Config{
		Server: ServerConfig{
			Host:         getEnv("SERVER_HOST", "0.0.0.0"),
			Port:         getEnvInt("SERVER_PORT", 8080),
			ReadTimeout:  getEnvDuration("SERVER_READ_TIMEOUT", 30*time.Second),
			WriteTimeout: getEnvDuration("SERVER_WRITE_TIMEOUT", 30*time.Second),
			IdleTimeout:  getEnvDuration("SERVER_IDLE_TIMEOUT", 60*time.Second),
			EnableCORS:   getEnvBool("ENABLE_CORS", true),
			EnableTLS:    getEnvBool("ENABLE_TLS", false),
			TLSCertFile:  getEnv("TLS_CERT_FILE", ""),
			TLSKeyFile:   getEnv("TLS_KEY_FILE", ""),
		},
		Database: DatabaseConfig{
			Type:            getEnv("DB_TYPE", "postgres"),
			Host:            getEnv("DB_HOST", "localhost"),
			Port:            getEnvInt("DB_PORT", 5432),
			Database:        getEnv("DB_NAME", "rival_analysis"),
			Username:        getEnv("DB_USER", "postgres"),
			Password:        getEnv("DB_PASSWORD", ""),
			SSLMode:         getEnv("DB_SSL_MODE", "disable"),
			MaxOpenConns:    getEnvInt("DB_MAX_OPEN_CONNS", 25),
			MaxIdleConns:    getEnvInt("DB_MAX_IDLE_CONNS", 5),
			ConnMaxLifetime: getEnvDuration("DB_CONN_MAX_LIFETIME", 5*time.Minute),
		},
		APIs: APIConfig{
			SimilarWebAPIKey: getEnv("SIMILARWEB_API_KEY", ""),
			LinkedInAPIKey:   getEnv("LINKEDIN_API_KEY", ""),
			CrunchbaseAPIKey: getEnv("CRUNCHBASE_API_KEY", ""),
			TwitterAPIKey:    getEnv("TWITTER_API_KEY", ""),
			TwitterAPISecret: getEnv("TWITTER_API_SECRET", ""),
			InstagramAPIKey:  getEnv("INSTAGRAM_API_KEY", ""),
			DefaultTimeout:   getEnvDuration("API_DEFAULT_TIMEOUT", 30*time.Second),
			MaxRetries:       getEnvInt("API_MAX_RETRIES", 3),
			RetryDelay:       getEnvDuration("API_RETRY_DELAY", 1*time.Second),
		},
		Cache: CacheConfig{
			Type:       getEnv("CACHE_TYPE", "memory"),
			Host:       getEnv("CACHE_HOST", "localhost"),
			Port:       getEnvInt("CACHE_PORT", 6379),
			Password:   getEnv("CACHE_PASSWORD", ""),
			Database:   getEnvInt("CACHE_DATABASE", 0),
			TTL:        getEnvDuration("CACHE_TTL", 1*time.Hour),
			MaxRetries: getEnvInt("CACHE_MAX_RETRIES", 3),
		},
		Logging: LoggingConfig{
			Level:      getEnv("LOG_LEVEL", "info"),
			Format:     getEnv("LOG_FORMAT", "json"),
			Output:     getEnv("LOG_OUTPUT", "stdout"),
			Filename:   getEnv("LOG_FILENAME", "app.log"),
			MaxSize:    getEnvInt("LOG_MAX_SIZE", 100),
			MaxAge:     getEnvInt("LOG_MAX_AGE", 28),
			MaxBackups: getEnvInt("LOG_MAX_BACKUPS", 3),
			Compress:   getEnvBool("LOG_COMPRESS", true),
		},
		Security: SecurityConfig{
			EnableRateLimit: getEnvBool("ENABLE_RATE_LIMIT", true),
			RateLimit:       getEnvInt("RATE_LIMIT", 100),
			RateLimitWindow: getEnvDuration("RATE_LIMIT_WINDOW", 1*time.Minute),
			EnableAPIKey:    getEnvBool("ENABLE_API_KEY", false),
			APIKeys:         getEnvSlice("API_KEYS", []string{}),
			EnableJWT:       getEnvBool("ENABLE_JWT", false),
			JWTSecret:       getEnv("JWT_SECRET", ""),
			JWTExpiry:       getEnvDuration("JWT_EXPIRY", 24*time.Hour),
			TrustedProxies:  getEnvSlice("TRUSTED_PROXIES", []string{}),
		},
		Analysis: AnalysisConfig{
			MaxConcurrentAnalyses: getEnvInt("MAX_CONCURRENT_ANALYSES", 10),
			AnalysisTimeout:       getEnvDuration("ANALYSIS_TIMEOUT", 5*time.Minute),
			RetryAttempts:         getEnvInt("RETRY_ATTEMPTS", 3),
			EnableCaching:         getEnvBool("ENABLE_ANALYSIS_CACHING", true),
			CacheTTL:              getEnvDuration("ANALYSIS_CACHE_TTL", 30*time.Minute),
			UserAgent:             getEnv("USER_AGENT", "Golang-Rival-Analysis/1.0"),
			MaxPageSize:           getEnvInt64("MAX_PAGE_SIZE", 10*1024*1024), // 10MB
			FollowRedirects:       getEnvBool("FOLLOW_REDIRECTS", true),
			MaxRedirects:          getEnvInt("MAX_REDIRECTS", 10),
		},
	}
}

// GetString returns string value for key
func (c *Config) GetString(key string) string {
	switch key {
	case "server.host":
		return c.Server.Host
	case "database.host":
		return c.Database.Host
	case "cache.host":
		return c.Cache.Host
	case "logging.level":
		return c.Logging.Level
	default:
		return ""
	}
}

// GetInt returns int value for key
func (c *Config) GetInt(key string) int {
	switch key {
	case "server.port":
		return c.Server.Port
	case "database.port":
		return c.Database.Port
	case "cache.port":
		return c.Cache.Port
	default:
		return 0
	}
}

// GetBool returns bool value for key
func (c *Config) GetBool(key string) bool {
	switch key {
	case "server.enable_cors":
		return c.Server.EnableCORS
	case "server.enable_tls":
		return c.Server.EnableTLS
	case "analysis.enable_caching":
		return c.Analysis.EnableCaching
	default:
		return false
	}
}

// GetDuration returns duration value for key
func (c *Config) GetDuration(key string) time.Duration {
	switch key {
	case "server.read_timeout":
		return c.Server.ReadTimeout
	case "server.write_timeout":
		return c.Server.WriteTimeout
	case "analysis.timeout":
		return c.Analysis.AnalysisTimeout
	default:
		return 0
	}
}

// GetAPIKey returns API key for service
func (c *Config) GetAPIKey(service string) string {
	switch service {
	case "similarweb":
		return c.APIs.SimilarWebAPIKey
	case "linkedin":
		return c.APIs.LinkedInAPIKey
	case "crunchbase":
		return c.APIs.CrunchbaseAPIKey
	case "twitter":
		return c.APIs.TwitterAPIKey
	case "instagram":
		return c.APIs.InstagramAPIKey
	default:
		return ""
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Server.Port <= 0 || c.Server.Port > 65535 {
		return ErrInvalidPort
	}
	
	if c.Analysis.MaxConcurrentAnalyses <= 0 {
		return ErrInvalidConcurrency
	}
	
	return nil
}

// Helper functions for environment variables
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
		logrus.WithField("key", key).WithField("value", value).Warn("Invalid integer value, using default")
	}
	return defaultValue
}

func getEnvInt64(key string, defaultValue int64) int64 {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.ParseInt(value, 10, 64); err == nil {
			return intValue
		}
		logrus.WithField("key", key).WithField("value", value).Warn("Invalid int64 value, using default")
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
		logrus.WithField("key", key).WithField("value", value).Warn("Invalid boolean value, using default")
	}
	return defaultValue
}

func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
		logrus.WithField("key", key).WithField("value", value).Warn("Invalid duration value, using default")
	}
	return defaultValue
}

func getEnvSlice(key string, defaultValue []string) []string {
	// For simplicity, returning default value
	// In a real implementation, you might parse comma-separated values
	return defaultValue
}

// Error definitions
var (
	ErrInvalidPort        = NewConfigError("invalid server port")
	ErrInvalidConcurrency = NewConfigError("invalid concurrency setting")
)

// ConfigError represents a configuration error
type ConfigError struct {
	Message string
}

func (e *ConfigError) Error() string {
	return e.Message
}

// NewConfigError creates a new configuration error
func NewConfigError(message string) *ConfigError {
	return &ConfigError{Message: message}
}