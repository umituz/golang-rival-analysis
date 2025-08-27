package logger

import (
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

// Logger wraps logrus.Logger to implement our domain interface
type Logger struct {
	*logrus.Logger
}

// Config holds logger configuration
type Config struct {
	Level      string
	Format     string
	Output     string
	Filename   string
	MaxSize    int
	MaxAge     int
	MaxBackups int
	Compress   bool
}

// New creates a new logger instance
func New(config Config) *Logger {
	logger := logrus.New()

	// Set log level
	level, err := logrus.ParseLevel(config.Level)
	if err != nil {
		level = logrus.InfoLevel
	}
	logger.SetLevel(level)

	// Set formatter
	switch config.Format {
	case "json":
		logger.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: time.RFC3339,
		})
	case "text":
		logger.SetFormatter(&logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: time.RFC3339,
		})
	default:
		logger.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: time.RFC3339,
		})
	}

	// Set output
	var output io.Writer
	switch config.Output {
	case "file":
		if config.Filename == "" {
			config.Filename = "app.log"
		}
		
		// Ensure log directory exists
		logDir := filepath.Dir(config.Filename)
		if err := os.MkdirAll(logDir, 0755); err != nil {
			logger.WithError(err).Error("Failed to create log directory")
			output = os.Stdout
		} else {
			output = &lumberjack.Logger{
				Filename:   config.Filename,
				MaxSize:    config.MaxSize,
				MaxAge:     config.MaxAge,
				MaxBackups: config.MaxBackups,
				Compress:   config.Compress,
				LocalTime:  true,
			}
		}
	case "both":
		if config.Filename == "" {
			config.Filename = "app.log"
		}
		
		logDir := filepath.Dir(config.Filename)
		if err := os.MkdirAll(logDir, 0755); err != nil {
			logger.WithError(err).Error("Failed to create log directory")
			output = os.Stdout
		} else {
			fileOutput := &lumberjack.Logger{
				Filename:   config.Filename,
				MaxSize:    config.MaxSize,
				MaxAge:     config.MaxAge,
				MaxBackups: config.MaxBackups,
				Compress:   config.Compress,
				LocalTime:  true,
			}
			output = io.MultiWriter(os.Stdout, fileOutput)
		}
	default:
		output = os.Stdout
	}

	logger.SetOutput(output)

	return &Logger{Logger: logger}
}

// Info logs an info message with optional fields
func (l *Logger) Info(msg string, fields ...interface{}) {
	entry := l.Logger.WithFields(l.parseFields(fields...))
	entry.Info(msg)
}

// Error logs an error message with optional fields
func (l *Logger) Error(msg string, err error, fields ...interface{}) {
	entry := l.Logger.WithError(err).WithFields(l.parseFields(fields...))
	entry.Error(msg)
}

// Warn logs a warning message with optional fields
func (l *Logger) Warn(msg string, fields ...interface{}) {
	entry := l.Logger.WithFields(l.parseFields(fields...))
	entry.Warn(msg)
}

// Debug logs a debug message with optional fields
func (l *Logger) Debug(msg string, fields ...interface{}) {
	entry := l.Logger.WithFields(l.parseFields(fields...))
	entry.Debug(msg)
}

// Fatal logs a fatal message and exits
func (l *Logger) Fatal(msg string, err error, fields ...interface{}) {
	entry := l.Logger.WithError(err).WithFields(l.parseFields(fields...))
	entry.Fatal(msg)
}

// WithField creates a new entry with a single field
func (l *Logger) WithField(key string, value interface{}) *logrus.Entry {
	return l.Logger.WithField(key, value)
}

// WithFields creates a new entry with multiple fields
func (l *Logger) WithFields(fields logrus.Fields) *logrus.Entry {
	return l.Logger.WithFields(fields)
}

// WithError creates a new entry with an error
func (l *Logger) WithError(err error) *logrus.Entry {
	return l.Logger.WithError(err)
}

// WithContext creates a new entry with request context information
func (l *Logger) WithContext(requestID, userID, method, path string) *logrus.Entry {
	return l.Logger.WithFields(logrus.Fields{
		"request_id": requestID,
		"user_id":    userID,
		"method":     method,
		"path":       path,
	})
}

// WithAnalysis creates a new entry with analysis context
func (l *Logger) WithAnalysis(analysisID, domain, analysisType string) *logrus.Entry {
	return l.Logger.WithFields(logrus.Fields{
		"analysis_id":   analysisID,
		"domain":        domain,
		"analysis_type": analysisType,
	})
}

// WithDuration creates a new entry with duration information
func (l *Logger) WithDuration(duration time.Duration) *logrus.Entry {
	return l.Logger.WithField("duration", duration.String())
}

// LogAnalysisStart logs the start of an analysis
func (l *Logger) LogAnalysisStart(analysisID, domain, analysisType string) {
	l.WithAnalysis(analysisID, domain, analysisType).Info("Analysis started")
}

// LogAnalysisComplete logs the completion of an analysis
func (l *Logger) LogAnalysisComplete(analysisID, domain, analysisType string, duration time.Duration) {
	l.WithAnalysis(analysisID, domain, analysisType).
		WithField("duration", duration.String()).
		Info("Analysis completed successfully")
}

// LogAnalysisError logs an analysis error
func (l *Logger) LogAnalysisError(analysisID, domain, analysisType string, err error, duration time.Duration) {
	l.WithAnalysis(analysisID, domain, analysisType).
		WithField("duration", duration.String()).
		WithError(err).
		Error("Analysis failed")
}

// LogHTTPRequest logs HTTP request information
func (l *Logger) LogHTTPRequest(method, path, userAgent, ip string, statusCode int, duration time.Duration) {
	l.WithFields(logrus.Fields{
		"method":      method,
		"path":        path,
		"user_agent":  userAgent,
		"ip":          ip,
		"status_code": statusCode,
		"duration":    duration.String(),
	}).Info("HTTP request processed")
}

// LogAPICall logs external API call information
func (l *Logger) LogAPICall(service, endpoint string, statusCode int, duration time.Duration, err error) {
	entry := l.WithFields(logrus.Fields{
		"service":     service,
		"endpoint":    endpoint,
		"status_code": statusCode,
		"duration":    duration.String(),
	})

	if err != nil {
		entry.WithError(err).Error("API call failed")
	} else {
		entry.Info("API call successful")
	}
}

// LogDatabaseQuery logs database query information
func (l *Logger) LogDatabaseQuery(operation, table string, duration time.Duration, err error) {
	entry := l.WithFields(logrus.Fields{
		"operation": operation,
		"table":     table,
		"duration":  duration.String(),
	})

	if err != nil {
		entry.WithError(err).Error("Database query failed")
	} else {
		entry.Debug("Database query successful")
	}
}

// LogCacheOperation logs cache operation information
func (l *Logger) LogCacheOperation(operation, key string, hit bool, duration time.Duration, err error) {
	entry := l.WithFields(logrus.Fields{
		"operation": operation,
		"key":       key,
		"hit":       hit,
		"duration":  duration.String(),
	})

	if err != nil {
		entry.WithError(err).Error("Cache operation failed")
	} else {
		entry.Debug("Cache operation successful")
	}
}

// parseFields converts interface{} slice to logrus.Fields
func (l *Logger) parseFields(fields ...interface{}) logrus.Fields {
	logFields := logrus.Fields{}
	
	for i := 0; i < len(fields); i += 2 {
		if i+1 < len(fields) {
			if key, ok := fields[i].(string); ok {
				logFields[key] = fields[i+1]
			}
		}
	}
	
	return logFields
}

// SetLevel sets the logger level
func (l *Logger) SetLevel(level string) {
	if parsedLevel, err := logrus.ParseLevel(level); err == nil {
		l.Logger.SetLevel(parsedLevel)
	}
}

// GetLevel returns the current logger level
func (l *Logger) GetLevel() string {
	return l.Logger.GetLevel().String()
}

// IsDebugEnabled returns true if debug logging is enabled
func (l *Logger) IsDebugEnabled() bool {
	return l.Logger.IsLevelEnabled(logrus.DebugLevel)
}

// Close closes any open file handles
func (l *Logger) Close() error {
	// If using lumberjack, we might need to close it
	// For now, this is a no-op since logrus doesn't require explicit closing
	return nil
}