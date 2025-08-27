package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/umituz/golang-rival-analysis/internal/handler"
	"github.com/umituz/golang-rival-analysis/internal/infrastructure"
	"github.com/umituz/golang-rival-analysis/internal/service"
	"github.com/umituz/golang-rival-analysis/pkg/config"
	"github.com/umituz/golang-rival-analysis/pkg/logger"
)

func main() {
	// Load configuration
	cfg := config.New()
	if err := cfg.Validate(); err != nil {
		panic(fmt.Sprintf("Invalid configuration: %v", err))
	}

	// Initialize logger
	log := logger.New(logger.Config{
		Level:      cfg.Logging.Level,
		Format:     cfg.Logging.Format,
		Output:     cfg.Logging.Output,
		Filename:   cfg.Logging.Filename,
		MaxSize:    cfg.Logging.MaxSize,
		MaxAge:     cfg.Logging.MaxAge,
		MaxBackups: cfg.Logging.MaxBackups,
		Compress:   cfg.Logging.Compress,
	})

	log.Info("Starting Golang Rival Analysis Server", "version", "1.0.0")

	// Initialize dependencies
	deps, err := initializeDependencies(cfg, log)
	if err != nil {
		log.Fatal("Failed to initialize dependencies", err)
	}
	defer deps.Cleanup()

	// Initialize analyzer service
	analyzerService := service.NewAnalyzerService(
		deps.HTTPClient,
		deps.DNSClient,
		deps.WHOISClient,
		deps.SSLClient,
		deps.WebScraper,
		deps.APIClient,
		deps.SecurityScanner,
		deps.PerformanceMonitor,
		deps.SEOAnalyzer,
		deps.CompetitorAnalyzer,
		deps.ReportGenerator,
		deps.ReportRepository,
		log,
		cfg,
		deps.Cache,
	)

	// Initialize handlers
	analyzerHandler := handler.NewAnalyzerHandler(analyzerService, log, cfg)

	// Setup Gin router
	router := setupRouter(cfg, log, analyzerHandler)

	// Create HTTP server
	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	// Start server in a goroutine
	go func() {
		log.Info("Server starting", "address", server.Addr)
		
		var err error
		if cfg.Server.EnableTLS {
			err = server.ListenAndServeTLS(cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile)
		} else {
			err = server.ListenAndServe()
		}
		
		if err != nil && err != http.ErrServerClosed {
			log.Fatal("Failed to start server", err)
		}
	}()

	log.Info("Server started successfully",
		"host", cfg.Server.Host,
		"port", cfg.Server.Port,
		"tls", cfg.Server.EnableTLS,
	)

	// Wait for interrupt signal to gracefully shut down the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("Shutting down server...")

	// The context is used to inform the server it has 30 seconds to finish
	// the request it is currently handling
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown", err)
	}

	log.Info("Server exited")
}

// setupRouter configures the Gin router with middleware and routes
func setupRouter(cfg *config.Config, log *logger.Logger, analyzerHandler *handler.AnalyzerHandler) *gin.Engine {
	// Set Gin mode
	if cfg.Logging.Level == "debug" {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()

	// Global middleware
	router.Use(gin.Recovery())
	
	// Custom logging middleware
	router.Use(ginLogger(log))

	// CORS middleware if enabled
	if cfg.Server.EnableCORS {
		router.Use(analyzerHandler.CORSMiddleware())
	}

	// Rate limiting middleware if enabled
	if cfg.Security.EnableRateLimit {
		router.Use(analyzerHandler.RateLimitMiddleware())
	}

	// API key middleware if enabled
	if cfg.Security.EnableAPIKey {
		router.Use(analyzerHandler.APIKeyMiddleware())
	}

	// Health check routes (no auth required)
	router.GET("/health", analyzerHandler.HealthCheck)
	router.GET("/status", analyzerHandler.Status)

	// Register analyzer routes
	analyzerHandler.RegisterRoutes(router)

	// Serve static files if needed
	router.Static("/static", "./web/static")

	return router
}

// ginLogger returns a gin.HandlerFunc that logs requests using our logger
func ginLogger(log *logger.Logger) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		// Process request
		c.Next()

		// Calculate request duration
		latency := time.Since(start)
		clientIP := c.ClientIP()
		method := c.Request.Method
		statusCode := c.Writer.Status()
		bodySize := c.Writer.Size()

		if raw != "" {
			path = path + "?" + raw
		}

		// Log request
		log.LogHTTPRequest(method, path, c.Request.UserAgent(), clientIP, statusCode, latency)
		
		// Log additional details for errors
		if statusCode >= 400 {
			log.Error("HTTP request error",
				nil,
				"method", method,
				"path", path,
				"status", statusCode,
				"size", bodySize,
				"duration", latency,
				"client_ip", clientIP,
			)
		}
	})
}

// Dependencies holds all application dependencies
type Dependencies struct {
	HTTPClient         *infrastructure.HTTPClientImpl
	DNSClient          *infrastructure.DNSClientImpl
	WHOISClient        *infrastructure.WHOISClientImpl
	SSLClient          *infrastructure.SSLClientImpl
	WebScraper         *infrastructure.WebScraperImpl
	APIClient          *infrastructure.APIClientImpl
	SecurityScanner    *infrastructure.SecurityScannerImpl
	PerformanceMonitor *infrastructure.PerformanceMonitorImpl
	SEOAnalyzer        *infrastructure.SEOAnalyzerImpl
	CompetitorAnalyzer *infrastructure.CompetitorAnalyzerImpl
	ReportGenerator    *infrastructure.ReportGeneratorImpl
	ReportRepository   *infrastructure.ReportRepositoryImpl
	Cache              *infrastructure.CacheImpl
}

// Cleanup cleans up all dependencies
func (d *Dependencies) Cleanup() {
	// Add cleanup logic here if needed
}

// initializeDependencies initializes all application dependencies
func initializeDependencies(cfg *config.Config, log *logger.Logger) (*Dependencies, error) {
	// Initialize HTTP client
	httpClient := infrastructure.NewHTTPClient(cfg, log)

	// Initialize DNS client
	dnsClient := infrastructure.NewDNSClient(cfg, log)

	// Initialize WHOIS client
	whoisClient := infrastructure.NewWHOISClient(cfg, log)

	// Initialize SSL client
	sslClient := infrastructure.NewSSLClient(cfg, log)

	// Initialize web scraper
	webScraper := infrastructure.NewWebScraper(cfg, log)

	// Initialize API client for external services
	apiClient := infrastructure.NewAPIClient(cfg, log)

	// Initialize security scanner
	securityScanner := infrastructure.NewSecurityScanner(cfg, log)

	// Initialize performance monitor
	performanceMonitor := infrastructure.NewPerformanceMonitor(cfg, log)

	// Initialize SEO analyzer
	seoAnalyzer := infrastructure.NewSEOAnalyzer(cfg, log)

	// Initialize competitor analyzer
	competitorAnalyzer := infrastructure.NewCompetitorAnalyzer(apiClient, webScraper, cfg, log)

	// Initialize report generator
	reportGenerator := infrastructure.NewReportGenerator(cfg, log)

	// Initialize repositories
	reportRepository := infrastructure.NewReportRepository(cfg, log)

	// Initialize cache
	cache := infrastructure.NewCache(cfg, log)

	return &Dependencies{
		HTTPClient:         httpClient,
		DNSClient:          dnsClient,
		WHOISClient:        whoisClient,
		SSLClient:          sslClient,
		WebScraper:         webScraper,
		APIClient:          apiClient,
		SecurityScanner:    securityScanner,
		PerformanceMonitor: performanceMonitor,
		SEOAnalyzer:        seoAnalyzer,
		CompetitorAnalyzer: competitorAnalyzer,
		ReportGenerator:    reportGenerator,
		ReportRepository:   reportRepository,
		Cache:              cache,
	}, nil
}