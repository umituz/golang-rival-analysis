package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/umituz/golang-rival-analysis/internal/domain"
	"github.com/umituz/golang-rival-analysis/pkg/config"
	"github.com/umituz/golang-rival-analysis/pkg/logger"
)

func simpleMain() {
	// Load configuration
	cfg := config.New()

	// Initialize logger
	log := logger.New(logger.Config{
		Level:  cfg.Logging.Level,
		Format: cfg.Logging.Format,
		Output: cfg.Logging.Output,
	})

	log.Info("Starting Golang Rival Analysis Server", "version", "1.0.0")

	// Setup Gin router
	router := gin.Default()

	// Health check endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":    "healthy",
			"timestamp": time.Now().UTC(),
			"version":   "1.0.0",
		})
	})

	// Simple website analysis endpoint
	router.GET("/api/v1/analyze/website/:domain", func(c *gin.Context) {
		domain := c.Param("domain")
		
		if domain == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "domain parameter is required",
			})
			return
		}

		// Simple analysis - just fetch the website
		url := fmt.Sprintf("https://%s", domain)
		
		// Create HTTP client with timeout
		client := &http.Client{
			Timeout: 10 * time.Second,
		}
		
		start := time.Now()
		resp, err := client.Get(url)
		duration := time.Since(start)
		
		if err != nil {
			log.Error("Website analysis failed", err, "domain", domain)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "analysis failed",
				"details": err.Error(),
			})
			return
		}
		defer resp.Body.Close()

		// Create basic website analysis
		website := &domain.Website{
			URL:          url,
			Domain:       domain,
			Title:        "Sample Title", // In production, parse HTML
			StatusCode:   resp.StatusCode,
			ResponseTime: duration,
			PageSize:     resp.ContentLength,
			Headers:      make(map[string]string),
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		}

		// Convert response headers
		for key, values := range resp.Header {
			if len(values) > 0 {
				website.Headers[key] = values[0]
			}
		}

		// Create analysis report
		report := &domain.AnalysisReport{
			ID:           fmt.Sprintf("analysis_%d", time.Now().Unix()),
			Domain:       domain,
			AnalysisType: "website",
			StartTime:    start,
			EndTime:      time.Now(),
			Duration:     duration,
			Status:       "completed",
			Website:      website,
		}

		log.Info("Website analysis completed", "domain", domain, "duration", duration.String())

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    report,
			"meta": gin.H{
				"duration": duration.String(),
			},
		})
	})

	// Simple DNS analysis endpoint
	router.GET("/api/v1/analyze/dns/:domain", func(c *gin.Context) {
		domain := c.Param("domain")
		
		if domain == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "domain parameter is required",
			})
			return
		}

		// Simple DNS lookup using net package
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Example: just do a basic lookup
		_, err := (&net.Resolver{}).LookupHost(ctx, domain)
		
		dnsRecord := &domain.DNSRecord{
			Domain:     domain,
			RecordType: "A",
			Records:    []string{},
			AllRecords: make(map[string][]string),
		}
		
		if err != nil {
			dnsRecord.AllRecords["error"] = []string{err.Error()}
		} else {
			dnsRecord.AllRecords["A"] = []string{"Lookup successful"}
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    dnsRecord,
		})
	})

	// Start server
	port := cfg.Server.Port
	log.Info("Server starting", "port", port)
	
	if err := router.Run(fmt.Sprintf(":%d", port)); err != nil {
		log.Fatal("Failed to start server", err)
	}
}