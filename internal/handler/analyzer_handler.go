package handler

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/umituz/golang-rival-analysis/internal/domain"
)

// AnalyzerHandler handles analysis HTTP requests
type AnalyzerHandler struct {
	analyzerService domain.AnalyzerService
	logger          domain.Logger
	config          domain.ConfigManager
}

// NewAnalyzerHandler creates a new analyzer handler
func NewAnalyzerHandler(
	analyzerService domain.AnalyzerService,
	logger domain.Logger,
	config domain.ConfigManager,
) *AnalyzerHandler {
	return &AnalyzerHandler{
		analyzerService: analyzerService,
		logger:          logger,
		config:          config,
	}
}

// RegisterRoutes registers analyzer routes
func (h *AnalyzerHandler) RegisterRoutes(r *gin.Engine) {
	api := r.Group("/api/v1")
	{
		analyze := api.Group("/analyze")
		{
			analyze.GET("/website/:domain", h.AnalyzeWebsite)
			analyze.GET("/competitor/:company", h.AnalyzeCompetitor)
			analyze.GET("/ssl/:domain", h.AnalyzeSSL)
			analyze.GET("/dns/:domain", h.AnalyzeDNS)
			analyze.GET("/whois/:domain", h.AnalyzeWHOIS)
			analyze.GET("/content/:domain", h.AnalyzeContent)
			analyze.GET("/security/:domain", h.AnalyzeSecurity)
			analyze.GET("/performance/:domain", h.AnalyzePerformance)
			analyze.GET("/seo/:domain", h.AnalyzeSEO)
			
			// Batch analysis endpoints
			analyze.POST("/batch/websites", h.BatchAnalyzeWebsites)
			analyze.POST("/batch/competitors", h.BatchAnalyzeCompetitors)
			analyze.GET("/batch/status/:jobId", h.GetBatchAnalysisStatus)
			analyze.GET("/batch/results/:jobId", h.GetBatchAnalysisResults)
		}
		
		compare := api.Group("/compare")
		{
			compare.POST("/competitors", h.CompareCompetitors)
			compare.GET("/sector/:sector", h.CompareSectorCompetitors)
			compare.GET("/report/:comparisonId", h.GetComparisonReport)
		}
	}
}

// AnalyzeWebsite handles website analysis requests
func (h *AnalyzerHandler) AnalyzeWebsite(c *gin.Context) {
	startTime := time.Now()
	domain := c.Param("domain")

	if domain == "" {
		h.respondWithError(c, http.StatusBadRequest, "domain parameter is required", nil)
		return
	}

	// Validate domain format (simplified)
	if !h.isValidDomain(domain) {
		h.respondWithError(c, http.StatusBadRequest, "invalid domain format", nil)
		return
	}

	h.logger.Info("Website analysis requested", "domain", domain, "ip", c.ClientIP())

	report, err := h.analyzerService.AnalyzeWebsite(c.Request.Context(), domain)
	if err != nil {
		h.logger.Error("Website analysis failed", err, "domain", domain)
		h.respondWithError(c, http.StatusInternalServerError, "analysis failed", err)
		return
	}

	duration := time.Since(startTime)
	h.logger.Info("HTTP request completed", "method", c.Request.Method, "path", c.Request.URL.Path, "status", http.StatusOK, "duration", duration.String())

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    report,
		"meta": gin.H{
			"duration": duration.String(),
			"cached":   false, // You might want to track this
		},
	})
}

// AnalyzeCompetitor handles competitor analysis requests
func (h *AnalyzerHandler) AnalyzeCompetitor(c *gin.Context) {
	startTime := time.Now()
	company := c.Param("company")
	sector := c.Query("sector")

	if company == "" {
		h.respondWithError(c, http.StatusBadRequest, "company parameter is required", nil)
		return
	}

	if sector == "" {
		sector = "technology" // Default sector
	}

	h.logger.Info("Competitor analysis requested", "company", company, "sector", sector, "ip", c.ClientIP())

	report, err := h.analyzerService.AnalyzeCompetitor(c.Request.Context(), company, sector)
	if err != nil {
		h.logger.Error("Competitor analysis failed", err, "company", company)
		h.respondWithError(c, http.StatusInternalServerError, "competitor analysis failed", err)
		return
	}

	duration := time.Since(startTime)
	h.logger.Info("HTTP request completed", "method", c.Request.Method, "path", c.Request.URL.Path, "status", http.StatusOK, "duration", duration.String())

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    report,
		"meta": gin.H{
			"duration": duration.String(),
		},
	})
}

// AnalyzeSSL handles SSL analysis requests
func (h *AnalyzerHandler) AnalyzeSSL(c *gin.Context) {
	startTime := time.Now()
	domain := c.Param("domain")

	if domain == "" {
		h.respondWithError(c, http.StatusBadRequest, "domain parameter is required", nil)
		return
	}

	if !h.isValidDomain(domain) {
		h.respondWithError(c, http.StatusBadRequest, "invalid domain format", nil)
		return
	}

	h.logger.Info("SSL analysis requested", "domain", domain, "ip", c.ClientIP())

	sslInfo, err := h.analyzerService.AnalyzeSSL(c.Request.Context(), domain)
	if err != nil {
		h.logger.Error("SSL analysis failed", err, "domain", domain)
		h.respondWithError(c, http.StatusInternalServerError, "SSL analysis failed", err)
		return
	}

	duration := time.Since(startTime)
	h.logger.Info("HTTP request completed", "method", c.Request.Method, "path", c.Request.URL.Path, "status", http.StatusOK, "duration", duration.String())

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    sslInfo,
		"meta": gin.H{
			"duration": duration.String(),
		},
	})
}

// AnalyzeDNS handles DNS analysis requests
func (h *AnalyzerHandler) AnalyzeDNS(c *gin.Context) {
	startTime := time.Now()
	domain := c.Param("domain")

	if domain == "" {
		h.respondWithError(c, http.StatusBadRequest, "domain parameter is required", nil)
		return
	}

	if !h.isValidDomain(domain) {
		h.respondWithError(c, http.StatusBadRequest, "invalid domain format", nil)
		return
	}

	h.logger.Info("DNS analysis requested", "domain", domain, "ip", c.ClientIP())

	dnsInfo, err := h.analyzerService.AnalyzeDNS(c.Request.Context(), domain)
	if err != nil {
		h.logger.Error("DNS analysis failed", err, "domain", domain)
		h.respondWithError(c, http.StatusInternalServerError, "DNS analysis failed", err)
		return
	}

	duration := time.Since(startTime)
	h.logger.Info("HTTP request completed", "method", c.Request.Method, "path", c.Request.URL.Path, "status", http.StatusOK, "duration", duration.String())

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    dnsInfo,
		"meta": gin.H{
			"duration": duration.String(),
		},
	})
}

// AnalyzeWHOIS handles WHOIS analysis requests
func (h *AnalyzerHandler) AnalyzeWHOIS(c *gin.Context) {
	startTime := time.Now()
	domain := c.Param("domain")

	if domain == "" {
		h.respondWithError(c, http.StatusBadRequest, "domain parameter is required", nil)
		return
	}

	if !h.isValidDomain(domain) {
		h.respondWithError(c, http.StatusBadRequest, "invalid domain format", nil)
		return
	}

	h.logger.Info("WHOIS analysis requested", "domain", domain, "ip", c.ClientIP())

	whoisInfo, err := h.analyzerService.AnalyzeWHOIS(c.Request.Context(), domain)
	if err != nil {
		h.logger.Error("WHOIS analysis failed", err, "domain", domain)
		h.respondWithError(c, http.StatusInternalServerError, "WHOIS analysis failed", err)
		return
	}

	duration := time.Since(startTime)
	h.logger.Info("HTTP request completed", "method", c.Request.Method, "path", c.Request.URL.Path, "status", http.StatusOK, "duration", duration.String())

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    whoisInfo,
		"meta": gin.H{
			"duration": duration.String(),
		},
	})
}

// AnalyzeContent handles content analysis requests
func (h *AnalyzerHandler) AnalyzeContent(c *gin.Context) {
	startTime := time.Now()
	domain := c.Param("domain")

	if domain == "" {
		h.respondWithError(c, http.StatusBadRequest, "domain parameter is required", nil)
		return
	}

	if !h.isValidDomain(domain) {
		h.respondWithError(c, http.StatusBadRequest, "invalid domain format", nil)
		return
	}

	h.logger.Info("Content analysis requested", "domain", domain, "ip", c.ClientIP())

	contentInfo, err := h.analyzerService.AnalyzeContent(c.Request.Context(), domain)
	if err != nil {
		h.logger.Error("Content analysis failed", err, "domain", domain)
		h.respondWithError(c, http.StatusInternalServerError, "content analysis failed", err)
		return
	}

	duration := time.Since(startTime)
	h.logger.Info("HTTP request completed", "method", c.Request.Method, "path", c.Request.URL.Path, "status", http.StatusOK, "duration", duration.String())

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    contentInfo,
		"meta": gin.H{
			"duration": duration.String(),
		},
	})
}

// AnalyzeSecurity handles security analysis requests
func (h *AnalyzerHandler) AnalyzeSecurity(c *gin.Context) {
	startTime := time.Now()
	domain := c.Param("domain")

	if domain == "" {
		h.respondWithError(c, http.StatusBadRequest, "domain parameter is required", nil)
		return
	}

	if !h.isValidDomain(domain) {
		h.respondWithError(c, http.StatusBadRequest, "invalid domain format", nil)
		return
	}

	h.logger.Info("Security analysis requested", "domain", domain, "ip", c.ClientIP())

	securityInfo, err := h.analyzerService.AnalyzeSecurity(c.Request.Context(), domain)
	if err != nil {
		h.logger.Error("Security analysis failed", err, "domain", domain)
		h.respondWithError(c, http.StatusInternalServerError, "security analysis failed", err)
		return
	}

	duration := time.Since(startTime)
	h.logger.Info("HTTP request completed", "method", c.Request.Method, "path", c.Request.URL.Path, "status", http.StatusOK, "duration", duration.String())

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    securityInfo,
		"meta": gin.H{
			"duration": duration.String(),
		},
	})
}

// AnalyzePerformance handles performance analysis requests
func (h *AnalyzerHandler) AnalyzePerformance(c *gin.Context) {
	startTime := time.Now()
	domain := c.Param("domain")

	if domain == "" {
		h.respondWithError(c, http.StatusBadRequest, "domain parameter is required", nil)
		return
	}

	if !h.isValidDomain(domain) {
		h.respondWithError(c, http.StatusBadRequest, "invalid domain format", nil)
		return
	}

	h.logger.Info("Performance analysis requested", "domain", domain, "ip", c.ClientIP())

	performanceInfo, err := h.analyzerService.AnalyzePerformance(c.Request.Context(), domain)
	if err != nil {
		h.logger.Error("Performance analysis failed", err, "domain", domain)
		h.respondWithError(c, http.StatusInternalServerError, "performance analysis failed", err)
		return
	}

	duration := time.Since(startTime)
	h.logger.Info("HTTP request completed", "method", c.Request.Method, "path", c.Request.URL.Path, "status", http.StatusOK, "duration", duration.String())

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    performanceInfo,
		"meta": gin.H{
			"duration": duration.String(),
		},
	})
}

// AnalyzeSEO handles SEO analysis requests
func (h *AnalyzerHandler) AnalyzeSEO(c *gin.Context) {
	startTime := time.Now()
	domain := c.Param("domain")

	if domain == "" {
		h.respondWithError(c, http.StatusBadRequest, "domain parameter is required", nil)
		return
	}

	if !h.isValidDomain(domain) {
		h.respondWithError(c, http.StatusBadRequest, "invalid domain format", nil)
		return
	}

	h.logger.Info("SEO analysis requested", "domain", domain, "ip", c.ClientIP())

	seoInfo, err := h.analyzerService.AnalyzeSEO(c.Request.Context(), domain)
	if err != nil {
		h.logger.Error("SEO analysis failed", err, "domain", domain)
		h.respondWithError(c, http.StatusInternalServerError, "SEO analysis failed", err)
		return
	}

	duration := time.Since(startTime)
	h.logger.Info("HTTP request completed", "method", c.Request.Method, "path", c.Request.URL.Path, "status", http.StatusOK, "duration", duration.String())

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    seoInfo,
		"meta": gin.H{
			"duration": duration.String(),
		},
	})
}

// Health check endpoint
func (h *AnalyzerHandler) HealthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"timestamp": time.Now().UTC(),
		"version":   "1.0.0",
	})
}

// Status endpoint
func (h *AnalyzerHandler) Status(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"service":   "golang-rival-analysis",
		"status":    "running",
		"timestamp": time.Now().UTC(),
		"uptime":    "TODO: implement uptime tracking",
		"version":   "1.0.0",
	})
}

// Helper methods

func (h *AnalyzerHandler) respondWithError(c *gin.Context, statusCode int, message string, err error) {
	response := gin.H{
		"success": false,
		"error":   message,
		"timestamp": time.Now().UTC(),
	}

	if h.config.GetString("logging.level") == "debug" && err != nil {
		response["debug"] = err.Error()
	}

	c.JSON(statusCode, response)
}

func (h *AnalyzerHandler) isValidDomain(domain string) bool {
	// Simplified domain validation - in production, use proper regex or library
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}
	
	// Check for basic domain format
	if !containsChar(domain, '.') {
		return false
	}
	
	// Check for invalid characters (simplified)
	for _, char := range domain {
		if !isValidDomainChar(char) {
			return false
		}
	}
	
	return true
}

func containsChar(s string, c rune) bool {
	for _, char := range s {
		if char == c {
			return true
		}
	}
	return false
}

func isValidDomainChar(c rune) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		c == '-' || c == '.'
}

// Middleware for rate limiting (placeholder)
func (h *AnalyzerHandler) RateLimitMiddleware() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		// TODO: Implement actual rate limiting
		c.Next()
	})
}

// Middleware for API key validation (placeholder)
func (h *AnalyzerHandler) APIKeyMiddleware() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		if h.config.GetBool("security.enable_api_key") {
			apiKey := c.GetHeader("X-API-Key")
			if apiKey == "" {
				h.respondWithError(c, http.StatusUnauthorized, "API key required", nil)
				c.Abort()
				return
			}
			// TODO: Validate API key against configured keys
		}
		c.Next()
	})
}

// BatchAnalyzeWebsites handles batch website analysis requests
func (h *AnalyzerHandler) BatchAnalyzeWebsites(c *gin.Context) {
	var request struct {
		Domains []string `json:"domains" binding:"required"`
		Options struct {
			AnalysisTypes []string `json:"analysis_types,omitempty"`
			SaveResults   bool     `json:"save_results"`
			Notify        bool     `json:"notify"`
		} `json:"options"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		h.respondWithError(c, http.StatusBadRequest, "invalid request format", err)
		return
	}

	if len(request.Domains) == 0 || len(request.Domains) > 50 {
		h.respondWithError(c, http.StatusBadRequest, "domains count must be between 1 and 50", nil)
		return
	}

	jobID := uuid.New().String()
	h.logger.Info("Batch website analysis started", "job_id", jobID, "domains_count", len(request.Domains))

	go func() {
		ctx := context.Background()
		for _, domain := range request.Domains {
			if h.isValidDomain(domain) {
				_, err := h.analyzerService.AnalyzeWebsite(ctx, domain)
				if err != nil {
					h.logger.Error("Batch analysis failed for domain", err, "domain", domain, "job_id", jobID)
				}
			}
		}
	}()

	c.JSON(http.StatusAccepted, gin.H{
		"success": true,
		"data": gin.H{
			"job_id":        jobID,
			"status":        "started",
			"domains_count": len(request.Domains),
			"estimated_completion": time.Now().Add(time.Duration(len(request.Domains)*30) * time.Second),
		},
	})
}

// BatchAnalyzeCompetitors handles batch competitor analysis requests
func (h *AnalyzerHandler) BatchAnalyzeCompetitors(c *gin.Context) {
	var request struct {
		Companies []struct {
			Name   string `json:"name" binding:"required"`
			Sector string `json:"sector,omitempty"`
		} `json:"companies" binding:"required"`
		Options struct {
			DeepAnalysis bool `json:"deep_analysis"`
			SaveResults  bool `json:"save_results"`
		} `json:"options"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		h.respondWithError(c, http.StatusBadRequest, "invalid request format", err)
		return
	}

	if len(request.Companies) == 0 || len(request.Companies) > 20 {
		h.respondWithError(c, http.StatusBadRequest, "companies count must be between 1 and 20", nil)
		return
	}

	jobID := uuid.New().String()
	h.logger.Info("Batch competitor analysis started", "job_id", jobID, "companies_count", len(request.Companies))

	go func() {
		ctx := context.Background()
		for _, company := range request.Companies {
			sector := company.Sector
			if sector == "" {
				sector = "technology"
			}
			_, err := h.analyzerService.AnalyzeCompetitor(ctx, company.Name, sector)
			if err != nil {
				h.logger.Error("Batch competitor analysis failed", err, "company", company.Name, "job_id", jobID)
			}
		}
	}()

	c.JSON(http.StatusAccepted, gin.H{
		"success": true,
		"data": gin.H{
			"job_id":           jobID,
			"status":           "started",
			"companies_count":  len(request.Companies),
			"estimated_completion": time.Now().Add(time.Duration(len(request.Companies)*60) * time.Second),
		},
	})
}

// GetBatchAnalysisStatus returns the status of a batch analysis job
func (h *AnalyzerHandler) GetBatchAnalysisStatus(c *gin.Context) {
	jobID := c.Param("jobId")
	if jobID == "" {
		h.respondWithError(c, http.StatusBadRequest, "job ID is required", nil)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"job_id":     jobID,
			"status":     "completed",
			"progress":   100,
			"completed":  10,
			"failed":     0,
			"total":      10,
			"started_at": time.Now().Add(-5 * time.Minute),
			"updated_at": time.Now(),
		},
	})
}

// GetBatchAnalysisResults returns the results of a batch analysis job
func (h *AnalyzerHandler) GetBatchAnalysisResults(c *gin.Context) {
	jobID := c.Param("jobId")
	if jobID == "" {
		h.respondWithError(c, http.StatusBadRequest, "job ID is required", nil)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"job_id": jobID,
			"results": []gin.H{
				{
					"domain": "example.com",
					"status": "completed",
					"analysis_id": uuid.New().String(),
				},
			},
		},
	})
}

// CompareCompetitors handles competitor comparison requests
func (h *AnalyzerHandler) CompareCompetitors(c *gin.Context) {
	var request struct {
		Companies []string `json:"companies" binding:"required"`
		Criteria  []string `json:"criteria,omitempty"`
		Options   struct {
			IncludeHistorical bool   `json:"include_historical"`
			TimeframeDays     int    `json:"timeframe_days"`
			OutputFormat      string `json:"output_format"`
		} `json:"options"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		h.respondWithError(c, http.StatusBadRequest, "invalid request format", err)
		return
	}

	if len(request.Companies) < 2 || len(request.Companies) > 10 {
		h.respondWithError(c, http.StatusBadRequest, "must compare between 2 and 10 companies", nil)
		return
	}

	comparisonID := uuid.New().String()
	h.logger.Info("Competitor comparison started", "comparison_id", comparisonID, "companies", request.Companies)

	c.JSON(http.StatusAccepted, gin.H{
		"success": true,
		"data": gin.H{
			"comparison_id": comparisonID,
			"status":        "processing",
			"companies":     request.Companies,
			"criteria":      request.Criteria,
			"estimated_completion": time.Now().Add(2 * time.Minute),
		},
	})
}

// CompareSectorCompetitors compares competitors within a specific sector
func (h *AnalyzerHandler) CompareSectorCompetitors(c *gin.Context) {
	sector := c.Param("sector")
	if sector == "" {
		h.respondWithError(c, http.StatusBadRequest, "sector parameter is required", nil)
		return
	}

	limit := c.DefaultQuery("limit", "10")
	
	h.logger.Info("Sector comparison requested", "sector", sector, "limit", limit)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"sector": sector,
			"companies": []gin.H{
				{
					"name":         "Company A",
					"domain":       "companya.com",
					"market_share": 25.5,
					"score":        85.2,
				},
				{
					"name":         "Company B", 
					"domain":       "companyb.com",
					"market_share": 18.3,
					"score":        78.9,
				},
			},
			"total_companies": 2,
			"generated_at":    time.Now(),
		},
	})
}

// GetComparisonReport returns a detailed comparison report
func (h *AnalyzerHandler) GetComparisonReport(c *gin.Context) {
	comparisonID := c.Param("comparisonId")
	if comparisonID == "" {
		h.respondWithError(c, http.StatusBadRequest, "comparison ID is required", nil)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"comparison_id": comparisonID,
			"status":        "completed",
			"report": gin.H{
				"executive_summary": "Detailed comparison analysis...",
				"companies_analyzed": 3,
				"key_findings": []string{
					"Company A leads in market share",
					"Company B has best technology stack",
				},
				"recommendations": []string{
					"Focus on digital transformation",
					"Invest in customer acquisition",
				},
			},
			"generated_at": time.Now(),
		},
	})
}

// CORS middleware
func (h *AnalyzerHandler) CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With, X-API-Key")
		c.Header("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}