package handler

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
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