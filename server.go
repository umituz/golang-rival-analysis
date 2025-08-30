package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/likexian/whois"
	"github.com/miekg/dns"
)

type AnalysisReport struct {
	ID           string                 `json:"id"`
	Domain       string                 `json:"domain"`
	AnalysisType string                 `json:"analysis_type"`
	StartTime    time.Time              `json:"start_time"`
	EndTime      time.Time              `json:"end_time"`
	Duration     time.Duration          `json:"duration"`
	Status       string                 `json:"status"`
	Data         map[string]interface{} `json:"data"`
}

func main() {
	router := gin.Default()

	// CORS middleware
	router.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	// Health check
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":    "healthy",
			"timestamp": time.Now(),
			"version":   "1.0.0",
		})
	})

	// Website analysis
	router.GET("/api/v1/analyze/website/:domain", func(c *gin.Context) {
		domain := c.Param("domain")
		if domain == "" {
			c.JSON(400, gin.H{"success": false, "message": "domain parameter required"})
			return
		}

		analysisID := uuid.New().String()
		startTime := time.Now()

		// Perform website analysis
		url := fmt.Sprintf("https://%s", domain)
		client := &http.Client{Timeout: 10 * time.Second}
		
		resp, err := client.Get(url)
		if err != nil {
			c.JSON(500, gin.H{"success": false, "message": "Failed to analyze website", "error": err.Error()})
			return
		}
		defer resp.Body.Close()

		report := AnalysisReport{
			ID:           analysisID,
			Domain:       domain,
			AnalysisType: "website",
			StartTime:    startTime,
			EndTime:      time.Now(),
			Duration:     time.Since(startTime),
			Status:       "completed",
			Data: map[string]interface{}{
				"url":           url,
				"status_code":   resp.StatusCode,
				"response_time": time.Since(startTime).String(),
				"content_type":  resp.Header.Get("Content-Type"),
				"server":        resp.Header.Get("Server"),
			},
		}

		// Save to output directory
		saveAnalysisResult(domain, "website", report)

		c.JSON(200, gin.H{
			"success": true,
			"data":    report,
			"meta":    gin.H{"duration": report.Duration.String()},
		})
	})

	// SSL analysis
	router.GET("/api/v1/analyze/ssl/:domain", func(c *gin.Context) {
		domain := c.Param("domain")
		if domain == "" {
			c.JSON(400, gin.H{"success": false, "message": "domain parameter required"})
			return
		}

		analysisID := uuid.New().String()
		startTime := time.Now()

		conn, err := tls.Dial("tcp", fmt.Sprintf("%s:443", domain), &tls.Config{
			ServerName: domain,
		})
		if err != nil {
			c.JSON(500, gin.H{"success": false, "message": "Failed to connect SSL", "error": err.Error()})
			return
		}
		defer conn.Close()

		cert := conn.ConnectionState().PeerCertificates[0]
		
		report := AnalysisReport{
			ID:           analysisID,
			Domain:       domain,
			AnalysisType: "ssl",
			StartTime:    startTime,
			EndTime:      time.Now(),
			Duration:     time.Since(startTime),
			Status:       "completed",
			Data: map[string]interface{}{
				"issuer":        cert.Issuer.String(),
				"subject":       cert.Subject.String(),
				"not_before":    cert.NotBefore,
				"not_after":     cert.NotAfter,
				"serial_number": cert.SerialNumber.String(),
				"version":       cert.Version,
				"is_valid":      time.Now().Before(cert.NotAfter),
				"days_to_expiry": int(time.Until(cert.NotAfter).Hours() / 24),
			},
		}

		saveAnalysisResult(domain, "ssl", report)

		c.JSON(200, gin.H{
			"success": true,
			"data":    report,
			"meta":    gin.H{"duration": report.Duration.String()},
		})
	})

	// DNS analysis
	router.GET("/api/v1/analyze/dns/:domain", func(c *gin.Context) {
		domain := c.Param("domain")
		if domain == "" {
			c.JSON(400, gin.H{"success": false, "message": "domain parameter required"})
			return
		}

		analysisID := uuid.New().String()
		startTime := time.Now()

		client := &dns.Client{Timeout: 10 * time.Second}
		recordTypes := map[string]uint16{
			"A":     dns.TypeA,
			"AAAA":  dns.TypeAAAA,
			"MX":    dns.TypeMX,
			"NS":    dns.TypeNS,
			"TXT":   dns.TypeTXT,
			"CNAME": dns.TypeCNAME,
		}

		allRecords := make(map[string][]string)
		for recordName, recordType := range recordTypes {
			msg := new(dns.Msg)
			msg.SetQuestion(dns.Fqdn(domain), recordType)

			response, _, err := client.Exchange(msg, "8.8.8.8:53")
			if err == nil && len(response.Answer) > 0 {
				var records []string
				for _, answer := range response.Answer {
					records = append(records, answer.String())
				}
				allRecords[recordName] = records
			}
		}

		report := AnalysisReport{
			ID:           analysisID,
			Domain:       domain,
			AnalysisType: "dns",
			StartTime:    startTime,
			EndTime:      time.Now(),
			Duration:     time.Since(startTime),
			Status:       "completed",
			Data: map[string]interface{}{
				"domain":      domain,
				"all_records": allRecords,
			},
		}

		saveAnalysisResult(domain, "dns", report)

		c.JSON(200, gin.H{
			"success": true,
			"data":    report,
			"meta":    gin.H{"duration": report.Duration.String()},
		})
	})

	// WHOIS analysis
	router.GET("/api/v1/analyze/whois/:domain", func(c *gin.Context) {
		domain := c.Param("domain")
		if domain == "" {
			c.JSON(400, gin.H{"success": false, "message": "domain parameter required"})
			return
		}

		analysisID := uuid.New().String()
		startTime := time.Now()

		result, err := whois.Whois(domain)
		if err != nil {
			c.JSON(500, gin.H{"success": false, "message": "WHOIS query failed", "error": err.Error()})
			return
		}

		registrar := extractWHOISField(result, "Registrar:")
		if registrar == "" {
			registrar = extractWHOISField(result, "registrar:")
		}

		report := AnalysisReport{
			ID:           analysisID,
			Domain:       domain,
			AnalysisType: "whois",
			StartTime:    startTime,
			EndTime:      time.Now(),
			Duration:     time.Since(startTime),
			Status:       "completed",
			Data: map[string]interface{}{
				"domain":    domain,
				"registrar": registrar,
				"raw_data":  result,
			},
		}

		saveAnalysisResult(domain, "whois", report)

		c.JSON(200, gin.H{
			"success": true,
			"data":    report,
			"meta":    gin.H{"duration": report.Duration.String()},
		})
	})

	port := ":9000"
	fmt.Printf("🚀 Server starting on http://localhost%s\n", port)
	router.Run(port)
}

func extractWHOISField(whoisData, field string) string {
	lines := strings.Split(whoisData, "\n")
	for _, line := range lines {
		if strings.Contains(strings.ToLower(line), strings.ToLower(field)) {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

func saveAnalysisResult(domain, analysisType string, report AnalysisReport) {
	// Create output directory
	outputDir := fmt.Sprintf("rivals/companies/%s/output", domain)
	log.Printf("🔄 Creating directory: %s", outputDir)
	err := os.MkdirAll(outputDir, 0755)
	if err != nil {
		log.Printf("❌ Error creating output directory %s: %v", outputDir, err)
		return
	}
	log.Printf("✅ Directory created successfully: %s", outputDir)

	// Save result to JSON file
	filename := fmt.Sprintf("%s/%s-analysis-%s.json", outputDir, analysisType, time.Now().Format("20060102-150405"))
	log.Printf("🔄 Saving file: %s", filename)
	
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		log.Printf("❌ Error marshaling analysis result: %v", err)
		return
	}

	err = os.WriteFile(filename, data, 0644)
	if err != nil {
		log.Printf("❌ Error saving analysis result to %s: %v", filename, err)
		return
	}

	log.Printf("✅ Analysis result saved: %s", filename)
}