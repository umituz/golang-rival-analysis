package infrastructure

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/likexian/whois"
	"github.com/miekg/dns"
	"github.com/umituz/golang-rival-analysis/internal/domain"
	"github.com/umituz/golang-rival-analysis/pkg/config"
	"github.com/umituz/golang-rival-analysis/pkg/logger"
)

// HTTPClientImpl implements domain.HTTPClient
type HTTPClientImpl struct {
	client *http.Client
	config *config.Config
	logger *logger.Logger
}

// NewHTTPClient creates a new HTTP client
func NewHTTPClient(cfg *config.Config, log *logger.Logger) *HTTPClientImpl {
	return &HTTPClientImpl{
		client: &http.Client{
			Timeout: cfg.APIs.DefaultTimeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
			},
		},
		config: cfg,
		logger: log,
	}
}

// Get performs HTTP GET request
func (h *HTTPClientImpl) Get(ctx context.Context, url string, headers map[string]string) (*domain.HTTPResponse, error) {
	start := time.Now()
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	
	// Set default User-Agent if not provided
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", h.config.Analysis.UserAgent)
	}

	resp, err := h.client.Do(req)
	if err != nil {
		h.logger.LogAPICall("http", url, 0, time.Since(start), err)
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	body := make([]byte, h.config.Analysis.MaxPageSize)
	n, _ := resp.Body.Read(body)
	body = body[:n]

	responseHeaders := make(map[string]string)
	for key, values := range resp.Header {
		if len(values) > 0 {
			responseHeaders[key] = values[0]
		}
	}

	duration := time.Since(start)
	h.logger.LogAPICall("http", url, resp.StatusCode, duration, nil)

	return &domain.HTTPResponse{
		StatusCode:   resp.StatusCode,
		Headers:      responseHeaders,
		Body:         body,
		ResponseTime: duration,
		Size:         int64(len(body)),
	}, nil
}

// Post performs HTTP POST request
func (h *HTTPClientImpl) Post(ctx context.Context, url string, body []byte, headers map[string]string) (*domain.HTTPResponse, error) {
	start := time.Now()
	
	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := h.client.Do(req)
	if err != nil {
		h.logger.LogAPICall("http", url, 0, time.Since(start), err)
		return nil, fmt.Errorf("HTTP POST failed: %w", err)
	}
	defer resp.Body.Close()

	respBody := make([]byte, h.config.Analysis.MaxPageSize)
	n, _ := resp.Body.Read(respBody)
	respBody = respBody[:n]

	responseHeaders := make(map[string]string)
	for key, values := range resp.Header {
		if len(values) > 0 {
			responseHeaders[key] = values[0]
		}
	}

	duration := time.Since(start)
	h.logger.LogAPICall("http", url, resp.StatusCode, duration, nil)

	return &domain.HTTPResponse{
		StatusCode:   resp.StatusCode,
		Headers:      responseHeaders,
		Body:         respBody,
		ResponseTime: duration,
		Size:         int64(len(respBody)),
	}, nil
}

// GetWithTimeout performs HTTP GET with custom timeout
func (h *HTTPClientImpl) GetWithTimeout(ctx context.Context, url string, timeout time.Duration) (*domain.HTTPResponse, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return h.Get(timeoutCtx, url, nil)
}

// DNSClientImpl implements domain.DNSClient
type DNSClientImpl struct {
	client *dns.Client
	config *config.Config
	logger *logger.Logger
}

// NewDNSClient creates a new DNS client
func NewDNSClient(cfg *config.Config, log *logger.Logger) *DNSClientImpl {
	return &DNSClientImpl{
		client: &dns.Client{Timeout: 10 * time.Second},
		config: cfg,
		logger: log,
	}
}

// QueryA queries A records
func (d *DNSClientImpl) QueryA(ctx context.Context, domain string) ([]string, error) {
	return d.query(ctx, domain, dns.TypeA)
}

// QueryAAAA queries AAAA records
func (d *DNSClientImpl) QueryAAAA(ctx context.Context, domain string) ([]string, error) {
	return d.query(ctx, domain, dns.TypeAAAA)
}

// QueryMX queries MX records
func (d *DNSClientImpl) QueryMX(ctx context.Context, domain string) ([]string, error) {
	return d.query(ctx, domain, dns.TypeMX)
}

// QueryNS queries NS records
func (d *DNSClientImpl) QueryNS(ctx context.Context, domain string) ([]string, error) {
	return d.query(ctx, domain, dns.TypeNS)
}

// QueryTXT queries TXT records
func (d *DNSClientImpl) QueryTXT(ctx context.Context, domain string) ([]string, error) {
	return d.query(ctx, domain, dns.TypeTXT)
}

// QuerySOA queries SOA records
func (d *DNSClientImpl) QuerySOA(ctx context.Context, domain string) ([]string, error) {
	return d.query(ctx, domain, dns.TypeSOA)
}

// QueryCNAME queries CNAME records
func (d *DNSClientImpl) QueryCNAME(ctx context.Context, domain string) ([]string, error) {
	return d.query(ctx, domain, dns.TypeCNAME)
}

// QueryAll queries all record types
func (d *DNSClientImpl) QueryAll(ctx context.Context, domain string) (map[string][]string, error) {
	recordTypes := map[string]uint16{
		"A":     dns.TypeA,
		"AAAA":  dns.TypeAAAA,
		"MX":    dns.TypeMX,
		"NS":    dns.TypeNS,
		"TXT":   dns.TypeTXT,
		"SOA":   dns.TypeSOA,
		"CNAME": dns.TypeCNAME,
	}

	results := make(map[string][]string)
	for recordName, recordType := range recordTypes {
		if records, err := d.query(ctx, domain, recordType); err == nil && len(records) > 0 {
			results[recordName] = records
		}
	}

	return results, nil
}

func (d *DNSClientImpl) query(ctx context.Context, domain string, recordType uint16) ([]string, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), recordType)

	response, _, err := d.client.ExchangeContext(ctx, msg, "8.8.8.8:53")
	if err != nil {
		return nil, fmt.Errorf("DNS query failed: %w", err)
	}

	var records []string
	for _, answer := range response.Answer {
		records = append(records, answer.String())
	}

	return records, nil
}

// WHOISClientImpl implements domain.WHOISClient
type WHOISClientImpl struct {
	config *config.Config
	logger *logger.Logger
}

// NewWHOISClient creates a new WHOIS client
func NewWHOISClient(cfg *config.Config, log *logger.Logger) *WHOISClientImpl {
	return &WHOISClientImpl{
		config: cfg,
		logger: log,
	}
}

// Query performs WHOIS query
func (w *WHOISClientImpl) Query(ctx context.Context, domain string) (*domain.WHOISInfo, error) {
	start := time.Now()
	
	result, err := whois.Whois(domain)
	if err != nil {
		w.logger.LogAPICall("whois", domain, 0, time.Since(start), err)
		return nil, fmt.Errorf("WHOIS query failed: %w", err)
	}

	w.logger.LogAPICall("whois", domain, 200, time.Since(start), nil)

	// Parse WHOIS result (simplified)
	return &domain.WHOISInfo{
		Domain:    domain,
		Registrar: w.extractField(result, "Registrar:"),
		// Add more parsing as needed
	}, nil
}

// QueryRaw returns raw WHOIS data
func (w *WHOISClientImpl) QueryRaw(ctx context.Context, domain string) (string, error) {
	result, err := whois.Whois(domain)
	if err != nil {
		return "", fmt.Errorf("WHOIS raw query failed: %w", err)
	}
	return result, nil
}

func (w *WHOISClientImpl) extractField(whoisData, field string) string {
	lines := strings.Split(whoisData, "\n")
	for _, line := range lines {
		if strings.Contains(line, field) {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

// SSLClientImpl implements domain.SSLClient
type SSLClientImpl struct {
	config *config.Config
	logger *logger.Logger
}

// NewSSLClient creates a new SSL client
func NewSSLClient(cfg *config.Config, log *logger.Logger) *SSLClientImpl {
	return &SSLClientImpl{
		config: cfg,
		logger: log,
	}
}

// GetCertificate retrieves SSL certificate information
func (s *SSLClientImpl) GetCertificate(ctx context.Context, domain string, port int) (*domain.SSLInfo, error) {
	start := time.Now()
	
	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", domain, port), &tls.Config{
		ServerName: domain,
	})
	if err != nil {
		s.logger.LogAPICall("ssl", domain, 0, time.Since(start), err)
		return nil, fmt.Errorf("SSL connection failed: %w", err)
	}
	defer conn.Close()

	cert := conn.ConnectionState().PeerCertificates[0]
	
	s.logger.LogAPICall("ssl", domain, 200, time.Since(start), nil)

	return &domain.SSLInfo{
		Domain:       domain,
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		SerialNumber: cert.SerialNumber.String(),
		Version:      cert.Version,
		IsValid:      time.Now().Before(cert.NotAfter),
		DaysToExpiry: int(time.Until(cert.NotAfter).Hours() / 24),
	}, nil
}

// ValidateCertificate validates SSL certificate
func (s *SSLClientImpl) ValidateCertificate(ctx context.Context, domain string) (*domain.SSLValidationResult, error) {
	cert, err := s.GetCertificate(ctx, domain, 443)
	if err != nil {
		return &domain.SSLValidationResult{
			IsValid:      false,
			ErrorMessage: err.Error(),
		}, nil
	}

	return &domain.SSLValidationResult{
		IsValid:   cert.IsValid,
		IsExpired: !cert.IsValid,
	}, nil
}

// CheckExpiry checks certificate expiry
func (s *SSLClientImpl) CheckExpiry(ctx context.Context, domain string) (time.Time, error) {
	cert, err := s.GetCertificate(ctx, domain, 443)
	if err != nil {
		return time.Time{}, err
	}
	return cert.NotAfter, nil
}

// Stub implementations for other infrastructure components

// WebScraperImpl is a stub implementation
type WebScraperImpl struct {
	config *config.Config
	logger *logger.Logger
}

func NewWebScraper(cfg *config.Config, log *logger.Logger) *WebScraperImpl {
	return &WebScraperImpl{config: cfg, logger: log}
}

func (w *WebScraperImpl) ScrapeContent(ctx context.Context, url string) (*domain.ScrapedContent, error) {
	// TODO: Implement with Colly or similar
	return &domain.ScrapedContent{URL: url, Title: "Sample Title"}, nil
}

func (w *WebScraperImpl) ExtractLinks(ctx context.Context, url string) ([]string, error) {
	return []string{}, nil
}

func (w *WebScraperImpl) ExtractImages(ctx context.Context, url string) ([]string, error) {
	return []string{}, nil
}

func (w *WebScraperImpl) ExtractText(ctx context.Context, url string) (string, error) {
	return "", nil
}

func (w *WebScraperImpl) DetectTechnologies(ctx context.Context, url string) (*domain.TechnologyStack, error) {
	return &domain.TechnologyStack{}, nil
}

// APIClientImpl is a stub implementation
type APIClientImpl struct {
	config *config.Config
	logger *logger.Logger
}

func NewAPIClient(cfg *config.Config, log *logger.Logger) *APIClientImpl {
	return &APIClientImpl{config: cfg, logger: log}
}

func (a *APIClientImpl) GetSimilarWebData(ctx context.Context, domain string) (*domain.WebsiteAnalysis, error) {
	return &domain.WebsiteAnalysis{}, nil
}

func (a *APIClientImpl) GetLinkedInData(ctx context.Context, companyName string) (*domain.SocialPlatformData, error) {
	return &domain.SocialPlatformData{}, nil
}

func (a *APIClientImpl) GetCrunchbaseData(ctx context.Context, companyName string) (*domain.MarketAnalysis, error) {
	return &domain.MarketAnalysis{}, nil
}

func (a *APIClientImpl) GetTwitterData(ctx context.Context, username string) (*domain.SocialPlatformData, error) {
	return &domain.SocialPlatformData{}, nil
}

func (a *APIClientImpl) GetInstagramData(ctx context.Context, username string) (*domain.SocialPlatformData, error) {
	return &domain.SocialPlatformData{}, nil
}

// SecurityScannerImpl is a stub implementation
type SecurityScannerImpl struct {
	config *config.Config
	logger *logger.Logger
}

func NewSecurityScanner(cfg *config.Config, log *logger.Logger) *SecurityScannerImpl {
	return &SecurityScannerImpl{config: cfg, logger: log}
}

func (s *SecurityScannerImpl) ScanPorts(ctx context.Context, domain string, ports []int) ([]int, error) {
	var openPorts []int
	for _, port := range ports {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", domain, port), 2*time.Second)
		if err == nil {
			openPorts = append(openPorts, port)
			conn.Close()
		}
	}
	return openPorts, nil
}

func (s *SecurityScannerImpl) CheckSecurityHeaders(ctx context.Context, url string) (map[string]string, error) {
	return map[string]string{}, nil
}

func (s *SecurityScannerImpl) DetectVulnerabilities(ctx context.Context, url string) ([]string, error) {
	return []string{}, nil
}

func (s *SecurityScannerImpl) CalculateSecurityScore(analysis *domain.SecurityAnalysis) int {
	return 80 // Stub score
}

// PerformanceMonitorImpl is a stub implementation
type PerformanceMonitorImpl struct {
	config *config.Config
	logger *logger.Logger
}

func NewPerformanceMonitor(cfg *config.Config, log *logger.Logger) *PerformanceMonitorImpl {
	return &PerformanceMonitorImpl{config: cfg, logger: log}
}

func (p *PerformanceMonitorImpl) MeasureResponseTime(ctx context.Context, url string) (time.Duration, error) {
	return 100 * time.Millisecond, nil
}

func (p *PerformanceMonitorImpl) MeasureLoadTime(ctx context.Context, url string) (*domain.PerformanceMetrics, error) {
	return &domain.PerformanceMetrics{
		ResponseTime:  100 * time.Millisecond,
		FirstByteTime: 50 * time.Millisecond,
		LoadTime:      200 * time.Millisecond,
		PageSize:      1024,
		RequestCount:  10,
	}, nil
}

func (p *PerformanceMonitorImpl) MonitorUptime(ctx context.Context, url string, interval time.Duration) (<-chan bool, error) {
	ch := make(chan bool)
	return ch, nil
}

func (p *PerformanceMonitorImpl) GetPerformanceScore(analysis *domain.PerformanceAnalysis) int {
	return 85 // Stub score
}

// SEOAnalyzerImpl is a stub implementation
type SEOAnalyzerImpl struct {
	config *config.Config
	logger *logger.Logger
}

func NewSEOAnalyzer(cfg *config.Config, log *logger.Logger) *SEOAnalyzerImpl {
	return &SEOAnalyzerImpl{config: cfg, logger: log}
}

func (s *SEOAnalyzerImpl) AnalyzeTitleTag(content string) *domain.SEOElement {
	return &domain.SEOElement{Content: "Sample Title", Length: 12, IsOptimal: true}
}

func (s *SEOAnalyzerImpl) AnalyzeMetaDescription(content string) *domain.SEOElement {
	return &domain.SEOElement{Content: "Sample Description", Length: 18, IsOptimal: true}
}

func (s *SEOAnalyzerImpl) AnalyzeHeadings(html string) map[string]int {
	return map[string]int{"h1": 1, "h2": 3}
}

func (s *SEOAnalyzerImpl) AnalyzeImages(html string) *domain.ImageSEOData {
	return &domain.ImageSEOData{Total: 5, WithAlt: 4, WithoutAlt: 1}
}

func (s *SEOAnalyzerImpl) AnalyzeLinks(html string, baseDomain string) *domain.LinkSEOData {
	return &domain.LinkSEOData{Internal: 10, External: 5, Total: 15}
}

func (s *SEOAnalyzerImpl) ExtractKeywords(content string) []string {
	return []string{"keyword1", "keyword2"}
}

func (s *SEOAnalyzerImpl) CalculateSEOScore(analysis *domain.SEOAnalysis) int {
	return 75 // Stub score
}

func (s *SEOAnalyzerImpl) GetSEORecommendations(analysis *domain.SEOAnalysis) []string {
	return []string{"Improve title tag", "Add more alt text"}
}

// CompetitorAnalyzerImpl is a stub implementation
type CompetitorAnalyzerImpl struct {
	apiClient  *APIClientImpl
	webScraper *WebScraperImpl
	config     *config.Config
	logger     *logger.Logger
}

func NewCompetitorAnalyzer(apiClient *APIClientImpl, webScraper *WebScraperImpl, cfg *config.Config, log *logger.Logger) *CompetitorAnalyzerImpl {
	return &CompetitorAnalyzerImpl{
		apiClient:  apiClient,
		webScraper: webScraper,
		config:     cfg,
		logger:     log,
	}
}

func (c *CompetitorAnalyzerImpl) AnalyzeCompany(ctx context.Context, companyName, sector string) (*domain.CompetitorInfo, error) {
	return &domain.CompetitorInfo{
		CompanyName:  companyName,
		Sector:       sector,
		AnalysisDate: time.Now(),
	}, nil
}

func (c *CompetitorAnalyzerImpl) CompareCompetitors(ctx context.Context, companies []string) (*domain.ComparisonReport, error) {
	return &domain.ComparisonReport{GeneratedAt: time.Now()}, nil
}

func (c *CompetitorAnalyzerImpl) GetMarketInsights(ctx context.Context, sector string) (*domain.MarketInsights, error) {
	return &domain.MarketInsights{Sector: sector, LastUpdated: time.Now()}, nil
}

func (c *CompetitorAnalyzerImpl) TrackCompetitorChanges(ctx context.Context, companyName string) (*domain.CompetitorChanges, error) {
	return &domain.CompetitorChanges{CompanyName: companyName, LastCheck: time.Now()}, nil
}

// ReportGeneratorImpl is a stub implementation
type ReportGeneratorImpl struct {
	config *config.Config
	logger *logger.Logger
}

func NewReportGenerator(cfg *config.Config, log *logger.Logger) *ReportGeneratorImpl {
	return &ReportGeneratorImpl{config: cfg, logger: log}
}

func (r *ReportGeneratorImpl) GenerateJSON(report *domain.AnalysisReport) ([]byte, error) {
	return json.Marshal(report)
}

func (r *ReportGeneratorImpl) GenerateMarkdown(report *domain.AnalysisReport) (string, error) {
	return fmt.Sprintf("# Analysis Report for %s\nGenerated: %s", report.Domain, report.StartTime), nil
}

func (r *ReportGeneratorImpl) GenerateHTML(report *domain.AnalysisReport) (string, error) {
	return fmt.Sprintf("<html><h1>Analysis Report for %s</h1></html>", report.Domain), nil
}

func (r *ReportGeneratorImpl) GeneratePDF(report *domain.AnalysisReport) ([]byte, error) {
	return []byte("PDF content"), nil
}

func (r *ReportGeneratorImpl) SaveReport(report *domain.AnalysisReport, format string, filepath string) error {
	return nil
}

// ReportRepositoryImpl is a stub implementation
type ReportRepositoryImpl struct {
	config *config.Config
	logger *logger.Logger
}

func NewReportRepository(cfg *config.Config, log *logger.Logger) *ReportRepositoryImpl {
	return &ReportRepositoryImpl{config: cfg, logger: log}
}

func (r *ReportRepositoryImpl) Save(ctx context.Context, report *domain.AnalysisReport) error {
	r.logger.Info("Saving report", "id", report.ID, "domain", report.Domain)
	
	// Create output directory for company
	outputDir := fmt.Sprintf("rivals/companies/%s/output", report.Domain)
	if err := r.ensureDir(outputDir); err != nil {
		r.logger.Error("Failed to create output directory", err, "dir", outputDir)
		return err
	}
	
	// Save report as JSON file
	filename := fmt.Sprintf("%s/%s-analysis-%s.json", 
		outputDir, 
		report.AnalysisType, 
		report.StartTime.Format("20060102-150405"))
	
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal report: %w", err)
	}
	
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create report file: %w", err)
	}
	defer file.Close()
	
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("failed to write report: %w", err)
	}
	
	r.logger.Info("Report saved successfully", "file", filename)
	return nil
}

func (r *ReportRepositoryImpl) ensureDir(path string) error {
	return os.MkdirAll(path, 0755)
}

func (r *ReportRepositoryImpl) GetByID(ctx context.Context, id string) (*domain.AnalysisReport, error) {
	return nil, fmt.Errorf("report not found")
}

func (r *ReportRepositoryImpl) GetByDomain(ctx context.Context, domain string, limit int) ([]*domain.AnalysisReport, error) {
	return []*domain.AnalysisReport{}, nil
}

func (r *ReportRepositoryImpl) GetAll(ctx context.Context, limit, offset int) ([]*domain.AnalysisReport, error) {
	return []*domain.AnalysisReport{}, nil
}

func (r *ReportRepositoryImpl) Delete(ctx context.Context, id string) error {
	return nil
}

func (r *ReportRepositoryImpl) Update(ctx context.Context, report *domain.AnalysisReport) error {
	return nil
}

// CacheImpl is a stub implementation
type CacheImpl struct {
	config *config.Config
	logger *logger.Logger
	data   map[string]interface{}
}

func NewCache(cfg *config.Config, log *logger.Logger) *CacheImpl {
	return &CacheImpl{
		config: cfg,
		logger: log,
		data:   make(map[string]interface{}),
	}
}

func (c *CacheImpl) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	c.data[key] = value
	return nil
}

func (c *CacheImpl) Get(ctx context.Context, key string) (interface{}, error) {
	if value, exists := c.data[key]; exists {
		return value, nil
	}
	return nil, fmt.Errorf("key not found")
}

func (c *CacheImpl) Delete(ctx context.Context, key string) error {
	delete(c.data, key)
	return nil
}

func (c *CacheImpl) Exists(ctx context.Context, key string) (bool, error) {
	_, exists := c.data[key]
	return exists, nil
}

func (c *CacheImpl) Clear(ctx context.Context) error {
	c.data = make(map[string]interface{})
	return nil
}