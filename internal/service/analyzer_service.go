package service

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/umituz/golang-rival-analysis/internal/domain"
)

// AnalyzerService implements domain.AnalyzerService
type AnalyzerService struct {
	httpClient       domain.HTTPClient
	dnsClient        domain.DNSClient
	whoisClient      domain.WHOISClient
	sslClient        domain.SSLClient
	webScraper       domain.WebScraper
	apiClient        domain.APIClient
	securityScanner  domain.SecurityScanner
	performanceMonitor domain.PerformanceMonitor
	seoAnalyzer      domain.SEOAnalyzer
	competitorAnalyzer domain.CompetitorAnalyzer
	reportGenerator  domain.ReportGenerator
	reportRepo       domain.ReportRepository
	logger           domain.Logger
	config           domain.ConfigManager
	cache            domain.CacheManager
	
	// Concurrent processing
	semaphore chan struct{}
	mu        sync.RWMutex
}

// NewAnalyzerService creates a new analyzer service
func NewAnalyzerService(
	httpClient domain.HTTPClient,
	dnsClient domain.DNSClient,
	whoisClient domain.WHOISClient,
	sslClient domain.SSLClient,
	webScraper domain.WebScraper,
	apiClient domain.APIClient,
	securityScanner domain.SecurityScanner,
	performanceMonitor domain.PerformanceMonitor,
	seoAnalyzer domain.SEOAnalyzer,
	competitorAnalyzer domain.CompetitorAnalyzer,
	reportGenerator domain.ReportGenerator,
	reportRepo domain.ReportRepository,
	logger domain.Logger,
	config domain.ConfigManager,
	cache domain.CacheManager,
) *AnalyzerService {
	maxConcurrent := config.GetInt("analysis.max_concurrent")
	if maxConcurrent <= 0 {
		maxConcurrent = 10
	}

	return &AnalyzerService{
		httpClient:         httpClient,
		dnsClient:          dnsClient,
		whoisClient:        whoisClient,
		sslClient:          sslClient,
		webScraper:         webScraper,
		apiClient:          apiClient,
		securityScanner:    securityScanner,
		performanceMonitor: performanceMonitor,
		seoAnalyzer:        seoAnalyzer,
		competitorAnalyzer: competitorAnalyzer,
		reportGenerator:    reportGenerator,
		reportRepo:         reportRepo,
		logger:             logger,
		config:             config,
		cache:              cache,
		semaphore:         make(chan struct{}, maxConcurrent),
	}
}

// AnalyzeWebsite performs comprehensive website analysis
func (s *AnalyzerService) AnalyzeWebsite(ctx context.Context, domain string) (*domain.AnalysisReport, error) {
	// Acquire semaphore for concurrent processing
	select {
	case s.semaphore <- struct{}{}:
		defer func() { <-s.semaphore }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	analysisID := uuid.New().String()
	startTime := time.Now()

	s.logger.Info("Analysis started", "analysis_id", analysisID, "domain", domain, "type", "website")

	report := &domain.AnalysisReport{
		ID:           analysisID,
		Domain:       domain,
		AnalysisType: "website",
		StartTime:    startTime,
		Status:       "running",
	}

	// Check cache first if enabled
	if s.config.GetBool("analysis.enable_caching") {
		if cached, err := s.getCachedReport(ctx, domain, "website"); err == nil && cached != nil {
			s.logger.Info("Using cached website analysis", "domain", domain, "analysis_id", analysisID)
			return cached, nil
		}
	}

	// Run all analyses concurrently
	var wg sync.WaitGroup
	var mu sync.Mutex
	
	// Basic website analysis
	wg.Add(1)
	go func() {
		defer wg.Done()
		if website, err := s.analyzeBasicWebsite(ctx, domain); err == nil {
			mu.Lock()
			report.Website = website
			mu.Unlock()
		} else {
			s.logger.Error("Basic website analysis failed", err, "domain", domain)
		}
	}()

	// SSL analysis
	wg.Add(1)
	go func() {
		defer wg.Done()
		if ssl, err := s.AnalyzeSSL(ctx, domain); err == nil {
			mu.Lock()
			report.SSL = ssl
			mu.Unlock()
		} else {
			s.logger.Error("SSL analysis failed", err, "domain", domain)
		}
	}()

	// DNS analysis
	wg.Add(1)
	go func() {
		defer wg.Done()
		if dns, err := s.AnalyzeDNS(ctx, domain); err == nil {
			mu.Lock()
			report.DNS = dns
			mu.Unlock()
		} else {
			s.logger.Error("DNS analysis failed", err, "domain", domain)
		}
	}()

	// WHOIS analysis
	wg.Add(1)
	go func() {
		defer wg.Done()
		if whois, err := s.AnalyzeWHOIS(ctx, domain); err == nil {
			mu.Lock()
			report.WHOIS = whois
			mu.Unlock()
		} else {
			s.logger.Error("WHOIS analysis failed", err, "domain", domain)
		}
	}()

	// Content analysis
	wg.Add(1)
	go func() {
		defer wg.Done()
		if content, err := s.AnalyzeContent(ctx, domain); err == nil {
			mu.Lock()
			report.Content = content
			mu.Unlock()
		} else {
			s.logger.Error("Content analysis failed", err, "domain", domain)
		}
	}()

	// Security analysis
	wg.Add(1)
	go func() {
		defer wg.Done()
		if security, err := s.AnalyzeSecurity(ctx, domain); err == nil {
			mu.Lock()
			report.Security = security
			mu.Unlock()
		} else {
			s.logger.Error("Security analysis failed", err, "domain", domain)
		}
	}()

	// Performance analysis
	wg.Add(1)
	go func() {
		defer wg.Done()
		if performance, err := s.AnalyzePerformance(ctx, domain); err == nil {
			mu.Lock()
			report.Performance = performance
			mu.Unlock()
		} else {
			s.logger.Error("Performance analysis failed", err, "domain", domain)
		}
	}()

	// SEO analysis
	wg.Add(1)
	go func() {
		defer wg.Done()
		if seo, err := s.AnalyzeSEO(ctx, domain); err == nil {
			mu.Lock()
			report.SEO = seo
			mu.Unlock()
		} else {
			s.logger.Error("SEO analysis failed", err, "domain", domain)
		}
	}()

	// Wait for all analyses to complete
	wg.Wait()

	// Finalize report
	report.EndTime = time.Now()
	report.Duration = report.EndTime.Sub(report.StartTime)
	report.Status = "completed"

	// Save report
	if err := s.reportRepo.Save(ctx, report); err != nil {
		s.logger.Error("Failed to save analysis report", err, "analysis_id", analysisID)
	}

	// Cache report if enabled
	if s.config.GetBool("analysis.enable_caching") {
		cacheTTL := s.config.GetDuration("analysis.cache_ttl")
		if err := s.cacheReport(ctx, domain, "website", report, cacheTTL); err != nil {
			s.logger.Error("Failed to cache analysis report", err, "analysis_id", analysisID)
		}
	}

	s.logger.Info("Analysis completed", "analysis_id", analysisID, "domain", domain, "type", "website", "duration", report.Duration.String())
	return report, nil
}

// AnalyzeCompetitor performs competitor analysis
func (s *AnalyzerService) AnalyzeCompetitor(ctx context.Context, companyName, sector string) (*domain.AnalysisReport, error) {
	select {
	case s.semaphore <- struct{}{}:
		defer func() { <-s.semaphore }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	analysisID := uuid.New().String()
	startTime := time.Now()

	s.logger.Info("Analysis started", "analysis_id", analysisID, "domain", companyName, "type", "competitor")

	// Use competitor analyzer service
	competitor, err := s.competitorAnalyzer.AnalyzeCompany(ctx, companyName, sector)
	if err != nil {
		s.logger.Error("Analysis failed", err, "analysis_id", analysisID, "domain", companyName, "type", "competitor", "duration", time.Since(startTime).String())
		return nil, fmt.Errorf("competitor analysis failed: %w", err)
	}

	report := &domain.AnalysisReport{
		ID:           analysisID,
		Domain:       competitor.Website,
		AnalysisType: "competitor",
		StartTime:    startTime,
		EndTime:      time.Now(),
		Duration:     time.Since(startTime),
		Status:       "completed",
		Competitor:   competitor,
	}

	// Save report
	if err := s.reportRepo.Save(ctx, report); err != nil {
		s.logger.Error("Failed to save competitor analysis report", err, "analysis_id", analysisID)
	}

	s.logger.Info("Analysis completed", "analysis_id", analysisID, "domain", companyName, "type", "competitor", "duration", report.Duration.String())
	return report, nil
}

// AnalyzeSSL analyzes SSL certificate information
func (s *AnalyzerService) AnalyzeSSL(ctx context.Context, domain string) (*domain.SSLInfo, error) {
	return s.sslClient.GetCertificate(ctx, domain, 443)
}

// AnalyzeDNS analyzes DNS records
func (s *AnalyzerService) AnalyzeDNS(ctx context.Context, domain string) (*domain.DNSRecord, error) {
	allRecords, err := s.dnsClient.QueryAll(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("DNS analysis failed: %w", err)
	}

	return &domain.DNSRecord{
		Domain:     domain,
		AllRecords: allRecords,
	}, nil
}

// AnalyzeWHOIS analyzes WHOIS information
func (s *AnalyzerService) AnalyzeWHOIS(ctx context.Context, domain string) (*domain.WHOISInfo, error) {
	return s.whoisClient.Query(ctx, domain)
}

// AnalyzeContent analyzes website content
func (s *AnalyzerService) AnalyzeContent(ctx context.Context, domain string) (*domain.ContentAnalysis, error) {
	url := fmt.Sprintf("https://%s", domain)
	
	// Scrape content
	content, err := s.webScraper.ScrapeContent(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("content scraping failed: %w", err)
	}

	// Detect technologies
	tech, err := s.webScraper.DetectTechnologies(ctx, url)
	if err != nil {
		s.logger.Error("Technology detection failed", err, "domain", domain)
		tech = &domain.TechnologyStack{} // Use empty struct if detection fails
	}

	return &domain.ContentAnalysis{
		MetaDescription: content.Description,
		MetaKeywords:    fmt.Sprintf("%v", content.Keywords),
		LinksCount:      len(content.Links),
		ImagesCount:     len(content.Images),
		SocialLinks:     s.extractSocialLinks(content.Links),
		TextLength:      len(content.Text),
		Languages:       content.Languages,
		Technologies:    tech,
	}, nil
}

// AnalyzeSecurity analyzes website security
func (s *AnalyzerService) AnalyzeSecurity(ctx context.Context, domain string) (*domain.SecurityAnalysis, error) {
	url := fmt.Sprintf("https://%s", domain)
	
	// Check security headers
	headers, err := s.securityScanner.CheckSecurityHeaders(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("security header check failed: %w", err)
	}

	// Scan common ports
	commonPorts := []int{80, 443, 21, 22, 25, 53, 110, 143, 993, 995}
	openPorts, err := s.securityScanner.ScanPorts(ctx, domain, commonPorts)
	if err != nil {
		s.logger.Error("Port scanning failed", err, "domain", domain)
		openPorts = []int{} // Use empty slice if scanning fails
	}

	analysis := &domain.SecurityAnalysis{
		SecurityHeaders: headers,
		OpenPorts:       openPorts,
		UsesHTTPS:       true, // We're using HTTPS URL
	}

	// Calculate security score
	analysis.SecurityScore = s.securityScanner.CalculateSecurityScore(analysis)

	return analysis, nil
}

// AnalyzePerformance analyzes website performance
func (s *AnalyzerService) AnalyzePerformance(ctx context.Context, domain string) (*domain.PerformanceAnalysis, error) {
	url := fmt.Sprintf("https://%s", domain)
	
	// Measure load time and other metrics
	metrics, err := s.performanceMonitor.MeasureLoadTime(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("performance measurement failed: %w", err)
	}

	analysis := &domain.PerformanceAnalysis{
		ResponseTime:     metrics.ResponseTime,
		FirstByteTime:    metrics.FirstByteTime,
		DOMContentLoaded: metrics.DOMContentLoaded,
		LoadTime:         metrics.LoadTime,
		PageSize:         metrics.PageSize,
		ResourcesCount: &domain.ResourceCount{
			Total: metrics.RequestCount,
		},
	}

	// Calculate performance score
	analysis.PerformanceScore = s.performanceMonitor.GetPerformanceScore(analysis)

	return analysis, nil
}

// AnalyzeSEO analyzes website SEO
func (s *AnalyzerService) AnalyzeSEO(ctx context.Context, domain string) (*domain.SEOAnalysis, error) {
	url := fmt.Sprintf("https://%s", domain)
	
	// Get HTML content
	resp, err := s.httpClient.Get(ctx, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch HTML content: %w", err)
	}

	htmlContent := string(resp.Body)

	// Analyze different SEO elements
	title := s.seoAnalyzer.AnalyzeTitleTag(htmlContent)
	metaDesc := s.seoAnalyzer.AnalyzeMetaDescription(htmlContent)
	headings := s.seoAnalyzer.AnalyzeHeadings(htmlContent)
	images := s.seoAnalyzer.AnalyzeImages(htmlContent)
	links := s.seoAnalyzer.AnalyzeLinks(htmlContent, domain)
	keywords := s.seoAnalyzer.ExtractKeywords(htmlContent)

	analysis := &domain.SEOAnalysis{
		Title:           title,
		MetaDescription: metaDesc,
		Headings:        headings,
		Images:          images,
		Links:           links,
		Keywords:        keywords,
		URL: &domain.URLSEOData{
			Length:        len(url),
			ContainsHTTPS: true,
			IsWWW:         false,
		},
	}

	// Calculate SEO score
	analysis.SEOScore = s.seoAnalyzer.CalculateSEOScore(analysis)
	analysis.Recommendations = s.seoAnalyzer.GetSEORecommendations(analysis)

	return analysis, nil
}

// Helper methods

func (s *AnalyzerService) analyzeBasicWebsite(ctx context.Context, domain string) (*domain.Website, error) {
	url := fmt.Sprintf("https://%s", domain)
	
	resp, err := s.httpClient.Get(ctx, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch website: %w", err)
	}

	// Extract title from HTML (simplified)
	title := s.extractTitle(string(resp.Body))

	return &domain.Website{
		URL:          url,
		Domain:       domain,
		Title:        title,
		StatusCode:   resp.StatusCode,
		ResponseTime: resp.ResponseTime,
		PageSize:     resp.Size,
		Headers:      resp.Headers,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}, nil
}

func (s *AnalyzerService) extractTitle(html string) string {
	// Simplified title extraction - in real implementation, use proper HTML parser
	if start := findString(html, "<title>"); start != -1 {
		if end := findString(html[start+7:], "</title>"); end != -1 {
			return html[start+7 : start+7+end]
		}
	}
	return "No title found"
}

func (s *AnalyzerService) extractSocialLinks(links []domain.Link) map[string]string {
	socialLinks := make(map[string]string)
	socialDomains := map[string]string{
		"facebook.com":  "facebook",
		"twitter.com":   "twitter",
		"instagram.com": "instagram",
		"linkedin.com":  "linkedin",
		"youtube.com":   "youtube",
	}

	for _, link := range links {
		for domain, platform := range socialDomains {
			if containsString(link.URL, domain) {
				socialLinks[platform] = link.URL
				break
			}
		}
	}

	return socialLinks
}

func (s *AnalyzerService) getCachedReport(ctx context.Context, domain, analysisType string) (*domain.AnalysisReport, error) {
	key := fmt.Sprintf("analysis:%s:%s", analysisType, domain)
	cached, err := s.cache.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	
	if report, ok := cached.(*domain.AnalysisReport); ok {
		return report, nil
	}
	
	return nil, fmt.Errorf("cached data is not an analysis report")
}

func (s *AnalyzerService) cacheReport(ctx context.Context, domain, analysisType string, report *domain.AnalysisReport, ttl time.Duration) error {
	key := fmt.Sprintf("analysis:%s:%s", analysisType, domain)
	return s.cache.Set(ctx, key, report, ttl)
}

// Utility functions
func findString(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func containsString(s, substr string) bool {
	return findString(s, substr) != -1
}