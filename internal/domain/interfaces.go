package domain

import (
	"context"
	"time"
)

// AnalyzerService defines the interface for analysis operations
type AnalyzerService interface {
	AnalyzeWebsite(ctx context.Context, domain string) (*AnalysisReport, error)
	AnalyzeCompetitor(ctx context.Context, companyName, sector string) (*AnalysisReport, error)
	AnalyzeSSL(ctx context.Context, domain string) (*SSLInfo, error)
	AnalyzeDNS(ctx context.Context, domain string) (*DNSRecord, error)
	AnalyzeWHOIS(ctx context.Context, domain string) (*WHOISInfo, error)
	AnalyzeContent(ctx context.Context, domain string) (*ContentAnalysis, error)
	AnalyzeSecurity(ctx context.Context, domain string) (*SecurityAnalysis, error)
	AnalyzePerformance(ctx context.Context, domain string) (*PerformanceAnalysis, error)
	AnalyzeSEO(ctx context.Context, domain string) (*SEOAnalysis, error)
}

// WebsiteRepository defines the interface for website data operations
type WebsiteRepository interface {
	Save(ctx context.Context, website *Website) error
	GetByDomain(ctx context.Context, domain string) (*Website, error)
	GetAll(ctx context.Context, limit, offset int) ([]*Website, error)
	Delete(ctx context.Context, domain string) error
	Update(ctx context.Context, website *Website) error
}

// ReportRepository defines the interface for report data operations
type ReportRepository interface {
	Save(ctx context.Context, report *AnalysisReport) error
	GetByID(ctx context.Context, id string) (*AnalysisReport, error)
	GetByDomain(ctx context.Context, domain string, limit int) ([]*AnalysisReport, error)
	GetAll(ctx context.Context, limit, offset int) ([]*AnalysisReport, error)
	Delete(ctx context.Context, id string) error
	Update(ctx context.Context, report *AnalysisReport) error
}

// HTTPClient defines the interface for HTTP operations
type HTTPClient interface {
	Get(ctx context.Context, url string, headers map[string]string) (*HTTPResponse, error)
	Post(ctx context.Context, url string, body []byte, headers map[string]string) (*HTTPResponse, error)
	GetWithTimeout(ctx context.Context, url string, timeout time.Duration) (*HTTPResponse, error)
}

// HTTPResponse represents HTTP response data
type HTTPResponse struct {
	StatusCode   int
	Headers      map[string]string
	Body         []byte
	ResponseTime time.Duration
	Size         int64
}

// DNSClient defines the interface for DNS operations
type DNSClient interface {
	QueryA(ctx context.Context, domain string) ([]string, error)
	QueryAAAA(ctx context.Context, domain string) ([]string, error)
	QueryMX(ctx context.Context, domain string) ([]string, error)
	QueryNS(ctx context.Context, domain string) ([]string, error)
	QueryTXT(ctx context.Context, domain string) ([]string, error)
	QuerySOA(ctx context.Context, domain string) ([]string, error)
	QueryCNAME(ctx context.Context, domain string) ([]string, error)
	QueryAll(ctx context.Context, domain string) (map[string][]string, error)
}

// WHOISClient defines the interface for WHOIS operations
type WHOISClient interface {
	Query(ctx context.Context, domain string) (*WHOISInfo, error)
	QueryRaw(ctx context.Context, domain string) (string, error)
}

// SSLClient defines the interface for SSL certificate operations
type SSLClient interface {
	GetCertificate(ctx context.Context, domain string, port int) (*SSLInfo, error)
	ValidateCertificate(ctx context.Context, domain string) (*SSLValidationResult, error)
	CheckExpiry(ctx context.Context, domain string) (time.Time, error)
}

// SSLValidationResult represents SSL certificate validation results
type SSLValidationResult struct {
	IsValid      bool
	ErrorMessage string
	Chain        []*SSLInfo
	IsSelfSigned bool
	IsExpired    bool
}

// WebScraper defines the interface for web scraping operations
type WebScraper interface {
	ScrapeContent(ctx context.Context, url string) (*ScrapedContent, error)
	ExtractLinks(ctx context.Context, url string) ([]string, error)
	ExtractImages(ctx context.Context, url string) ([]string, error)
	ExtractText(ctx context.Context, url string) (string, error)
	DetectTechnologies(ctx context.Context, url string) (*TechnologyStack, error)
}

// ScrapedContent represents scraped web content
type ScrapedContent struct {
	URL         string
	Title       string
	Description string
	Keywords    []string
	Headings    map[string][]string
	Links       []Link
	Images      []Image
	Text        string
	Languages   []string
}

// Link represents a link found on a webpage
type Link struct {
	URL      string `json:"url"`
	Text     string `json:"text"`
	IsInternal bool `json:"is_internal"`
	IsExternal bool `json:"is_external"`
}

// Image represents an image found on a webpage
type Image struct {
	URL    string `json:"url"`
	Alt    string `json:"alt"`
	Width  int    `json:"width"`
	Height int    `json:"height"`
}

// APIClient defines the interface for external API operations
type APIClient interface {
	GetSimilarWebData(ctx context.Context, domain string) (*WebsiteAnalysis, error)
	GetLinkedInData(ctx context.Context, companyName string) (*SocialPlatformData, error)
	GetCrunchbaseData(ctx context.Context, companyName string) (*MarketAnalysis, error)
	GetTwitterData(ctx context.Context, username string) (*SocialPlatformData, error)
	GetInstagramData(ctx context.Context, username string) (*SocialPlatformData, error)
}

// Logger defines the interface for logging operations
type Logger interface {
	Info(msg string, fields ...interface{})
	Error(msg string, err error, fields ...interface{})
	Warn(msg string, fields ...interface{})
	Debug(msg string, fields ...interface{})
	Fatal(msg string, err error, fields ...interface{})
}

// ConfigManager defines the interface for configuration management
type ConfigManager interface {
	GetString(key string) string
	GetInt(key string) int
	GetBool(key string) bool
	GetDuration(key string) time.Duration
	GetAPIKey(service string) string
}

// CacheManager defines the interface for caching operations
type CacheManager interface {
	Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error
	Get(ctx context.Context, key string) (interface{}, error)
	Delete(ctx context.Context, key string) error
	Exists(ctx context.Context, key string) (bool, error)
	Clear(ctx context.Context) error
}

// ReportGenerator defines the interface for report generation
type ReportGenerator interface {
	GenerateJSON(report *AnalysisReport) ([]byte, error)
	GenerateMarkdown(report *AnalysisReport) (string, error)
	GenerateHTML(report *AnalysisReport) (string, error)
	GeneratePDF(report *AnalysisReport) ([]byte, error)
	SaveReport(report *AnalysisReport, format string, filepath string) error
}

// SecurityScanner defines the interface for security scanning operations
type SecurityScanner interface {
	ScanPorts(ctx context.Context, domain string, ports []int) ([]int, error)
	CheckSecurityHeaders(ctx context.Context, url string) (map[string]string, error)
	DetectVulnerabilities(ctx context.Context, url string) ([]string, error)
	CalculateSecurityScore(analysis *SecurityAnalysis) int
}

// PerformanceMonitor defines the interface for performance monitoring
type PerformanceMonitor interface {
	MeasureResponseTime(ctx context.Context, url string) (time.Duration, error)
	MeasureLoadTime(ctx context.Context, url string) (*PerformanceMetrics, error)
	MonitorUptime(ctx context.Context, url string, interval time.Duration) (<-chan bool, error)
	GetPerformanceScore(analysis *PerformanceAnalysis) int
}

// PerformanceMetrics represents detailed performance metrics
type PerformanceMetrics struct {
	ResponseTime     time.Duration
	FirstByteTime    time.Duration
	DOMContentLoaded time.Duration
	LoadTime         time.Duration
	PageSize         int64
	RequestCount     int
}

// SEOAnalyzer defines the interface for SEO analysis operations
type SEOAnalyzer interface {
	AnalyzeTitleTag(content string) *SEOElement
	AnalyzeMetaDescription(content string) *SEOElement
	AnalyzeHeadings(html string) map[string]int
	AnalyzeImages(html string) *ImageSEOData
	AnalyzeLinks(html string, baseDomain string) *LinkSEOData
	ExtractKeywords(content string) []string
	CalculateSEOScore(analysis *SEOAnalysis) int
	GetSEORecommendations(analysis *SEOAnalysis) []string
}

// CompetitorAnalyzer defines the interface for competitor analysis
type CompetitorAnalyzer interface {
	AnalyzeCompany(ctx context.Context, companyName, sector string) (*CompetitorInfo, error)
	CompareCompetitors(ctx context.Context, companies []string) (*ComparisonReport, error)
	GetMarketInsights(ctx context.Context, sector string) (*MarketInsights, error)
	TrackCompetitorChanges(ctx context.Context, companyName string) (*CompetitorChanges, error)
}

// ComparisonReport represents competitor comparison results
type ComparisonReport struct {
	Companies    []*CompetitorInfo `json:"companies"`
	Metrics      *ComparisonMetrics `json:"metrics"`
	Rankings     map[string]int     `json:"rankings"`
	Insights     []string           `json:"insights"`
	GeneratedAt  time.Time          `json:"generated_at"`
}

// ComparisonMetrics represents comparison metrics between competitors
type ComparisonMetrics struct {
	TrafficComparison  map[string]int64   `json:"traffic_comparison"`
	SocialComparison   map[string]int64   `json:"social_comparison"`
	FundingComparison  map[string]int64   `json:"funding_comparison"`
	EmployeeComparison map[string]int     `json:"employee_comparison"`
}

// MarketInsights represents market analysis insights
type MarketInsights struct {
	Sector          string                 `json:"sector"`
	MarketSize      int64                  `json:"market_size"`
	GrowthRate      float64                `json:"growth_rate"`
	TopPlayers      []string               `json:"top_players"`
	Trends          []string               `json:"trends"`
	Opportunities   []string               `json:"opportunities"`
	Threats         []string               `json:"threats"`
	KeyMetrics      map[string]interface{} `json:"key_metrics"`
	LastUpdated     time.Time              `json:"last_updated"`
}

// CompetitorChanges represents tracked changes in competitor data
type CompetitorChanges struct {
	CompanyName     string                 `json:"company_name"`
	Changes         []Change               `json:"changes"`
	LastCheck       time.Time              `json:"last_check"`
	SignificantChanges bool                `json:"significant_changes"`
}

// Change represents a tracked change
type Change struct {
	Field       string      `json:"field"`
	OldValue    interface{} `json:"old_value"`
	NewValue    interface{} `json:"new_value"`
	ChangedAt   time.Time   `json:"changed_at"`
	Significance string     `json:"significance"`
}