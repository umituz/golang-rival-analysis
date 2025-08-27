package domain

import (
	"time"
)

// Website represents a website being analyzed
type Website struct {
	URL          string            `json:"url"`
	Domain       string            `json:"domain"`
	Title        string            `json:"title"`
	StatusCode   int               `json:"status_code"`
	ResponseTime time.Duration     `json:"response_time"`
	PageSize     int64             `json:"page_size"`
	Headers      map[string]string `json:"headers"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
}

// SSLInfo represents SSL certificate information
type SSLInfo struct {
	Domain       string            `json:"domain"`
	Issuer       map[string]string `json:"issuer"`
	Subject      map[string]string `json:"subject"`
	NotBefore    time.Time         `json:"not_before"`
	NotAfter     time.Time         `json:"not_after"`
	SerialNumber string            `json:"serial_number"`
	Version      int               `json:"version"`
	IsValid      bool              `json:"is_valid"`
	DaysToExpiry int               `json:"days_to_expiry"`
}

// DNSRecord represents DNS record information
type DNSRecord struct {
	Domain     string              `json:"domain"`
	RecordType string              `json:"record_type"`
	Records    []string            `json:"records"`
	TTL        uint32              `json:"ttl"`
	AllRecords map[string][]string `json:"all_records"`
}

// WHOISInfo represents WHOIS domain information
type WHOISInfo struct {
	Domain         string    `json:"domain"`
	Registrar      string    `json:"registrar"`
	CreationDate   time.Time `json:"creation_date"`
	ExpirationDate time.Time `json:"expiration_date"`
	NameServers    []string  `json:"name_servers"`
	Status         []string  `json:"status"`
	Organization   string    `json:"organization"`
	Country        string    `json:"country"`
	Email          string    `json:"email"`
}

// CompetitorInfo represents competitor analysis data
type CompetitorInfo struct {
	CompanyName   string                 `json:"company_name"`
	Sector        string                 `json:"sector"`
	Website       string                 `json:"website"`
	SocialMedia   map[string]string      `json:"social_media"`
	WebsiteData   *WebsiteAnalysis       `json:"website_data,omitempty"`
	SocialData    *SocialMediaAnalysis   `json:"social_data,omitempty"`
	MarketData    *MarketAnalysis        `json:"market_data,omitempty"`
	AnalysisDate  time.Time              `json:"analysis_date"`
}

// WebsiteAnalysis represents website traffic and performance data
type WebsiteAnalysis struct {
	MonthlyVisits      int64   `json:"monthly_visits"`
	AverageVisitTime   float64 `json:"average_visit_time"`
	BounceRate         float64 `json:"bounce_rate"`
	PageViews          int64   `json:"page_views"`
	UniqueVisitors     int64   `json:"unique_visitors"`
	TrafficSources     map[string]float64 `json:"traffic_sources"`
	TopCountries       map[string]float64 `json:"top_countries"`
	MobileTrafficShare float64 `json:"mobile_traffic_share"`
}

// SocialMediaAnalysis represents social media presence data
type SocialMediaAnalysis struct {
	Platforms map[string]*SocialPlatformData `json:"platforms"`
	TotalFollowers int64 `json:"total_followers"`
	EngagementRate float64 `json:"engagement_rate"`
}

// SocialPlatformData represents data for a specific social media platform
type SocialPlatformData struct {
	Platform        string  `json:"platform"`
	Username        string  `json:"username"`
	URL             string  `json:"url"`
	Followers       int64   `json:"followers"`
	Following       int64   `json:"following"`
	Posts           int64   `json:"posts"`
	EngagementRate  float64 `json:"engagement_rate"`
	Verified        bool    `json:"verified"`
	LastPostDate    *time.Time `json:"last_post_date"`
}

// MarketAnalysis represents market positioning and financial data
type MarketAnalysis struct {
	CompanyType        string  `json:"company_type"`
	Founded            string  `json:"founded"`
	EmployeeCount      string  `json:"employee_count"`
	TotalFundingUSD    int64   `json:"total_funding_usd"`
	LastFundingDate    *time.Time `json:"last_funding_date"`
	LastFundingAmount  int64   `json:"last_funding_amount"`
	InvestorsCount     int     `json:"investors_count"`
	CompetitorsCount   int     `json:"competitors_count"`
	MarketShare        float64 `json:"market_share"`
	Revenue            int64   `json:"revenue"`
	RevenueGrowth      float64 `json:"revenue_growth"`
}

// ContentAnalysis represents website content analysis
type ContentAnalysis struct {
	MetaDescription    string            `json:"meta_description"`
	MetaKeywords       string            `json:"meta_keywords"`
	LinksCount         int               `json:"links_count"`
	ImagesCount        int               `json:"images_count"`
	ScriptsCount       int               `json:"scripts_count"`
	StylesCount        int               `json:"styles_count"`
	SocialLinks        map[string]string `json:"social_links"`
	ParagraphsCount    int               `json:"paragraphs_count"`
	HeadingsCount      int               `json:"headings_count"`
	TextLength         int               `json:"text_length"`
	Languages          []string          `json:"languages"`
	Technologies       *TechnologyStack  `json:"technologies"`
}

// TechnologyStack represents detected technologies
type TechnologyStack struct {
	WebServer            string   `json:"web_server"`
	ProgrammingLanguages []string `json:"programming_languages"`
	Frameworks           []string `json:"frameworks"`
	Analytics            []string `json:"analytics"`
	CDN                  []string `json:"cdn"`
	CMS                  []string `json:"cms"`
	JavaScriptLibraries  []string `json:"javascript_libraries"`
	DatabaseSystems      []string `json:"database_systems"`
}

// SecurityAnalysis represents security assessment results
type SecurityAnalysis struct {
	SecurityHeaders map[string]string `json:"security_headers"`
	OpenPorts       []int             `json:"open_ports"`
	UsesHTTPS       bool              `json:"uses_https"`
	SecurityScore   int               `json:"security_score"`
	Vulnerabilities []string          `json:"vulnerabilities"`
	Certificates    []*SSLInfo        `json:"certificates"`
}

// PerformanceAnalysis represents performance metrics
type PerformanceAnalysis struct {
	ResponseTime     time.Duration `json:"response_time"`
	PageSize         int64         `json:"page_size"`
	ResourcesCount   *ResourceCount `json:"resources_count"`
	LoadTime         time.Duration `json:"load_time"`
	FirstByteTime    time.Duration `json:"first_byte_time"`
	DOMContentLoaded time.Duration `json:"dom_content_loaded"`
	PerformanceScore int           `json:"performance_score"`
}

// ResourceCount represents count of different resource types
type ResourceCount struct {
	Images      int `json:"images"`
	Scripts     int `json:"scripts"`
	Stylesheets int `json:"stylesheets"`
	Fonts       int `json:"fonts"`
	Videos      int `json:"videos"`
	Total       int `json:"total"`
}

// SEOAnalysis represents SEO analysis results
type SEOAnalysis struct {
	Title           *SEOElement       `json:"title"`
	MetaDescription *SEOElement       `json:"meta_description"`
	Headings        map[string]int    `json:"headings"`
	Images          *ImageSEOData     `json:"images"`
	Links           *LinkSEOData      `json:"links"`
	URL             *URLSEOData       `json:"url"`
	Keywords        []string          `json:"keywords"`
	SEOScore        int               `json:"seo_score"`
	Issues          []string          `json:"issues"`
	Recommendations []string          `json:"recommendations"`
}

// SEOElement represents SEO-related element data
type SEOElement struct {
	Content  string `json:"content"`
	Length   int    `json:"length"`
	IsOptimal bool   `json:"is_optimal"`
}

// ImageSEOData represents image SEO analysis
type ImageSEOData struct {
	Total      int `json:"total"`
	WithAlt    int `json:"with_alt"`
	WithoutAlt int `json:"without_alt"`
}

// LinkSEOData represents link SEO analysis
type LinkSEOData struct {
	Internal int `json:"internal"`
	External int `json:"external"`
	Total    int `json:"total"`
}

// URLSEOData represents URL SEO analysis
type URLSEOData struct {
	Length       int  `json:"length"`
	ContainsHTTPS bool `json:"contains_https"`
	IsWWW        bool `json:"is_www"`
	HasParameters bool `json:"has_parameters"`
}

// AnalysisReport represents the complete analysis report
type AnalysisReport struct {
	ID            string                `json:"id"`
	Domain        string                `json:"domain"`
	AnalysisType  string                `json:"analysis_type"`
	StartTime     time.Time             `json:"start_time"`
	EndTime       time.Time             `json:"end_time"`
	Duration      time.Duration         `json:"duration"`
	Status        string                `json:"status"`
	
	// Analysis Results
	Website     *Website             `json:"website,omitempty"`
	SSL         *SSLInfo             `json:"ssl,omitempty"`
	DNS         *DNSRecord           `json:"dns,omitempty"`
	WHOIS       *WHOISInfo           `json:"whois,omitempty"`
	Content     *ContentAnalysis     `json:"content,omitempty"`
	Security    *SecurityAnalysis    `json:"security,omitempty"`
	Performance *PerformanceAnalysis `json:"performance,omitempty"`
	SEO         *SEOAnalysis         `json:"seo,omitempty"`
	Competitor  *CompetitorInfo      `json:"competitor,omitempty"`
	
	// Metadata
	RequestedBy string                `json:"requested_by,omitempty"`
	Notes       string                `json:"notes,omitempty"`
	Tags        []string              `json:"tags,omitempty"`
	Error       string                `json:"error,omitempty"`
}