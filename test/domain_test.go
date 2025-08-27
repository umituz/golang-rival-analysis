package test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/umituz/golang-rival-analysis/internal/domain"
)

func TestWebsiteEntity(t *testing.T) {
	website := &domain.Website{
		URL:          "https://example.com",
		Domain:       "example.com",
		Title:        "Example Site",
		StatusCode:   200,
		ResponseTime: 100 * time.Millisecond,
		PageSize:     1024,
		Headers:      map[string]string{"Content-Type": "text/html"},
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	assert.Equal(t, "https://example.com", website.URL)
	assert.Equal(t, "example.com", website.Domain)
	assert.Equal(t, "Example Site", website.Title)
	assert.Equal(t, 200, website.StatusCode)
	assert.Equal(t, int64(1024), website.PageSize)
}

func TestSSLInfo(t *testing.T) {
	ssl := &domain.SSLInfo{
		Domain:       "example.com",
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		SerialNumber: "123456",
		Version:      3,
		IsValid:      true,
		DaysToExpiry: 365,
	}

	assert.Equal(t, "example.com", ssl.Domain)
	assert.True(t, ssl.IsValid)
	assert.Equal(t, 365, ssl.DaysToExpiry)
}

func TestDNSRecord(t *testing.T) {
	dns := &domain.DNSRecord{
		Domain:     "example.com",
		RecordType: "A",
		Records:    []string{"1.2.3.4"},
		TTL:        300,
		AllRecords: map[string][]string{
			"A":  {"1.2.3.4"},
			"MX": {"mail.example.com"},
		},
	}

	assert.Equal(t, "example.com", dns.Domain)
	assert.Equal(t, "A", dns.RecordType)
	assert.Contains(t, dns.Records, "1.2.3.4")
	assert.Equal(t, uint32(300), dns.TTL)
}

func TestAnalysisReport(t *testing.T) {
	startTime := time.Now()
	endTime := startTime.Add(5 * time.Second)

	report := &domain.AnalysisReport{
		ID:           "test-123",
		Domain:       "example.com",
		AnalysisType: "website",
		StartTime:    startTime,
		EndTime:      endTime,
		Duration:     5 * time.Second,
		Status:       "completed",
		Website: &domain.Website{
			Domain: "example.com",
		},
	}

	assert.Equal(t, "test-123", report.ID)
	assert.Equal(t, "example.com", report.Domain)
	assert.Equal(t, "website", report.AnalysisType)
	assert.Equal(t, "completed", report.Status)
	assert.NotNil(t, report.Website)
	assert.Equal(t, 5*time.Second, report.Duration)
}

func TestCompetitorInfo(t *testing.T) {
	competitor := &domain.CompetitorInfo{
		CompanyName:  "Test Corp",
		Sector:       "Technology",
		Website:      "https://testcorp.com",
		SocialMedia:  map[string]string{"twitter": "@testcorp"},
		AnalysisDate: time.Now(),
	}

	assert.Equal(t, "Test Corp", competitor.CompanyName)
	assert.Equal(t, "Technology", competitor.Sector)
	assert.Equal(t, "https://testcorp.com", competitor.Website)
	assert.Contains(t, competitor.SocialMedia, "twitter")
}

func TestContentAnalysis(t *testing.T) {
	content := &domain.ContentAnalysis{
		MetaDescription: "Test description",
		MetaKeywords:    "test, keywords",
		LinksCount:      50,
		ImagesCount:     10,
		ScriptsCount:    5,
		StylesCount:     3,
		SocialLinks:     map[string]string{"facebook": "https://facebook.com/test"},
		ParagraphsCount: 20,
		HeadingsCount:   5,
		TextLength:      2000,
		Languages:       []string{"en"},
		Technologies: &domain.TechnologyStack{
			WebServer:            "nginx",
			ProgrammingLanguages: []string{"Go", "JavaScript"},
			Frameworks:           []string{"Gin", "React"},
			Analytics:            []string{"Google Analytics"},
			CDN:                  []string{"Cloudflare"},
		},
	}

	assert.Equal(t, "Test description", content.MetaDescription)
	assert.Equal(t, 50, content.LinksCount)
	assert.Equal(t, 10, content.ImagesCount)
	assert.Contains(t, content.Languages, "en")
	assert.NotNil(t, content.Technologies)
	assert.Equal(t, "nginx", content.Technologies.WebServer)
}

func TestSecurityAnalysis(t *testing.T) {
	security := &domain.SecurityAnalysis{
		SecurityHeaders: map[string]string{
			"X-Frame-Options":        "DENY",
			"X-Content-Type-Options": "nosniff",
		},
		OpenPorts:     []int{80, 443},
		UsesHTTPS:     true,
		SecurityScore: 85,
		Vulnerabilities: []string{},
	}

	assert.True(t, security.UsesHTTPS)
	assert.Equal(t, 85, security.SecurityScore)
	assert.Contains(t, security.OpenPorts, 443)
	assert.Equal(t, "DENY", security.SecurityHeaders["X-Frame-Options"])
	assert.Empty(t, security.Vulnerabilities)
}

func TestPerformanceAnalysis(t *testing.T) {
	performance := &domain.PerformanceAnalysis{
		ResponseTime:     100 * time.Millisecond,
		PageSize:         1024,
		LoadTime:         500 * time.Millisecond,
		FirstByteTime:    50 * time.Millisecond,
		DOMContentLoaded: 300 * time.Millisecond,
		PerformanceScore: 90,
		ResourcesCount: &domain.ResourceCount{
			Images:      5,
			Scripts:     3,
			Stylesheets: 2,
			Fonts:       1,
			Videos:      0,
			Total:       11,
		},
	}

	assert.Equal(t, 100*time.Millisecond, performance.ResponseTime)
	assert.Equal(t, int64(1024), performance.PageSize)
	assert.Equal(t, 90, performance.PerformanceScore)
	assert.NotNil(t, performance.ResourcesCount)
	assert.Equal(t, 11, performance.ResourcesCount.Total)
}

func TestSEOAnalysis(t *testing.T) {
	seo := &domain.SEOAnalysis{
		Title: &domain.SEOElement{
			Content:   "Test Page Title",
			Length:    15,
			IsOptimal: true,
		},
		MetaDescription: &domain.SEOElement{
			Content:   "This is a test page description",
			Length:    32,
			IsOptimal: false,
		},
		Headings: map[string]int{
			"h1": 1,
			"h2": 3,
			"h3": 5,
		},
		Images: &domain.ImageSEOData{
			Total:      10,
			WithAlt:    8,
			WithoutAlt: 2,
		},
		Links: &domain.LinkSEOData{
			Internal: 20,
			External: 5,
			Total:    25,
		},
		Keywords:        []string{"test", "page", "seo"},
		SEOScore:        75,
		Issues:          []string{"Missing alt tags", "Meta description too short"},
		Recommendations: []string{"Add alt text to images", "Extend meta description"},
	}

	assert.NotNil(t, seo.Title)
	assert.Equal(t, "Test Page Title", seo.Title.Content)
	assert.True(t, seo.Title.IsOptimal)
	assert.Equal(t, 75, seo.SEOScore)
	assert.Contains(t, seo.Keywords, "test")
	assert.Contains(t, seo.Issues, "Missing alt tags")
	assert.NotNil(t, seo.Images)
	assert.Equal(t, 8, seo.Images.WithAlt)
}