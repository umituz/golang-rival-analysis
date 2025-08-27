package test

import (
	"testing"
	
	"github.com/umituz/golang-rival-analysis/internal/domain"
)

func TestDomainTypes(t *testing.T) {
	// Test that we can create domain types
	website := &domain.Website{
		Domain: "example.com",
	}
	
	if website.Domain != "example.com" {
		t.Errorf("Expected domain to be example.com, got %s", website.Domain)
	}
	
	// Test AnalysisReport
	report := &domain.AnalysisReport{
		Domain: "test.com",
	}
	
	if report.Domain != "test.com" {
		t.Errorf("Expected domain to be test.com, got %s", report.Domain)
	}
}