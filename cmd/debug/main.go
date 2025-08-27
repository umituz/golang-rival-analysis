package main

import (
	"fmt"
	
	"github.com/umituz/golang-rival-analysis/internal/domain"
)

func main() {
	// Test direct usage of domain types
	website := domain.Website{
		Domain: "test.com",
	}
	
	fmt.Printf("Website: %+v\n", website)
	
	report := domain.AnalysisReport{
		Domain: "test.com",
	}
	
	fmt.Printf("Report: %+v\n", report)
	
	fmt.Println("Domain types work correctly!")
}