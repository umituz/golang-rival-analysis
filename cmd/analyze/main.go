package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// Simple website analysis tool
func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run ./cmd/analyze <domain>")
		fmt.Println("Example: go run ./cmd/analyze umituz.com")
		os.Exit(1)
	}

	domain := os.Args[1]
	fmt.Printf("🔍 Analyzing website: %s\n", domain)
	fmt.Println(strings.Repeat("=", 50))

	// Basic website analysis
	analyzeBasicWebsite(domain)
	fmt.Println()

	// DNS analysis
	analyzeDNS(domain)
	fmt.Println()

	// SSL analysis
	analyzeSSL(domain)
	fmt.Println()

	// Performance analysis
	analyzePerformance(domain)
}

func analyzeBasicWebsite(domain string) {
	fmt.Println("📊 Basic Website Analysis:")
	
	url := fmt.Sprintf("https://%s", domain)
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	start := time.Now()
	resp, err := client.Get(url)
	duration := time.Since(start)

	if err != nil {
		fmt.Printf("❌ Error: %v\n", err)
		return
	}
	defer resp.Body.Close()

	fmt.Printf("- Status Code: %d\n", resp.StatusCode)
	fmt.Printf("- Response Time: %s\n", duration)
	fmt.Printf("- Content Length: %d bytes\n", resp.ContentLength)
	fmt.Printf("- Server: %s\n", resp.Header.Get("Server"))
	fmt.Printf("- Content-Type: %s\n", resp.Header.Get("Content-Type"))
}

func analyzeDNS(domain string) {
	fmt.Println("🌐 DNS Analysis:")
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// A record lookup
	ips, err := (&net.Resolver{}).LookupHost(ctx, domain)
	if err != nil {
		fmt.Printf("❌ A Record Error: %v\n", err)
	} else {
		fmt.Printf("- A Records: %v\n", ips)
	}

	// MX record lookup
	mxRecords, err := (&net.Resolver{}).LookupMX(ctx, domain)
	if err != nil {
		fmt.Printf("- MX Records: Error - %v\n", err)
	} else {
		fmt.Printf("- MX Records: %d found\n", len(mxRecords))
		for _, mx := range mxRecords {
			fmt.Printf("  • %s (priority: %d)\n", mx.Host, mx.Pref)
		}
	}

	// TXT record lookup
	txtRecords, err := (&net.Resolver{}).LookupTXT(ctx, domain)
	if err != nil {
		fmt.Printf("- TXT Records: Error - %v\n", err)
	} else {
		fmt.Printf("- TXT Records: %d found\n", len(txtRecords))
		for _, txt := range txtRecords {
			if len(txt) > 100 {
				fmt.Printf("  • %s...\n", txt[:100])
			} else {
				fmt.Printf("  • %s\n", txt)
			}
		}
	}
}

func analyzeSSL(domain string) {
	fmt.Println("🔒 SSL Certificate Analysis:")
	
	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:443", domain), &tls.Config{
		ServerName: domain,
	})
	if err != nil {
		fmt.Printf("❌ SSL Error: %v\n", err)
		return
	}
	defer conn.Close()

	cert := conn.ConnectionState().PeerCertificates[0]
	
	fmt.Printf("- Issuer: %s\n", cert.Issuer.Organization)
	fmt.Printf("- Subject: %s\n", cert.Subject.CommonName)
	fmt.Printf("- Valid From: %s\n", cert.NotBefore.Format("2006-01-02 15:04:05"))
	fmt.Printf("- Valid To: %s\n", cert.NotAfter.Format("2006-01-02 15:04:05"))
	
	daysUntilExpiry := int(time.Until(cert.NotAfter).Hours() / 24)
	fmt.Printf("- Days Until Expiry: %d\n", daysUntilExpiry)
	
	if daysUntilExpiry > 30 {
		fmt.Println("- Status: ✅ Valid")
	} else if daysUntilExpiry > 0 {
		fmt.Println("- Status: ⚠️  Expiring Soon")
	} else {
		fmt.Println("- Status: ❌ Expired")
	}
}

func analyzePerformance(domain string) {
	fmt.Println("⚡ Performance Analysis:")
	
	url := fmt.Sprintf("https://%s", domain)
	client := &http.Client{
		Timeout: 15 * time.Second,
	}

	// Test multiple requests for average
	var totalTime time.Duration
	successCount := 0
	attempts := 3

	for i := 0; i < attempts; i++ {
		start := time.Now()
		resp, err := client.Get(url)
		duration := time.Since(start)

		if err == nil {
			resp.Body.Close()
			totalTime += duration
			successCount++
		}
	}

	if successCount > 0 {
		avgTime := totalTime / time.Duration(successCount)
		fmt.Printf("- Average Response Time: %s (%d successful requests)\n", avgTime, successCount)
		
		if avgTime < 200*time.Millisecond {
			fmt.Println("- Performance: 🚀 Excellent (< 200ms)")
		} else if avgTime < 500*time.Millisecond {
			fmt.Println("- Performance: ✅ Good (< 500ms)")
		} else if avgTime < 1*time.Second {
			fmt.Println("- Performance: ⚠️  Fair (< 1s)")
		} else {
			fmt.Println("- Performance: ❌ Poor (> 1s)")
		}
	} else {
		fmt.Println("- Performance: ❌ All requests failed")
	}

	// Basic port scanning
	fmt.Println("- Open Ports:")
	commonPorts := []int{80, 443, 22, 21}
	for _, port := range commonPorts {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", domain, port), 2*time.Second)
		if err == nil {
			conn.Close()
			portName := getPortName(port)
			fmt.Printf("  • Port %d (%s): ✅ Open\n", port, portName)
		}
	}
}

func getPortName(port int) string {
	switch port {
	case 80:
		return "HTTP"
	case 443:
		return "HTTPS"
	case 22:
		return "SSH"
	case 21:
		return "FTP"
	default:
		return "Unknown"
	}
}