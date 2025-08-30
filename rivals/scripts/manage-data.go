package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DataManager handles rivals analysis data management operations
type DataManager struct {
	RivalsPath string
}

// CompanyProfile represents the structure for company profile data
type CompanyProfile struct {
	Name         string            `json:"name"`
	Domain       string            `json:"domain"`
	Sector       string            `json:"sector"`
	LastAnalyzed time.Time         `json:"last_analyzed"`
	DataFiles    map[string]string `json:"data_files"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// SectorSummary represents sector analysis summary
type SectorSummary struct {
	Name            string    `json:"name"`
	CompanyCount    int       `json:"company_count"`
	LastUpdated     time.Time `json:"last_updated"`
	TopCompanies    []string  `json:"top_companies"`
	TotalAnalyses   int       `json:"total_analyses"`
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	// Get the rivals directory path (parent of scripts directory)
	scriptDir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		log.Fatal("Failed to get script directory:", err)
	}
	rivalsPath := filepath.Dir(scriptDir)

	dm := &DataManager{RivalsPath: rivalsPath}

	command := os.Args[1]
	switch command {
	case "list":
		if len(os.Args) < 3 {
			dm.listAll()
		} else {
			dm.listByType(os.Args[2])
		}
	case "summary":
		dm.generateSummary()
	case "cleanup":
		dm.performCleanup()
	case "export":
		if len(os.Args) < 3 {
			fmt.Println("Export command requires format: go run manage-data.go export [json|csv]")
			os.Exit(1)
		}
		dm.exportData(os.Args[2])
	case "validate":
		dm.validateData()
	case "backup":
		dm.createBackup()
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Rivals Data Management Utility")
	fmt.Println("")
	fmt.Println("Usage:")
	fmt.Println("  go run manage-data.go <command> [options]")
	fmt.Println("")
	fmt.Println("Commands:")
	fmt.Println("  list [type]       List all data or filter by type (companies|sectors|comparisons)")
	fmt.Println("  summary          Generate data summary report") 
	fmt.Println("  cleanup          Clean up old and invalid data")
	fmt.Println("  export <format>  Export data in specified format (json|csv)")
	fmt.Println("  validate         Validate data integrity")
	fmt.Println("  backup           Create backup of all data")
	fmt.Println("")
	fmt.Println("Examples:")
	fmt.Println("  go run manage-data.go list companies")
	fmt.Println("  go run manage-data.go summary")
	fmt.Println("  go run manage-data.go export json")
}

func (dm *DataManager) listAll() {
	fmt.Println("📊 Rivals Analysis Data Overview")
	fmt.Println("=" + strings.Repeat("=", 40))
	
	dm.listByType("companies")
	dm.listByType("sectors")
	dm.listByType("comparisons")
	dm.listByType("historical")
}

func (dm *DataManager) listByType(dataType string) {
	dirPath := filepath.Join(dm.RivalsPath, dataType)
	
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		fmt.Printf("📁 %s: Directory does not exist\n", strings.Title(dataType))
		return
	}

	var count int
	var totalSize int64

	err := filepath.WalkDir(dirPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			count++
			if info, err := d.Info(); err == nil {
				totalSize += info.Size()
			}
		}
		return nil
	})

	if err != nil {
		fmt.Printf("❌ Error reading %s directory: %v\n", dataType, err)
		return
	}

	fmt.Printf("📁 %s: %d files (%.2f MB)\n", 
		strings.Title(dataType), 
		count, 
		float64(totalSize)/(1024*1024))

	// Show specific details for companies
	if dataType == "companies" {
		dm.listCompanies(dirPath)
	}
}

func (dm *DataManager) listCompanies(companiesPath string) {
	entries, err := os.ReadDir(companiesPath)
	if err != nil {
		return
	}

	fmt.Println("   Companies:")
	for _, entry := range entries {
		if entry.IsDir() {
			profilePath := filepath.Join(companiesPath, entry.Name(), "profile.json")
			if profile := dm.loadCompanyProfile(profilePath); profile != nil {
				fmt.Printf("   • %s (%s) - %s\n", 
					profile.Name, 
					profile.Sector,
					profile.LastAnalyzed.Format("2006-01-02"))
			} else {
				fmt.Printf("   • %s (no profile)\n", entry.Name())
			}
		}
	}
}

func (dm *DataManager) loadCompanyProfile(profilePath string) *CompanyProfile {
	data, err := os.ReadFile(profilePath)
	if err != nil {
		return nil
	}

	var profile CompanyProfile
	if err := json.Unmarshal(data, &profile); err != nil {
		return nil
	}

	return &profile
}

func (dm *DataManager) generateSummary() {
	fmt.Println("📈 Rivals Analysis Data Summary")
	fmt.Println("=" + strings.Repeat("=", 50))
	fmt.Printf("Generated: %s\n\n", time.Now().Format("2006-01-02 15:04:05"))

	// Company statistics
	companiesPath := filepath.Join(dm.RivalsPath, "companies")
	companyStats := dm.getCompanyStats(companiesPath)
	fmt.Printf("👥 Companies Analyzed: %d\n", companyStats.Total)
	fmt.Printf("🏢 Sectors Covered: %d\n", len(companyStats.Sectors))
	fmt.Printf("📊 Most Active Sector: %s (%d companies)\n", 
		companyStats.TopSector, companyStats.TopSectorCount)
	fmt.Printf("🗓️  Most Recent Analysis: %s\n\n", 
		companyStats.LatestAnalysis.Format("2006-01-02"))

	// Sector breakdown
	fmt.Println("🏭 Sector Breakdown:")
	for sector, count := range companyStats.Sectors {
		fmt.Printf("   • %s: %d companies\n", sector, count)
	}

	// Comparison statistics
	comparisonsPath := filepath.Join(dm.RivalsPath, "comparisons")
	if comparisonCount := dm.countFiles(comparisonsPath); comparisonCount > 0 {
		fmt.Printf("\n🔄 Comparisons Generated: %d\n", comparisonCount)
	}

	// Historical data
	historicalPath := filepath.Join(dm.RivalsPath, "historical")
	if historicalCount := dm.countFiles(historicalPath); historicalCount > 0 {
		fmt.Printf("📜 Historical Records: %d\n", historicalCount)
	}

	// Storage usage
	totalSize := dm.calculateTotalSize(dm.RivalsPath)
	fmt.Printf("\n💾 Total Storage Used: %.2f MB\n", float64(totalSize)/(1024*1024))
}

type CompanyStats struct {
	Total           int
	Sectors         map[string]int
	TopSector       string
	TopSectorCount  int
	LatestAnalysis  time.Time
}

func (dm *DataManager) getCompanyStats(companiesPath string) CompanyStats {
	stats := CompanyStats{
		Sectors: make(map[string]int),
	}

	entries, err := os.ReadDir(companiesPath)
	if err != nil {
		return stats
	}

	for _, entry := range entries {
		if entry.IsDir() {
			stats.Total++
			profilePath := filepath.Join(companiesPath, entry.Name(), "profile.json")
			if profile := dm.loadCompanyProfile(profilePath); profile != nil {
				// Count sectors
				if profile.Sector != "" {
					stats.Sectors[profile.Sector]++
				}
				
				// Track latest analysis
				if profile.LastAnalyzed.After(stats.LatestAnalysis) {
					stats.LatestAnalysis = profile.LastAnalyzed
				}
			}
		}
	}

	// Find top sector
	for sector, count := range stats.Sectors {
		if count > stats.TopSectorCount {
			stats.TopSector = sector
			stats.TopSectorCount = count
		}
	}

	return stats
}

func (dm *DataManager) countFiles(dirPath string) int {
	var count int
	filepath.WalkDir(dirPath, func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			count++
		}
		return nil
	})
	return count
}

func (dm *DataManager) calculateTotalSize(dirPath string) int64 {
	var totalSize int64
	filepath.WalkDir(dirPath, func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if info, err := d.Info(); err == nil {
				totalSize += info.Size()
			}
		}
		return nil
	})
	return totalSize
}

func (dm *DataManager) performCleanup() {
	fmt.Println("🧹 Starting data cleanup...")
	
	// Remove empty directories
	emptyDirs := dm.findEmptyDirectories(dm.RivalsPath)
	for _, dir := range emptyDirs {
		fmt.Printf("🗑️  Removing empty directory: %s\n", dir)
		os.Remove(dir)
	}
	
	// Find and remove invalid JSON files
	invalidFiles := dm.findInvalidJSONFiles(dm.RivalsPath)
	for _, file := range invalidFiles {
		fmt.Printf("🗑️  Removing invalid JSON file: %s\n", file)
		os.Remove(file)
	}
	
	fmt.Printf("✅ Cleanup completed. Removed %d empty directories and %d invalid files\n", 
		len(emptyDirs), len(invalidFiles))
}

func (dm *DataManager) findEmptyDirectories(rootPath string) []string {
	var emptyDirs []string
	filepath.WalkDir(rootPath, func(path string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() && path != rootPath {
			entries, err := os.ReadDir(path)
			if err == nil && len(entries) == 0 {
				emptyDirs = append(emptyDirs, path)
			}
		}
		return nil
	})
	return emptyDirs
}

func (dm *DataManager) findInvalidJSONFiles(rootPath string) []string {
	var invalidFiles []string
	filepath.WalkDir(rootPath, func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(path, ".json") {
			if !dm.isValidJSON(path) {
				invalidFiles = append(invalidFiles, path)
			}
		}
		return nil
	})
	return invalidFiles
}

func (dm *DataManager) isValidJSON(filePath string) bool {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return false
	}
	
	var js interface{}
	return json.Unmarshal(data, &js) == nil
}

func (dm *DataManager) exportData(format string) {
	fmt.Printf("📤 Exporting rivals data in %s format...\n", format)
	
	timestamp := time.Now().Format("20060102-150405")
	outputDir := filepath.Join(dm.RivalsPath, "exports")
	os.MkdirAll(outputDir, 0755)
	
	switch format {
	case "json":
		outputFile := filepath.Join(outputDir, fmt.Sprintf("rivals-export-%s.json", timestamp))
		dm.exportToJSON(outputFile)
	case "csv":
		outputFile := filepath.Join(outputDir, fmt.Sprintf("rivals-export-%s.csv", timestamp))
		dm.exportToCSV(outputFile)
	default:
		fmt.Printf("❌ Unsupported export format: %s\n", format)
		return
	}
}

func (dm *DataManager) exportToJSON(outputFile string) {
	exportData := map[string]interface{}{
		"export_timestamp": time.Now(),
		"companies":        dm.exportCompanies(),
		"sectors":          dm.exportSectors(),
		"summary":          dm.generateExportSummary(),
	}
	
	data, err := json.MarshalIndent(exportData, "", "  ")
	if err != nil {
		fmt.Printf("❌ Failed to marshal export data: %v\n", err)
		return
	}
	
	if err := os.WriteFile(outputFile, data, 0644); err != nil {
		fmt.Printf("❌ Failed to write export file: %v\n", err)
		return
	}
	
	fmt.Printf("✅ Data exported to: %s\n", outputFile)
}

func (dm *DataManager) exportToCSV(outputFile string) {
	fmt.Printf("📊 CSV export not yet implemented. Use JSON export for now.\n")
}

func (dm *DataManager) exportCompanies() []map[string]interface{} {
	var companies []map[string]interface{}
	companiesPath := filepath.Join(dm.RivalsPath, "companies")
	
	entries, err := os.ReadDir(companiesPath)
	if err != nil {
		return companies
	}
	
	for _, entry := range entries {
		if entry.IsDir() {
			profilePath := filepath.Join(companiesPath, entry.Name(), "profile.json")
			if profile := dm.loadCompanyProfile(profilePath); profile != nil {
				companies = append(companies, map[string]interface{}{
					"name":           profile.Name,
					"domain":         profile.Domain,
					"sector":         profile.Sector,
					"last_analyzed":  profile.LastAnalyzed,
					"data_files":     profile.DataFiles,
				})
			}
		}
	}
	
	return companies
}

func (dm *DataManager) exportSectors() map[string]interface{} {
	sectors := make(map[string]interface{})
	// This would load sector data if we have it
	// For now, return empty map
	return sectors
}

func (dm *DataManager) generateExportSummary() map[string]interface{} {
	stats := dm.getCompanyStats(filepath.Join(dm.RivalsPath, "companies"))
	return map[string]interface{}{
		"total_companies":    stats.Total,
		"sectors_count":      len(stats.Sectors),
		"latest_analysis":    stats.LatestAnalysis,
		"export_generated":   time.Now(),
	}
}

func (dm *DataManager) validateData() {
	fmt.Println("🔍 Validating rivals data integrity...")
	
	issues := []string{}
	
	// Validate company profiles
	companiesPath := filepath.Join(dm.RivalsPath, "companies")
	companyIssues := dm.validateCompanyProfiles(companiesPath)
	issues = append(issues, companyIssues...)
	
	// Validate JSON files
	jsonIssues := dm.validateJSONFiles(dm.RivalsPath)
	issues = append(issues, jsonIssues...)
	
	if len(issues) == 0 {
		fmt.Println("✅ Data validation completed successfully. No issues found.")
	} else {
		fmt.Printf("⚠️  Found %d validation issues:\n", len(issues))
		for _, issue := range issues {
			fmt.Printf("   • %s\n", issue)
		}
	}
}

func (dm *DataManager) validateCompanyProfiles(companiesPath string) []string {
	var issues []string
	
	entries, err := os.ReadDir(companiesPath)
	if err != nil {
		issues = append(issues, fmt.Sprintf("Cannot read companies directory: %v", err))
		return issues
	}
	
	for _, entry := range entries {
		if entry.IsDir() {
			profilePath := filepath.Join(companiesPath, entry.Name(), "profile.json")
			if profile := dm.loadCompanyProfile(profilePath); profile != nil {
				if profile.Name == "" {
					issues = append(issues, fmt.Sprintf("Company %s has empty name", entry.Name()))
				}
				if profile.Domain == "" {
					issues = append(issues, fmt.Sprintf("Company %s has empty domain", entry.Name()))
				}
				if profile.Sector == "" {
					issues = append(issues, fmt.Sprintf("Company %s has empty sector", entry.Name()))
				}
			} else {
				issues = append(issues, fmt.Sprintf("Company %s has invalid or missing profile.json", entry.Name()))
			}
		}
	}
	
	return issues
}

func (dm *DataManager) validateJSONFiles(rootPath string) []string {
	var issues []string
	
	filepath.WalkDir(rootPath, func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(path, ".json") {
			if !dm.isValidJSON(path) {
				relPath, _ := filepath.Rel(rootPath, path)
				issues = append(issues, fmt.Sprintf("Invalid JSON file: %s", relPath))
			}
		}
		return nil
	})
	
	return issues
}

func (dm *DataManager) createBackup() {
	timestamp := time.Now().Format("20060102-150405")
	backupName := fmt.Sprintf("rivals-backup-%s.tar.gz", timestamp)
	backupPath := filepath.Join(dm.RivalsPath, "..", backupName)
	
	fmt.Printf("💾 Creating backup: %s\n", backupName)
	
	// This is a simplified backup - in production you'd use proper tar/gzip
	fmt.Printf("⚠️  Backup functionality requires tar/gzip implementation\n")
	fmt.Printf("📁 Manual backup: copy the entire rivals/ directory to %s\n", backupPath)
}