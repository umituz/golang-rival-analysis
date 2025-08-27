# Golang Rival Analysis

A modern Go application for competitor analysis and website intelligence gathering.

## Features

- **Website Analysis**: HTTP response analysis, performance metrics, SEO evaluation
- **SSL/TLS Analysis**: Certificate validation and security assessment  
- **DNS Analysis**: Comprehensive DNS record analysis
- **WHOIS Analysis**: Domain registration information
- **Competitor Intelligence**: Social media tracking, market positioning
- **API Integrations**: SimilarWeb, LinkedIn, Crunchbase
- **Concurrent Processing**: High-performance parallel analysis
- **Report Generation**: JSON and Markdown reports

## Architecture

Built following clean architecture principles:

- **Domain Layer**: Core business logic and entities
- **Service Layer**: Business rules and orchestration
- **Repository Layer**: Data access and external APIs
- **Handler Layer**: HTTP handlers and routing
- **Infrastructure Layer**: External services and utilities

## Tech Stack

- **Go 1.21+**: Modern Go with generics support
- **Gin**: High-performance web framework
- **Colly**: Web scraping and crawling
- **Go-DNS**: DNS query library
- **Go-WHOIS**: WHOIS lookup functionality
- **Testify**: Testing framework
- **Logrus**: Structured logging

## Getting Started

```bash
# Clone the repository
git clone https://github.com/umituz/golang-rival-analysis

# Install dependencies  
go mod download

# Run the application
go run cmd/server/main.go

# Run tests
go test ./...
```

## Usage

### API Endpoints

- `GET /api/v1/analyze/website/{domain}` - Analyze website
- `GET /api/v1/analyze/competitor/{company}` - Competitor analysis
- `GET /api/v1/analyze/ssl/{domain}` - SSL certificate analysis
- `GET /api/v1/analyze/dns/{domain}` - DNS record analysis
- `GET /api/v1/analyze/whois/{domain}` - WHOIS information

### Configuration

Set environment variables:

```bash
export SIMILARWEB_API_KEY="your-api-key"
export LINKEDIN_API_KEY="your-api-key"  
export CRUNCHBASE_API_KEY="your-api-key"
export PORT="8080"
```

## Development

This project follows Go best practices:

- **SOLID Principles**: Single responsibility, dependency injection
- **DRY Principle**: Reusable components and utilities
- **Error Handling**: Comprehensive error handling with context
- **Testing**: Unit tests with high coverage
- **Documentation**: Comprehensive code documentation

## License

MIT License