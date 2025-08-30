# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the simple server
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main server.go

# Runtime stage  
FROM alpine:latest

# Add ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy the binary from builder
COPY --from=builder /app/main .

# Create output directories
RUN mkdir -p rivals/companies rivals/sectors rivals/comparisons rivals/historical

# Expose port 9000
EXPOSE 9000

# Run the application
CMD ["./main"]