.PHONY: test test-int test-system test-coverage build deploy e2e clean

# Run unit tests (fast, no external API calls)
test:
	go test -v -short ./internal/... ./cmd/...

# Run unit tests with coverage report
test-coverage:
	go test -short -coverprofile=coverage.out ./internal/... ./cmd/...
	@echo ""
	@echo "=== Coverage by Package ==="
	@go tool cover -func=coverage.out | grep -v "total:" | awk '{printf "%-60s %s\n", $$1, $$3}'
	@echo ""
	@go tool cover -func=coverage.out | grep "total:" | awk '{print "Total Coverage: " $$3}'

# Run integration tests
test-int:
	go test -v ./tests/...

# Run system tests (requires real API credentials)
test-system:
	go test -v ./internal/... ./cmd/...

# Build Lambda binary and create deployment package
# Use -trimpath and -buildvcs=false for deterministic builds
# Set SOURCE_DATE_EPOCH to create deterministic zip files (reproducible builds)
# This ensures identical source code produces identical binaries with the same hash
build:
	mkdir -p bin
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w" -o bin/bootstrap cmd/server/main.go
	# Set fixed timestamp for deterministic zip (Jan 1, 2020)
	touch -t 202001010000.00 bin/bootstrap
	cd bin && TZ=UTC zip -X bootstrap.zip bootstrap
	@ls -lh bin/bootstrap.zip | awk '{print "✓ Built bin/bootstrap.zip (" $$5 ")"}'

# Deploy to AWS
deploy:
	cd terraform && terraform apply

# End-to-end test with real webhook against deployed Lambda
# Requires: LAMBDA_URL and WEBHOOK_SECRET environment variables
# Example: LAMBDA_URL=https://... WEBHOOK_SECRET=... make e2e
e2e:
	@./scripts/e2e-test.sh

# Clean build artifacts
clean:
	rm -rf bin
	rm -f bootstrap
	rm -f *.zip
