.PHONY: test test-int test-system build deploy e2e clean

# Run unit tests (fast, no external API calls)
test:
	go test -v -short ./internal/... ./cmd/...

# Run integration tests
test-int:
	go test -v ./tests/...

# Run system tests (requires real API credentials)
test-system:
	go test -v ./internal/... ./cmd/...

# Build Lambda binary and create deployment package
build:
	mkdir -p bin
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/bootstrap cmd/server/main.go
	cd bin && zip bootstrap.zip bootstrap
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
