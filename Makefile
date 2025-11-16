.PHONY: test test-int build deploy e2e clean

# Run all unit tests
test:
	go test -v ./internal/... ./cmd/...

# Run integration tests
test-int:
	go test -v ./tests/...

# Build Lambda binary
build:
	GOOS=linux GOARCH=amd64 go build -o bootstrap cmd/server/main.go

# Deploy to AWS
deploy:
	cd terraform && terraform apply

# End-to-end test with real webhook
e2e:
	@echo "E2E test not yet implemented"

# Clean build artifacts
clean:
	rm -f bootstrap
	rm -f *.zip
