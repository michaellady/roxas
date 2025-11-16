.PHONY: test test-int build deploy e2e clean

# Run all unit tests
test:
	go test -v ./internal/... ./cmd/...

# Run integration tests
test-int:
	go test -v ./tests/...

# Build Lambda binary and create deployment package
build:
	mkdir -p bin
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/bootstrap cmd/server/main.go
	cd bin && zip bootstrap.zip bootstrap
	@ls -lh bin/bootstrap.zip | awk '{print "✓ Built bin/bootstrap.zip (" $$5 ")"}'

# Deploy to AWS
deploy:
	cd terraform && terraform apply

# End-to-end test with real webhook
e2e:
	@echo "E2E test not yet implemented"

# Clean build artifacts
clean:
	rm -rf bin
	rm -f bootstrap
	rm -f *.zip
