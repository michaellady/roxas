package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// =============================================================================
// Server Unit Tests (hq-cdvi)
// Tests for HTTP server lifecycle management
// =============================================================================

func TestNewServer_ReturnsServer(t *testing.T) {
	server := NewServer(":8080")

	if server == nil {
		t.Fatal("NewServer() returned nil")
	}
	if server.addr != ":8080" {
		t.Errorf("server.addr = %q, want %q", server.addr, ":8080")
	}
}

func TestNewServer_DefaultsToPort8080(t *testing.T) {
	server := NewServer("")

	if server.addr != ":8080" {
		t.Errorf("server.addr = %q, want default %q", server.addr, ":8080")
	}
}

func TestServer_Handler_ReturnsHTTP200OnRoot(t *testing.T) {
	server := NewServer(":8080")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	server.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("GET / status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestServer_Handler_ReturnsHTMLContentType(t *testing.T) {
	server := NewServer(":8080")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	server.Handler().ServeHTTP(rr, req)

	contentType := rr.Header().Get("Content-Type")
	if contentType != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want %q", contentType, "text/html; charset=utf-8")
	}
}

func TestServer_WithRouter_UsesProvidedRouter(t *testing.T) {
	router := NewRouter()
	server := NewServer(":8080").WithRouter(router)

	if server.router != router {
		t.Error("WithRouter() should set the router")
	}
}

func TestServer_Shutdown_GracefullyStops(t *testing.T) {
	server := NewServer(":0") // Use port 0 for random available port

	// Start server in background
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Start()
	}()

	// Give server time to start
	time.Sleep(50 * time.Millisecond)

	// Shutdown gracefully
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown() error = %v", err)
	}

	// Server should have stopped
	select {
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			t.Errorf("Start() returned unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("Server did not stop after Shutdown()")
	}
}

func TestServerConfig_WithReadTimeout(t *testing.T) {
	config := DefaultServerConfig()
	config.ReadTimeout = 30 * time.Second

	server := NewServerWithConfig(":8080", config)

	if server.config.ReadTimeout != 30*time.Second {
		t.Errorf("ReadTimeout = %v, want %v", server.config.ReadTimeout, 30*time.Second)
	}
}

func TestDefaultServerConfig_HasReasonableDefaults(t *testing.T) {
	config := DefaultServerConfig()

	if config.ReadTimeout == 0 {
		t.Error("DefaultServerConfig() ReadTimeout should not be zero")
	}
	if config.WriteTimeout == 0 {
		t.Error("DefaultServerConfig() WriteTimeout should not be zero")
	}
	if config.IdleTimeout == 0 {
		t.Error("DefaultServerConfig() IdleTimeout should not be zero")
	}
}
