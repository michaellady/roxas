package web

import (
	"context"
	"net/http"
	"time"
)

// =============================================================================
// HTTP Server (hq-cdvi)
// Server lifecycle management wrapping the Router
// =============================================================================

// ServerConfig holds HTTP server configuration
type ServerConfig struct {
	// ReadTimeout is the maximum duration for reading the entire request
	ReadTimeout time.Duration

	// WriteTimeout is the maximum duration before timing out writes of the response
	WriteTimeout time.Duration

	// IdleTimeout is the maximum time to wait for the next request when keep-alives are enabled
	IdleTimeout time.Duration

	// MaxHeaderBytes controls the maximum number of bytes the server will read parsing the request header
	MaxHeaderBytes int
}

// DefaultServerConfig returns sensible defaults for production use
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		ReadTimeout:    15 * time.Second,
		WriteTimeout:   15 * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1 MB
	}
}

// Server wraps an HTTP server with the web Router
type Server struct {
	addr       string
	config     ServerConfig
	router     *Router
	httpServer *http.Server
}

// NewServer creates a new Server with default configuration
func NewServer(addr string) *Server {
	return NewServerWithConfig(addr, DefaultServerConfig())
}

// NewServerWithConfig creates a new Server with custom configuration
func NewServerWithConfig(addr string, config ServerConfig) *Server {
	if addr == "" {
		addr = ":8080"
	}

	s := &Server{
		addr:   addr,
		config: config,
		router: NewRouter(),
	}

	return s
}

// WithRouter sets a custom router (useful for dependency injection in tests)
func (s *Server) WithRouter(router *Router) *Server {
	s.router = router
	return s
}

// Handler returns the HTTP handler (the Router)
func (s *Server) Handler() http.Handler {
	return s.router
}

// Start starts the HTTP server and blocks until it's shut down
func (s *Server) Start() error {
	s.httpServer = &http.Server{
		Addr:           s.addr,
		Handler:        s.router,
		ReadTimeout:    s.config.ReadTimeout,
		WriteTimeout:   s.config.WriteTimeout,
		IdleTimeout:    s.config.IdleTimeout,
		MaxHeaderBytes: s.config.MaxHeaderBytes,
	}

	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully shuts down the server without interrupting active connections
func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpServer == nil {
		return nil
	}
	return s.httpServer.Shutdown(ctx)
}

// Addr returns the server address
func (s *Server) Addr() string {
	return s.addr
}
