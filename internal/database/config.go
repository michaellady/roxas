package database

import "fmt"

// Config holds database connection configuration
type Config struct {
	Host     string
	Port     string
	User     string
	Password string
	Database string
	SSLMode  string
}

// ConnectionString returns a PostgreSQL connection string
func (c *Config) ConnectionString() string {
	return fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		c.Host, c.Port, c.User, c.Password, c.Database, c.SSLMode,
	)
}

// Validate checks if all required fields are set
func (c *Config) Validate() error {
	if c.Host == "" {
		return fmt.Errorf("database host is required")
	}
	if c.Port == "" {
		return fmt.Errorf("database port is required")
	}
	if c.User == "" {
		return fmt.Errorf("database user is required")
	}
	if c.Password == "" {
		return fmt.Errorf("database password is required")
	}
	if c.Database == "" {
		return fmt.Errorf("database name is required")
	}
	if c.SSLMode == "" {
		c.SSLMode = "require" // Default to require SSL
	}
	return nil
}
