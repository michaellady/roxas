package database

import (
	"testing"
)

func TestConfig_ConnectionString(t *testing.T) {
	tests := []struct {
		name     string
		config   Config
		expected string
	}{
		{
			name: "valid config with all fields",
			config: Config{
				Host:     "localhost",
				Port:     "5432",
				User:     "testuser",
				Password: "testpass",
				Database: "testdb",
				SSLMode:  "require",
			},
			expected: "host=localhost port=5432 user=testuser password=testpass dbname=testdb sslmode=require",
		},
		{
			name: "config with special characters in password",
			config: Config{
				Host:     "db.example.com",
				Port:     "5433",
				User:     "admin",
				Password: "p@ss$word!123",
				Database: "myapp",
				SSLMode:  "disable",
			},
			expected: "host=db.example.com port=5433 user=admin password=p@ss$word!123 dbname=myapp sslmode=disable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.ConnectionString()
			if result != tt.expected {
				t.Errorf("ConnectionString() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config",
			config: Config{
				Host:     "localhost",
				Port:     "5432",
				User:     "testuser",
				Password: "testpass",
				Database: "testdb",
				SSLMode:  "require",
			},
			wantErr: false,
		},
		{
			name: "valid config with default sslmode",
			config: Config{
				Host:     "localhost",
				Port:     "5432",
				User:     "testuser",
				Password: "testpass",
				Database: "testdb",
			},
			wantErr: false,
		},
		{
			name: "missing host",
			config: Config{
				Port:     "5432",
				User:     "testuser",
				Password: "testpass",
				Database: "testdb",
			},
			wantErr: true,
			errMsg:  "database host is required",
		},
		{
			name: "missing port",
			config: Config{
				Host:     "localhost",
				User:     "testuser",
				Password: "testpass",
				Database: "testdb",
			},
			wantErr: true,
			errMsg:  "database port is required",
		},
		{
			name: "missing user",
			config: Config{
				Host:     "localhost",
				Port:     "5432",
				Password: "testpass",
				Database: "testdb",
			},
			wantErr: true,
			errMsg:  "database user is required",
		},
		{
			name: "missing password",
			config: Config{
				Host:     "localhost",
				Port:     "5432",
				User:     "testuser",
				Database: "testdb",
			},
			wantErr: true,
			errMsg:  "database password is required",
		},
		{
			name: "missing database",
			config: Config{
				Host:     "localhost",
				Port:     "5432",
				User:     "testuser",
				Password: "testpass",
			},
			wantErr: true,
			errMsg:  "database name is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				if err == nil {
					t.Errorf("Validate() expected error but got none")
					return
				}
				if err.Error() != tt.errMsg {
					t.Errorf("Validate() error = %v, want %v", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("Validate() unexpected error: %v", err)
				}
				// Check that SSLMode defaults to "require"
				if tt.config.SSLMode == "" {
					t.Errorf("Validate() should set default SSLMode to 'require', but it's empty")
				}
			}
		})
	}
}
