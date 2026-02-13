package database

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateDatabaseName(t *testing.T) {
	tests := []struct {
		name    string
		dbName  string
		wantErr bool
		errMsg  string
	}{
		{"valid simple name", "mydb", false, ""},
		{"valid with underscore", "my_db", false, ""},
		{"valid with numbers", "db123", false, ""},
		{"valid starts with underscore", "_mydb", false, ""},
		{"valid all uppercase", "MYDB", false, ""},
		{"valid mixed case", "MyDb123", false, ""},
		{"empty name", "", true, "database name cannot be empty"},
		{"starts with number", "123db", true, "database name must start with a letter or underscore"},
		{"starts with dash", "-mydb", true, "database name must start with a letter or underscore"},
		{"contains dash", "my-db", true, "database name can only contain letters, numbers, and underscores"},
		{"contains space", "my db", true, "database name can only contain letters, numbers, and underscores"},
		{"contains dot", "my.db", true, "database name can only contain letters, numbers, and underscores"},
		{"contains special chars", "my$db", true, "database name can only contain letters, numbers, and underscores"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDatabaseName(tt.dbName)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Equal(t, tt.errMsg, err.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
