package clients

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateTestKey(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	pemBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}
	pemBytes := pem.EncodeToMemory(pemBlock)
	return key, pemBytes
}

func TestNewGitHubAppClient(t *testing.T) {
	_, pemBytes := generateTestKey(t)

	client, err := NewGitHubAppClient(12345, pemBytes, "")
	require.NoError(t, err)
	assert.NotNil(t, client)
	assert.Equal(t, int64(12345), client.appID)
	assert.Equal(t, "https://api.github.com", client.baseURL)
}

func TestNewGitHubAppClient_CustomBaseURL(t *testing.T) {
	_, pemBytes := generateTestKey(t)

	client, err := NewGitHubAppClient(12345, pemBytes, "https://custom.github.com")
	require.NoError(t, err)
	assert.Equal(t, "https://custom.github.com", client.baseURL)
}

func TestNewGitHubAppClient_InvalidPEM(t *testing.T) {
	_, err := NewGitHubAppClient(12345, []byte("not a pem key"), "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode PEM block")
}

func TestCreateJWT(t *testing.T) {
	key, pemBytes := generateTestKey(t)

	client, err := NewGitHubAppClient(12345, pemBytes, "")
	require.NoError(t, err)

	tokenStr, err := client.CreateJWT()
	require.NoError(t, err)
	assert.NotEmpty(t, tokenStr)

	// Verify the JWT can be parsed with the public key
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return &key.PublicKey, nil
	})
	require.NoError(t, err)
	assert.True(t, token.Valid)

	claims, ok := token.Claims.(jwt.MapClaims)
	require.True(t, ok)
	assert.Equal(t, "12345", claims["iss"])
}

func TestCreateInstallationToken(t *testing.T) {
	_, pemBytes := generateTestKey(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/app/installations/999/access_tokens", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Contains(t, r.Header.Get("Authorization"), "Bearer ")

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"token":      "ghs_test_token_123",
			"expires_at": time.Now().Add(time.Hour).Format(time.RFC3339),
		})
	}))
	defer server.Close()

	client, err := NewGitHubAppClient(12345, pemBytes, server.URL)
	require.NoError(t, err)

	token, err := client.CreateInstallationToken(context.Background(), 999)
	require.NoError(t, err)
	assert.Equal(t, "ghs_test_token_123", token.Token)
}

func TestGetInstallation(t *testing.T) {
	_, pemBytes := generateTestKey(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/app/installations/999", r.URL.Path)
		assert.Equal(t, http.MethodGet, r.Method)

		json.NewEncoder(w).Encode(map[string]interface{}{
			"id": 999,
			"account": map[string]interface{}{
				"login": "testuser",
				"id":    42,
				"type":  "User",
			},
			"app_id": 12345,
		})
	}))
	defer server.Close()

	client, err := NewGitHubAppClient(12345, pemBytes, server.URL)
	require.NoError(t, err)

	info, err := client.GetInstallation(context.Background(), 999)
	require.NoError(t, err)
	assert.Equal(t, int64(999), info.ID)
	assert.Equal(t, "testuser", info.Account.Login)
	assert.Equal(t, int64(42), info.Account.ID)
	assert.Equal(t, "User", info.Account.Type)
}

func TestListInstallationRepos(t *testing.T) {
	_, pemBytes := generateTestKey(t)

	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			// First call: create installation token
			assert.Equal(t, "/app/installations/999/access_tokens", r.URL.Path)
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"token":      "ghs_test_token",
				"expires_at": time.Now().Add(time.Hour).Format(time.RFC3339),
			})
			return
		}
		// Second call: list repos
		assert.Equal(t, "/installation/repositories", r.URL.Path)
		assert.Equal(t, "token ghs_test_token", r.Header.Get("Authorization"))

		json.NewEncoder(w).Encode(map[string]interface{}{
			"repositories": []map[string]interface{}{
				{
					"id":             123,
					"full_name":      "testuser/repo1",
					"html_url":       "https://github.com/testuser/repo1",
					"private":        false,
					"default_branch": "main",
				},
			},
		})
	}))
	defer server.Close()

	client, err := NewGitHubAppClient(12345, pemBytes, server.URL)
	require.NoError(t, err)

	repos, err := client.ListInstallationRepos(context.Background(), 999)
	require.NoError(t, err)
	require.Len(t, repos, 1)
	assert.Equal(t, int64(123), repos[0].ID)
	assert.Equal(t, "testuser/repo1", repos[0].FullName)
}

func TestCreateInstallationToken_APIError(t *testing.T) {
	_, pemBytes := generateTestKey(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message": "Not Found"}`))
	}))
	defer server.Close()

	client, err := NewGitHubAppClient(12345, pemBytes, server.URL)
	require.NoError(t, err)

	_, err = client.CreateInstallationToken(context.Background(), 999)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "status 404")
}
