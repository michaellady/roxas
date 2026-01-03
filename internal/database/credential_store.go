package database

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/mikelady/roxas/internal/services"
)

// Compile-time interface compliance check
var _ services.CredentialStore = (*CredentialStore)(nil)

// CredentialStore implements services.CredentialStore using PostgreSQL
type CredentialStore struct {
	pool          *Pool
	encryptionKey []byte // 32 bytes for AES-256
}

// NewCredentialStore creates a new database-backed credential store
// encryptionKey must be exactly 32 bytes for AES-256
func NewCredentialStore(pool *Pool, encryptionKey []byte) (*CredentialStore, error) {
	if len(encryptionKey) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes, got %d", len(encryptionKey))
	}
	return &CredentialStore{
		pool:          pool,
		encryptionKey: encryptionKey,
	}, nil
}

// encrypt encrypts plaintext using AES-256-GCM
func (s *CredentialStore) encrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}

	block, err := aes.NewCipher(s.encryptionKey)
	if err != nil {
		return "", fmt.Errorf("%w: %v", services.ErrEncryptionFailed, err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("%w: %v", services.ErrEncryptionFailed, err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("%w: %v", services.ErrEncryptionFailed, err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decrypt decrypts ciphertext using AES-256-GCM
func (s *CredentialStore) decrypt(ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}

	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("%w: invalid base64", services.ErrDecryptionFailed)
	}

	block, err := aes.NewCipher(s.encryptionKey)
	if err != nil {
		return "", fmt.Errorf("%w: %v", services.ErrDecryptionFailed, err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("%w: %v", services.ErrDecryptionFailed, err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("%w: ciphertext too short", services.ErrDecryptionFailed)
	}

	nonce, ciphertextBytes := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return "", fmt.Errorf("%w: %v", services.ErrDecryptionFailed, err)
	}

	return string(plaintext), nil
}

// GetCredentials retrieves credentials for a user and platform
func (s *CredentialStore) GetCredentials(ctx context.Context, userID, platform string) (*services.PlatformCredentials, error) {
	if err := services.ValidatePlatform(platform); err != nil {
		return nil, err
	}

	var creds services.PlatformCredentials
	var encryptedAccessToken, encryptedRefreshToken string
	var refreshToken, platformUserID, scopes *string
	var tokenExpiresAt *time.Time

	err := s.pool.QueryRow(ctx,
		`SELECT id, user_id, platform, access_token, refresh_token,
		        token_expires_at, platform_user_id, scopes, created_at, updated_at
		 FROM platform_credentials
		 WHERE user_id = $1 AND platform = $2`,
		userID, platform,
	).Scan(
		&creds.ID, &creds.UserID, &creds.Platform,
		&encryptedAccessToken, &refreshToken,
		&tokenExpiresAt, &platformUserID, &scopes,
		&creds.CreatedAt, &creds.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, services.ErrCredentialsNotFound
		}
		return nil, fmt.Errorf("querying credentials: %w", err)
	}

	// Decrypt tokens
	accessToken, err := s.decrypt(encryptedAccessToken)
	if err != nil {
		return nil, err
	}
	creds.AccessToken = accessToken

	if refreshToken != nil {
		encryptedRefreshToken = *refreshToken
		rt, err := s.decrypt(encryptedRefreshToken)
		if err != nil {
			return nil, err
		}
		creds.RefreshToken = rt
	}

	creds.TokenExpiresAt = tokenExpiresAt
	if platformUserID != nil {
		creds.PlatformUserID = *platformUserID
	}
	if scopes != nil {
		creds.Scopes = *scopes
	}

	return &creds, nil
}

// SaveCredentials creates or updates credentials for a user and platform
func (s *CredentialStore) SaveCredentials(ctx context.Context, creds *services.PlatformCredentials) error {
	if err := services.ValidatePlatform(creds.Platform); err != nil {
		return err
	}

	// Encrypt tokens
	encryptedAccessToken, err := s.encrypt(creds.AccessToken)
	if err != nil {
		return err
	}

	var encryptedRefreshToken *string
	if creds.RefreshToken != "" {
		rt, err := s.encrypt(creds.RefreshToken)
		if err != nil {
			return err
		}
		encryptedRefreshToken = &rt
	}

	var platformUserID, scopes *string
	if creds.PlatformUserID != "" {
		platformUserID = &creds.PlatformUserID
	}
	if creds.Scopes != "" {
		scopes = &creds.Scopes
	}

	_, err = s.pool.Exec(ctx,
		`INSERT INTO platform_credentials
		 (user_id, platform, access_token, refresh_token, token_expires_at, platform_user_id, scopes)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 ON CONFLICT (user_id, platform) DO UPDATE SET
		     access_token = EXCLUDED.access_token,
		     refresh_token = EXCLUDED.refresh_token,
		     token_expires_at = EXCLUDED.token_expires_at,
		     platform_user_id = EXCLUDED.platform_user_id,
		     scopes = EXCLUDED.scopes,
		     updated_at = NOW()`,
		creds.UserID, creds.Platform, encryptedAccessToken, encryptedRefreshToken,
		creds.TokenExpiresAt, platformUserID, scopes,
	)

	if err != nil {
		return fmt.Errorf("saving credentials: %w", err)
	}

	return nil
}

// DeleteCredentials removes credentials for a user and platform
func (s *CredentialStore) DeleteCredentials(ctx context.Context, userID, platform string) error {
	if err := services.ValidatePlatform(platform); err != nil {
		return err
	}

	result, err := s.pool.Exec(ctx,
		`DELETE FROM platform_credentials WHERE user_id = $1 AND platform = $2`,
		userID, platform,
	)

	if err != nil {
		return fmt.Errorf("deleting credentials: %w", err)
	}

	if result.RowsAffected() == 0 {
		return services.ErrCredentialsNotFound
	}

	return nil
}

// GetCredentialsForUser retrieves all credentials for a user
func (s *CredentialStore) GetCredentialsForUser(ctx context.Context, userID string) ([]*services.PlatformCredentials, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, user_id, platform, access_token, refresh_token,
		        token_expires_at, platform_user_id, scopes, created_at, updated_at
		 FROM platform_credentials
		 WHERE user_id = $1
		 ORDER BY platform`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("querying user credentials: %w", err)
	}
	defer rows.Close()

	var credentials []*services.PlatformCredentials
	for rows.Next() {
		var creds services.PlatformCredentials
		var encryptedAccessToken string
		var refreshToken, platformUserID, scopes *string
		var tokenExpiresAt *time.Time

		err := rows.Scan(
			&creds.ID, &creds.UserID, &creds.Platform,
			&encryptedAccessToken, &refreshToken,
			&tokenExpiresAt, &platformUserID, &scopes,
			&creds.CreatedAt, &creds.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scanning credential row: %w", err)
		}

		// Decrypt tokens
		accessToken, err := s.decrypt(encryptedAccessToken)
		if err != nil {
			return nil, err
		}
		creds.AccessToken = accessToken

		if refreshToken != nil {
			rt, err := s.decrypt(*refreshToken)
			if err != nil {
				return nil, err
			}
			creds.RefreshToken = rt
		}

		creds.TokenExpiresAt = tokenExpiresAt
		if platformUserID != nil {
			creds.PlatformUserID = *platformUserID
		}
		if scopes != nil {
			creds.Scopes = *scopes
		}

		credentials = append(credentials, &creds)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating credential rows: %w", err)
	}

	return credentials, nil
}

// GetExpiringCredentials retrieves credentials expiring within the given duration
func (s *CredentialStore) GetExpiringCredentials(ctx context.Context, within time.Duration) ([]*services.PlatformCredentials, error) {
	expiryThreshold := time.Now().Add(within)

	rows, err := s.pool.Query(ctx,
		`SELECT id, user_id, platform, access_token, refresh_token,
		        token_expires_at, platform_user_id, scopes, created_at, updated_at
		 FROM platform_credentials
		 WHERE token_expires_at IS NOT NULL AND token_expires_at <= $1
		 ORDER BY token_expires_at`,
		expiryThreshold,
	)
	if err != nil {
		return nil, fmt.Errorf("querying expiring credentials: %w", err)
	}
	defer rows.Close()

	var credentials []*services.PlatformCredentials
	for rows.Next() {
		var creds services.PlatformCredentials
		var encryptedAccessToken string
		var refreshToken, platformUserID, scopes *string
		var tokenExpiresAt *time.Time

		err := rows.Scan(
			&creds.ID, &creds.UserID, &creds.Platform,
			&encryptedAccessToken, &refreshToken,
			&tokenExpiresAt, &platformUserID, &scopes,
			&creds.CreatedAt, &creds.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scanning credential row: %w", err)
		}

		// Decrypt tokens
		accessToken, err := s.decrypt(encryptedAccessToken)
		if err != nil {
			return nil, err
		}
		creds.AccessToken = accessToken

		if refreshToken != nil {
			rt, err := s.decrypt(*refreshToken)
			if err != nil {
				return nil, err
			}
			creds.RefreshToken = rt
		}

		creds.TokenExpiresAt = tokenExpiresAt
		if platformUserID != nil {
			creds.PlatformUserID = *platformUserID
		}
		if scopes != nil {
			creds.Scopes = *scopes
		}

		credentials = append(credentials, &creds)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating credential rows: %w", err)
	}

	return credentials, nil
}

// UpdateTokens updates just the access and refresh tokens (and expiry)
func (s *CredentialStore) UpdateTokens(ctx context.Context, userID, platform, accessToken, refreshToken string, expiresAt *time.Time) error {
	if err := services.ValidatePlatform(platform); err != nil {
		return err
	}

	// Encrypt tokens
	encryptedAccessToken, err := s.encrypt(accessToken)
	if err != nil {
		return err
	}

	var encryptedRefreshToken *string
	if refreshToken != "" {
		rt, err := s.encrypt(refreshToken)
		if err != nil {
			return err
		}
		encryptedRefreshToken = &rt
	}

	result, err := s.pool.Exec(ctx,
		`UPDATE platform_credentials
		 SET access_token = $3, refresh_token = $4, token_expires_at = $5, updated_at = NOW()
		 WHERE user_id = $1 AND platform = $2`,
		userID, platform, encryptedAccessToken, encryptedRefreshToken, expiresAt,
	)

	if err != nil {
		return fmt.Errorf("updating tokens: %w", err)
	}

	if result.RowsAffected() == 0 {
		return services.ErrCredentialsNotFound
	}

	return nil
}
