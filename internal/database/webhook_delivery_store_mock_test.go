package database

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var deliveryColumns = []string{"id", "repository_id", "delivery_id", "event_type", "ref", "before_sha", "after_sha", "payload", "status_code", "error_message", "processed_at", "created_at"}

func TestWebhookDeliveryStore_NewWebhookDeliveryStoreWithDB(t *testing.T) {
	mock := NewMockPool(t)
	store := NewWebhookDeliveryStoreWithDB(mock)
	require.NotNil(t, store)
}

func TestWebhookDelivery_IsSuccess(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		want       bool
	}{
		{"200 is success", 200, true},
		{"201 is success", 201, true},
		{"299 is success", 299, true},
		{"300 is not success", 300, false},
		{"400 is not success", 400, false},
		{"500 is not success", 500, false},
		{"199 is not success", 199, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &WebhookDelivery{StatusCode: tt.statusCode}
			assert.Equal(t, tt.want, d.IsSuccess())
		})
	}
}

func TestWebhookDelivery_PayloadPreview(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		maxLen  int
		want    string
	}{
		{"short payload", `{"key":"val"}`, 50, `{"key":"val"}`},
		{"exact length", "12345", 5, "12345"},
		{"truncated", "1234567890", 5, "12345..."},
		{"empty payload", "", 10, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &WebhookDelivery{Payload: json.RawMessage(tt.payload)}
			assert.Equal(t, tt.want, d.PayloadPreview(tt.maxLen))
		})
	}
}

func TestWebhookDeliveryStore_CreateDelivery_Success(t *testing.T) {
	mock := NewMockPool(t)
	store := NewWebhookDeliveryStoreWithDB(mock)

	now := time.Now().Truncate(time.Microsecond)
	ref := "refs/heads/main"
	beforeSHA := "abc123"
	afterSHA := "def456"
	payload := json.RawMessage(`{"key":"value"}`)

	rows := pgxmock.NewRows(deliveryColumns).
		AddRow("del-1", "repo-1", "gh-delivery-1", "push", &ref, &beforeSHA, &afterSHA, payload, 200, nil, &now, now)

	mock.ExpectQuery(`INSERT INTO webhook_deliveries`).
		WithArgs("repo-1", "gh-delivery-1", "push", &ref, &beforeSHA, &afterSHA, payload, 200, pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnRows(rows)

	delivery, err := store.CreateDelivery(context.Background(), CreateDeliveryParams{
		RepositoryID: "repo-1",
		DeliveryID:   "gh-delivery-1",
		EventType:    "push",
		Ref:          &ref,
		BeforeSHA:    &beforeSHA,
		AfterSHA:     &afterSHA,
		Payload:      payload,
		StatusCode:   200,
	})

	require.NoError(t, err)
	require.NotNil(t, delivery)
	assert.Equal(t, "del-1", delivery.ID)
	assert.Equal(t, "repo-1", delivery.RepositoryID)
	assert.Equal(t, "gh-delivery-1", delivery.DeliveryID)
	assert.Equal(t, "push", delivery.EventType)
	assert.Equal(t, 200, delivery.StatusCode)
}

func TestWebhookDeliveryStore_CreateDelivery_GeneratedID(t *testing.T) {
	mock := NewMockPool(t)
	store := NewWebhookDeliveryStoreWithDB(mock)

	now := time.Now().Truncate(time.Microsecond)
	payload := json.RawMessage(`{}`)

	rows := pgxmock.NewRows(deliveryColumns).
		AddRow("del-1", "repo-1", "generated-id", "push", nil, nil, nil, payload, 200, nil, &now, now)

	mock.ExpectQuery(`INSERT INTO webhook_deliveries`).
		WithArgs("repo-1", pgxmock.AnyArg(), "push", pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), payload, 200, pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnRows(rows)

	delivery, err := store.CreateDelivery(context.Background(), CreateDeliveryParams{
		RepositoryID: "repo-1",
		DeliveryID:   "", // empty, should be generated
		EventType:    "push",
		Payload:      payload,
		StatusCode:   200,
	})

	require.NoError(t, err)
	require.NotNil(t, delivery)
}

func TestWebhookDeliveryStore_CreateDelivery_Error(t *testing.T) {
	mock := NewMockPool(t)
	store := NewWebhookDeliveryStoreWithDB(mock)

	payload := json.RawMessage(`{}`)

	mock.ExpectQuery(`INSERT INTO webhook_deliveries`).
		WithArgs("repo-1", pgxmock.AnyArg(), "push", pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), payload, 200, pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnError(errors.New("db error"))

	delivery, err := store.CreateDelivery(context.Background(), CreateDeliveryParams{
		RepositoryID: "repo-1",
		EventType:    "push",
		Payload:      payload,
		StatusCode:   200,
	})

	assert.Error(t, err)
	assert.Nil(t, delivery)
}

func TestWebhookDeliveryStore_CreateDeliveryLegacy(t *testing.T) {
	mock := NewMockPool(t)
	store := NewWebhookDeliveryStoreWithDB(mock)

	now := time.Now().Truncate(time.Microsecond)
	payload := json.RawMessage(`{"push":"data"}`)

	rows := pgxmock.NewRows(deliveryColumns).
		AddRow("del-1", "repo-1", "generated-legacy", "push", nil, nil, nil, payload, 200, nil, &now, now)

	mock.ExpectQuery(`INSERT INTO webhook_deliveries`).
		WithArgs("repo-1", pgxmock.AnyArg(), "push", pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), payload, 200, pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnRows(rows)

	delivery, err := store.CreateDeliveryLegacy(context.Background(), "repo-1", "push", payload, 200, nil)

	require.NoError(t, err)
	require.NotNil(t, delivery)
	assert.Equal(t, "del-1", delivery.ID)
}

func TestWebhookDeliveryStore_ExistsByDeliveryID_True(t *testing.T) {
	mock := NewMockPool(t)
	store := NewWebhookDeliveryStoreWithDB(mock)

	rows := pgxmock.NewRows([]string{"exists"}).AddRow(true)

	mock.ExpectQuery(`SELECT EXISTS`).
		WithArgs("repo-1", "delivery-1").
		WillReturnRows(rows)

	exists, err := store.ExistsByDeliveryID(context.Background(), "repo-1", "delivery-1")

	require.NoError(t, err)
	assert.True(t, exists)
}

func TestWebhookDeliveryStore_ExistsByDeliveryID_False(t *testing.T) {
	mock := NewMockPool(t)
	store := NewWebhookDeliveryStoreWithDB(mock)

	rows := pgxmock.NewRows([]string{"exists"}).AddRow(false)

	mock.ExpectQuery(`SELECT EXISTS`).
		WithArgs("repo-1", "delivery-1").
		WillReturnRows(rows)

	exists, err := store.ExistsByDeliveryID(context.Background(), "repo-1", "delivery-1")

	require.NoError(t, err)
	assert.False(t, exists)
}

func TestWebhookDeliveryStore_ExistsByDeliveryID_Error(t *testing.T) {
	mock := NewMockPool(t)
	store := NewWebhookDeliveryStoreWithDB(mock)

	mock.ExpectQuery(`SELECT EXISTS`).
		WithArgs("repo-1", "delivery-1").
		WillReturnError(errors.New("db error"))

	_, err := store.ExistsByDeliveryID(context.Background(), "repo-1", "delivery-1")

	assert.Error(t, err)
}

func TestWebhookDeliveryStore_DeliveryExists_True(t *testing.T) {
	mock := NewMockPool(t)
	store := NewWebhookDeliveryStoreWithDB(mock)

	rows := pgxmock.NewRows([]string{"exists"}).AddRow(true)

	mock.ExpectQuery(`SELECT EXISTS`).
		WithArgs("delivery-1").
		WillReturnRows(rows)

	exists, err := store.DeliveryExists(context.Background(), "delivery-1")

	require.NoError(t, err)
	assert.True(t, exists)
}

func TestWebhookDeliveryStore_DeliveryExists_False(t *testing.T) {
	mock := NewMockPool(t)
	store := NewWebhookDeliveryStoreWithDB(mock)

	rows := pgxmock.NewRows([]string{"exists"}).AddRow(false)

	mock.ExpectQuery(`SELECT EXISTS`).
		WithArgs("delivery-1").
		WillReturnRows(rows)

	exists, err := store.DeliveryExists(context.Background(), "delivery-1")

	require.NoError(t, err)
	assert.False(t, exists)
}

func TestWebhookDeliveryStore_ListDeliveriesByRepository_Success(t *testing.T) {
	mock := NewMockPool(t)
	store := NewWebhookDeliveryStoreWithDB(mock)

	now := time.Now().Truncate(time.Microsecond)
	payload := json.RawMessage(`{}`)

	rows := pgxmock.NewRows(deliveryColumns).
		AddRow("del-1", "repo-1", "gh-1", "push", nil, nil, nil, payload, 200, nil, &now, now).
		AddRow("del-2", "repo-1", "gh-2", "push", nil, nil, nil, payload, 500, nil, &now, now)

	mock.ExpectQuery(`SELECT id, repository_id, delivery_id`).
		WithArgs("repo-1", 20).
		WillReturnRows(rows)

	deliveries, err := store.ListDeliveriesByRepository(context.Background(), "repo-1", 0)

	require.NoError(t, err)
	require.Len(t, deliveries, 2)
	assert.Equal(t, "del-1", deliveries[0].ID)
	assert.Equal(t, "del-2", deliveries[1].ID)
}

func TestWebhookDeliveryStore_ListDeliveriesByRepository_CustomLimit(t *testing.T) {
	mock := NewMockPool(t)
	store := NewWebhookDeliveryStoreWithDB(mock)

	rows := pgxmock.NewRows(deliveryColumns)

	mock.ExpectQuery(`SELECT id, repository_id, delivery_id`).
		WithArgs("repo-1", 5).
		WillReturnRows(rows)

	_, err := store.ListDeliveriesByRepository(context.Background(), "repo-1", 5)

	assert.NoError(t, err)
}

func TestWebhookDeliveryStore_ListDeliveriesByRepository_Empty(t *testing.T) {
	mock := NewMockPool(t)
	store := NewWebhookDeliveryStoreWithDB(mock)

	rows := pgxmock.NewRows(deliveryColumns)

	mock.ExpectQuery(`SELECT id, repository_id, delivery_id`).
		WithArgs("repo-1", 20).
		WillReturnRows(rows)

	deliveries, err := store.ListDeliveriesByRepository(context.Background(), "repo-1", 0)

	require.NoError(t, err)
	assert.Empty(t, deliveries)
}

func TestWebhookDeliveryStore_ListDeliveriesByRepository_QueryError(t *testing.T) {
	mock := NewMockPool(t)
	store := NewWebhookDeliveryStoreWithDB(mock)

	mock.ExpectQuery(`SELECT id, repository_id`).
		WithArgs("repo-1", 20).
		WillReturnError(errors.New("query error"))

	deliveries, err := store.ListDeliveriesByRepository(context.Background(), "repo-1", 0)

	assert.Error(t, err)
	assert.Nil(t, deliveries)
}

func TestWebhookDeliveryStore_ListDeliveriesByRepository_ScanError(t *testing.T) {
	mock := NewMockPool(t)
	store := NewWebhookDeliveryStoreWithDB(mock)

	payload := json.RawMessage(`{}`)
	now := time.Now()

	rows := pgxmock.NewRows(deliveryColumns).
		AddRow("del-1", "repo-1", "gh-1", "push", nil, nil, nil, payload, 200, nil, &now, now).
		RowError(0, errors.New("scan error"))

	mock.ExpectQuery(`SELECT id, repository_id`).
		WithArgs("repo-1", 20).
		WillReturnRows(rows)

	deliveries, err := store.ListDeliveriesByRepository(context.Background(), "repo-1", 0)

	assert.Error(t, err)
	assert.Nil(t, deliveries)
}

func TestWebhookDeliveryStore_GetDeliveryByID_Success(t *testing.T) {
	mock := NewMockPool(t)
	store := NewWebhookDeliveryStoreWithDB(mock)

	now := time.Now().Truncate(time.Microsecond)
	payload := json.RawMessage(`{"event":"push"}`)
	ref := "refs/heads/main"

	rows := pgxmock.NewRows(deliveryColumns).
		AddRow("del-1", "repo-1", "gh-1", "push", &ref, nil, nil, payload, 200, nil, &now, now)

	mock.ExpectQuery(`SELECT id, repository_id, delivery_id`).
		WithArgs("del-1").
		WillReturnRows(rows)

	delivery, err := store.GetDeliveryByID(context.Background(), "del-1")

	require.NoError(t, err)
	require.NotNil(t, delivery)
	assert.Equal(t, "del-1", delivery.ID)
	assert.Equal(t, "push", delivery.EventType)
	assert.Equal(t, &ref, delivery.Ref)
}

func TestWebhookDeliveryStore_GetDeliveryByID_Error(t *testing.T) {
	mock := NewMockPool(t)
	store := NewWebhookDeliveryStoreWithDB(mock)

	mock.ExpectQuery(`SELECT id, repository_id`).
		WithArgs("del-1").
		WillReturnError(errors.New("not found"))

	delivery, err := store.GetDeliveryByID(context.Background(), "del-1")

	assert.Error(t, err)
	assert.Nil(t, delivery)
}

func TestWebhookDeliveryStore_CheckDeliveryProcessed_True(t *testing.T) {
	mock := NewMockPool(t)
	store := NewWebhookDeliveryStoreWithDB(mock)

	rows := pgxmock.NewRows([]string{"exists"}).AddRow(true)

	mock.ExpectQuery(`SELECT EXISTS`).
		WithArgs("delivery-1").
		WillReturnRows(rows)

	processed, err := store.CheckDeliveryProcessed(context.Background(), "delivery-1")

	require.NoError(t, err)
	assert.True(t, processed)
}

func TestWebhookDeliveryStore_CheckDeliveryProcessed_False(t *testing.T) {
	mock := NewMockPool(t)
	store := NewWebhookDeliveryStoreWithDB(mock)

	rows := pgxmock.NewRows([]string{"exists"}).AddRow(false)

	mock.ExpectQuery(`SELECT EXISTS`).
		WithArgs("delivery-1").
		WillReturnRows(rows)

	processed, err := store.CheckDeliveryProcessed(context.Background(), "delivery-1")

	require.NoError(t, err)
	assert.False(t, processed)
}

func TestWebhookDeliveryStore_CheckDeliveryProcessed_Error(t *testing.T) {
	mock := NewMockPool(t)
	store := NewWebhookDeliveryStoreWithDB(mock)

	mock.ExpectQuery(`SELECT EXISTS`).
		WithArgs("delivery-1").
		WillReturnError(errors.New("db error"))

	_, err := store.CheckDeliveryProcessed(context.Background(), "delivery-1")

	assert.Error(t, err)
}

func TestWebhookDeliveryStore_MarkDeliveryProcessed_Success(t *testing.T) {
	mock := NewMockPool(t)
	store := NewWebhookDeliveryStoreWithDB(mock)

	mock.ExpectExec(`INSERT INTO webhook_deliveries`).
		WithArgs("repo-1", "delivery-1").
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	err := store.MarkDeliveryProcessed(context.Background(), "delivery-1", "repo-1")

	assert.NoError(t, err)
}

func TestWebhookDeliveryStore_MarkDeliveryProcessed_Error(t *testing.T) {
	mock := NewMockPool(t)
	store := NewWebhookDeliveryStoreWithDB(mock)

	mock.ExpectExec(`INSERT INTO webhook_deliveries`).
		WithArgs("repo-1", "delivery-1").
		WillReturnError(errors.New("db error"))

	err := store.MarkDeliveryProcessed(context.Background(), "delivery-1", "repo-1")

	assert.Error(t, err)
}
