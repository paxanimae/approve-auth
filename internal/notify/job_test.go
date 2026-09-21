package notify_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/frid-iks/approve-auth/internal/notify"
	"github.com/frid-iks/approve-auth/internal/store"
)

// fakeJobStore is an in-memory stand-in for notify.JobStore, so
// DeliverPending's orchestration (which application each row resolves
// to, how success/failure update the row) can be tested without a real
// Postgres.
type fakeJobStore struct {
	mu    sync.Mutex
	items []store.NotificationOutboxItem
	apps  map[uuid.UUID]store.Application

	delivered    map[uuid.UUID]bool
	failed       map[uuid.UUID]string
	nextAttempts map[uuid.UUID]time.Time
}

func newFakeJobStore() *fakeJobStore {
	return &fakeJobStore{
		apps: make(map[uuid.UUID]store.Application), delivered: make(map[uuid.UUID]bool),
		failed: make(map[uuid.UUID]string), nextAttempts: make(map[uuid.UUID]time.Time),
	}
}

func (f *fakeJobStore) ListPendingNotifications(context.Context, int) ([]store.NotificationOutboxItem, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.items, nil
}

func (f *fakeJobStore) GetApplicationByID(_ context.Context, id uuid.UUID) (store.Application, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	app, ok := f.apps[id]
	return app, ok, nil
}

func (f *fakeJobStore) MarkNotificationDelivered(_ context.Context, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.delivered[id] = true
	return nil
}

func (f *fakeJobStore) MarkNotificationFailed(_ context.Context, id uuid.UUID, nextAttemptAt time.Time, lastError string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failed[id] = lastError
	f.nextAttempts[id] = nextAttemptAt
	return nil
}

func strPtr(s string) *string { return &s }

func TestDeliverPending_SuccessMarksDelivered(t *testing.T) {
	var receivedBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	appID := uuid.New()
	itemID := uuid.New()
	payload, err := json.Marshal(notify.RequestCreatedPayload{RequestID: "req-1", VerificationCode: "XYZ789", RequestedAt: time.Now()})
	if err != nil {
		t.Fatalf("marshaling payload: %v", err)
	}

	s := newFakeJobStore()
	s.items = []store.NotificationOutboxItem{{ID: itemID, ApplicationID: appID, EventType: notify.EventRequestCreated, Payload: payload}}
	s.apps[appID] = store.Application{ID: appID, Hostname: "app-a.example.test", DisplayName: "App A", NotifyWebhookURL: strPtr(srv.URL)}

	d := notify.New(notify.Config{})
	delivered, err := d.DeliverPending(context.Background(), s, 10)
	if err != nil {
		t.Fatalf("DeliverPending: %v", err)
	}
	if delivered != 1 {
		t.Errorf("delivered = %d, want 1", delivered)
	}
	if !s.delivered[itemID] {
		t.Error("item was not marked delivered")
	}
	if receivedBody["verification_code"] != "XYZ789" {
		t.Errorf("webhook body = %+v, missing expected verification_code", receivedBody)
	}
}

func TestDeliverPending_FailureIncrementsAttemptsAndBacksOff(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	appID := uuid.New()
	itemID := uuid.New()
	payload, _ := json.Marshal(notify.RequestCreatedPayload{RequestID: "req-2", VerificationCode: "AAA111", RequestedAt: time.Now()})

	s := newFakeJobStore()
	s.items = []store.NotificationOutboxItem{{ID: itemID, ApplicationID: appID, EventType: notify.EventRequestCreated, Payload: payload, Attempts: 0}}
	s.apps[appID] = store.Application{ID: appID, Hostname: "app-a.example.test", DisplayName: "App A", NotifyWebhookURL: strPtr(srv.URL)}

	d := notify.New(notify.Config{})
	before := time.Now()
	delivered, err := d.DeliverPending(context.Background(), s, 10)
	if err != nil {
		t.Fatalf("DeliverPending: %v", err)
	}
	if delivered != 0 {
		t.Errorf("delivered = %d, want 0", delivered)
	}
	if s.delivered[itemID] {
		t.Error("item was incorrectly marked delivered")
	}
	if s.failed[itemID] == "" {
		t.Error("expected a non-empty last_error")
	}
	if !s.nextAttempts[itemID].After(before) {
		t.Errorf("next_attempt_at = %v, want it pushed into the future", s.nextAttempts[itemID])
	}
}

func TestDeliverPending_NothingConfiguredStillMarksDelivered(t *testing.T) {
	appID := uuid.New()
	itemID := uuid.New()
	payload, _ := json.Marshal(notify.RequestCreatedPayload{RequestID: "req-3", VerificationCode: "BBB222", RequestedAt: time.Now()})

	s := newFakeJobStore()
	s.items = []store.NotificationOutboxItem{{ID: itemID, ApplicationID: appID, EventType: notify.EventRequestCreated, Payload: payload}}
	// No NotifyEmail/NotifyWebhookURL override on the app, and no
	// global default configured on the Dispatcher either.
	s.apps[appID] = store.Application{ID: appID, Hostname: "app-a.example.test", DisplayName: "App A"}

	d := notify.New(notify.Config{})
	delivered, err := d.DeliverPending(context.Background(), s, 10)
	if err != nil {
		t.Fatalf("DeliverPending: %v", err)
	}
	if delivered != 1 {
		t.Errorf("delivered = %d, want 1 (nothing configured is a vacuous success)", delivered)
	}
}

func TestDeliverPending_AppOverrideTakesPriorityOverGlobalDefault(t *testing.T) {
	var hitOverride, hitDefault bool
	overrideSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hitOverride = true; w.WriteHeader(http.StatusOK) }))
	defer overrideSrv.Close()
	defaultSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hitDefault = true; w.WriteHeader(http.StatusOK) }))
	defer defaultSrv.Close()

	appID := uuid.New()
	itemID := uuid.New()
	payload, _ := json.Marshal(notify.RequestCreatedPayload{RequestID: "req-4", VerificationCode: "CCC333", RequestedAt: time.Now()})

	s := newFakeJobStore()
	s.items = []store.NotificationOutboxItem{{ID: itemID, ApplicationID: appID, EventType: notify.EventRequestCreated, Payload: payload}}
	s.apps[appID] = store.Application{ID: appID, Hostname: "app-a.example.test", DisplayName: "App A", NotifyWebhookURL: strPtr(overrideSrv.URL)}

	d := notify.New(notify.Config{DefaultWebhookURL: defaultSrv.URL})
	if _, err := d.DeliverPending(context.Background(), s, 10); err != nil {
		t.Fatalf("DeliverPending: %v", err)
	}
	if !hitOverride {
		t.Error("expected the application's own webhook override to be used")
	}
	if hitDefault {
		t.Error("expected the global default webhook to be skipped when an override exists")
	}
}
