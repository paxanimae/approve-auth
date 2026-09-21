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

	"github.com/paxanimae/approve-auth/internal/notify"
	"github.com/paxanimae/approve-auth/internal/store"
)

// fakeJobStore is an in-memory stand-in for notify.JobStore, so
// DeliverPending's orchestration (which application each row resolves
// to, how success/failure update the row) can be tested without a real
// Postgres.
type fakeJobStore struct {
	mu       sync.Mutex
	items    []store.NotificationOutboxItem
	apps     map[uuid.UUID]store.Application
	settings store.GlobalSettings

	delivered        map[uuid.UUID]bool
	channelDelivered map[uuid.UUID]map[string]bool
	failed           map[uuid.UUID]string
	nextAttempts     map[uuid.UUID]time.Time
	givenUp          map[uuid.UUID]string
}

func newFakeJobStore() *fakeJobStore {
	return &fakeJobStore{
		apps: make(map[uuid.UUID]store.Application), delivered: make(map[uuid.UUID]bool),
		channelDelivered: make(map[uuid.UUID]map[string]bool),
		failed:           make(map[uuid.UUID]string), nextAttempts: make(map[uuid.UUID]time.Time),
		givenUp: make(map[uuid.UUID]string),
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

func (f *fakeJobStore) MarkNotificationChannelDelivered(_ context.Context, id uuid.UUID, channel string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.channelDelivered[id] == nil {
		f.channelDelivered[id] = make(map[string]bool)
	}
	f.channelDelivered[id][channel] = true
	return nil
}

func (f *fakeJobStore) MarkNotificationFailed(_ context.Context, id uuid.UUID, nextAttemptAt time.Time, lastError string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failed[id] = lastError
	f.nextAttempts[id] = nextAttemptAt
	return nil
}

func (f *fakeJobStore) GiveUpOnNotification(_ context.Context, id uuid.UUID, reason string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.givenUp[id] = reason
	return nil
}

func (f *fakeJobStore) GetGlobalSettings(context.Context) (store.GlobalSettings, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.settings, nil
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
	s.items = []store.NotificationOutboxItem{{ID: itemID, ApplicationID: appID, EventType: notify.EventRequestCreated, Payload: payload, CreatedAt: time.Now()}}
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
	s.items = []store.NotificationOutboxItem{{ID: itemID, ApplicationID: appID, EventType: notify.EventRequestCreated, Payload: payload, Attempts: 0, CreatedAt: time.Now()}}
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
	s.items = []store.NotificationOutboxItem{{ID: itemID, ApplicationID: appID, EventType: notify.EventRequestCreated, Payload: payload, CreatedAt: time.Now()}}
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
	s.items = []store.NotificationOutboxItem{{ID: itemID, ApplicationID: appID, EventType: notify.EventRequestCreated, Payload: payload, CreatedAt: time.Now()}}
	s.apps[appID] = store.Application{ID: appID, Hostname: "app-a.example.test", DisplayName: "App A", NotifyWebhookURL: strPtr(overrideSrv.URL)}
	s.settings = store.GlobalSettings{NotifyDefaultWebhookURL: strPtr(defaultSrv.URL)}

	d := notify.New(notify.Config{})
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

// TestDeliverPending_SkipsAlreadyDeliveredChannel covers endpoint-
// review.md F4: a channel already recorded delivered on a prior
// attempt must never be re-attempted, even while the row as a whole is
// still pending because another channel keeps failing.
func TestDeliverPending_SkipsAlreadyDeliveredChannel(t *testing.T) {
	webhookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer webhookSrv.Close()

	appID := uuid.New()
	itemID := uuid.New()
	payload, _ := json.Marshal(notify.RequestCreatedPayload{RequestID: "req-5", VerificationCode: "DDD444", RequestedAt: time.Now()})
	alreadyDelivered := time.Now().Add(-time.Hour)

	s := newFakeJobStore()
	s.items = []store.NotificationOutboxItem{{
		ID: itemID, ApplicationID: appID, EventType: notify.EventRequestCreated, Payload: payload,
		CreatedAt: time.Now(), EmailDeliveredAt: &alreadyDelivered,
	}}
	// SMTPHost points at an address nothing listens on -- if the
	// delivery job re-attempts email despite EmailDeliveredAt already
	// being set, this dial fails and the row would not end up fully
	// delivered below.
	s.apps[appID] = store.Application{ID: appID, Hostname: "app-a.example.test", DisplayName: "App A", NotifyEmail: strPtr("ops@example.test"), NotifyWebhookURL: strPtr(webhookSrv.URL)}
	s.settings = store.GlobalSettings{NotifyEmailFrom: strPtr("approve-auth@example.test")}

	d := notify.New(notify.Config{SMTPHost: "127.0.0.1", SMTPPort: 1})
	delivered, err := d.DeliverPending(context.Background(), s, 10)
	if err != nil {
		t.Fatalf("DeliverPending: %v", err)
	}
	if delivered != 1 {
		t.Errorf("delivered = %d, want 1 -- the already-delivered email channel must not be re-attempted", delivered)
	}
	if !s.channelDelivered[itemID]["webhook"] {
		t.Error("expected the webhook channel to be recorded delivered")
	}
	if s.channelDelivered[itemID]["email"] {
		t.Error("email channel should not have been re-attempted -- it was already delivered")
	}
}

// TestDeliverPending_GivesUpAfterMaxAttempts and
// TestDeliverPending_GivesUpAfterMaxAge cover endpoint-review.md F4:
// "apply maximum retry age, queue size, and terminal-failure handling."
func TestDeliverPending_GivesUpAfterMaxAttempts(t *testing.T) {
	appID := uuid.New()
	itemID := uuid.New()
	payload, _ := json.Marshal(notify.RequestCreatedPayload{RequestID: "req-6", VerificationCode: "EEE555", RequestedAt: time.Now()})

	s := newFakeJobStore()
	s.items = []store.NotificationOutboxItem{{
		ID: itemID, ApplicationID: appID, EventType: notify.EventRequestCreated, Payload: payload,
		Attempts: 999, CreatedAt: time.Now(),
	}}
	s.apps[appID] = store.Application{ID: appID, Hostname: "app-a.example.test", DisplayName: "App A", NotifyWebhookURL: strPtr("http://127.0.0.1:1")}

	d := notify.New(notify.Config{})
	delivered, err := d.DeliverPending(context.Background(), s, 10)
	if err != nil {
		t.Fatalf("DeliverPending: %v", err)
	}
	if delivered != 0 {
		t.Errorf("delivered = %d, want 0", delivered)
	}
	if s.givenUp[itemID] == "" {
		t.Error("expected the row to be given up on after exceeding the max attempt count")
	}
	if s.failed[itemID] != "" {
		t.Error("a given-up row should not also be recorded as an ordinary retry failure")
	}
}

func TestDeliverPending_GivesUpAfterMaxAge(t *testing.T) {
	appID := uuid.New()
	itemID := uuid.New()
	payload, _ := json.Marshal(notify.RequestCreatedPayload{RequestID: "req-7", VerificationCode: "FFF666", RequestedAt: time.Now()})

	s := newFakeJobStore()
	s.items = []store.NotificationOutboxItem{{
		ID: itemID, ApplicationID: appID, EventType: notify.EventRequestCreated, Payload: payload,
		CreatedAt: time.Now().Add(-48 * time.Hour),
	}}
	s.apps[appID] = store.Application{ID: appID, Hostname: "app-a.example.test", DisplayName: "App A", NotifyWebhookURL: strPtr("http://127.0.0.1:1")}

	d := notify.New(notify.Config{})
	if _, err := d.DeliverPending(context.Background(), s, 10); err != nil {
		t.Fatalf("DeliverPending: %v", err)
	}
	if s.givenUp[itemID] == "" {
		t.Error("expected the row to be given up on after exceeding the max retry age")
	}
}
