package enrollment

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/frid-iks/approve-auth/internal/metrics"
	"github.com/frid-iks/approve-auth/internal/store"
)

var (
	// ErrApplicationUnavailable covers unknown and disabled hostnames
	// alike -- callers must not distinguish them in what they show the
	// browser (spec section 5: unknown host gets a generic message, no
	// enrollment).
	ErrApplicationUnavailable   = errors.New("enrollment: application is unknown or disabled")
	ErrInvalidPendingProof      = errors.New("enrollment: pending proof is missing, expired, or unrecognized")
	ErrInvalidCSRF              = errors.New("enrollment: invalid CSRF token")
	ErrRateLimited              = errors.New("enrollment: rate limit exceeded")
	ErrNotClaimable             = errors.New("enrollment: request is not in a claimable/cancelable state")
	ErrAlreadyClaimedNoEnvelope = errors.New("enrollment: already claimed and the retry window has passed")
)

type Service struct {
	store Store
	cfg   Config
}

func New(s Store, cfg Config) *Service {
	return &Service{store: s, cfg: cfg}
}

func (s *Service) Bootstrap(ctx context.Context, in BootstrapInput) (BootstrapResult, error) {
	if s.cfg.BootstrapPerMinutePerIP > 0 && in.ClientIP != "" {
		windowStart := time.Now().Truncate(time.Minute)
		count, err := s.store.IncrementRateLimit(ctx, "bootstrap:"+in.ClientIP, windowStart, time.Minute)
		if err != nil {
			return BootstrapResult{}, fmt.Errorf("enrollment: bootstrap: rate limit: %w", err)
		}
		if count > s.cfg.BootstrapPerMinutePerIP {
			metrics.RateLimitRejections.WithLabelValues("bootstrap_per_minute_per_ip").Inc()
			return BootstrapResult{}, ErrRateLimited
		}
	}

	app, ok, err := s.store.GetApplicationByHostname(ctx, in.Hostname)
	if err != nil {
		return BootstrapResult{}, fmt.Errorf("enrollment: bootstrap: %w", err)
	}
	if !ok || !app.Enabled {
		return BootstrapResult{}, ErrApplicationUnavailable
	}

	if in.ExistingPendingToken != "" {
		hash := hashToken(in.ExistingPendingToken)
		ec, found, err := s.store.GetLiveEnrollmentContextByTokenHash(ctx, hash)
		if err != nil {
			return BootstrapResult{}, fmt.Errorf("enrollment: bootstrap: %w", err)
		}
		if found && ec.ApplicationID == app.ID {
			return BootstrapResult{
				ApplicationDisplayName: app.DisplayName,
				ApplicationHostname:    app.Hostname,
				CSRFToken:              csrfToken(ec.CSRFSecret),
			}, nil
		}
	}

	rawToken, err := generateRawToken()
	if err != nil {
		return BootstrapResult{}, err
	}
	csrfSecret, err := generateCSRFSecret()
	if err != nil {
		return BootstrapResult{}, err
	}
	ec, err := s.store.CreateEnrollmentContext(ctx, app.ID, hashToken(rawToken), csrfSecret, time.Now().Add(s.cfg.RequestTTL))
	if err != nil {
		return BootstrapResult{}, fmt.Errorf("enrollment: bootstrap: creating context: %w", err)
	}

	return BootstrapResult{
		ApplicationDisplayName: app.DisplayName,
		ApplicationHostname:    app.Hostname,
		RawPendingToken:        rawToken,
		CSRFToken:              csrfToken(ec.CSRFSecret),
	}, nil
}

func (s *Service) SubmitRequest(ctx context.Context, in SubmitRequestInput) (SubmitRequestResult, error) {
	if in.PendingTokenRaw == "" {
		return SubmitRequestResult{}, ErrInvalidPendingProof
	}
	hash := hashToken(in.PendingTokenRaw)

	ec, found, err := s.store.GetLiveEnrollmentContextByTokenHash(ctx, hash)
	if err != nil {
		return SubmitRequestResult{}, fmt.Errorf("enrollment: submit: %w", err)
	}
	if !found {
		return SubmitRequestResult{}, ErrInvalidPendingProof
	}
	if !validCSRFToken(ec.CSRFSecret, in.CSRFToken) {
		return SubmitRequestResult{}, ErrInvalidCSRF
	}

	// Repeated submissions with the same pending proof reuse the
	// existing pending request (spec section 5, step 3) -- idempotent,
	// checked before creating anything new.
	if existing, found, err := s.store.GetApprovalRequestByTokenHash(ctx, hash); err != nil {
		return SubmitRequestResult{}, fmt.Errorf("enrollment: submit: %w", err)
	} else if found {
		return SubmitRequestResult{RequestID: existing.ID.String(), VerificationCode: existing.VerificationCode}, nil
	}

	if s.cfg.PendingRequestsPerHourPerAppIP > 0 && in.ClientIP != "" {
		windowStart := time.Now().Truncate(time.Hour)
		bucketKey := "requests:" + ec.ApplicationID.String() + ":" + in.ClientIP
		count, err := s.store.IncrementRateLimit(ctx, bucketKey, windowStart, time.Hour)
		if err != nil {
			return SubmitRequestResult{}, fmt.Errorf("enrollment: submit: rate limit: %w", err)
		}
		if count > s.cfg.PendingRequestsPerHourPerAppIP {
			metrics.RateLimitRejections.WithLabelValues("pending_requests_per_hour_per_app_ip").Inc()
			return SubmitRequestResult{}, ErrRateLimited
		}
	}

	label := truncateRunes(in.Label, 100)
	message := truncateRunes(in.Message, 500)
	returnPath := validateReturnPath(in.ReturnTo)

	params := store.CreateApprovalRequestParams{
		ApplicationID:    ec.ApplicationID,
		PendingTokenHash: hash,
		Label:            label,
		Message:          message,
		ReturnPath:       returnPath,
		DeadlineAt:       time.Now().Add(s.cfg.RequestTTL),
		SourceIP:         in.ClientIP,
		UserAgent:        in.UserAgent,
	}

	const maxAttempts = 5
	for attempt := 0; attempt < maxAttempts; attempt++ {
		code, err := generateVerificationCode()
		if err != nil {
			return SubmitRequestResult{}, err
		}
		params.VerificationCode = code

		req, err := s.store.CreateApprovalRequest(ctx, params)
		if err == nil {
			return SubmitRequestResult{RequestID: req.ID.String(), VerificationCode: req.VerificationCode}, nil
		}

		switch pgConstraintName(err) {
		case "approval_requests_pending_token_hash_key":
			// A concurrent identical submission won the race.
			if existing, found, ferr := s.store.GetApprovalRequestByTokenHash(ctx, hash); ferr == nil && found {
				return SubmitRequestResult{RequestID: existing.ID.String(), VerificationCode: existing.VerificationCode}, nil
			}
			return SubmitRequestResult{}, fmt.Errorf("enrollment: submit: %w", err)
		case "approval_requests_live_verification_code_key":
			continue // collided with another live request's code; retry with a fresh one
		default:
			return SubmitRequestResult{}, fmt.Errorf("enrollment: submit: %w", err)
		}
	}
	return SubmitRequestResult{}, fmt.Errorf("enrollment: submit: exhausted verification code attempts")
}

func (s *Service) Status(ctx context.Context, pendingTokenRaw string) (StatusResult, error) {
	if pendingTokenRaw == "" {
		return StatusResult{}, ErrInvalidPendingProof
	}

	if s.cfg.StatusPerMinutePerPendingProof > 0 {
		windowStart := time.Now().Truncate(time.Minute)
		bucketKey := "status:" + hex.EncodeToString(hashToken(pendingTokenRaw))
		count, err := s.store.IncrementRateLimit(ctx, bucketKey, windowStart, time.Minute)
		if err != nil {
			return StatusResult{}, fmt.Errorf("enrollment: status: rate limit: %w", err)
		}
		if count > s.cfg.StatusPerMinutePerPendingProof {
			metrics.RateLimitRejections.WithLabelValues("status_per_minute_per_pending_proof").Inc()
			return StatusResult{}, ErrRateLimited
		}
	}

	req, found, err := s.store.GetApprovalRequestByTokenHash(ctx, hashToken(pendingTokenRaw))
	if err != nil {
		return StatusResult{}, fmt.Errorf("enrollment: status: %w", err)
	}
	if !found {
		return StatusResult{}, ErrInvalidPendingProof
	}

	result := StatusResult{
		State:            req.Status,
		VerificationCode: req.VerificationCode,
		RequestedAt:      req.RequestedAt,
		DeadlineAt:       req.DeadlineAt,
		ClaimDeadlineAt:  req.ClaimDeadlineAt,
		ServerTime:       time.Now(),
	}
	if req.Status == "denied" {
		result.PublicMessage = derefString(req.PublicDecisionMessage)
	}
	if ec, found, err := s.store.GetLiveEnrollmentContextByTokenHash(ctx, hashToken(pendingTokenRaw)); err == nil && found {
		result.CSRFToken = csrfToken(ec.CSRFSecret)
	}
	return result, nil
}

func (s *Service) Cancel(ctx context.Context, pendingTokenRaw, csrfTokenIn string) error {
	_, req, err := s.lookupContextAndRequest(ctx, pendingTokenRaw, csrfTokenIn)
	if err != nil {
		return err
	}

	if err := s.store.CancelApprovalRequest(ctx, req.ID); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return ErrNotClaimable
		}
		return fmt.Errorf("enrollment: cancel: %w", err)
	}
	return nil
}

func (s *Service) Claim(ctx context.Context, pendingTokenRaw, csrfTokenIn string) (ClaimOutcome, error) {
	_, req, err := s.lookupContextAndRequest(ctx, pendingTokenRaw, csrfTokenIn)
	if err != nil {
		return ClaimOutcome{}, err
	}

	candidateRaw, err := generateRawToken()
	if err != nil {
		return ClaimOutcome{}, err
	}

	credentialID, applicationID, alreadyClaimed, err := s.store.ClaimApproved(ctx, req.ID, hashToken(candidateRaw), s.cfg.CredentialMaxAge)
	if err != nil {
		if errors.Is(err, store.ErrRequestNotClaimable) {
			return ClaimOutcome{}, ErrNotClaimable
		}
		return ClaimOutcome{}, fmt.Errorf("enrollment: claim: %w", err)
	}

	returnTo := validateReturnPath(derefString(req.ReturnPath))

	if alreadyClaimed {
		envelope, found, err := s.store.GetLiveClaimEnvelope(ctx, req.ID)
		if err != nil {
			return ClaimOutcome{}, fmt.Errorf("enrollment: claim: %w", err)
		}
		if !found {
			return ClaimOutcome{}, ErrAlreadyClaimedNoEnvelope
		}
		rawToken, err := decryptEnvelope(s.cfg.ClaimEncryptionKey, req.ID, applicationID, envelope.Nonce, envelope.Ciphertext)
		if err != nil {
			return ClaimOutcome{}, fmt.Errorf("enrollment: claim: decrypting retry envelope: %w", err)
		}
		return ClaimOutcome{RawAccessToken: rawToken, ReturnTo: returnTo}, nil
	}

	nonce, ciphertext, err := encryptEnvelope(s.cfg.ClaimEncryptionKey, req.ID, applicationID, candidateRaw)
	if err != nil {
		return ClaimOutcome{}, err
	}
	if err := s.store.SaveClaimEnvelope(ctx, req.ID, credentialID, s.cfg.ClaimEncryptionKeyID, nonce, ciphertext, time.Now().Add(s.cfg.ClaimRetryTTL)); err != nil {
		return ClaimOutcome{}, fmt.Errorf("enrollment: claim: %w", err)
	}

	return ClaimOutcome{RawAccessToken: candidateRaw, ReturnTo: returnTo}, nil
}

// Ack consumes the claim envelope and the enrollment context (spec
// section 5, step 7-8) and returns the validated return path.
func (s *Service) Ack(ctx context.Context, pendingTokenRaw string) (string, error) {
	if pendingTokenRaw == "" {
		return "", ErrInvalidPendingProof
	}
	hash := hashToken(pendingTokenRaw)
	req, found, err := s.store.GetApprovalRequestByTokenHash(ctx, hash)
	if err != nil {
		return "", fmt.Errorf("enrollment: ack: %w", err)
	}
	if !found {
		return "", ErrInvalidPendingProof
	}
	if req.Status != "claimed" {
		return "", ErrNotClaimable
	}

	if err := s.store.DeleteClaimEnvelope(ctx, req.ID); err != nil {
		return "", fmt.Errorf("enrollment: ack: %w", err)
	}
	if ec, found, err := s.store.GetLiveEnrollmentContextByTokenHash(ctx, hash); err == nil && found {
		_ = s.store.ConsumeEnrollmentContext(ctx, ec.ID)
	}

	return validateReturnPath(derefString(req.ReturnPath)), nil
}

// lookupContextAndRequest is the common prelude for Cancel and Claim:
// resolve the enrollment context (for CSRF), validate the token, then
// resolve the approval request itself.
func (s *Service) lookupContextAndRequest(ctx context.Context, pendingTokenRaw, csrfTokenIn string) (store.EnrollmentContext, store.ApprovalRequest, error) {
	if pendingTokenRaw == "" {
		return store.EnrollmentContext{}, store.ApprovalRequest{}, ErrInvalidPendingProof
	}
	hash := hashToken(pendingTokenRaw)

	ec, found, err := s.store.GetLiveEnrollmentContextByTokenHash(ctx, hash)
	if err != nil {
		return store.EnrollmentContext{}, store.ApprovalRequest{}, fmt.Errorf("enrollment: %w", err)
	}
	if !found {
		return store.EnrollmentContext{}, store.ApprovalRequest{}, ErrInvalidPendingProof
	}
	if !validCSRFToken(ec.CSRFSecret, csrfTokenIn) {
		return store.EnrollmentContext{}, store.ApprovalRequest{}, ErrInvalidCSRF
	}

	req, found, err := s.store.GetApprovalRequestByTokenHash(ctx, hash)
	if err != nil {
		return store.EnrollmentContext{}, store.ApprovalRequest{}, fmt.Errorf("enrollment: %w", err)
	}
	if !found {
		return store.EnrollmentContext{}, store.ApprovalRequest{}, ErrInvalidPendingProof
	}
	return ec, req, nil
}

// Logout revokes the browser's own authorization for hostname (spec
// section 9). Always a no-op rather than an error if the cookie doesn't
// match anything live -- the browser clears its cookies either way.
func (s *Service) Logout(ctx context.Context, hostname, accessCookieValue string) error {
	if accessCookieValue == "" {
		return nil
	}
	if err := s.store.RevokeByCredentialHash(ctx, hostname, hashToken(accessCookieValue), "self"); err != nil {
		return fmt.Errorf("enrollment: logout: %w", err)
	}
	return nil
}

func pgConstraintName(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.ConstraintName
	}
	return ""
}

func derefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func truncateRunes(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max])
}
