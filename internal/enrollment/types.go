package enrollment

// SubmitRequestInput is what a browser's POST /__manual-approval/requests
// carries (spec section 5, step 3).
type SubmitRequestInput struct {
	ApplicationID string
	Label         string
	Message       string
	ReturnTo      string
	PendingProof  string
}

type SubmitRequestResult struct {
	RequestID        string
	VerificationCode string
}
