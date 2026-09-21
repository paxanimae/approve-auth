package notify

// BuildEmailMessageForTest exposes the otherwise-unexported
// buildEmailMessage to notify_test's black-box tests (the standard Go
// export_test.go idiom) -- it's a pure function worth unit testing
// directly (header sanitization, body content) without a real SMTP
// server, and doesn't belong in this package's actual public API.
var BuildEmailMessageForTest = buildEmailMessage
