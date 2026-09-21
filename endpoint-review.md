# Anonymous enrollment endpoint security review

Date: 2026-09-21  
Scope: `GET /__approve-auth/request`, `POST /__approve-auth/requests`, and downstream handling of anonymous labels and messages.  
Status: analysis and recommendations; no remediation implemented by this review.

## Assessment

Anonymous request messages create a meaningful attack surface. The inspected implementation has protections against direct SQL injection and browser script execution, but important gaps remain in resource limits, abuse prevention, notification delivery, and the presentation of unverified text to approvers.

**Recommendation: disable anonymous free-text messages by default, preserve the request-and-verification-code flow, and harden the submission endpoint regardless.** Where messages are necessary, make them an explicit per-application option with server-side enforcement and the safeguards below. Apply the same policy to the anonymous label so it cannot become a replacement message field.

Removing the visible textarea alone does not secure the endpoint: callers can still send arbitrary HTTP bodies. Conversely, escaping text prevents executable markup but does not prevent phishing or manipulation of approval decisions.

## Scope and evidence limits

This review examined the working tree, including an ongoing migration to database-backed global settings. Source references identify the implementation inspected, not a frozen release. Reassess findings against the final changes before release.

The review traced submission, storage, admin rendering, email, webhook delivery, and retention. A bounded test exercised the actual public HTTP handler in an isolated Docker container using a Go test overlay and a read-only project mount. It did not modify project files, contact a deployed service, send notifications, or write to a database.

The test used a stub enrollment service that returned `ErrInvalidPendingProof`, isolating the HTTP handler's parsing order. It demonstrated that an oversized message reaches the service before rejection; it did not demonstrate successful storage, an authorization bypass, or a measured service outage.

Production proxy configuration, external notification consumers, and browser execution were not independently penetration-tested. Severity below is a remediation priority based on the inspected code; deployment exposure affects exploitability.

## Data flow and trust boundaries

```text
Anonymous browser
  -> public request parser
  -> pending-cookie and CSRF validation
  -> per-application/IP submission quota
  -> label/message truncation
  -> PostgreSQL approval request
       -> admin request list and approval dialog
       -> notification outbox
            -> email body
            -> webhook JSON
```

The message is attacker-controlled data throughout this flow. Authentication of the administrator does not make content displayed to that administrator trustworthy. Similarly, a notification sent by this service can contain unverified content supplied by someone else.

An anonymous requester can legitimately bootstrap their own pending cookie and CSRF token. Those controls protect request integrity and cross-site interactions; they do not authenticate the requester or stop a bot operating its own session.

## Findings

### F1 — High priority: request bodies are parsed before validation without a small explicit limit

**Evidence**

- `internal/httpserver/enrollment_handlers.go`: `submitRequestHandler` calls `parseSubmitForm` before invoking the enrollment service.
- The handler checks origin and the presence of a pending cookie first, but does not validate that cookie before parsing.
- `parseSubmitForm` decodes JSON directly from `r.Body` without `http.MaxBytesReader` or an equivalent explicit cap.
- Ordinary URL-encoded forms use Go's `ParseForm`, which has a default 10 MiB body limit when no smaller limit is installed. That is still much larger than this form needs.
- `internal/enrollment/service.go`: pending proof, CSRF, and submission quota checks happen after parsing; message truncation to 500 runes happens later still.
- `cmd/server/main.go`: the HTTP server configurations do not specify read, read-header, or idle timeouts. Effective external slow-request exposure depends on Traefik and any upstream proxy.

**Bounded reproduction**

The actual public mux received a same-origin request with a non-empty but invalid pending cookie and a 1 MiB message. A stub service rejected it after recording the parsed input.

| Encoding | Body bytes read | Message bytes passed to service | Final response |
|---|---:|---:|---:|
| JSON | 1,048,590 | 1,048,576 | 401 |
| URL-encoded form | 1,048,584 | 1,048,576 | 401 |

This confirms the late-rejection boundary. A valid enrollment session is not required to consume these parsing resources. The JSON path has no explicit application body-size bound; the test deliberately stopped at 1 MiB.

**Impact**

Concurrent large or slow requests can consume memory, CPU, connections, and goroutines. Public enrollment and authorization run in the same process, so resource exhaustion could interrupt access to protected applications even when authorization fails closed.

**Remediation**

- Install a small body-byte limit before either parser and return `413 Payload Too Large` on overflow.
- Start with a proposed 16 KiB total submission limit, then verify legitimate Unicode, URL-encoded fields, CSRF tokens, and return paths fit.
- Apply the limit to streaming/chunked bodies, not only the declared `Content-Length`.
- Add appropriate server and proxy deadlines and early request/concurrency limits.
- Accept only the intended content types; reject unsupported types explicitly.
- Reject oversized fields rather than silently truncating them. Validate the complete JSON document, including trailing data, and define consistent handling of duplicate fields.

### F2 — High priority: abuse controls are incomplete and client-IP trust is not enforced locally

**Existing controls**

The default configuration limits new requests to five per application/IP/hour and bootstrap operations to 30 per IP/minute. Repeated submission with the same pending proof reuses the existing request. Database counters provide shared state across replicas.

**Gaps**

- `GlobalEnrollmentPerHour` defaults to 1,000 in `internal/config/config.go`, but the inspected enrollment implementation does not consume it.
- Submission quota checks occur after body parsing and database lookups.
- Rotating addresses can bypass per-IP quotas; shared office addresses can cause legitimate users to block one another.
- The checks are conditional on positive configured values; non-positive values disable them. Explicit configuration validation should prevent accidental disabling.
- `clientIP` delegates to `clientAddr`, which takes the final `X-Forwarded-For` value without verifying that the immediate peer is an approved proxy.
- `TrustedTraefikCIDRs` is configured and validated but is not applied to this extraction path.
- The supplied public Traefik router does not attach an enrollment-specific rate-limit or body-size middleware. Additional infrastructure protections may exist outside this repository.

**Deployment qualification**

A correctly isolated listener behind correctly configured Traefik reduces forwarded-header spoofing exposure. A caller able to reach the public listener directly can supply arbitrary forwarded metadata. The isolated handler test also confirmed that its supplied forwarded IP was passed through; this does not establish spoofability through the deployed Traefik instance.

**Remediation**

- Apply inexpensive edge limits before parsing and database work.
- Enforce shared per-application and global quotas, plus pending-request and notification-backlog ceilings.
- Define trusted-proxy processing from the immediate peer outward; normalize client addresses and strip ports correctly.
- Restrict direct listener access and verify the full proxy chain in integration tests.
- Account for IPv6 address rotation and shared networks without treating an IP address as identity.
- Validate enabled quotas at startup and make any intentional disabling explicit.

### F3 — High priority: anonymous text can manipulate approvers and lend credibility to phishing

**Evidence**

- `web/admin/src/lib/Requests.svelte` displays the message in the request list and repeats it in the approval dialog as “Message from the device.”
- `internal/notify/dispatcher.go` places the label and message verbatim in the plain-text email body.
- Message validation does not explicitly constrain line count or misleading control characters.

**Impact**

A requester can impersonate a colleague, claim urgency, or direct the administrator to an external verification page. Plain-text email clients may automatically make URLs clickable. Newlines can imitate service-generated fields inside the email body, and Unicode direction controls can obscure how text is read.

This is a human trust problem even when scripts never execute. The message's arrival through a trusted service must not be interpreted as verification of its author.

**Remediation**

- Exclude anonymous message and label content from email and webhook notifications by default.
- Send server-controlled application details, a request identifier, and a link built from the configured admin origin.
- Where retained, show the message in a visually separate area labelled “Unverified text supplied by the requester.”
- Keep the application, request code, and proposed duration prominent in approval confirmation; do not let anonymous text substitute for these facts.
- Do not render message HTML or Markdown, automatically create links, fetch previews, or load remote images.
- Require independent verification appropriate to the deployment, such as physically checking the TV or contacting a known person through an established channel.
- Treat the verification code as a way to match a request, not as proof of identity.
- Never approve automatically based on message contents.

For controlled devices, consider administrator-issued, short-lived, single-use enrollment invitations. Bind invitations to the intended application and define whether they merely permit submission or confer any additional trust. Do not silently turn an invitation into an access grant.

### F4 — Medium priority: notifications amplify abuse and retain failed messages indefinitely

**Evidence**

- A new request queues a notification containing its label and message.
- `internal/notify/job.go` retries failures with increasing delay, capped at one hour, without a maximum retry age or attempt count.
- Email and webhook delivery share a combined result. If email succeeds and webhook delivery fails, retrying the event can send the email again.
- `internal/store/notifications.go` purges delivered notifications only.
- The outbox payload is independent of request deletion; its schema references the application, not the request with cascading deletion.

**Impact**

Abuse can flood inboxes and exhaust approvers' attention. A failed destination can retain anonymous content indefinitely and grow the outbox. Successful email delivery combined with repeated webhook failure can multiply emails from one request.

**Remediation**

- Use digests, coalescing, and per-application notification delivery budgets.
- Track successful delivery separately for each channel and avoid replaying completed channels.
- Apply maximum retry age, queue size, and terminal-failure handling.
- Remove sensitive payload content from expired or failed events, retaining only necessary operational metadata.
- Add explicit SMTP connection/protocol deadlines; the inspected SMTP path ignores the provided context.
- Monitor queue size, age, delivery failures, and abnormal notification volume without logging message bodies.

### F5 — Medium priority: free-text retention should be independent of access-record retention

Approval request messages currently follow the request record's lifecycle. Defaults retain resolved request records for 90 days, while a request supporting a live authorization is retained longer. Delivered outbox payloads have a separate 30-day default; failed payloads have the retention gap described above. External mailboxes and webhook receivers create further copies outside this service's cleanup control.

Anonymous users may enter passwords, personal information, or abusive content even when instructed otherwise.

**Remediation**

- Minimize collection and state that secrets should not be entered.
- Define a short, explicit retention period for label/message content independently of authorization and audit records.
- Redact all internal copies, including outbox payloads, when that period expires.
- Keep raw messages out of routine logs, metrics, and immutable audit details.
- Review external destination access and retention before enabling content delivery.

## Injection assessment

| Threat | Assessment of the inspected path |
|---|---|
| SQL injection | Approval-request insertion uses parameterized queries. No direct message-to-SQL injection path found. |
| Stored browser XSS | Svelte renders messages through text expressions, including the approval dialog; no raw-HTML message rendering found. CSP adds defense in depth. |
| Email header injection | Anonymous message text is inserted after the header/body separator. No direct recipient or header injection path found. Body impersonation remains possible. |
| Server-side URL fetching | Message URLs are not fetched by the service. Webhook destinations are administrator-configured. |
| Shell execution | No message-to-command execution path found. |
| Downstream injection | JSON encoding protects transport structure, not how receivers interpret values. Consumers must independently prevent HTML, command, spreadsheet-formula, and other injection. |
| AI-assisted processing | If a downstream consumer feeds messages to an AI system, treat them as untrusted content, not instructions. No such integration was established in this review. Never let message interpretation authorize access. |

The database also constrains stored message length to 500 characters, and the service truncates to 500 runes. These are useful storage bounds but do not limit input parsing costs or establish trust.

Preserve contextual output encoding and parameterized queries. A blacklist of words, punctuation, or apparent attack strings is not a substitute. Do not require ASCII-only text; legitimate international text should remain usable.

## Recommended implementation order

1. **Close the resource-exhaustion gap:** early body limits, explicit deadlines, supported content types, strict parsing, and early edge limits. Apply relevant controls to adjacent public mutation endpoints too.
2. **Reduce anonymous content exposure:** default messages off, reject non-empty submissions server-side when disabled, and apply an equivalent label policy. Keep the request/code flow usable without text.
3. **Repair abuse enforcement:** implement the configured global limit, application quotas and queue ceilings, verified proxy processing, and safe quota validation.
4. **Protect approval decisions:** clearly distinguish unverified text, remove it from notifications by default, and establish independent device/request verification.
5. **Bound downstream effects:** per-channel delivery tracking, notification budgets, retry expiry, SMTP deadlines, and independent content retention.

If optional messages remain enabled, use constrained plain text with server-side character and byte limits. Reject invalid encoding, NUL and inappropriate control characters, explicitly handle direction overrides, and bound line count. These controls supplement safe rendering; they do not make the message's claims trustworthy.

## Verification and acceptance criteria

Before considering remediation complete, verify:

- Oversized JSON, URL-encoded, and chunked requests return `413` before expensive parsing or service/database work.
- Invalid cookies, malformed input, and excessive repeated attempts cannot bypass early resource controls.
- Exact-boundary inputs and legitimate multilingual text work within documented byte/character limits.
- Unsupported content types, trailing JSON, and duplicate fields receive defined, consistent responses.
- Slow headers and bodies are bounded by tested deadlines.
- Disabled messages cannot be submitted through direct HTTP calls; labels cannot bypass the policy.
- HTML-like text, quotes, newlines, URLs, and Unicode direction-control cases remain inert and clearly unverified in the actual admin browser UI.
- Anonymous content is absent from notifications by default and is never interpreted as instructions by downstream automation.
- Per-IP, per-application, and global limits hold across replicas and under concurrent submissions.
- Forged forwarded headers cannot change the effective client identity through the supported proxy path; direct listener exposure is restricted.
- One pending proof creates at most one request and initial notification under retries and concurrency.
- A successful email is not resent merely because another channel fails.
- Failed notifications expire, queue limits hold, and message redaction covers all internal copies.
- The no-JavaScript/TV flow remains usable, with actionable errors and no need for text entry where messages are disabled.
- Load tests confirm enrollment traffic cannot starve authorization decisions within the intended operating envelope.

## References

Local implementation references:

- `internal/httpserver/enrollment_handlers.go` — parsing and public submission handler.
- `internal/httpserver/auth.go` — forwarded client-IP extraction.
- `internal/httpserver/httpserver.go` — public routes and security headers.
- `internal/enrollment/service.go` — pending proof, CSRF, quotas, truncation, notification enqueueing.
- `internal/config/config.go` — configured rate limits and retention defaults.
- `internal/store/approval_requests.go` — parameterized insertion and audit event.
- `migrations/000003_approval_requests.up.sql` — stored message length constraint.
- `web/admin/src/lib/Requests.svelte` and `DurationDialog.svelte` — message presentation.
- `internal/notify/dispatcher.go` and `job.go` — email/webhook composition and retry behavior.
- `internal/store/notifications.go`, `internal/store/retention.go`, and `internal/worker/jobs.go` — cleanup behavior.
- `migrations/000017_notifications.up.sql` — outbox schema and relationships.
- `cmd/server/main.go` — listener configuration and shared-process architecture.
- `deploy/traefik-approve-auth-middleware.yml` — supplied public routing and proxy assumptions.

External guidance consulted:

- [Go net/http: MaxBytesReader](https://pkg.go.dev/net/http#MaxBytesReader) — limiting incoming request bodies.
- [Go net/http: Request.ParseForm](https://pkg.go.dev/net/http#Request.ParseForm) — default URL-encoded form parsing limit.
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html) — validation of free text and the need for contextual output encoding.
- [OWASP Denial of Service Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html) — request-size and resource-consumption controls.

These references support the mitigation approach. The project-specific findings above come from source inspection and the bounded handler test, not from a third-party security audit.
