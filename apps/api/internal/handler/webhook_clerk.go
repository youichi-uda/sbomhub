package handler

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/config"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// Error contract (M46 Track C-3b). Retry facts, verified 2026-07-26 against
// the official docs: Clerk delegates webhook delivery to Svix
// (clerk.com/docs/webhooks/overview → docs.svix.com/retries). A non-2xx
// response (3xx included) is retried on a FINITE schedule of 8 total
// attempts — "Immediately, 5 seconds, 5 minutes, 30 minutes, 2 hours,
// 5 hours, 10 hours, 10 hours" — after which the message is marked Failed
// and can still be replayed manually from the Clerk Dashboard. Automatic
// endpoint disabling only kicks in after ~5 days of CONTINUOUS failure, so
// answering 500 on a transient error is safe and buys a clean redelivery
// once the dependency recovers. Conversely, a 2xx is never retried: any
// event answered 200 without its writes committed is lost forever.
//
// Contract per failure class (mirrors webhook_lemonsqueezy.go, 3a7d483):
//   - Lookup errors: only sql.ErrNoRows means "not found". Any other error
//     answers 500 — misreading infra trouble as not-found either drops a
//     deletion forever or falls through to Create and collides with the
//     clerk_org_id UNIQUE index on redelivery.
//   - State-changing writes (Upsert / Create / Update / Delete /
//     Add|RemoveFromTenant): failure answers 500. All of them are
//     idempotent, so the Svix redelivery is a clean re-run.
//   - Audit-log failure after a committed UPSERT: answers 500. The audit
//     row is the ONLY history write on those paths and the upsert is
//     idempotent, so redelivery recovers the audit trail with no
//     duplication risk (unlike Lemon Squeezy's two history writes, where a
//     redelivery could duplicate rows — hence its 200-and-slog contract).
//   - Audit-log failure after a committed DELETE: keeps the 200 and logs
//     via slog. A 5xx could never recover the row: the redelivery's lookup
//     hits ErrNoRows (the row is already gone) and answers 200 without
//     writing the audit row, so the 5xx would be pure retry noise.
//
// KNOWN LIMIT (M46 residual, out of scope this wave): Svix regular
// endpoints deliver on a BEST-EFFORT order (svix.com/blog/
// guaranteeing-webhook-ordering; only FIFO endpoints guarantee order), so
// a stale lifecycle event can arrive — or be redelivered after a 500 —
// AFTER a newer event already applied: e.g. a late user.updated after
// user.deleted re-creates the row via Upsert. This handler predates any
// event bookkeeping and cannot reject superseded events; the durable fix
// is the same inbox design already flagged in webhook_lemonsqueezy.go
// (persist svix-id + event timestamp, dedupe replays, drop events older
// than the row they touch) and needs schema + repository changes.

// ClerkWebhookHandler handles Clerk webhook events
type ClerkWebhookHandler struct {
	cfg        *config.Config
	tenantRepo *repository.TenantRepository
	userRepo   *repository.UserRepository
	auditRepo  *repository.AuditRepository
}

// NewClerkWebhookHandler creates a new ClerkWebhookHandler
func NewClerkWebhookHandler(
	cfg *config.Config,
	tenantRepo *repository.TenantRepository,
	userRepo *repository.UserRepository,
	auditRepo *repository.AuditRepository,
) *ClerkWebhookHandler {
	return &ClerkWebhookHandler{
		cfg:        cfg,
		tenantRepo: tenantRepo,
		userRepo:   userRepo,
		auditRepo:  auditRepo,
	}
}

// ClerkWebhookPayload represents the Clerk webhook payload structure
type ClerkWebhookPayload struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

// ClerkUserData represents user data from Clerk
type ClerkUserData struct {
	ID             string `json:"id"`
	EmailAddresses []struct {
		EmailAddress string `json:"email_address"`
	} `json:"email_addresses"`
	FirstName      string `json:"first_name"`
	LastName       string `json:"last_name"`
	ImageURL       string `json:"image_url"`
	PrimaryEmailID string `json:"primary_email_address_id"`
}

// ClerkOrgData represents organization data from Clerk
type ClerkOrgData struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Slug      string `json:"slug"`
	ImageURL  string `json:"image_url"`
	CreatedBy string `json:"created_by"`
}

// ClerkOrgMembershipData represents organization membership data from Clerk
type ClerkOrgMembershipData struct {
	ID             string       `json:"id"`
	Organization   ClerkOrgData `json:"organization"`
	PublicUserData struct {
		UserID string `json:"user_id"`
	} `json:"public_user_data"`
	Role string `json:"role"`
}

// Handle processes Clerk webhook events
func (h *ClerkWebhookHandler) Handle(c echo.Context) error {
	// Skip in self-hosted mode
	if h.cfg.IsSelfHosted() {
		return c.JSON(http.StatusOK, map[string]string{"status": "skipped", "reason": "self-hosted mode"})
	}

	// Read body
	body, err := io.ReadAll(c.Request().Body)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "failed to read body"})
	}

	// Verify Svix signature. M47: `has_secret=false` in this log is the
	// operator's cue that the endpoint is refusing everything because
	// CLERK_WEBHOOK_SECRET was never set — the pre-fix code accepted those
	// deliveries instead (see verifySignature).
	if !h.verifySignature(c.Request(), body) {
		slog.Warn("clerk webhook signature verification failed",
			"has_secret", h.cfg.ClerkWebhookSecret != "", "ip", c.RealIP())
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid signature"})
	}

	// Parse payload
	var payload ClerkWebhookPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid payload"})
	}

	ctx := c.Request().Context()

	slog.Info("received Clerk webhook", "type", payload.Type)

	switch payload.Type {
	case "user.created", "user.updated":
		var userData ClerkUserData
		if err := json.Unmarshal(payload.Data, &userData); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid user data"})
		}
		return h.handleUserEvent(c, payload.Type, &userData)

	case "user.deleted":
		var userData ClerkUserData
		if err := json.Unmarshal(payload.Data, &userData); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid user data"})
		}
		// Delete user. Only sql.ErrNoRows means "already gone" (idempotent
		// success); a transient lookup error must NOT be misread as
		// not-found — that would answer 200 and drop the deletion forever
		// (Svix never retries a 2xx; see the contract comment above).
		user, err := h.userRepo.GetByClerkUserID(ctx, userData.ID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return c.JSON(http.StatusOK, map[string]string{"status": "ok", "note": "user not found"})
			}
			slog.Error("user.deleted: user lookup failed", "error", err, "clerk_user_id", userData.ID)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to look up user"})
		}
		if err := h.userRepo.Delete(ctx, user.ID); err != nil {
			// M47R (Codex cross-wave review, Low): a 0-row DELETE is the
			// DESIRED end state for a delete event, not a failure.
			// UserRepository.Delete reports it as ErrUserNotFound (wrapping
			// sql.ErrNoRows); without this branch, two concurrent deliveries
			// of one Svix event — both pass the lookup, one deletes the row,
			// the other's DELETE matches nothing — made the second answer 500
			// and burn retry budget on work that was already done. This is the
			// same branch organizationMembership.deleted got in M47 W2 and the
			// same reading the lookup above already applies to sql.ErrNoRows.
			//
			// 0 rows is unambiguous here, which is what makes the 200 safe:
			// the statement is `DELETE FROM users WHERE id = $1` — primary key
			// only, and `users` carries no RLS (migration 007 never covered it)
			// — so there is no predicate that could have filtered a row that
			// still exists.
			//
			// No audit row is written here: writing one is the job of the
			// delivery that actually removed the user. That delivery only
			// ATTEMPTS it — the audit write on the path below is tolerated on
			// failure (see the comment there) — so this branch is not a
			// guarantee that an audit row exists, only a refusal to write a
			// second one.
			if errors.Is(err, sql.ErrNoRows) {
				slog.Info("user.deleted: user already deleted (idempotent redelivery)",
					"user_id", user.ID, "clerk_user_id", userData.ID)
				return c.JSON(http.StatusOK, map[string]string{"status": "ok", "note": "user already deleted"})
			}
			slog.Error("user.deleted: failed to delete user", "error", err, "user_id", user.ID)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to delete user"})
		}
		// UserID is deliberately ABSENT (NULL): audit_logs.user_id is FK'd
		// to users(id) and the row was just deleted, so a non-NULL value
		// can never insert — which is exactly why deletion audit rows were
		// silently lost forever pre-fix (M46 Codex C-3b round 1). NULL
		// user_id/tenant_id is the documented convention for system-level
		// webhook events (see AuditRepository.List); the deleted id stays
		// queryable via resource_id, which carries no FK.
		//
		// Keep the 200 on audit failure: the user row is already deleted,
		// so a 5xx redelivery would hit the ErrNoRows branch above and
		// answer 200 without ever writing the audit row — the loss is
		// irreversible either way; surface it via slog.
		if err := h.auditRepo.Log(ctx, &model.CreateAuditLogInput{
			Action:       model.ActionUserDeleted,
			ResourceType: model.ResourceUser,
			ResourceID:   &user.ID,
		}); err != nil {
			slog.Error("failed to write user deletion audit log",
				"error", err, "action", model.ActionUserDeleted, "user_id", user.ID)
		}
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})

	case "organization.created", "organization.updated":
		var orgData ClerkOrgData
		if err := json.Unmarshal(payload.Data, &orgData); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid org data"})
		}
		return h.handleOrgEvent(c, payload.Type, &orgData)

	case "organization.deleted":
		var orgData ClerkOrgData
		if err := json.Unmarshal(payload.Data, &orgData); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid org data"})
		}
		// Delete tenant. Same lookup / delete / audit contract as
		// user.deleted above.
		tenant, err := h.tenantRepo.GetByClerkOrgID(ctx, orgData.ID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return c.JSON(http.StatusOK, map[string]string{"status": "ok", "note": "tenant not found"})
			}
			slog.Error("organization.deleted: tenant lookup failed", "error", err, "clerk_org_id", orgData.ID)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to look up tenant"})
		}
		if err := h.tenantRepo.Delete(ctx, tenant.ID); err != nil {
			// M47R: same idempotency branch as user.deleted above, and 0 rows
			// is unambiguous for the same reason (`DELETE FROM tenants WHERE
			// id = $1`, primary key only, no RLS on `tenants`).
			// TenantRepository.Delete reports 0 rows as ErrTenantNotFound,
			// which likewise wraps sql.ErrNoRows.
			if errors.Is(err, sql.ErrNoRows) {
				slog.Info("organization.deleted: tenant already deleted (idempotent redelivery)",
					"tenant_id", tenant.ID, "clerk_org_id", orgData.ID)
				return c.JSON(http.StatusOK, map[string]string{"status": "ok", "note": "tenant already deleted"})
			}
			slog.Error("organization.deleted: failed to delete tenant", "error", err, "tenant_id", tenant.ID)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to delete tenant"})
		}
		// TenantID is deliberately ABSENT (NULL): audit_logs.tenant_id is
		// FK'd to tenants(id) ON DELETE CASCADE, so a non-NULL value is
		// doubly impossible here — the post-delete INSERT violates the FK,
		// and even a row written BEFORE the delete would be cascaded away
		// with the tenant (M46 Codex C-3b round 1). Same NULL system-event
		// convention and 200-on-audit-failure rationale as user.deleted.
		if err := h.auditRepo.Log(ctx, &model.CreateAuditLogInput{
			Action:       model.ActionTenantDeleted,
			ResourceType: model.ResourceTenant,
			ResourceID:   &tenant.ID,
		}); err != nil {
			slog.Error("failed to write tenant deletion audit log",
				"error", err, "action", model.ActionTenantDeleted, "tenant_id", tenant.ID)
		}
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})

	case "organizationMembership.created", "organizationMembership.updated":
		var memberData ClerkOrgMembershipData
		if err := json.Unmarshal(payload.Data, &memberData); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid membership data"})
		}
		return h.handleMembershipEvent(c, &memberData)

	case "organizationMembership.deleted":
		var memberData ClerkOrgMembershipData
		if err := json.Unmarshal(payload.Data, &memberData); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid membership data"})
		}
		// Remove user from tenant. Only sql.ErrNoRows means "not found";
		// transient lookup errors answer 500 so Svix redelivers.
		tenant, err := h.tenantRepo.GetByClerkOrgID(ctx, memberData.Organization.ID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return c.JSON(http.StatusOK, map[string]string{"status": "ok", "note": "tenant not found"})
			}
			slog.Error("organizationMembership.deleted: tenant lookup failed",
				"error", err, "clerk_org_id", memberData.Organization.ID)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to look up tenant"})
		}
		user, err := h.userRepo.GetByClerkUserID(ctx, memberData.PublicUserData.UserID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return c.JSON(http.StatusOK, map[string]string{"status": "ok", "note": "user not found"})
			}
			slog.Error("organizationMembership.deleted: user lookup failed",
				"error", err, "clerk_user_id", memberData.PublicUserData.UserID)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to look up user"})
		}
		if err := h.userRepo.RemoveFromTenant(ctx, tenant.ID, user.ID); err != nil {
			// M47 W2 made RemoveFromTenant report a 0-row DELETE instead of
			// swallowing it, which is right for the API paths (a silent
			// "member removed" that removed nobody is a lie). Here it needs
			// the opposite reading: this event is a DELETE and Svix
			// redelivers it, so "already not a member" is the DESIRED end
			// state, not a failure. Answering 5xx would burn the retry
			// budget on work that is already done — the same reasoning the
			// lookup path above applies to sql.ErrNoRows.
			if errors.Is(err, sql.ErrNoRows) {
				slog.Info("organizationMembership.deleted: membership already absent (idempotent redelivery)",
					"tenant_id", tenant.ID, "user_id", user.ID)
				return c.JSON(http.StatusOK, map[string]string{"status": "ok", "note": "membership not found"})
			}
			slog.Error("organizationMembership.deleted: failed to remove user from tenant",
				"error", err, "tenant_id", tenant.ID, "user_id", user.ID)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to remove user from tenant"})
		}
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})

	default:
		slog.Info("unhandled Clerk webhook event", "type", payload.Type)
		return c.JSON(http.StatusOK, map[string]string{"status": "ok", "note": "unhandled event type"})
	}
}

func (h *ClerkWebhookHandler) handleUserEvent(c echo.Context, eventType string, userData *ClerkUserData) error {
	ctx := c.Request().Context()

	// Get primary email
	email := ""
	for _, e := range userData.EmailAddresses {
		email = e.EmailAddress
		break
	}

	name := userData.FirstName
	if userData.LastName != "" {
		name += " " + userData.LastName
	}

	now := time.Now()
	user := &model.User{
		ID:          uuid.New(),
		ClerkUserID: userData.ID,
		Email:       email,
		Name:        name,
		AvatarURL:   userData.ImageURL,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := h.userRepo.Upsert(ctx, user); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to upsert user"})
	}

	// Re-read the persisted row: Upsert is ON CONFLICT (clerk_user_id)
	// DO UPDATE and the conflict branch KEEPS the original row id, so for
	// an existing user the uuid.New() above never hits the table. Logging
	// that discarded id violated the audit_logs.user_id → users.id FK on
	// EVERY user.updated — update audit rows were silently lost forever
	// pre-fix (M46 Codex C-3b round 1). One extra SELECT per user event is
	// the price of a correct audit reference without widening the
	// repository contract (Upsert ... RETURNING id is the follow-up).
	persisted, err := h.userRepo.GetByClerkUserID(ctx, userData.ID)
	if err != nil {
		slog.Error("clerk user event: post-upsert lookup failed",
			"error", err, "event", eventType, "clerk_user_id", userData.ID)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to look up user"})
	}

	action := model.ActionUserCreated
	if eventType == "user.updated" {
		action = model.ActionUserUpdated
	}
	// 500 on audit failure: the upsert above is idempotent and this audit
	// row is the only history write, so the finite Svix redelivery (see the
	// contract comment at the top) recovers the audit trail with no
	// duplication risk. A 200 here would lose the row forever.
	if err := h.auditRepo.Log(ctx, &model.CreateAuditLogInput{
		UserID:       &persisted.ID,
		Action:       action,
		ResourceType: model.ResourceUser,
		ResourceID:   &persisted.ID,
	}); err != nil {
		slog.Error("failed to write user audit log",
			"error", err, "action", action, "user_id", persisted.ID)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to write audit log"})
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
}

func (h *ClerkWebhookHandler) handleOrgEvent(c echo.Context, eventType string, orgData *ClerkOrgData) error {
	ctx := c.Request().Context()
	now := time.Now()

	// The audit action follows the DELIVERED EVENT (like handleUserEvent),
	// not the branch taken. This is load-bearing for audit recovery: when
	// an organization.created delivery commits the tenant row but fails the
	// audit write (500 below), the redelivery finds the row, takes the
	// update branch — and must still log tenant.created, because that is
	// what happened per the IdP.
	action := model.ActionTenantCreated
	if eventType == "organization.updated" {
		action = model.ActionTenantUpdated
	}

	// Check if tenant exists. Only sql.ErrNoRows takes the create branch:
	// falling through on a transient lookup error would collide with the
	// clerk_org_id UNIQUE index on redelivery (same class as the Lemon
	// Squeezy lookup finding, M46 Codex round A).
	existing, err := h.tenantRepo.GetByClerkOrgID(ctx, orgData.ID)
	switch {
	case err == nil:
		// Update existing tenant
		existing.Name = orgData.Name
		existing.Slug = orgData.Slug
		existing.UpdatedAt = now
		if err := h.tenantRepo.Update(ctx, existing); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to update tenant"})
		}
		// 500 on audit failure: update is idempotent, single history
		// write — redelivery recovers the row (contract comment on top).
		if err := h.auditRepo.Log(ctx, &model.CreateAuditLogInput{
			TenantID:     &existing.ID,
			Action:       action,
			ResourceType: model.ResourceTenant,
			ResourceID:   &existing.ID,
		}); err != nil {
			slog.Error("failed to write tenant audit log",
				"error", err, "action", action, "tenant_id", existing.ID)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to write audit log"})
		}
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})

	case !errors.Is(err, sql.ErrNoRows):
		slog.Error("clerk org event: tenant lookup failed",
			"error", err, "event", eventType, "clerk_org_id", orgData.ID)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to look up tenant"})
	}

	// Create new tenant
	tenant := &model.Tenant{
		ID:         uuid.New(),
		ClerkOrgID: orgData.ID,
		Name:       orgData.Name,
		Slug:       orgData.Slug,
		Plan:       "", // Empty - user must select plan on billing page
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	if err := h.tenantRepo.Create(ctx, tenant); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to create tenant"})
	}

	// 500 on audit failure — same recovery contract as the update branch;
	// the redelivery takes the update branch and logs the same action.
	if err := h.auditRepo.Log(ctx, &model.CreateAuditLogInput{
		TenantID:     &tenant.ID,
		Action:       action,
		ResourceType: model.ResourceTenant,
		ResourceID:   &tenant.ID,
	}); err != nil {
		slog.Error("failed to write tenant audit log",
			"error", err, "action", action, "tenant_id", tenant.ID)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to write audit log"})
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
}

func (h *ClerkWebhookHandler) handleMembershipEvent(c echo.Context, memberData *ClerkOrgMembershipData) error {
	ctx := c.Request().Context()

	// Get or create tenant. Only sql.ErrNoRows takes the create branch
	// (same rationale as handleOrgEvent).
	tenant, err := h.tenantRepo.GetByClerkOrgID(ctx, memberData.Organization.ID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		slog.Error("clerk membership event: tenant lookup failed",
			"error", err, "clerk_org_id", memberData.Organization.ID)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to look up tenant"})
	}
	if err != nil {
		// Create tenant if not exists
		now := time.Now()
		tenant = &model.Tenant{
			ID:         uuid.New(),
			ClerkOrgID: memberData.Organization.ID,
			Name:       memberData.Organization.Name,
			Slug:       memberData.Organization.Slug,
			Plan:       "", // Empty - user must select plan on billing page
			CreatedAt:  now,
			UpdatedAt:  now,
		}
		if err := h.tenantRepo.Create(ctx, tenant); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to create tenant"})
		}
	}

	// Get user. ErrNoRows means the user.created event has not arrived yet
	// (event ordering is not guaranteed) — answer 200 so Svix does not
	// burn its retry budget on an event we cannot apply; the membership is
	// re-synced by the next membership event. Transient errors answer 500.
	user, err := h.userRepo.GetByClerkUserID(ctx, memberData.PublicUserData.UserID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return c.JSON(http.StatusOK, map[string]string{"status": "ok", "note": "user not found"})
		}
		slog.Error("clerk membership event: user lookup failed",
			"error", err, "clerk_user_id", memberData.PublicUserData.UserID)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to look up user"})
	}

	// Map Clerk role to our role
	role := model.RoleMember
	switch memberData.Role {
	case "org:admin":
		role = model.RoleOwner
	case "org:member":
		role = model.RoleMember
	}

	// Add or update membership
	now := time.Now()
	tu := &model.TenantUser{
		TenantID:  tenant.ID,
		UserID:    user.ID,
		Role:      role,
		CreatedAt: now,
	}

	if err := h.userRepo.AddToTenant(ctx, tu); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to add user to tenant"})
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
}

// verifySignature verifies the Svix webhook signature.
//
// M47 (High) — FAIL-CLOSED since this wave. It previously returned
// `!IsProduction()` when CLERK_WEBHOOK_SECRET was unset, and APP_ENV
// defaults to "development", so an unconfigured deployment accepted
// unsigned Clerk events from anyone: organization.deleted removes a tenant
// (and cascades its projects/SBOMs), organizationMembership.created adds an
// arbitrary Clerk user to an arbitrary org, user.updated rewrites a user
// row. Pinned by TestClerkWebhook_NoSecret_UnsignedPayloadIsRejected.
//
// The bypass now requires the explicit SBOMHUB_ALLOW_UNSIGNED_WEBHOOKS
// opt-in outside production (config.UnsignedWebhooksAllowed) and announces
// itself on every accepted delivery. See the same change in
// webhook_lemonsqueezy.go and the startup guard in cmd/server/main.go.
func (h *ClerkWebhookHandler) verifySignature(r *http.Request, body []byte) bool {
	if h.cfg.ClerkWebhookSecret == "" {
		if !h.cfg.UnsignedWebhooksAllowed() {
			return false
		}
		slog.Warn("Clerk webhook signature verification BYPASSED — "+
			"SBOMHUB_ALLOW_UNSIGNED_WEBHOOKS is set and no CLERK_WEBHOOK_SECRET is configured. "+
			"Anyone who can reach this endpoint can create, rename or delete tenants and users. "+
			"Development only.",
			"app_env", h.cfg.Environment, "ip", r.RemoteAddr)
		return true
	}

	svixID := r.Header.Get("svix-id")
	svixTimestamp := r.Header.Get("svix-timestamp")
	svixSignature := r.Header.Get("svix-signature")

	if svixID == "" || svixTimestamp == "" || svixSignature == "" {
		slog.Warn("Missing Svix headers",
			"svix-id", svixID != "",
			"svix-timestamp", svixTimestamp != "",
			"svix-signature", svixSignature != "")
		return false
	}

	// Decode the webhook secret
	// Clerk webhook secret format: "whsec_<base64-encoded-key>"
	secret := strings.TrimPrefix(h.cfg.ClerkWebhookSecret, "whsec_")

	secretBytes, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		slog.Error("Failed to decode webhook secret", "error", err)
		return false
	}

	// Create the signed payload
	signedPayload := svixID + "." + svixTimestamp + "." + string(body)

	// Compute expected signature using decoded secret
	mac := hmac.New(sha256.New, secretBytes)
	mac.Write([]byte(signedPayload))
	expectedSig := "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))

	// Compare signatures (svix-signature can have multiple signatures)
	for _, sig := range splitSignatures(svixSignature) {
		if hmac.Equal([]byte(sig), []byte(expectedSig)) {
			return true
		}
	}

	slog.Warn("Webhook signature verification failed",
		"received_signatures", svixSignature,
		"expected_signature", expectedSig)
	return false
}

func splitSignatures(header string) []string {
	return splitBySpace(header)
}

func splitBySpace(s string) []string {
	var result []string
	current := ""
	for _, c := range s {
		if c == ' ' {
			if current != "" {
				result = append(result, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}
