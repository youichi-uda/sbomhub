package handler

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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
	ID            string `json:"id"`
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
	ID             string `json:"id"`
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

	// Verify Svix signature
	if !h.verifySignature(c.Request(), body) {
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
		// Delete user
		user, err := h.userRepo.GetByClerkUserID(ctx, userData.ID)
		if err == nil {
			h.userRepo.Delete(ctx, user.ID)
			h.auditRepo.Log(ctx, &model.CreateAuditLogInput{
				UserID:       &user.ID,
				Action:       model.ActionUserDeleted,
				ResourceType: model.ResourceUser,
				ResourceID:   &user.ID,
			})
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
		// Delete tenant
		tenant, err := h.tenantRepo.GetByClerkOrgID(ctx, orgData.ID)
		if err == nil {
			h.tenantRepo.Delete(ctx, tenant.ID)
			h.auditRepo.Log(ctx, &model.CreateAuditLogInput{
				TenantID:     &tenant.ID,
				Action:       model.ActionTenantDeleted,
				ResourceType: model.ResourceTenant,
				ResourceID:   &tenant.ID,
			})
		}
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})

	case "organizationMembership.created", "organizationMembership.updated":
		var memberData ClerkOrgMembershipData
		if err := json.Unmarshal(payload.Data, &memberData); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid membership data"})
		}
		return h.handleMembershipEvent(c, payload.Type, &memberData)

	case "organizationMembership.deleted":
		var memberData ClerkOrgMembershipData
		if err := json.Unmarshal(payload.Data, &memberData); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid membership data"})
		}
		// Remove user from tenant
		tenant, err := h.tenantRepo.GetByClerkOrgID(ctx, memberData.Organization.ID)
		if err != nil {
			return c.JSON(http.StatusOK, map[string]string{"status": "ok", "note": "tenant not found"})
		}
		user, err := h.userRepo.GetByClerkUserID(ctx, memberData.PublicUserData.UserID)
		if err != nil {
			return c.JSON(http.StatusOK, map[string]string{"status": "ok", "note": "user not found"})
		}
		h.userRepo.RemoveFromTenant(ctx, tenant.ID, user.ID)
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

	action := model.ActionUserCreated
	if eventType == "user.updated" {
		action = model.ActionUserUpdated
	}
	h.auditRepo.Log(ctx, &model.CreateAuditLogInput{
		UserID:       &user.ID,
		Action:       action,
		ResourceType: model.ResourceUser,
		ResourceID:   &user.ID,
	})

	return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
}

func (h *ClerkWebhookHandler) handleOrgEvent(c echo.Context, eventType string, orgData *ClerkOrgData) error {
	ctx := c.Request().Context()
	now := time.Now()

	// Check if tenant exists
	existing, err := h.tenantRepo.GetByClerkOrgID(ctx, orgData.ID)
	if err == nil {
		// Update existing tenant
		existing.Name = orgData.Name
		existing.Slug = orgData.Slug
		existing.UpdatedAt = now
		if err := h.tenantRepo.Update(ctx, existing); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to update tenant"})
		}
		h.auditRepo.Log(ctx, &model.CreateAuditLogInput{
			TenantID:     &existing.ID,
			Action:       model.ActionTenantUpdated,
			ResourceType: model.ResourceTenant,
			ResourceID:   &existing.ID,
		})
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	}

	// Create new tenant
	tenant := &model.Tenant{
		ID:         uuid.New(),
		ClerkOrgID: orgData.ID,
		Name:       orgData.Name,
		Slug:       orgData.Slug,
		Plan:       model.PlanFree, // Start with free plan
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	if err := h.tenantRepo.Create(ctx, tenant); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to create tenant"})
	}

	h.auditRepo.Log(ctx, &model.CreateAuditLogInput{
		TenantID:     &tenant.ID,
		Action:       model.ActionTenantCreated,
		ResourceType: model.ResourceTenant,
		ResourceID:   &tenant.ID,
	})

	return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
}

func (h *ClerkWebhookHandler) handleMembershipEvent(c echo.Context, eventType string, memberData *ClerkOrgMembershipData) error {
	ctx := c.Request().Context()

	// Get or create tenant
	tenant, err := h.tenantRepo.GetByClerkOrgID(ctx, memberData.Organization.ID)
	if err != nil {
		// Create tenant if not exists
		now := time.Now()
		tenant = &model.Tenant{
			ID:         uuid.New(),
			ClerkOrgID: memberData.Organization.ID,
			Name:       memberData.Organization.Name,
			Slug:       memberData.Organization.Slug,
			Plan:       model.PlanFree,
			CreatedAt:  now,
			UpdatedAt:  now,
		}
		if err := h.tenantRepo.Create(ctx, tenant); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to create tenant"})
		}
	}

	// Get user
	user, err := h.userRepo.GetByClerkUserID(ctx, memberData.PublicUserData.UserID)
	if err != nil {
		return c.JSON(http.StatusOK, map[string]string{"status": "ok", "note": "user not found"})
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

// verifySignature verifies the Svix webhook signature
func (h *ClerkWebhookHandler) verifySignature(r *http.Request, body []byte) bool {
	if h.cfg.ClerkWebhookSecret == "" {
		// No secret configured - skip verification in development
		return !h.cfg.IsProduction()
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
	secret := h.cfg.ClerkWebhookSecret
	if strings.HasPrefix(secret, "whsec_") {
		secret = strings.TrimPrefix(secret, "whsec_")
	}

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
	var sigs []string
	for _, part := range splitBySpace(header) {
		sigs = append(sigs, part)
	}
	return sigs
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
