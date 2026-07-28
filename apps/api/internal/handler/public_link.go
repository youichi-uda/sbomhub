package handler

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/service"
)

type PublicLinkHandler struct {
	publicLinkService *service.PublicLinkService
}

func NewPublicLinkHandler(pls *service.PublicLinkService) *PublicLinkHandler {
	return &PublicLinkHandler{publicLinkService: pls}
}

type createPublicLinkRequest struct {
	Name             string  `json:"name"`
	SbomID           *string `json:"sbom_id"`
	ExpiresAt        string  `json:"expires_at"`
	IsActive         *bool   `json:"is_active"`
	AllowedDownloads *int    `json:"allowed_downloads"`
	Password         string  `json:"password"`
}

func (h *PublicLinkHandler) Create(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project id"})
	}

	var req createPublicLinkRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}

	expiresAt, err := time.Parse(time.RFC3339, req.ExpiresAt)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid expires_at"})
	}

	var sbomID *uuid.UUID
	if req.SbomID != nil && *req.SbomID != "" {
		id, err := uuid.Parse(*req.SbomID)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid sbom id"})
		}
		sbomID = &id
	}

	isActive := true
	if req.IsActive != nil {
		isActive = *req.IsActive
	}

	link, err := h.publicLinkService.Create(c.Request().Context(), service.CreatePublicLinkInput{
		TenantID:         middleware.GetTenantID(c),
		ProjectID:        projectID,
		Name:             strings.TrimSpace(req.Name),
		SbomID:           sbomID,
		ExpiresAt:        expiresAt,
		IsActive:         isActive,
		AllowedDownloads: req.AllowedDownloads,
		Password:         req.Password,
	})
	if err != nil {
		// M47 W1: an sbom_id outside this (tenant, project) is 404, not
		// 400 — unknown / foreign / other-project collapse into one
		// answer so the form cannot be used to probe for SBOM UUIDs.
		if errors.Is(err, service.ErrPublicLinkSbomNotInProject) {
			slog.Warn("public_link: create rejected, sbom is not in the project",
				"tenant_id", middleware.GetTenantID(c), "project_id", projectID)
			return c.JSON(http.StatusNotFound, map[string]string{"error": "sbom not found"})
		}
		// M47 W1 (Codex round 1, Medium): a %w-wrapped repository failure
		// from the new scope query is an INFRASTRUCTURE fault and must not
		// keep masquerading as a client 400 — that hid real outages behind
		// "your request was bad". Only the service's own caller-facing
		// validation ("name is required") stays a 400.
		if errors.Is(err, service.ErrPublicLinkScopeCheckFailed) {
			slog.Error("public_link: create failed on the scope check",
				"tenant_id", middleware.GetTenantID(c), "project_id", projectID, "error", err)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to create public link"})
		}
		// F442 + M47 W1: the remaining errors split two ways. Only the
		// service's own caller-fixable validation ("name is required")
		// deserves a 400; token generation, bcrypt and the repository
		// INSERT are all server faults and must not be reported to the
		// caller as a bad request. Either way the detail stays in the log
		// and the body is generic (info disclosure for a security product).
		if errors.Is(err, service.ErrValidation) {
			slog.Warn("public_link: create rejected by validation",
				"tenant_id", middleware.GetTenantID(c), "project_id", projectID, "error", err)
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "failed to create public link"})
		}
		slog.Error("public_link: create failed",
			"tenant_id", middleware.GetTenantID(c), "project_id", projectID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to create public link"})
	}

	// F208 / M14-1: publish the newly-minted public-link UUID so the
	// audit middleware records audit_logs.resource_id = link.ID instead
	// of the parent project UUID. POST /projects/:id/public-links has
	// :id in the path, so without this override the resource_id would
	// point at the project and forensic joins to public_links would
	// silently drop.
	if link != nil {
		middleware.SetAuditResourceID(c, link.ID)
	}

	return c.JSON(http.StatusCreated, link)
}

func (h *PublicLinkHandler) List(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project id"})
	}

	links, err := h.publicLinkService.ListByProject(c.Request().Context(), middleware.GetTenantID(c), projectID)
	if err != nil {
		slog.Warn("public_link: list failed",
			"tenant_id", middleware.GetTenantID(c), "project_id", projectID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to list public links"})
	}
	return c.JSON(http.StatusOK, links)
}

type updatePublicLinkRequest struct {
	Name             string  `json:"name"`
	SbomID           *string `json:"sbom_id"`
	ExpiresAt        string  `json:"expires_at"`
	IsActive         bool    `json:"is_active"`
	AllowedDownloads *int    `json:"allowed_downloads"`
	Password         *string `json:"password"`
}

func (h *PublicLinkHandler) Update(c echo.Context) error {
	linkID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid public link id"})
	}

	var req updatePublicLinkRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}

	expiresAt, err := time.Parse(time.RFC3339, req.ExpiresAt)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid expires_at"})
	}

	var sbomID *uuid.UUID
	if req.SbomID != nil && *req.SbomID != "" {
		id, err := uuid.Parse(*req.SbomID)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid sbom id"})
		}
		sbomID = &id
	}

	link, err := h.publicLinkService.Update(c.Request().Context(), middleware.GetTenantID(c), linkID, service.UpdatePublicLinkInput{
		Name:             strings.TrimSpace(req.Name),
		SbomID:           sbomID,
		ExpiresAt:        expiresAt,
		IsActive:         req.IsActive,
		AllowedDownloads: req.AllowedDownloads,
		Password:         req.Password,
	})
	if err != nil {
		// M47 W1: same 404 mapping as Create — an update must not be able
		// to repoint a live share link at an SBOM outside its project. A
		// link id that does not resolve inside the caller's tenant answers
		// with the SAME 404 (Codex round 1, Medium): it used to be a 400
		// that a prober could tell apart from every other rejection.
		if errors.Is(err, service.ErrPublicLinkSbomNotInProject) ||
			errors.Is(err, service.ErrPublicLinkNotFound) {
			slog.Warn("public_link: update rejected, target not in scope",
				"tenant_id", middleware.GetTenantID(c), "link_id", linkID)
			return c.JSON(http.StatusNotFound, map[string]string{"error": "public link not found"})
		}
		// M47 W1 (Codex round 1, Medium): infrastructure faults from the
		// scope query are 500, not 400 — see Create.
		if errors.Is(err, service.ErrPublicLinkScopeCheckFailed) {
			slog.Error("public_link: update failed on the scope check",
				"tenant_id", middleware.GetTenantID(c), "link_id", linkID, "error", err)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to update public link"})
		}
		// F442 + M47 W1: nothing left in this bucket is caller-fixable —
		// the link lookup, bcrypt and the repository UPDATE are all server
		// faults, so they are 500 with a generic body and the detail in the
		// log. (Update takes no `name is required` path; Create does.)
		slog.Error("public_link: update failed",
			"tenant_id", middleware.GetTenantID(c), "link_id", linkID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to update public link"})
	}

	return c.JSON(http.StatusOK, link)
}

func (h *PublicLinkHandler) Delete(c echo.Context) error {
	linkID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid public link id"})
	}

	if err := h.publicLinkService.Delete(c.Request().Context(), middleware.GetTenantID(c), linkID); err != nil {
		// M47R (Codex cross-wave review, Low): a link that is not in the
		// caller's tenant is 404, exactly as on Update — until now the two
		// verbs disagreed about the same resource, and a link that simply did
		// not exist came back as a server error. Everything else (driver
		// faults) stays 500, so "the link is gone" and "we could not tell"
		// remain different answers. No existence oracle is created: see
		// PublicLinkService.Delete.
		if errors.Is(err, service.ErrPublicLinkNotFound) {
			slog.Warn("public_link: delete matched no link in this tenant",
				"tenant_id", middleware.GetTenantID(c), "link_id", linkID)
			return c.JSON(http.StatusNotFound, map[string]string{"error": "public link not found"})
		}
		slog.Error("public_link: delete failed",
			"tenant_id", middleware.GetTenantID(c), "link_id", linkID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to delete public link"})
	}
	return c.NoContent(http.StatusNoContent)
}

func (h *PublicLinkHandler) PublicGet(c echo.Context) error {
	token := c.Param("token")
	password := c.Request().Header.Get("X-Public-Password")
	if password == "" {
		password = c.QueryParam("password")
	}

	view, link, err := h.publicLinkService.GetPublicView(c.Request().Context(), token, password)
	if err != nil {
		// F442: this anonymous share-flow error mixes self-authored token-
		// validation sentinels (bad password / inactive / expired / not
		// found) with raw DB errors from the token lookup and the tenant-
		// scoped content reads. A single payload cannot safely echo the
		// latter, so return one generic 403 that still signals an access /
		// credential problem without leaking internals; the precise cause
		// is logged. Status unchanged (403).
		slog.Warn("public_link: public view denied", "ip", c.RealIP(), "error", err)
		return c.JSON(http.StatusForbidden, map[string]string{"error": "invalid password or the share link is unavailable"})
	}

	// The anonymous /public/:token route has no tenant middleware; the
	// link returned by GetByToken (above, application-layer secret) is
	// what supplies the tenant id for these defense-in-depth scoped
	// mutations. See PublicLinkRepository.IncrementView for rationale.
	//
	// M46 B-1 codex round 1 / Medium-1: TryRegisterView re-checks active +
	// not-expired server-side at send time, in the same statement that
	// bumps view_count. GetPublicView validated those in Go against the
	// row read BEFORE the tenant-scoped content reads, so an owner who
	// revoked the link mid-request (or an expires_at that passed) had no
	// effect on the response. Withhold the assembled view when the link is
	// no longer live.
	live, err := h.publicLinkService.TryRegisterView(c.Request().Context(), link.TenantID, link.ID)
	if err != nil {
		slog.Warn("public_link: view registration failed", "link_id", link.ID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to process request"})
	}
	if !live {
		slog.Warn("public_link: link revoked or expired during the request", "ip", c.RealIP(), "link_id", link.ID)
		return c.JSON(http.StatusForbidden, map[string]string{"error": "invalid password or the share link is unavailable"})
	}
	_ = h.publicLinkService.LogAccess(c.Request().Context(), link.ID, "view", c.RealIP(), c.Request().UserAgent())

	return c.JSON(http.StatusOK, view)
}

func (h *PublicLinkHandler) PublicDownload(c echo.Context) error {
	token := c.Param("token")
	password := c.Request().Header.Get("X-Public-Password")
	if password == "" {
		password = c.QueryParam("password")
	}

	raw, link, err := h.publicLinkService.GetPublicSbomRaw(c.Request().Context(), token, password)
	if err != nil {
		// F442: same anonymous share-flow mix as PublicGet — token-
		// validation sentinels alongside raw DB errors. Return one generic
		// 403 (access / credential signal, no internals) and log the cause.
		slog.Warn("public_link: public download denied", "ip", c.RealIP(), "error", err)
		return c.JSON(http.StatusForbidden, map[string]string{"error": "invalid password or the share link is unavailable"})
	}

	// Same defense-in-depth tenant scoping as PublicGet: the anonymous
	// route has no tenant middleware, so link.TenantID (derived from the
	// token lookup) is what we pass to the counter/log calls.
	//
	// M46 B-1 High-2: check + consume is ONE conditional UPDATE. The old
	// shape (IsDownloadLimitReached → serve → IncrementDownload) let N
	// concurrent requests pass the check before any increment committed,
	// so a 1-download link could be downloaded N times; and because the
	// increment was `download_count + 1`, a NULL counter never advanced
	// at all, making the cap permanently unenforceable. The consume
	// happens BEFORE the bytes are written, so a cap-exhausted request
	// cannot receive the SBOM.
	admitted, err := h.publicLinkService.TryConsumeDownload(c.Request().Context(), link.TenantID, link.ID)
	if err != nil {
		slog.Warn("public_link: download limit check failed",
			"link_id", link.ID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to process download"})
	}
	if !admitted {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "download limit reached"})
	}

	_ = h.publicLinkService.LogAccess(c.Request().Context(), link.ID, "download", c.RealIP(), c.Request().UserAgent())

	c.Response().Header().Set("Content-Type", "application/json")
	c.Response().Header().Set("Content-Disposition", "attachment; filename=sbom.json")
	return c.Blob(http.StatusOK, "application/json", raw)
}
