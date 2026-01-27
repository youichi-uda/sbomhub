package handler

import (
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
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusCreated, link)
}

func (h *PublicLinkHandler) List(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project id"})
	}

	links, err := h.publicLinkService.ListByProject(c.Request().Context(), projectID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
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

	link, err := h.publicLinkService.Update(c.Request().Context(), linkID, service.UpdatePublicLinkInput{
		Name:             strings.TrimSpace(req.Name),
		SbomID:           sbomID,
		ExpiresAt:        expiresAt,
		IsActive:         req.IsActive,
		AllowedDownloads: req.AllowedDownloads,
		Password:         req.Password,
	})
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, link)
}

func (h *PublicLinkHandler) Delete(c echo.Context) error {
	linkID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid public link id"})
	}

	if err := h.publicLinkService.Delete(c.Request().Context(), linkID); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
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
		return c.JSON(http.StatusForbidden, map[string]string{"error": err.Error()})
	}

	_ = h.publicLinkService.IncrementView(c.Request().Context(), link.ID)
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
		return c.JSON(http.StatusForbidden, map[string]string{"error": err.Error()})
	}

	limitReached, err := h.publicLinkService.IsDownloadLimitReached(c.Request().Context(), link.ID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	if limitReached {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "download limit reached"})
	}

	_ = h.publicLinkService.IncrementDownload(c.Request().Context(), link.ID)
	_ = h.publicLinkService.LogAccess(c.Request().Context(), link.ID, "download", c.RealIP(), c.Request().UserAgent())

	c.Response().Header().Set("Content-Type", "application/json")
	c.Response().Header().Set("Content-Disposition", "attachment; filename=sbom.json")
	return c.Blob(http.StatusOK, "application/json", raw)
}
