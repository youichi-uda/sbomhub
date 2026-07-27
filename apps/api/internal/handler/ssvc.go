package handler

import (
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/service"
	"github.com/sbomhub/sbomhub/internal/validation"
)

// SSVCHandler handles SSVC-related HTTP requests
type SSVCHandler struct {
	ssvcService *service.SSVCService
}

// NewSSVCHandler creates a new SSVCHandler
func NewSSVCHandler(ssvcService *service.SSVCService) *SSVCHandler {
	return &SSVCHandler{
		ssvcService: ssvcService,
	}
}

// GetProjectDefaults returns SSVC defaults for a project
// GET /api/v1/projects/:id/ssvc/defaults
func (h *SSVCHandler) GetProjectDefaults(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid project ID")
	}

	defaults, err := h.ssvcService.GetProjectDefaults(c.Request().Context(), projectID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	if defaults == nil {
		// Return default values if no project defaults exist
		return c.JSON(http.StatusOK, map[string]interface{}{
			"mission_prevalence":       model.SSVCMissionPrevalenceSupport,
			"safety_impact":            model.SSVCSafetyImpactMinimal,
			"system_exposure":          "internet",
			"auto_assess_enabled":      true,
			"auto_assess_exploitation": true,
			"auto_assess_automatable":  true,
		})
	}

	return c.JSON(http.StatusOK, defaults)
}

// UpdateProjectDefaults updates SSVC defaults for a project
// PUT /api/v1/projects/:id/ssvc/defaults
func (h *SSVCHandler) UpdateProjectDefaults(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid project ID")
	}

	// Get tenant ID from context
	tenantID, ok := c.Get("tenant_id").(uuid.UUID)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "tenant ID not found")
	}

	var input service.UpdateSSVCDefaultsInput
	if err := c.Bind(&input); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}

	defaults, err := h.ssvcService.UpdateProjectDefaults(c.Request().Context(), projectID, tenantID, input)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	return c.JSON(http.StatusOK, defaults)
}

// AssessVulnerabilityRequest represents the request body for assessing a vulnerability
type AssessVulnerabilityRequest struct {
	Exploitation      model.SSVCExploitation      `json:"exploitation"`
	Automatable       model.SSVCAutomatable       `json:"automatable"`
	TechnicalImpact   model.SSVCTechnicalImpact   `json:"technical_impact"`
	MissionPrevalence model.SSVCMissionPrevalence `json:"mission_prevalence"`
	SafetyImpact      model.SSVCSafetyImpact      `json:"safety_impact"`
	Notes             string                      `json:"notes,omitempty"`
}

// AssessVulnerability creates or updates an SSVC assessment for a vulnerability
// POST /api/v1/projects/:id/vulnerabilities/:vuln_id/ssvc
func (h *SSVCHandler) AssessVulnerability(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid project ID")
	}

	vulnID, err := uuid.Parse(c.Param("vuln_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid vulnerability ID")
	}

	// Get tenant ID from context
	tenantID, ok := c.Get("tenant_id").(uuid.UUID)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "tenant ID not found")
	}

	// Get user ID from context (optional for manual assessment)
	var assessedBy *uuid.UUID
	if userID, ok := c.Get("user_id").(uuid.UUID); ok {
		assessedBy = &userID
	}

	var req AssessVulnerabilityRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}

	// M46 Codex final round (Medium #1, second route): the cve_id query
	// parameter is intentionally NOT read — same posture as
	// AutoAssessVulnerability below. It used to be REQUIRED here and stored
	// verbatim as the assessment's cve_id, so a caller could pair :vuln_id
	// with any CVE it liked; :vuln_id itself was never checked against the
	// project either. The service now derives the CVE server-side from
	// :vuln_id and verifies (tenant, project, vulnerability) membership.
	// Legacy clients still sending ?cve_id= keep working — the parameter is
	// simply inert, and its former "400 when absent" is gone because the
	// server no longer needs it.
	input := model.SSVCAssessmentInput{
		Exploitation:      req.Exploitation,
		Automatable:       req.Automatable,
		TechnicalImpact:   req.TechnicalImpact,
		MissionPrevalence: req.MissionPrevalence,
		SafetyImpact:      req.SafetyImpact,
		Notes:             req.Notes,
	}

	assessment, err := h.ssvcService.AssessVulnerability(c.Request().Context(), projectID, tenantID, vulnID, input, assessedBy)
	if err != nil {
		if errors.Is(err, service.ErrSSVCVulnerabilityNotInProject) {
			return echo.NewHTTPError(http.StatusNotFound, "vulnerability not found in project")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	// F208 / M14-1: publish the newly-minted (or upserted) SSVC
	// assessment UUID so the audit middleware records
	// audit_logs.resource_id = assessment.ID instead of the parent
	// :vuln_id (which would point at the vulnerability, not the
	// assessment row). POST /projects/:id/vulnerabilities/:vuln_id/ssvc
	// has both :id and :vuln_id bound, so without this override the
	// resourceIDParamPriority list would pick up :vuln_id first and
	// forensic joins to ssvc_assessments would silently drop.
	if assessment != nil {
		middleware.SetAuditResourceID(c, assessment.ID)
	}

	return c.JSON(http.StatusOK, assessment)
}

// AutoAssessVulnerability automatically assesses a vulnerability using KEV/EPSS data
// POST /api/v1/projects/:id/vulnerabilities/:vuln_id/ssvc/auto
func (h *SSVCHandler) AutoAssessVulnerability(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid project ID")
	}

	vulnID, err := uuid.Parse(c.Param("vuln_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid vulnerability ID")
	}

	// Get tenant ID from context
	tenantID, ok := c.Get("tenant_id").(uuid.UUID)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "tenant ID not found")
	}

	// M46 Codex final round (Medium #1): the cve_id query parameter is
	// intentionally NOT read. It used to be forwarded verbatim as the
	// KEV/EPSS/CVSS evidence key, letting a caller assess vulnerability
	// :vuln_id on a DIFFERENT CVE's data. The service now derives the CVE
	// server-side from :vuln_id and verifies project/tenant membership;
	// legacy clients still sending ?cve_id= keep working — the parameter
	// is simply inert.
	assessment, err := h.ssvcService.AutoAssessVulnerability(c.Request().Context(), projectID, tenantID, vulnID)
	if err != nil {
		if errors.Is(err, service.ErrSSVCVulnerabilityNotInProject) {
			return echo.NewHTTPError(http.StatusNotFound, "vulnerability not found in project")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	// F208 / M14-1: same rationale as AssessVulnerability above —
	// publish the assessment UUID so audit_logs.resource_id reflects
	// the auto-assess row, not the parent :vuln_id.
	if assessment != nil {
		middleware.SetAuditResourceID(c, assessment.ID)
	}

	return c.JSON(http.StatusOK, assessment)
}

// GetAssessment gets an SSVC assessment for a vulnerability
// GET /api/v1/projects/:id/vulnerabilities/:vuln_id/ssvc
func (h *SSVCHandler) GetAssessment(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid project ID")
	}

	vulnID, err := uuid.Parse(c.Param("vuln_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid vulnerability ID")
	}

	assessment, err := h.ssvcService.GetAssessment(c.Request().Context(), projectID, vulnID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	if assessment == nil {
		return echo.NewHTTPError(http.StatusNotFound, "assessment not found")
	}

	return c.JSON(http.StatusOK, assessment)
}

// GetAssessmentByCVE gets an SSVC assessment by CVE ID
// GET /api/v1/projects/:id/ssvc/cve/:cve_id
func (h *SSVCHandler) GetAssessmentByCVE(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid project ID")
	}

	cveID, err := validation.ValidateCVEID(c.Param("cve_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid CVE ID format")
	}

	assessment, err := h.ssvcService.GetAssessmentByCVE(c.Request().Context(), projectID, cveID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	if assessment == nil {
		return echo.NewHTTPError(http.StatusNotFound, "assessment not found")
	}

	return c.JSON(http.StatusOK, assessment)
}

// ListAssessmentsQuery represents query parameters for listing assessments
type ListAssessmentsQuery struct {
	Decision string `query:"decision"`
	Limit    int    `query:"limit"`
	Offset   int    `query:"offset"`
}

// ListAssessments lists SSVC assessments for a project
// GET /api/v1/projects/:id/ssvc/assessments
func (h *SSVCHandler) ListAssessments(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid project ID")
	}

	var query ListAssessmentsQuery
	if err := c.Bind(&query); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid query parameters")
	}

	// Default pagination
	if query.Limit <= 0 {
		query.Limit = 50
	}
	if query.Limit > 100 {
		query.Limit = 100
	}

	// Parse decision filter
	var decisionFilter *model.SSVCDecision
	if query.Decision != "" {
		decision := model.SSVCDecision(query.Decision)
		decisionFilter = &decision
	}

	assessments, total, err := h.ssvcService.ListAssessments(c.Request().Context(), projectID, decisionFilter, query.Limit, query.Offset)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"assessments": assessments,
		"total":       total,
		"limit":       query.Limit,
		"offset":      query.Offset,
	})
}

// GetSummary gets SSVC assessment summary for a project
// GET /api/v1/projects/:id/ssvc/summary
func (h *SSVCHandler) GetSummary(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid project ID")
	}

	summary, err := h.ssvcService.GetSummary(c.Request().Context(), projectID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	if summary == nil {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"project_id":     projectID,
			"total_assessed": 0,
			"immediate":      0,
			"out_of_cycle":   0,
			"scheduled":      0,
			"defer":          0,
			"unassessed":     0,
		})
	}

	return c.JSON(http.StatusOK, summary)
}

// DeleteAssessment deletes an SSVC assessment
// DELETE /api/v1/projects/:id/ssvc/assessments/:assessment_id
//
// M46 Codex final round (Medium #1, route sweep): :id was PARSED NOWHERE and
// the repository ran a bare `DELETE FROM ssvc_assessments WHERE id = $1`, so
// the route's project segment was decorative — any assessment in the tenant
// could be deleted through any project's URL, and the endpoint always
// answered 204 whether or not it hit anything. Cross-tenant was held only by
// the FORCE RLS policy, with no application-layer predicate as
// defence-in-depth (the posture the rest of this file and
// repository/meti_assessments.go's ClearOverride use). Now both ids are bound
// and a miss is a 404 instead of a lying 204.
func (h *SSVCHandler) DeleteAssessment(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid project ID")
	}

	assessmentID, err := uuid.Parse(c.Param("assessment_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid assessment ID")
	}

	tenantID, ok := c.Get("tenant_id").(uuid.UUID)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "tenant ID not found")
	}

	if err := h.ssvcService.DeleteAssessment(c.Request().Context(), projectID, tenantID, assessmentID); err != nil {
		if errors.Is(err, service.ErrSSVCAssessmentNotInProject) {
			return echo.NewHTTPError(http.StatusNotFound, "assessment not found in project")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	return c.NoContent(http.StatusNoContent)
}

// GetAssessmentHistory gets history for an assessment
// GET /api/v1/projects/:id/ssvc/assessments/:assessment_id/history
//
// M46 Codex final round (route sweep, round 2): :id used to be parsed
// nowhere here either, so any assessment's decision-change history was
// readable through any project's URL. Both ids are now bound and the
// repository constrains the parent assessment row.
func (h *SSVCHandler) GetAssessmentHistory(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid project ID")
	}

	assessmentID, err := uuid.Parse(c.Param("assessment_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid assessment ID")
	}

	tenantID, ok := c.Get("tenant_id").(uuid.UUID)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "tenant ID not found")
	}

	history, err := h.ssvcService.GetAssessmentHistory(c.Request().Context(), projectID, tenantID, assessmentID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	return c.JSON(http.StatusOK, history)
}

// GetImmediateAssessments gets all assessments requiring immediate action
// GET /api/v1/ssvc/immediate
func (h *SSVCHandler) GetImmediateAssessments(c echo.Context) error {
	assessments, err := h.ssvcService.GetImmediateAssessments(c.Request().Context())
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	return c.JSON(http.StatusOK, assessments)
}

// CalculateDecisionRequest represents a request to calculate SSVC decision
type CalculateDecisionRequest struct {
	Exploitation      model.SSVCExploitation      `json:"exploitation"`
	Automatable       model.SSVCAutomatable       `json:"automatable"`
	TechnicalImpact   model.SSVCTechnicalImpact   `json:"technical_impact"`
	MissionPrevalence model.SSVCMissionPrevalence `json:"mission_prevalence"`
	SafetyImpact      model.SSVCSafetyImpact      `json:"safety_impact"`
}

// CalculateDecision calculates SSVC decision without saving
// POST /api/v1/ssvc/calculate
func (h *SSVCHandler) CalculateDecision(c echo.Context) error {
	var req CalculateDecisionRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}

	decision := h.ssvcService.CalculateDecision(
		req.Exploitation,
		req.Automatable,
		req.TechnicalImpact,
		req.MissionPrevalence,
		req.SafetyImpact,
	)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"decision":           decision,
		"exploitation":       req.Exploitation,
		"automatable":        req.Automatable,
		"technical_impact":   req.TechnicalImpact,
		"mission_prevalence": req.MissionPrevalence,
		"safety_impact":      req.SafetyImpact,
	})
}
