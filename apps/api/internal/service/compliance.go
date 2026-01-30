package service

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/johnfercher/maroto/v2"
	"github.com/johnfercher/maroto/v2/pkg/components/col"
	"github.com/johnfercher/maroto/v2/pkg/components/row"
	"github.com/johnfercher/maroto/v2/pkg/components/text"
	"github.com/johnfercher/maroto/v2/pkg/config"
	"github.com/johnfercher/maroto/v2/pkg/consts/align"
	"github.com/johnfercher/maroto/v2/pkg/consts/fontstyle"
	"github.com/johnfercher/maroto/v2/pkg/core"
	"github.com/johnfercher/maroto/v2/pkg/props"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/xuri/excelize/v2"
)

type ComplianceService struct {
	sbomRepo            *repository.SbomRepository
	componentRepo       *repository.ComponentRepository
	vulnRepo            *repository.VulnerabilityRepository
	vexRepo             *repository.VEXRepository
	licensePolicyRepo   *repository.LicensePolicyRepository
	dashboardRepo       *repository.DashboardRepository
	checklistRepo       *repository.ChecklistRepository
	visualizationRepo   *repository.VisualizationRepository
	publicLinkRepo      *repository.PublicLinkRepository
}

func NewComplianceService(
	sbomRepo *repository.SbomRepository,
	componentRepo *repository.ComponentRepository,
	vulnRepo *repository.VulnerabilityRepository,
	vexRepo *repository.VEXRepository,
	licensePolicyRepo *repository.LicensePolicyRepository,
	dashboardRepo *repository.DashboardRepository,
) *ComplianceService {
	return &ComplianceService{
		sbomRepo:          sbomRepo,
		componentRepo:     componentRepo,
		vulnRepo:          vulnRepo,
		vexRepo:           vexRepo,
		licensePolicyRepo: licensePolicyRepo,
		dashboardRepo:     dashboardRepo,
	}
}

// NewComplianceServiceFull creates a ComplianceService with all repositories
func NewComplianceServiceFull(
	sbomRepo *repository.SbomRepository,
	componentRepo *repository.ComponentRepository,
	vulnRepo *repository.VulnerabilityRepository,
	vexRepo *repository.VEXRepository,
	licensePolicyRepo *repository.LicensePolicyRepository,
	dashboardRepo *repository.DashboardRepository,
	checklistRepo *repository.ChecklistRepository,
	visualizationRepo *repository.VisualizationRepository,
	publicLinkRepo *repository.PublicLinkRepository,
) *ComplianceService {
	return &ComplianceService{
		sbomRepo:            sbomRepo,
		componentRepo:       componentRepo,
		vulnRepo:            vulnRepo,
		vexRepo:             vexRepo,
		licensePolicyRepo:   licensePolicyRepo,
		dashboardRepo:       dashboardRepo,
		checklistRepo:       checklistRepo,
		visualizationRepo:   visualizationRepo,
		publicLinkRepo:      publicLinkRepo,
	}
}

// CheckCompliance performs all compliance checks for a project
func (s *ComplianceService) CheckCompliance(ctx context.Context, projectID uuid.UUID) (*model.ComplianceResult, error) {
	result := &model.ComplianceResult{
		ProjectID:  projectID,
		Categories: []model.ComplianceCategory{},
	}

	// SBOM Generation checks
	sbomCategory, err := s.checkSBOMGeneration(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("SBOM checks failed: %w", err)
	}
	result.Categories = append(result.Categories, sbomCategory)

	// Vulnerability Management checks
	vulnCategory, err := s.checkVulnerabilityManagement(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("vulnerability checks failed: %w", err)
	}
	result.Categories = append(result.Categories, vulnCategory)

	// License Management checks
	licenseCategory, err := s.checkLicenseManagement(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("license checks failed: %w", err)
	}
	result.Categories = append(result.Categories, licenseCategory)

	// METI Minimum Elements checks
	minElementsCategory, err := s.checkMinimumElements(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("minimum elements checks failed: %w", err)
	}
	result.Categories = append(result.Categories, minElementsCategory)

	// Calculate total scores
	for _, cat := range result.Categories {
		result.Score += cat.Score
		result.MaxScore += cat.MaxScore
	}

	return result, nil
}

func (s *ComplianceService) checkSBOMGeneration(ctx context.Context, projectID uuid.UUID) (model.ComplianceCategory, error) {
	category := model.ComplianceCategory{
		Name:     string(model.ComplianceCategorySBOM),
		Label:    "SBOM生成",
		MaxScore: 3,
		Checks:   []model.ComplianceCheck{},
	}

	// Check 1: SBOM exists
	sbom, err := s.sbomRepo.GetLatest(ctx, projectID)
	sbomExists := err == nil && sbom != nil
	check1 := model.ComplianceCheck{
		ID:     "sbom_exists",
		Label:  "SBOMが登録されている",
		Passed: sbomExists,
	}
	if sbomExists {
		category.Score++
	} else {
		detail := "SBOMがアップロードされていません"
		check1.Details = &detail
	}
	category.Checks = append(category.Checks, check1)

	// Check 2: Required fields (if SBOM exists)
	check2 := model.ComplianceCheck{
		ID:     "required_fields",
		Label:  "必須フィールドが含まれている",
		Passed: false,
	}
	if sbomExists {
		// Check if components have required fields (name, version)
		components, err := s.componentRepo.ListBySbom(ctx, sbom.ID)
		if err == nil && len(components) > 0 {
			hasRequiredFields := true
			for _, c := range components {
				if c.Name == "" || c.Version == "" {
					hasRequiredFields = false
					break
				}
			}
			check2.Passed = hasRequiredFields
			if hasRequiredFields {
				category.Score++
			} else {
				detail := "一部のコンポーネントに名前またはバージョンがありません"
				check2.Details = &detail
			}
		}
	} else {
		detail := "SBOMが存在しないため確認できません"
		check2.Details = &detail
	}
	category.Checks = append(category.Checks, check2)

	// Check 3: Recently updated (within 30 days)
	check3 := model.ComplianceCheck{
		ID:     "recently_updated",
		Label:  "定期的に更新されている（30日以内）",
		Passed: false,
	}
	if sbomExists {
		thirtyDaysAgo := time.Now().AddDate(0, 0, -30)
		if sbom.CreatedAt.After(thirtyDaysAgo) {
			check3.Passed = true
			category.Score++
		} else {
			detail := fmt.Sprintf("最終更新: %s", sbom.CreatedAt.Format("2006-01-02"))
			check3.Details = &detail
		}
	} else {
		detail := "SBOMが存在しないため確認できません"
		check3.Details = &detail
	}
	category.Checks = append(category.Checks, check3)

	return category, nil
}

func (s *ComplianceService) checkVulnerabilityManagement(ctx context.Context, projectID uuid.UUID) (model.ComplianceCategory, error) {
	category := model.ComplianceCategory{
		Name:     string(model.ComplianceCategoryVulnerability),
		Label:    "脆弱性管理",
		MaxScore: 3,
		Checks:   []model.ComplianceCheck{},
	}

	// Check 1: Vulnerability scan performed
	vulnCounts, err := s.dashboardRepo.GetProjectVulnerabilityCounts(ctx, projectID)
	scanPerformed := err == nil
	check1 := model.ComplianceCheck{
		ID:     "scan_performed",
		Label:  "脆弱性スキャンを実施している",
		Passed: scanPerformed,
	}
	if scanPerformed {
		category.Score++
	} else {
		detail := "脆弱性スキャンが実行されていません"
		check1.Details = &detail
	}
	category.Checks = append(category.Checks, check1)

	// Check 2: No unresolved critical vulnerabilities
	check2 := model.ComplianceCheck{
		ID:     "no_unresolved_critical",
		Label:  "Critical脆弱性が未対応でない",
		Passed: false,
	}

	// Get VEX statements to check resolved status
	vexStatements, _ := s.vexRepo.ListByProject(ctx, projectID)
	resolvedCritical := 0
	for _, vex := range vexStatements {
		if vex.VulnerabilitySeverity == "CRITICAL" &&
			(vex.Status == model.VEXStatusNotAffected || vex.Status == model.VEXStatusFixed) {
			resolvedCritical++
		}
	}

	unresolvedCritical := vulnCounts.Critical - resolvedCritical
	if unresolvedCritical < 0 {
		unresolvedCritical = 0
	}

	if unresolvedCritical == 0 {
		check2.Passed = true
		category.Score++
	} else {
		detail := fmt.Sprintf("%d件のCritical脆弱性が未対応", unresolvedCritical)
		check2.Details = &detail
	}
	category.Checks = append(category.Checks, check2)

	// Check 3: VEX management in use
	check3 := model.ComplianceCheck{
		ID:     "vex_in_use",
		Label:  "VEXで対応状況を管理している",
		Passed: len(vexStatements) > 0,
	}
	if len(vexStatements) > 0 {
		category.Score++
	} else {
		detail := "VEXステートメントが登録されていません"
		check3.Details = &detail
	}
	category.Checks = append(category.Checks, check3)

	return category, nil
}

func (s *ComplianceService) checkLicenseManagement(ctx context.Context, projectID uuid.UUID) (model.ComplianceCategory, error) {
	category := model.ComplianceCategory{
		Name:     string(model.ComplianceCategoryLicense),
		Label:    "ライセンス管理",
		MaxScore: 2,
		Checks:   []model.ComplianceCheck{},
	}

	// Check 1: License policy configured
	policies, err := s.licensePolicyRepo.ListByProject(ctx, projectID)
	policyConfigured := err == nil && len(policies) > 0
	check1 := model.ComplianceCheck{
		ID:     "policy_configured",
		Label:  "ライセンスポリシーを設定している",
		Passed: policyConfigured,
	}
	if policyConfigured {
		category.Score++
	} else {
		detail := "ライセンスポリシーが設定されていません"
		check1.Details = &detail
	}
	category.Checks = append(category.Checks, check1)

	// Check 2: No license violations
	check2 := model.ComplianceCheck{
		ID:     "no_violations",
		Label:  "ライセンス違反がない",
		Passed: true, // Default to true if no policies
	}

	if policyConfigured {
		// Get latest SBOM
		sbom, err := s.sbomRepo.GetLatest(ctx, projectID)
		if err == nil && sbom != nil {
			// Get components
			components, _ := s.componentRepo.ListBySbom(ctx, sbom.ID)

			// Check for denied licenses
			violationCount := 0
			for _, comp := range components {
				if comp.License == "" {
					continue
				}
				for _, policy := range policies {
					if policy.LicenseID == comp.License && policy.PolicyType == model.LicensePolicyDenied {
						violationCount++
						break
					}
				}
			}

			if violationCount > 0 {
				check2.Passed = false
				detail := fmt.Sprintf("%d件のライセンス違反があります", violationCount)
				check2.Details = &detail
			} else {
				category.Score++
			}
		}
	} else {
		category.Score++ // No policies = no violations by definition
	}
	category.Checks = append(category.Checks, check2)

	return category, nil
}

// checkMinimumElements checks METI guideline ver2.0 minimum elements (7 items)
func (s *ComplianceService) checkMinimumElements(ctx context.Context, projectID uuid.UUID) (model.ComplianceCategory, error) {
	category := model.ComplianceCategory{
		Name:     string(model.ComplianceCategoryMinimumElements),
		Label:    "経産省ガイドライン最小要素（7項目）",
		MaxScore: 7,
		Checks:   []model.ComplianceCheck{},
	}

	// Get latest SBOM
	sbom, err := s.sbomRepo.GetLatest(ctx, projectID)
	if err != nil || sbom == nil {
		// No SBOM exists - all checks fail
		checks := []struct {
			id      string
			label   string
			details string
		}{
			{"supplier_name", "サプライヤー名", "SBOMが存在しないため確認できません"},
			{"component_name", "コンポーネント名", "SBOMが存在しないため確認できません"},
			{"component_version", "コンポーネントのバージョン", "SBOMが存在しないため確認できません"},
			{"unique_identifier", "一意な識別子（PURL等）", "SBOMが存在しないため確認できません"},
			{"dependency_relationship", "依存関係", "SBOMが存在しないため確認できません"},
			{"sbom_author", "SBOM作成者", "SBOMが存在しないため確認できません"},
			{"timestamp", "タイムスタンプ", "SBOMが存在しないため確認できません"},
		}
		for _, c := range checks {
			detail := c.details
			category.Checks = append(category.Checks, model.ComplianceCheck{
				ID:      c.id,
				Label:   c.label,
				Passed:  false,
				Details: &detail,
			})
		}
		return category, nil
	}

	// Get components
	components, err := s.componentRepo.ListBySbom(ctx, sbom.ID)
	if err != nil {
		return category, fmt.Errorf("failed to get components: %w", err)
	}

	totalComponents := len(components)
	if totalComponents == 0 {
		detail := "コンポーネントが存在しません"
		checks := []string{"supplier_name", "component_name", "component_version", "unique_identifier", "dependency_relationship", "sbom_author", "timestamp"}
		labels := []string{"サプライヤー名", "コンポーネント名", "コンポーネントのバージョン", "一意な識別子（PURL等）", "依存関係", "SBOM作成者", "タイムスタンプ"}
		for i, c := range checks {
			category.Checks = append(category.Checks, model.ComplianceCheck{
				ID:      c,
				Label:   labels[i],
				Passed:  false,
				Details: &detail,
			})
		}
		return category, nil
	}

	// Parse raw SBOM data
	var rawData map[string]interface{}
	if err := json.Unmarshal(sbom.RawData, &rawData); err != nil {
		return category, fmt.Errorf("failed to parse SBOM raw data: %w", err)
	}

	// Threshold for passing (80%)
	threshold := 0.8

	// 1. Supplier Name - Check purl namespace or supplier field in raw data
	supplierCount := countComponentsWithSupplier(components, rawData, sbom.Format)
	supplierPct := float64(supplierCount) / float64(totalComponents)
	check1 := model.ComplianceCheck{
		ID:     "supplier_name",
		Label:  "サプライヤー名",
		Passed: supplierPct >= threshold,
	}
	if !check1.Passed {
		detail := fmt.Sprintf("%d/%d コンポーネント (%.0f%%) にサプライヤー情報があります", supplierCount, totalComponents, supplierPct*100)
		check1.Details = &detail
	} else {
		category.Score++
	}
	category.Checks = append(category.Checks, check1)

	// 2. Component Name
	nameCount := 0
	for _, c := range components {
		if c.Name != "" {
			nameCount++
		}
	}
	namePct := float64(nameCount) / float64(totalComponents)
	check2 := model.ComplianceCheck{
		ID:     "component_name",
		Label:  "コンポーネント名",
		Passed: namePct >= threshold,
	}
	if !check2.Passed {
		detail := fmt.Sprintf("%d/%d コンポーネント (%.0f%%) に名前があります", nameCount, totalComponents, namePct*100)
		check2.Details = &detail
	} else {
		category.Score++
	}
	category.Checks = append(category.Checks, check2)

	// 3. Component Version
	versionCount := 0
	for _, c := range components {
		if c.Version != "" {
			versionCount++
		}
	}
	versionPct := float64(versionCount) / float64(totalComponents)
	check3 := model.ComplianceCheck{
		ID:     "component_version",
		Label:  "コンポーネントのバージョン",
		Passed: versionPct >= threshold,
	}
	if !check3.Passed {
		detail := fmt.Sprintf("%d/%d コンポーネント (%.0f%%) にバージョンがあります", versionCount, totalComponents, versionPct*100)
		check3.Details = &detail
	} else {
		category.Score++
	}
	category.Checks = append(category.Checks, check3)

	// 4. Unique Identifier (PURL)
	purlCount := 0
	for _, c := range components {
		if c.Purl != "" {
			purlCount++
		}
	}
	purlPct := float64(purlCount) / float64(totalComponents)
	check4 := model.ComplianceCheck{
		ID:     "unique_identifier",
		Label:  "一意な識別子（PURL等）",
		Passed: purlPct >= threshold,
	}
	if !check4.Passed {
		detail := fmt.Sprintf("%d/%d コンポーネント (%.0f%%) にPURLがあります", purlCount, totalComponents, purlPct*100)
		check4.Details = &detail
	} else {
		category.Score++
	}
	category.Checks = append(category.Checks, check4)

	// 5. Dependency Relationship - Check if dependencies section exists in SBOM
	hasDependencies := checkDependenciesExist(rawData, sbom.Format)
	check5 := model.ComplianceCheck{
		ID:     "dependency_relationship",
		Label:  "依存関係",
		Passed: hasDependencies,
	}
	if !hasDependencies {
		detail := "SBOMに依存関係情報が含まれていません"
		check5.Details = &detail
	} else {
		category.Score++
	}
	category.Checks = append(category.Checks, check5)

	// 6. SBOM Author
	hasAuthor := checkAuthorExists(rawData, sbom.Format)
	check6 := model.ComplianceCheck{
		ID:     "sbom_author",
		Label:  "SBOM作成者",
		Passed: hasAuthor,
	}
	if !hasAuthor {
		detail := "SBOMに作成者情報が含まれていません"
		check6.Details = &detail
	} else {
		category.Score++
	}
	category.Checks = append(category.Checks, check6)

	// 7. Timestamp
	hasTimestamp := checkTimestampExists(rawData, sbom.Format)
	check7 := model.ComplianceCheck{
		ID:     "timestamp",
		Label:  "タイムスタンプ",
		Passed: hasTimestamp,
	}
	if !hasTimestamp {
		detail := "SBOMにタイムスタンプが含まれていません"
		check7.Details = &detail
	} else {
		category.Score++
	}
	category.Checks = append(category.Checks, check7)

	return category, nil
}

// countComponentsWithSupplier counts components that have supplier information
func countComponentsWithSupplier(components []model.Component, rawData map[string]interface{}, format string) int {
	count := 0
	for _, c := range components {
		// Check if PURL has namespace (supplier info)
		if c.Purl != "" {
			// PURL format: pkg:type/namespace/name@version
			// If there's a namespace, it indicates supplier
			parts := strings.Split(c.Purl, "/")
			if len(parts) >= 3 {
				// Has namespace
				count++
				continue
			}
		}

		// Fallback: check raw data for supplier info
		if hasSupplierInRawData(c.Name, rawData, format) {
			count++
		}
	}
	return count
}

// hasSupplierInRawData checks if a component has supplier info in raw SBOM data
func hasSupplierInRawData(componentName string, rawData map[string]interface{}, format string) bool {
	if format == string(model.FormatCycloneDX) {
		// CycloneDX: components[].supplier or components[].publisher
		if comps, ok := rawData["components"].([]interface{}); ok {
			for _, comp := range comps {
				if c, ok := comp.(map[string]interface{}); ok {
					if name, ok := c["name"].(string); ok && name == componentName {
						if _, hasSupplier := c["supplier"]; hasSupplier {
							return true
						}
						if _, hasPublisher := c["publisher"]; hasPublisher {
							return true
						}
					}
				}
			}
		}
	} else if format == string(model.FormatSPDX) {
		// SPDX: packages[].supplier
		if pkgs, ok := rawData["packages"].([]interface{}); ok {
			for _, pkg := range pkgs {
				if p, ok := pkg.(map[string]interface{}); ok {
					if name, ok := p["name"].(string); ok && name == componentName {
						if supplier, ok := p["supplier"].(string); ok && supplier != "" && supplier != "NOASSERTION" {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

// checkDependenciesExist checks if the SBOM contains dependency information
func checkDependenciesExist(rawData map[string]interface{}, format string) bool {
	if format == string(model.FormatCycloneDX) {
		// CycloneDX: dependencies array
		if deps, ok := rawData["dependencies"].([]interface{}); ok && len(deps) > 0 {
			return true
		}
	} else if format == string(model.FormatSPDX) {
		// SPDX: relationships array
		if rels, ok := rawData["relationships"].([]interface{}); ok && len(rels) > 0 {
			return true
		}
	}
	return false
}

// checkAuthorExists checks if the SBOM contains author information
func checkAuthorExists(rawData map[string]interface{}, format string) bool {
	if format == string(model.FormatCycloneDX) {
		// CycloneDX: metadata.authors or metadata.tools
		if metadata, ok := rawData["metadata"].(map[string]interface{}); ok {
			if authors, ok := metadata["authors"].([]interface{}); ok && len(authors) > 0 {
				return true
			}
			// Also accept tools as they often indicate the creator
			if tools, ok := metadata["tools"].([]interface{}); ok && len(tools) > 0 {
				return true
			}
			// CycloneDX 1.5+: tools.components or tools.services
			if tools, ok := metadata["tools"].(map[string]interface{}); ok {
				if comps, ok := tools["components"].([]interface{}); ok && len(comps) > 0 {
					return true
				}
			}
		}
	} else if format == string(model.FormatSPDX) {
		// SPDX: creationInfo.creators
		if creationInfo, ok := rawData["creationInfo"].(map[string]interface{}); ok {
			if creators, ok := creationInfo["creators"].([]interface{}); ok && len(creators) > 0 {
				return true
			}
		}
	}
	return false
}

// checkTimestampExists checks if the SBOM contains timestamp information
func checkTimestampExists(rawData map[string]interface{}, format string) bool {
	if format == string(model.FormatCycloneDX) {
		// CycloneDX: metadata.timestamp
		if metadata, ok := rawData["metadata"].(map[string]interface{}); ok {
			if timestamp, ok := metadata["timestamp"].(string); ok && timestamp != "" {
				return true
			}
		}
	} else if format == string(model.FormatSPDX) {
		// SPDX: creationInfo.created
		if creationInfo, ok := rawData["creationInfo"].(map[string]interface{}); ok {
			if created, ok := creationInfo["created"].(string); ok && created != "" {
				return true
			}
		}
	}
	return false
}

// GetMinimumElementsCoverage returns detailed coverage stats for minimum elements
func (s *ComplianceService) GetMinimumElementsCoverage(ctx context.Context, projectID uuid.UUID) (*model.MinimumElementsCoverage, error) {
	// Get latest SBOM
	sbom, err := s.sbomRepo.GetLatest(ctx, projectID)
	if err != nil || sbom == nil {
		return &model.MinimumElementsCoverage{
			TotalComponents: 0,
			Elements:        []model.MinimumElementStats{},
			OverallScore:    0,
		}, nil
	}

	// Get components
	components, err := s.componentRepo.ListBySbom(ctx, sbom.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get components: %w", err)
	}

	totalComponents := len(components)
	if totalComponents == 0 {
		return &model.MinimumElementsCoverage{
			TotalComponents: 0,
			Elements:        []model.MinimumElementStats{},
			OverallScore:    0,
		}, nil
	}

	// Parse raw SBOM data
	var rawData map[string]interface{}
	if err := json.Unmarshal(sbom.RawData, &rawData); err != nil {
		return nil, fmt.Errorf("failed to parse SBOM raw data: %w", err)
	}

	// Calculate stats for each element
	elements := []model.MinimumElementStats{}

	// 1. Supplier Name
	supplierCount := countComponentsWithSupplier(components, rawData, sbom.Format)
	elements = append(elements, model.MinimumElementStats{
		ID:         "supplier_name",
		Label:      "Supplier Name",
		LabelJa:    "サプライヤー名",
		Count:      supplierCount,
		Percentage: int(float64(supplierCount) / float64(totalComponents) * 100),
	})

	// 2. Component Name
	nameCount := 0
	for _, c := range components {
		if c.Name != "" {
			nameCount++
		}
	}
	elements = append(elements, model.MinimumElementStats{
		ID:         "component_name",
		Label:      "Component Name",
		LabelJa:    "コンポーネント名",
		Count:      nameCount,
		Percentage: int(float64(nameCount) / float64(totalComponents) * 100),
	})

	// 3. Component Version
	versionCount := 0
	for _, c := range components {
		if c.Version != "" {
			versionCount++
		}
	}
	elements = append(elements, model.MinimumElementStats{
		ID:         "component_version",
		Label:      "Version",
		LabelJa:    "コンポーネントのバージョン",
		Count:      versionCount,
		Percentage: int(float64(versionCount) / float64(totalComponents) * 100),
	})

	// 4. Unique Identifier
	purlCount := 0
	for _, c := range components {
		if c.Purl != "" {
			purlCount++
		}
	}
	elements = append(elements, model.MinimumElementStats{
		ID:         "unique_identifier",
		Label:      "Unique Identifier (PURL)",
		LabelJa:    "一意な識別子（PURL等）",
		Count:      purlCount,
		Percentage: int(float64(purlCount) / float64(totalComponents) * 100),
	})

	// 5. Dependency Relationship (document-level, not per component)
	hasDeps := checkDependenciesExist(rawData, sbom.Format)
	depsPct := 0
	if hasDeps {
		depsPct = 100
	}
	elements = append(elements, model.MinimumElementStats{
		ID:         "dependency_relationship",
		Label:      "Dependency Relationship",
		LabelJa:    "依存関係",
		Count:      depsPct / 100 * totalComponents, // Approximation
		Percentage: depsPct,
	})

	// 6. SBOM Author (document-level)
	hasAuthor := checkAuthorExists(rawData, sbom.Format)
	authorPct := 0
	if hasAuthor {
		authorPct = 100
	}
	elements = append(elements, model.MinimumElementStats{
		ID:         "sbom_author",
		Label:      "Author of SBOM Data",
		LabelJa:    "SBOM作成者",
		Count:      authorPct / 100 * totalComponents, // Approximation
		Percentage: authorPct,
	})

	// 7. Timestamp (document-level)
	hasTimestamp := checkTimestampExists(rawData, sbom.Format)
	tsPct := 0
	if hasTimestamp {
		tsPct = 100
	}
	elements = append(elements, model.MinimumElementStats{
		ID:         "timestamp",
		Label:      "Timestamp",
		LabelJa:    "タイムスタンプ",
		Count:      tsPct / 100 * totalComponents, // Approximation
		Percentage: tsPct,
	})

	// Calculate overall score (percentage of elements meeting 80% threshold)
	passingElements := 0
	threshold := 80
	for _, e := range elements {
		if e.Percentage >= threshold {
			passingElements++
		}
	}
	overallScore := int(float64(passingElements) / float64(len(elements)) * 100)

	return &model.MinimumElementsCoverage{
		TotalComponents: totalComponents,
		Elements:        elements,
		OverallScore:    overallScore,
	}, nil
}

// GenerateCompliancePDF generates a PDF compliance report using maroto
func (s *ComplianceService) GenerateCompliancePDF(ctx context.Context, projectID uuid.UUID, result *model.ComplianceResult) ([]byte, error) {
	cfg := config.NewBuilder().
		WithPageNumber().
		WithLeftMargin(15).
		WithTopMargin(15).
		WithRightMargin(15).
		Build()

	m := maroto.New(cfg)

	// Title
	m.AddRows(s.buildCompliancePDFTitle("経産省SBOMガイドライン コンプライアンスレポート"))

	// Metadata
	m.AddRows(s.buildCompliancePDFSubtitle(fmt.Sprintf("プロジェクトID: %s", projectID.String()[:8])))
	m.AddRows(s.buildCompliancePDFSubtitle(fmt.Sprintf("評価日時: %s", time.Now().Format("2006-01-02 15:04"))))

	// Summary Section
	pct := 0.0
	if result.MaxScore > 0 {
		pct = float64(result.Score) / float64(result.MaxScore) * 100
	}
	m.AddRows(s.buildCompliancePDFSectionHeader("総合スコア"))
	m.AddRows(s.buildCompliancePDFKeyValue("スコア", fmt.Sprintf("%d / %d (%.0f%%)", result.Score, result.MaxScore, pct)))

	// Categories
	m.AddRows(s.buildCompliancePDFSectionHeader("カテゴリ別評価"))
	for _, category := range result.Categories {
		catPct := 0.0
		if category.MaxScore > 0 {
			catPct = float64(category.Score) / float64(category.MaxScore) * 100
		}
		m.AddRows(s.buildCompliancePDFKeyValue(category.Label, fmt.Sprintf("%d / %d (%.0f%%)", category.Score, category.MaxScore, catPct)))
	}

	// Checklist Details
	m.AddRows(s.buildCompliancePDFSectionHeader("チェック項目詳細"))
	for _, category := range result.Categories {
		m.AddRows(s.buildCompliancePDFSubsection(category.Label))
		for _, check := range category.Checks {
			status := "○"
			if !check.Passed {
				status = "×"
			}
			m.AddRows(s.buildCompliancePDFCheckItem(status, check.Label))
		}
	}

	// Recommendations
	hasFailures := false
	for _, category := range result.Categories {
		for _, check := range category.Checks {
			if !check.Passed {
				hasFailures = true
				break
			}
		}
	}

	if hasFailures {
		m.AddRows(s.buildCompliancePDFSectionHeader("推奨事項"))
		for _, category := range result.Categories {
			for _, check := range category.Checks {
				if !check.Passed {
					m.AddRows(s.buildCompliancePDFRecommendation(check.Label, getRecommendation(check.ID)))
				}
			}
		}
	}

	// Footer
	m.AddRows(s.buildCompliancePDFFooter())

	// Generate PDF
	doc, err := m.Generate()
	if err != nil {
		return nil, fmt.Errorf("failed to generate PDF: %w", err)
	}

	return doc.GetBytes(), nil
}

// PDF helper functions for compliance
func (s *ComplianceService) buildCompliancePDFTitle(title string) core.Row {
	return row.New(12).Add(
		col.New(12).Add(
			text.New(title, props.Text{
				Size:  16,
				Style: fontstyle.Bold,
				Align: align.Center,
			}),
		),
	)
}

func (s *ComplianceService) buildCompliancePDFSubtitle(subtitle string) core.Row {
	return row.New(6).Add(
		col.New(12).Add(
			text.New(subtitle, props.Text{
				Size:  10,
				Align: align.Center,
				Color: &props.Color{Red: 100, Green: 100, Blue: 100},
			}),
		),
	)
}

func (s *ComplianceService) buildCompliancePDFSectionHeader(header string) core.Row {
	return row.New(10).Add(
		col.New(12).Add(
			text.New(header, props.Text{
				Size:  12,
				Style: fontstyle.Bold,
				Top:   5,
			}),
		),
	)
}

func (s *ComplianceService) buildCompliancePDFSubsection(header string) core.Row {
	return row.New(7).Add(
		col.New(12).Add(
			text.New("■ "+header, props.Text{
				Size:  10,
				Style: fontstyle.Bold,
				Top:   3,
			}),
		),
	)
}

func (s *ComplianceService) buildCompliancePDFKeyValue(key, value string) core.Row {
	return row.New(6).Add(
		col.New(6).Add(
			text.New(key, props.Text{
				Size: 10,
			}),
		),
		col.New(6).Add(
			text.New(value, props.Text{
				Size:  10,
				Align: align.Right,
			}),
		),
	)
}

func (s *ComplianceService) buildCompliancePDFCheckItem(status, label string) core.Row {
	return row.New(5).Add(
		col.New(1).Add(
			text.New(status, props.Text{
				Size:  10,
				Align: align.Center,
			}),
		),
		col.New(11).Add(
			text.New(label, props.Text{
				Size: 9,
			}),
		),
	)
}

func (s *ComplianceService) buildCompliancePDFRecommendation(label, recommendation string) core.Row {
	return row.New(8).Add(
		col.New(12).Add(
			text.New(fmt.Sprintf("・%s: %s", label, recommendation), props.Text{
				Size: 9,
			}),
		),
	)
}

func (s *ComplianceService) buildCompliancePDFFooter() core.Row {
	return row.New(10).Add(
		col.New(12).Add(
			text.New("※本レポートは経済産業省「ソフトウェア管理に向けたSBOM導入に関する手引」に基づく自己評価です", props.Text{
				Size:  8,
				Align: align.Center,
				Top:   5,
				Color: &props.Color{Red: 100, Green: 100, Blue: 100},
			}),
		),
	)
}

// GenerateComplianceExcel generates an Excel compliance report using excelize
func (s *ComplianceService) GenerateComplianceExcel(ctx context.Context, projectID uuid.UUID, result *model.ComplianceResult) ([]byte, error) {
	f := excelize.NewFile()
	defer f.Close()

	// Create Summary sheet
	sheetName := "サマリー"
	f.SetSheetName("Sheet1", sheetName)

	// Set column widths
	f.SetColWidth(sheetName, "A", "A", 25)
	f.SetColWidth(sheetName, "B", "B", 35)

	// Header style
	headerStyle, _ := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true, Size: 14, Color: "#FFFFFF"},
		Fill:      excelize.Fill{Type: "pattern", Color: []string{"#4472C4"}, Pattern: 1},
		Alignment: &excelize.Alignment{Horizontal: "center", Vertical: "center"},
	})

	// Title
	f.MergeCell(sheetName, "A1", "B1")
	f.SetCellValue(sheetName, "A1", "経産省SBOMガイドライン コンプライアンスレポート")
	f.SetCellStyle(sheetName, "A1", "B1", headerStyle)
	f.SetRowHeight(sheetName, 1, 30)

	// Metadata
	f.SetCellValue(sheetName, "A3", "プロジェクトID")
	f.SetCellValue(sheetName, "B3", projectID.String()[:8])
	f.SetCellValue(sheetName, "A4", "評価日時")
	f.SetCellValue(sheetName, "B4", time.Now().Format("2006-01-02 15:04:05"))

	// Summary
	pct := 0.0
	if result.MaxScore > 0 {
		pct = float64(result.Score) / float64(result.MaxScore) * 100
	}
	f.SetCellValue(sheetName, "A6", "総合スコア")
	f.SetCellValue(sheetName, "B6", fmt.Sprintf("%d / %d (%.0f%%)", result.Score, result.MaxScore, pct))

	// Category scores
	row := 8
	f.SetCellValue(sheetName, fmt.Sprintf("A%d", row), "カテゴリ別スコア")
	f.SetCellStyle(sheetName, fmt.Sprintf("A%d", row), fmt.Sprintf("A%d", row), headerStyle)
	row++

	for _, category := range result.Categories {
		catPct := 0.0
		if category.MaxScore > 0 {
			catPct = float64(category.Score) / float64(category.MaxScore) * 100
		}
		f.SetCellValue(sheetName, fmt.Sprintf("A%d", row), category.Label)
		f.SetCellValue(sheetName, fmt.Sprintf("B%d", row), fmt.Sprintf("%d / %d (%.0f%%)", category.Score, category.MaxScore, catPct))
		row++
	}

	// Create Details sheet
	detailSheet := "チェック項目詳細"
	f.NewSheet(detailSheet)
	f.SetColWidth(detailSheet, "A", "A", 25)
	f.SetColWidth(detailSheet, "B", "B", 40)
	f.SetColWidth(detailSheet, "C", "C", 10)
	f.SetColWidth(detailSheet, "D", "D", 30)
	f.SetColWidth(detailSheet, "E", "E", 40)

	// Headers
	f.SetCellValue(detailSheet, "A1", "カテゴリ")
	f.SetCellValue(detailSheet, "B1", "チェック項目")
	f.SetCellValue(detailSheet, "C1", "結果")
	f.SetCellValue(detailSheet, "D1", "詳細")
	f.SetCellValue(detailSheet, "E1", "推奨事項")
	f.SetCellStyle(detailSheet, "A1", "E1", headerStyle)

	// Pass/Fail styles
	passStyle, _ := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{Color: "#008000"},
	})
	failStyle, _ := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{Color: "#FF0000"},
	})

	// Data rows
	row = 2
	for _, category := range result.Categories {
		for _, check := range category.Checks {
			f.SetCellValue(detailSheet, fmt.Sprintf("A%d", row), category.Label)
			f.SetCellValue(detailSheet, fmt.Sprintf("B%d", row), check.Label)

			if check.Passed {
				f.SetCellValue(detailSheet, fmt.Sprintf("C%d", row), "達成")
				f.SetCellStyle(detailSheet, fmt.Sprintf("C%d", row), fmt.Sprintf("C%d", row), passStyle)
			} else {
				f.SetCellValue(detailSheet, fmt.Sprintf("C%d", row), "未達成")
				f.SetCellStyle(detailSheet, fmt.Sprintf("C%d", row), fmt.Sprintf("C%d", row), failStyle)
			}

			if check.Details != nil {
				f.SetCellValue(detailSheet, fmt.Sprintf("D%d", row), *check.Details)
			}

			if !check.Passed {
				f.SetCellValue(detailSheet, fmt.Sprintf("E%d", row), getRecommendation(check.ID))
			}
			row++
		}
	}

	// Create Recommendations sheet
	recSheet := "推奨事項"
	f.NewSheet(recSheet)
	f.SetColWidth(recSheet, "A", "A", 40)
	f.SetColWidth(recSheet, "B", "B", 50)

	f.SetCellValue(recSheet, "A1", "未達成項目")
	f.SetCellValue(recSheet, "B1", "推奨事項")
	f.SetCellStyle(recSheet, "A1", "B1", headerStyle)

	row = 2
	for _, category := range result.Categories {
		for _, check := range category.Checks {
			if !check.Passed {
				f.SetCellValue(recSheet, fmt.Sprintf("A%d", row), check.Label)
				f.SetCellValue(recSheet, fmt.Sprintf("B%d", row), getRecommendation(check.ID))
				row++
			}
		}
	}

	// Write to buffer
	var buf bytes.Buffer
	if err := f.Write(&buf); err != nil {
		return nil, fmt.Errorf("failed to write Excel: %w", err)
	}

	return buf.Bytes(), nil
}

// Deprecated: Keep for backward compatibility
func (s *ComplianceService) GenerateComplianceCSV(ctx context.Context, projectID uuid.UUID, result *model.ComplianceResult) ([]byte, error) {
	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)

	// Write BOM for Excel compatibility
	buf.Write([]byte{0xEF, 0xBB, 0xBF})

	// Header
	writer.Write([]string{"経済産業省コンプライアンスレポート"})
	writer.Write([]string{"プロジェクトID", projectID.String()})
	writer.Write([]string{"評価日時", time.Now().Format("2006-01-02 15:04:05")})
	writer.Write([]string{"総合スコア", fmt.Sprintf("%d / %d", result.Score, result.MaxScore)})
	writer.Write([]string{""})

	// Column headers
	writer.Write([]string{"カテゴリ", "チェック項目", "結果", "詳細", "推奨事項"})

	// Data rows
	for _, category := range result.Categories {
		for _, check := range category.Checks {
			status := "未達成"
			if check.Passed {
				status = "達成"
			}
			details := ""
			if check.Details != nil {
				details = *check.Details
			}
			recommendation := ""
			if !check.Passed {
				recommendation = getRecommendation(check.ID)
			}
			writer.Write([]string{
				category.Label,
				check.Label,
				status,
				details,
				recommendation,
			})
		}
	}

	writer.Flush()
	return buf.Bytes(), nil
}

// getRecommendation returns a recommendation for a failed check
func getRecommendation(checkID string) string {
	recommendations := map[string]string{
		"sbom_exists":            "CycloneDXまたはSPDX形式のSBOMをアップロードしてください",
		"required_fields":        "全てのコンポーネントに名前とバージョンを設定してください",
		"recently_updated":       "SBOMを定期的に更新してください（推奨: 30日以内）",
		"scan_performed":         "脆弱性データベース（NVD/JVN）との照合を実行してください",
		"no_unresolved_critical": "Critical脆弱性に対してVEXステートメントを作成し、対応状況を記録してください",
		"vex_in_use":             "脆弱性の対応状況をVEXで管理してください",
		"policy_configured":      "ライセンスポリシーを設定してください",
		"no_violations":          "禁止ライセンスを含むコンポーネントを除去または置換してください",
		// METI Minimum Elements recommendations
		"supplier_name":           "SBOMツールでサプライヤー情報を含めるか、PURLにnamespaceを含めてください",
		"component_name":          "全てのコンポーネントに名前を設定してください",
		"component_version":       "全てのコンポーネントにバージョンを設定してください",
		"unique_identifier":       "全てのコンポーネントにPURL（Package URL）を設定してください",
		"dependency_relationship": "SBOMに依存関係情報を含めてください（CycloneDX: dependencies、SPDX: relationships）",
		"sbom_author":             "SBOMに作成者情報を含めてください（CycloneDX: metadata.authors、SPDX: creationInfo.creators）",
		"timestamp":               "SBOMにタイムスタンプを含めてください（CycloneDX: metadata.timestamp、SPDX: creationInfo.created）",
	}
	if rec, ok := recommendations[checkID]; ok {
		return rec
	}
	return ""
}

// ============================================================================
// METI Checklist (18 items) Methods
// ============================================================================

// GetChecklist returns the full checklist with auto-verification and manual responses
func (s *ComplianceService) GetChecklist(ctx context.Context, tenantID, projectID uuid.UUID) (*model.ChecklistResult, error) {
	// Get all checklist items definition
	allItems := model.GetAllChecklistItems()
	phaseLabels := model.GetChecklistPhaseLabels()

	// Get manual responses from database
	var manualResponses []model.ChecklistResponse
	if s.checklistRepo != nil {
		var err error
		manualResponses, err = s.checklistRepo.ListByProject(ctx, projectID)
		if err != nil {
			return nil, fmt.Errorf("failed to get checklist responses: %w", err)
		}
	}

	// Create response map for quick lookup
	responseMap := make(map[string]*model.ChecklistResponse)
	for i := range manualResponses {
		responseMap[manualResponses[i].CheckID] = &manualResponses[i]
	}

	// Get auto-verification results
	autoResults := s.getAutoVerificationResults(ctx, projectID)

	// Group items by phase
	phaseItems := map[model.ChecklistPhase][]model.ChecklistItemResult{
		model.PhaseSetup:     {},
		model.PhaseCreation:  {},
		model.PhaseOperation: {},
	}

	totalScore := 0
	totalMax := 0

	for _, item := range allItems {
		result := model.ChecklistItemResult{
			ChecklistItem: item,
			Passed:        false,
		}

		// Check if auto-verifiable
		if item.AutoVerify {
			if autoResult, ok := autoResults[item.ID]; ok {
				result.AutoResult = &autoResult
				result.Passed = autoResult
			}
		}

		// Check if manual response exists (manual can override auto)
		if resp, ok := responseMap[item.ID]; ok {
			result.Response = &resp.Response
			result.Note = resp.Note
			// Manual response takes precedence for pass/fail
			if !item.AutoVerify || resp.Response {
				result.Passed = resp.Response
			}
		}

		// For non-auto items without response, check manual response
		if !item.AutoVerify && result.Response == nil {
			result.Passed = false
		}

		phaseItems[item.Phase] = append(phaseItems[item.Phase], result)
		totalMax++
		if result.Passed {
			totalScore++
		}
	}

	// Build phase results
	phases := []model.ChecklistPhaseResult{}
	for _, phase := range []model.ChecklistPhase{model.PhaseSetup, model.PhaseCreation, model.PhaseOperation} {
		items := phaseItems[phase]
		labels := phaseLabels[phase]
		phaseScore := 0
		for _, item := range items {
			if item.Passed {
				phaseScore++
			}
		}
		phases = append(phases, model.ChecklistPhaseResult{
			Phase:    phase,
			Label:    labels.Label,
			LabelJa:  labels.LabelJa,
			Items:    items,
			Score:    phaseScore,
			MaxScore: len(items),
		})
	}

	return &model.ChecklistResult{
		ProjectID: projectID,
		Phases:    phases,
		Score:     totalScore,
		MaxScore:  totalMax,
	}, nil
}

// getAutoVerificationResults performs auto-verification for applicable checklist items
func (s *ComplianceService) getAutoVerificationResults(ctx context.Context, projectID uuid.UUID) map[string]bool {
	results := make(map[string]bool)

	// Get SBOM data
	sbom, sbomErr := s.sbomRepo.GetLatest(ctx, projectID)
	sbomExists := sbomErr == nil && sbom != nil

	// setup_07: SBOMツールを選定 - SBOM exists means tool was selected
	results["setup_07"] = sbomExists

	// create_01: コンポーネントを解析 - Components exist
	if sbomExists {
		components, err := s.componentRepo.ListBySbom(ctx, sbom.ID)
		results["create_01"] = err == nil && len(components) > 0
	} else {
		results["create_01"] = false
	}

	// create_05: 要件を満たすSBOMを作成 - Use minimum elements verification
	if sbomExists {
		minElements, err := s.GetMinimumElementsCoverage(ctx, projectID)
		// Pass if overall score >= 80%
		results["create_05"] = err == nil && minElements != nil && minElements.OverallScore >= 80
	} else {
		results["create_05"] = false
	}

	// create_06: SBOMを共有 - Public link exists
	if s.publicLinkRepo != nil {
		links, err := s.publicLinkRepo.ListByProject(ctx, projectID)
		results["create_06"] = err == nil && len(links) > 0
	} else {
		results["create_06"] = false
	}

	// operate_01: 脆弱性対応を実施 - VEX exists
	vexStatements, _ := s.vexRepo.ListByProject(ctx, projectID)
	results["operate_01"] = len(vexStatements) > 0

	// operate_02: 脆弱性情報を特定 - Vulnerability scan performed
	vulnCounts, err := s.dashboardRepo.GetProjectVulnerabilityCounts(ctx, projectID)
	// If we can get vulnerability counts, scan was performed (even if 0 vulns)
	results["operate_02"] = err == nil && (vulnCounts.Critical >= 0)

	// operate_03: 脆弱性を優先付け - EPSS usage (SBOMHub supports EPSS, so always true if vulns exist)
	results["operate_03"] = results["operate_02"]

	// operate_04: ライセンス違反を確認 - License policy is configured
	policies, err := s.licensePolicyRepo.ListByProject(ctx, projectID)
	results["operate_04"] = err == nil && len(policies) > 0

	// operate_05: SBOM情報を適切に管理 - SBOM history has 2+ entries
	sboms, err := s.sbomRepo.ListByProject(ctx, projectID)
	results["operate_05"] = err == nil && len(sboms) >= 2

	return results
}

// UpdateChecklistResponse updates a manual checklist response
func (s *ComplianceService) UpdateChecklistResponse(ctx context.Context, tenantID, projectID uuid.UUID, checkID string, response bool, note *string, updatedBy string) error {
	if s.checklistRepo == nil {
		return fmt.Errorf("checklist repository not configured")
	}

	// Validate checkID
	allItems := model.GetAllChecklistItems()
	valid := false
	for _, item := range allItems {
		if item.ID == checkID {
			valid = true
			break
		}
	}
	if !valid {
		return fmt.Errorf("invalid check_id: %s", checkID)
	}

	resp := &model.ChecklistResponse{
		ID:        uuid.New(),
		TenantID:  tenantID,
		ProjectID: projectID,
		CheckID:   checkID,
		Response:  response,
		Note:      note,
		UpdatedBy: updatedBy,
		UpdatedAt: time.Now(),
	}

	return s.checklistRepo.Upsert(ctx, resp)
}

// DeleteChecklistResponse removes a manual checklist response
func (s *ComplianceService) DeleteChecklistResponse(ctx context.Context, projectID uuid.UUID, checkID string) error {
	if s.checklistRepo == nil {
		return fmt.Errorf("checklist repository not configured")
	}
	return s.checklistRepo.Delete(ctx, projectID, checkID)
}

// ============================================================================
// Visualization Framework Methods
// ============================================================================

// GetVisualizationSettings returns visualization settings for a project
func (s *ComplianceService) GetVisualizationSettings(ctx context.Context, projectID uuid.UUID) (*model.VisualizationFramework, error) {
	framework := &model.VisualizationFramework{
		Options: model.GetVisualizationOptions(),
	}

	if s.visualizationRepo != nil {
		settings, err := s.visualizationRepo.GetByProject(ctx, projectID)
		if err != nil {
			return nil, fmt.Errorf("failed to get visualization settings: %w", err)
		}
		framework.Settings = settings
	}

	return framework, nil
}

// UpdateVisualizationSettings updates visualization settings for a project
func (s *ComplianceService) UpdateVisualizationSettings(ctx context.Context, tenantID, projectID uuid.UUID, input *model.VisualizationSettingsInput) (*model.VisualizationSettings, error) {
	if s.visualizationRepo == nil {
		return nil, fmt.Errorf("visualization repository not configured")
	}

	// Get existing settings or create new
	existing, err := s.visualizationRepo.GetByProject(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to get existing settings: %w", err)
	}

	settings := &model.VisualizationSettings{
		TenantID:         tenantID,
		ProjectID:        projectID,
		SBOMAuthorScope:  input.SBOMAuthorScope,
		DependencyScope:  input.DependencyScope,
		GenerationMethod: input.GenerationMethod,
		DataFormat:       input.DataFormat,
		UtilizationScope: input.UtilizationScope,
		UtilizationActor: input.UtilizationActor,
	}

	if existing != nil {
		settings.ID = existing.ID
		settings.CreatedAt = existing.CreatedAt
	} else {
		settings.ID = uuid.New()
		settings.CreatedAt = time.Now()
	}
	settings.UpdatedAt = time.Now()

	if err := s.visualizationRepo.Upsert(ctx, settings); err != nil {
		return nil, fmt.Errorf("failed to save visualization settings: %w", err)
	}

	return settings, nil
}

// DeleteVisualizationSettings removes visualization settings for a project
func (s *ComplianceService) DeleteVisualizationSettings(ctx context.Context, projectID uuid.UUID) error {
	if s.visualizationRepo == nil {
		return fmt.Errorf("visualization repository not configured")
	}
	return s.visualizationRepo.Delete(ctx, projectID)
}
