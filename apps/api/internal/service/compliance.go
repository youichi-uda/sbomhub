package service

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

type ComplianceService struct {
	sbomRepo          *repository.SbomRepository
	componentRepo     *repository.ComponentRepository
	vulnRepo          *repository.VulnerabilityRepository
	vexRepo           *repository.VEXRepository
	licensePolicyRepo *repository.LicensePolicyRepository
	dashboardRepo     *repository.DashboardRepository
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

// GenerateCompliancePDF generates a PDF compliance report
func (s *ComplianceService) GenerateCompliancePDF(ctx context.Context, projectID uuid.UUID, result *model.ComplianceResult) ([]byte, error) {
	// Simplified text-based report (in production, use maroto library for proper PDF)
	content := fmt.Sprintf(`
経済産業省 ソフトウェア管理ガイドライン
コンプライアンス評価レポート
======================================

プロジェクトID: %s
評価日時: %s
総合スコア: %d / %d (%.1f%%)

`,
		projectID.String(),
		time.Now().Format("2006-01-02 15:04:05"),
		result.Score, result.MaxScore,
		float64(result.Score)/float64(result.MaxScore)*100,
	)

	for _, category := range result.Categories {
		content += fmt.Sprintf(`
%s
--------------------
スコア: %d / %d

チェック項目:
`, category.Label, category.Score, category.MaxScore)

		for _, check := range category.Checks {
			status := "[ ] 未達成"
			if check.Passed {
				status = "[✓] 達成"
			}
			content += fmt.Sprintf("  %s %s\n", status, check.Label)
			if check.Details != nil && *check.Details != "" {
				content += fmt.Sprintf("      詳細: %s\n", *check.Details)
			}
		}
	}

	content += `
======================================
推奨事項:

`
	for _, category := range result.Categories {
		for _, check := range category.Checks {
			if !check.Passed {
				content += fmt.Sprintf("- %s: %s\n", check.Label, getRecommendation(check.ID))
			}
		}
	}

	content += `
本レポートは経済産業省「ソフトウェア管理に向けたSBOM（Software Bill of Materials）
の導入に関する手引」に基づいて作成されています。

生成元: SBOMHub
`

	return []byte(content), nil
}

// GenerateComplianceExcel generates an Excel/CSV compliance report
func (s *ComplianceService) GenerateComplianceExcel(ctx context.Context, projectID uuid.UUID, result *model.ComplianceResult) ([]byte, error) {
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
	}
	if rec, ok := recommendations[checkID]; ok {
		return rec
	}
	return ""
}
