package model

import (
	"time"

	"github.com/google/uuid"
)

// ChecklistPhase represents the 3 phases of METI checklist
type ChecklistPhase string

const (
	PhaseSetup     ChecklistPhase = "setup"     // 環境構築・体制整備
	PhaseCreation  ChecklistPhase = "creation"  // SBOM作成・共有
	PhaseOperation ChecklistPhase = "operation" // SBOM運用・管理
)

// ChecklistItem represents a single checklist item definition
type ChecklistItem struct {
	ID          string         `json:"id"`
	Phase       ChecklistPhase `json:"phase"`
	Label       string         `json:"label"`
	LabelJa     string         `json:"label_ja"`
	Description string         `json:"description"`
	AutoVerify  bool           `json:"auto_verify"` // Can be auto-verified
}

// ChecklistResponse represents a user's response to a checklist item
type ChecklistResponse struct {
	ID        uuid.UUID `json:"id" db:"id"`
	TenantID  uuid.UUID `json:"tenant_id" db:"tenant_id"`
	ProjectID uuid.UUID `json:"project_id" db:"project_id"`
	CheckID   string    `json:"check_id" db:"check_id"`
	Response  bool      `json:"response" db:"response"`
	Note      *string   `json:"note,omitempty" db:"note"`
	UpdatedBy string    `json:"updated_by" db:"updated_by"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// ChecklistResult represents the full checklist with responses
type ChecklistResult struct {
	ProjectID uuid.UUID              `json:"project_id"`
	Phases    []ChecklistPhaseResult `json:"phases"`
	Score     int                    `json:"score"`
	MaxScore  int                    `json:"max_score"`
}

type ChecklistPhaseResult struct {
	Phase    ChecklistPhase        `json:"phase"`
	Label    string                `json:"label"`
	LabelJa  string                `json:"label_ja"`
	Items    []ChecklistItemResult `json:"items"`
	Score    int                   `json:"score"`
	MaxScore int                   `json:"max_score"`
}

type ChecklistItemResult struct {
	ChecklistItem
	Passed     bool    `json:"passed"`
	Response   *bool   `json:"response,omitempty"`    // Manual response if any
	Note       *string `json:"note,omitempty"`        // User note
	AutoResult *bool   `json:"auto_result,omitempty"` // Auto-verify result if applicable
}

// GetAllChecklistItems returns all 18 checklist items
func GetAllChecklistItems() []ChecklistItem {
	return []ChecklistItem{
		// Phase 1: 環境構築・体制整備 (7 items)
		{ID: "setup_01", Phase: PhaseSetup, LabelJa: "対象ソフトウェアの情報を明確化", Label: "Clarify target software information", AutoVerify: false},
		{ID: "setup_02", Phase: PhaseSetup, LabelJa: "SBOM適用対象を可視化", Label: "Visualize SBOM application scope", AutoVerify: false},
		{ID: "setup_03", Phase: PhaseSetup, LabelJa: "契約形態・取引慣行を明確化", Label: "Clarify contract and trading practices", AutoVerify: false},
		{ID: "setup_04", Phase: PhaseSetup, LabelJa: "規制・要求事項を確認", Label: "Confirm regulations and requirements", AutoVerify: false},
		{ID: "setup_05", Phase: PhaseSetup, LabelJa: "組織内制約を明確化", Label: "Clarify organizational constraints", AutoVerify: false},
		{ID: "setup_06", Phase: PhaseSetup, LabelJa: "SBOM適用範囲（5W1H）を明確化", Label: "Clarify SBOM scope (5W1H)", AutoVerify: false},
		{ID: "setup_07", Phase: PhaseSetup, LabelJa: "SBOMツールを選定", Label: "Select SBOM tool", AutoVerify: true},

		// Phase 2: SBOM作成・共有 (6 items)
		{ID: "create_01", Phase: PhaseCreation, LabelJa: "コンポーネントを解析", Label: "Analyze components", AutoVerify: true},
		{ID: "create_02", Phase: PhaseCreation, LabelJa: "解析エラーがない", Label: "No analysis errors", AutoVerify: false},
		{ID: "create_03", Phase: PhaseCreation, LabelJa: "誤検出・検出漏れを確認", Label: "Verify false positives/negatives", AutoVerify: false},
		{ID: "create_04", Phase: PhaseCreation, LabelJa: "SBOM要件を決定", Label: "Determine SBOM requirements", AutoVerify: false},
		{ID: "create_05", Phase: PhaseCreation, LabelJa: "要件を満たすSBOMを作成", Label: "Create SBOM meeting requirements", AutoVerify: true},
		{ID: "create_06", Phase: PhaseCreation, LabelJa: "SBOMを共有", Label: "Share SBOM", AutoVerify: true},

		// Phase 3: SBOM運用・管理 (5 items)
		{ID: "operate_01", Phase: PhaseOperation, LabelJa: "脆弱性対応を実施", Label: "Implement vulnerability response", AutoVerify: true},
		{ID: "operate_02", Phase: PhaseOperation, LabelJa: "脆弱性情報を特定", Label: "Identify vulnerability information", AutoVerify: true},
		{ID: "operate_03", Phase: PhaseOperation, LabelJa: "脆弱性を優先付け", Label: "Prioritize vulnerabilities", AutoVerify: true},
		{ID: "operate_04", Phase: PhaseOperation, LabelJa: "ライセンス違反を確認", Label: "Check license violations", AutoVerify: true},
		{ID: "operate_05", Phase: PhaseOperation, LabelJa: "SBOM情報を適切に管理", Label: "Properly manage SBOM information", AutoVerify: true},
	}
}

// GetChecklistPhaseLabels returns phase labels
func GetChecklistPhaseLabels() map[ChecklistPhase]struct{ Label, LabelJa string } {
	return map[ChecklistPhase]struct{ Label, LabelJa string }{
		PhaseSetup:     {Label: "Environment Setup & Organizational Preparation", LabelJa: "環境構築・体制整備"},
		PhaseCreation:  {Label: "SBOM Creation & Sharing", LabelJa: "SBOM作成・共有"},
		PhaseOperation: {Label: "SBOM Operation & Management", LabelJa: "SBOM運用・管理"},
	}
}
