package model

import (
	"time"

	"github.com/google/uuid"
)

// VisualizationSettings represents METI visualization framework settings
type VisualizationSettings struct {
	ID               uuid.UUID `json:"id" db:"id"`
	TenantID         uuid.UUID `json:"tenant_id" db:"tenant_id"`
	ProjectID        uuid.UUID `json:"project_id" db:"project_id"`
	SBOMAuthorScope  string    `json:"sbom_author_scope" db:"sbom_author_scope"`
	DependencyScope  string    `json:"dependency_scope" db:"dependency_scope"`
	GenerationMethod string    `json:"generation_method" db:"generation_method"`
	DataFormat       string    `json:"data_format" db:"data_format"`
	UtilizationScope []string  `json:"utilization_scope" db:"utilization_scope"`
	UtilizationActor string    `json:"utilization_actor" db:"utilization_actor"`
	CreatedAt        time.Time `json:"created_at" db:"created_at"`
	UpdatedAt        time.Time `json:"updated_at" db:"updated_at"`
}

// VisualizationSettingsInput represents input for creating/updating settings
type VisualizationSettingsInput struct {
	SBOMAuthorScope  string   `json:"sbom_author_scope"`
	DependencyScope  string   `json:"dependency_scope"`
	GenerationMethod string   `json:"generation_method"`
	DataFormat       string   `json:"data_format"`
	UtilizationScope []string `json:"utilization_scope"`
	UtilizationActor string   `json:"utilization_actor"`
}

// VisualizationFramework represents the complete visualization framework with options
type VisualizationFramework struct {
	Settings *VisualizationSettings  `json:"settings,omitempty"`
	Options  VisualizationOptions    `json:"options"`
}

// VisualizationOptions represents available options for visualization settings
type VisualizationOptions struct {
	SBOMAuthorScope  []VisualizationOption `json:"sbom_author_scope"`
	DependencyScope  []VisualizationOption `json:"dependency_scope"`
	GenerationMethod []VisualizationOption `json:"generation_method"`
	DataFormat       []VisualizationOption `json:"data_format"`
	UtilizationScope []VisualizationOption `json:"utilization_scope"`
	UtilizationActor []VisualizationOption `json:"utilization_actor"`
}

// VisualizationOption represents a single option with label
type VisualizationOption struct {
	Value   string `json:"value"`
	Label   string `json:"label"`
	LabelJa string `json:"label_ja"`
}

// GetVisualizationOptions returns all available options for visualization framework
func GetVisualizationOptions() VisualizationOptions {
	return VisualizationOptions{
		SBOMAuthorScope: []VisualizationOption{
			{Value: "supplier", Label: "Supplier", LabelJa: "サプライヤー"},
			{Value: "operator", Label: "Operator", LabelJa: "運用事業者"},
			{Value: "both", Label: "Both", LabelJa: "両方"},
		},
		DependencyScope: []VisualizationOption{
			{Value: "direct", Label: "Direct dependencies only", LabelJa: "直接依存のみ"},
			{Value: "transitive", Label: "Including transitive dependencies", LabelJa: "推移的依存を含む"},
			{Value: "all", Label: "All dependencies", LabelJa: "全ての依存"},
		},
		GenerationMethod: []VisualizationOption{
			{Value: "auto", Label: "Automatic generation", LabelJa: "自動生成"},
			{Value: "manual", Label: "Manual creation", LabelJa: "手動作成"},
			{Value: "hybrid", Label: "Hybrid (auto + manual)", LabelJa: "ハイブリッド（自動+手動）"},
		},
		DataFormat: []VisualizationOption{
			{Value: "cyclonedx", Label: "CycloneDX", LabelJa: "CycloneDX"},
			{Value: "spdx", Label: "SPDX", LabelJa: "SPDX"},
			{Value: "both", Label: "Both formats", LabelJa: "両形式"},
		},
		UtilizationScope: []VisualizationOption{
			{Value: "vulnerability", Label: "Vulnerability management", LabelJa: "脆弱性管理"},
			{Value: "license", Label: "License compliance", LabelJa: "ライセンス遵守"},
			{Value: "eol", Label: "End-of-life management", LabelJa: "EOL管理"},
			{Value: "supply_chain", Label: "Supply chain management", LabelJa: "サプライチェーン管理"},
			{Value: "audit", Label: "Audit trail", LabelJa: "監査証跡"},
		},
		UtilizationActor: []VisualizationOption{
			{Value: "development", Label: "Development team", LabelJa: "開発チーム"},
			{Value: "security", Label: "Security team", LabelJa: "セキュリティチーム"},
			{Value: "procurement", Label: "Procurement department", LabelJa: "調達部門"},
			{Value: "management", Label: "Management", LabelJa: "経営層"},
			{Value: "all", Label: "All stakeholders", LabelJa: "全ステークホルダー"},
		},
	}
}
