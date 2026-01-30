package service

// ReportTranslations contains all translatable strings for reports
type ReportTranslations struct {
	// Report titles
	TitleExecutive  string
	TitleTechnical  string
	TitleCompliance string
	TitleDefault    string

	// Section headers
	Summary               string
	VulnerabilityBreakdown string
	VulnerabilityDetailed string
	Compliance            string
	TopRisks              string
	TopRisksDetailed      string
	SecurityMetrics       string
	VulnerabilityTrend    string
	ComplianceScore       string
	METIChecklist         string
	VisualizationFramework string
	VulnerabilitySummary  string

	// Labels
	Projects           string
	Components         string
	TotalVulnerabilities string
	ResolvedInPeriod   string
	AverageMTTR        string
	SLOAchievement     string
	Score              string
	AchievementRate    string
	TotalProgress      string
	Period             string
	GeneratedAt        string

	// Severity labels
	Critical      string
	High          string
	Medium        string
	Low           string
	CriticalCount string
	HighCount     string
	MediumCount   string
	LowCount      string

	// Status
	Completed   string
	NotCompleted string
	Auto        string

	// Visualization framework
	VizSBOMAuthor     string
	VizDependency     string
	VizGeneration     string
	VizDataFormat     string
	VizUtilization    string
	VizSBOMAuthorDesc string
	VizDependencyDesc string
	VizGenerationDesc string
	VizDataFormatDesc string
	VizUtilizationDesc string

	// Excel specific
	SheetSummary      string
	SheetTopRisks     string
	SheetTrend        string
	SheetChecklist    string
	SheetVisualization string

	// Table headers
	CVEID       string
	Project     string
	Component   string
	CVSS        string
	EPSS        string
	Date        string
	Total       string
	Phase       string
	Item        string
	AutoVerify  string
	Status      string
	Notes       string
	Perspective string
	Setting     string
	Description string

	// Misc
	Hours       string
	CriticalHigh string
}

// Japanese translations
var translationsJa = ReportTranslations{
	TitleExecutive:  "SBOMHub エグゼクティブレポート",
	TitleTechnical:  "SBOMHub テクニカルレポート",
	TitleCompliance: "SBOMHub コンプライアンスレポート",
	TitleDefault:    "SBOMHub セキュリティレポート",

	Summary:               "サマリー",
	VulnerabilityBreakdown: "脆弱性内訳",
	VulnerabilityDetailed: "脆弱性 詳細内訳",
	Compliance:            "コンプライアンス",
	TopRisks:              "TOP リスク",
	TopRisksDetailed:      "TOP リスク 詳細",
	SecurityMetrics:       "セキュリティメトリクス",
	VulnerabilityTrend:    "脆弱性トレンド (直近7日)",
	ComplianceScore:       "コンプライアンススコア",
	METIChecklist:         "経産省ガイドライン チェックリスト",
	VisualizationFramework: "SBOM可視化フレームワーク",
	VulnerabilitySummary:  "脆弱性サマリー (参考)",

	Projects:           "プロジェクト数",
	Components:         "コンポーネント数",
	TotalVulnerabilities: "脆弱性総数",
	ResolvedInPeriod:   "期間内解決数",
	AverageMTTR:        "平均MTTR",
	SLOAchievement:     "SLO達成率",
	Score:              "スコア",
	AchievementRate:    "達成率",
	TotalProgress:      "総合進捗",
	Period:             "期間",
	GeneratedAt:        "生成日時",

	Critical:      "Critical",
	High:          "High",
	Medium:        "Medium",
	Low:           "Low",
	CriticalCount: "Critical (緊急)",
	HighCount:     "High (重要)",
	MediumCount:   "Medium (警告)",
	LowCount:      "Low (注意)",

	Completed:    "完了",
	NotCompleted: "未完了",
	Auto:         "自動",

	VizSBOMAuthor:     "(a) SBOM作成主体 (Who)",
	VizDependency:     "(b) 依存関係 (What/Where)",
	VizGeneration:     "(c) 生成手段 (How)",
	VizDataFormat:     "(d) データ様式 (What)",
	VizUtilization:    "(f) 活用主体 (Who)",
	VizSBOMAuthorDesc: "SBOMを作成する主体",
	VizDependencyDesc: "SBOMに含める依存関係の範囲",
	VizGenerationDesc: "SBOMの生成方法",
	VizDataFormatDesc: "SBOMのデータ形式",
	VizUtilizationDesc: "SBOMを活用する主体",

	SheetSummary:      "サマリー",
	SheetTopRisks:     "TOPリスク",
	SheetTrend:        "トレンド",
	SheetChecklist:    "チェックリスト",
	SheetVisualization: "可視化フレームワーク",

	CVEID:       "CVE ID",
	Project:     "プロジェクト",
	Component:   "コンポーネント",
	CVSS:        "CVSS",
	EPSS:        "EPSS",
	Date:        "日付",
	Total:       "合計",
	Phase:       "フェーズ",
	Item:        "項目",
	AutoVerify:  "自動検証",
	Status:      "状態",
	Notes:       "備考",
	Perspective: "観点",
	Setting:     "設定値",
	Description: "説明",

	Hours:       "時間",
	CriticalHigh: "Critical/High",
}

// English translations
var translationsEn = ReportTranslations{
	TitleExecutive:  "SBOMHub Executive Report",
	TitleTechnical:  "SBOMHub Technical Report",
	TitleCompliance: "SBOMHub Compliance Report",
	TitleDefault:    "SBOMHub Security Report",

	Summary:               "Summary",
	VulnerabilityBreakdown: "Vulnerability Breakdown",
	VulnerabilityDetailed: "Vulnerability Details",
	Compliance:            "Compliance",
	TopRisks:              "Top Risks",
	TopRisksDetailed:      "Top Risks (Detailed)",
	SecurityMetrics:       "Security Metrics",
	VulnerabilityTrend:    "Vulnerability Trend (Last 7 Days)",
	ComplianceScore:       "Compliance Score",
	METIChecklist:         "METI Guidelines Checklist",
	VisualizationFramework: "SBOM Visualization Framework",
	VulnerabilitySummary:  "Vulnerability Summary (Reference)",

	Projects:           "Projects",
	Components:         "Components",
	TotalVulnerabilities: "Total Vulnerabilities",
	ResolvedInPeriod:   "Resolved in Period",
	AverageMTTR:        "Average MTTR",
	SLOAchievement:     "SLO Achievement",
	Score:              "Score",
	AchievementRate:    "Achievement Rate",
	TotalProgress:      "Total Progress",
	Period:             "Period",
	GeneratedAt:        "Generated At",

	Critical:      "Critical",
	High:          "High",
	Medium:        "Medium",
	Low:           "Low",
	CriticalCount: "Critical (Urgent)",
	HighCount:     "High (Important)",
	MediumCount:   "Medium (Warning)",
	LowCount:      "Low (Notice)",

	Completed:    "Completed",
	NotCompleted: "Not Completed",
	Auto:         "Auto",

	VizSBOMAuthor:     "(a) SBOM Author (Who)",
	VizDependency:     "(b) Dependencies (What/Where)",
	VizGeneration:     "(c) Generation Method (How)",
	VizDataFormat:     "(d) Data Format (What)",
	VizUtilization:    "(f) Utilization Actor (Who)",
	VizSBOMAuthorDesc: "Entity that creates the SBOM",
	VizDependencyDesc: "Scope of dependencies included in SBOM",
	VizGenerationDesc: "Method of SBOM generation",
	VizDataFormatDesc: "Data format of SBOM",
	VizUtilizationDesc: "Entity that utilizes the SBOM",

	SheetSummary:      "Summary",
	SheetTopRisks:     "Top Risks",
	SheetTrend:        "Trend",
	SheetChecklist:    "Checklist",
	SheetVisualization: "Visualization Framework",

	CVEID:       "CVE ID",
	Project:     "Project",
	Component:   "Component",
	CVSS:        "CVSS",
	EPSS:        "EPSS",
	Date:        "Date",
	Total:       "Total",
	Phase:       "Phase",
	Item:        "Item",
	AutoVerify:  "Auto Verify",
	Status:      "Status",
	Notes:       "Notes",
	Perspective: "Perspective",
	Setting:     "Setting",
	Description: "Description",

	Hours:       "hours",
	CriticalHigh: "Critical/High",
}

// GetTranslations returns translations for the given locale
func GetTranslations(locale string) *ReportTranslations {
	if locale == "en" {
		return &translationsEn
	}
	return &translationsJa // Default to Japanese
}
