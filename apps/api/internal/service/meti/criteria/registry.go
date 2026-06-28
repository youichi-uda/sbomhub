package criteria

// registry.go — single dispatch surface that maps a catalog criterion
// id (e.g. "meti.env_setup.07") onto its concrete evaluator function.
//
// Why a registry instead of a switch in service/meti/evaluator.go:
//   - keeps every per-criterion file the only place that names its
//     own id (no second source of truth to drift);
//   - lets tests assert "every catalog id is registered" without
//     reflecting over a switch statement;
//   - the M3-4 handler can look up a single criterion (e.g. for
//     re-evaluate-one endpoints) without standing up the full
//     evaluator orchestration.

// Registry is the canonical criterion_id -> Func dispatch table.
// IDs are stable (catalog.yaml is sealed at build time via go:embed
// — see meti/catalog.go header). Adding a criterion to the catalog
// without adding a Registry entry is a build-time error caught by
// TestRegistry_CoversCatalog in evaluator_test.go.
var Registry = map[string]Func{
	// env_setup (11; +3 in M8-1 / #62) -------------------------------------
	"meti.env_setup.01": EvaluateEnvSetup01,
	"meti.env_setup.02": EvaluateEnvSetup02,
	"meti.env_setup.03": EvaluateEnvSetup03,
	"meti.env_setup.04": EvaluateEnvSetup04,
	"meti.env_setup.05": EvaluateEnvSetup05,
	"meti.env_setup.06": EvaluateEnvSetup06,
	"meti.env_setup.07": EvaluateEnvSetup07,
	"meti.env_setup.08": EvaluateEnvSetup08,
	"meti.env_setup.09": EvaluateEnvSetup09, // M8-1: 4.1.4 構成図可視化
	"meti.env_setup.10": EvaluateEnvSetup10, // M8-1: 4.4 ツール導入・設定
	"meti.env_setup.11": EvaluateEnvSetup11, // M8-1: 4.5 ツール学習

	// sbom_creation (10; +1 in M8-1 / #62) ---------------------------------
	"meti.sbom_creation.01": EvaluateSBOMCreation01,
	"meti.sbom_creation.02": EvaluateSBOMCreation02,
	"meti.sbom_creation.03": EvaluateSBOMCreation03,
	"meti.sbom_creation.04": EvaluateSBOMCreation04,
	"meti.sbom_creation.05": EvaluateSBOMCreation05,
	"meti.sbom_creation.06": EvaluateSBOMCreation06,
	"meti.sbom_creation.07": EvaluateSBOMCreation07,
	"meti.sbom_creation.08": EvaluateSBOMCreation08,
	"meti.sbom_creation.09": EvaluateSBOMCreation09,
	"meti.sbom_creation.10": EvaluateSBOMCreation10, // M8-1: 5.3 共有 個別運用

	// sbom_operation (11; +1 in M8-1 / #62) --------------------------------
	"meti.sbom_operation.01": EvaluateSBOMOperation01,
	"meti.sbom_operation.02": EvaluateSBOMOperation02,
	"meti.sbom_operation.03": EvaluateSBOMOperation03,
	"meti.sbom_operation.04": EvaluateSBOMOperation04,
	"meti.sbom_operation.05": EvaluateSBOMOperation05,
	"meti.sbom_operation.06": EvaluateSBOMOperation06,
	"meti.sbom_operation.07": EvaluateSBOMOperation07,
	"meti.sbom_operation.08": EvaluateSBOMOperation08,
	"meti.sbom_operation.09": EvaluateSBOMOperation09,
	"meti.sbom_operation.10": EvaluateSBOMOperation10,
	"meti.sbom_operation.11": EvaluateSBOMOperation11, // M8-1: 6.3 提供期間 個別運用
}

// Lookup returns the evaluator function for id, or (nil, false) when
// id is not in the registry. The handler layer uses this for the
// re-evaluate-one path so an unknown id resolves to 404 rather than a
// 500.
func Lookup(id string) (Func, bool) {
	f, ok := Registry[id]
	return f, ok
}
