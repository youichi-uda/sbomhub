package model

import (
	"testing"
)

func TestGetAllChecklistItems(t *testing.T) {
	items := GetAllChecklistItems()

	// Should have exactly 18 items
	if len(items) != 18 {
		t.Errorf("Expected 18 checklist items, got %d", len(items))
	}

	// Count items by phase
	phaseCounts := map[ChecklistPhase]int{
		PhaseSetup:     0,
		PhaseCreation:  0,
		PhaseOperation: 0,
	}

	for _, item := range items {
		phaseCounts[item.Phase]++
	}

	// Phase 1: 環境構築・体制整備 should have 7 items
	if phaseCounts[PhaseSetup] != 7 {
		t.Errorf("Expected 7 setup items, got %d", phaseCounts[PhaseSetup])
	}

	// Phase 2: SBOM作成・共有 should have 6 items
	if phaseCounts[PhaseCreation] != 6 {
		t.Errorf("Expected 6 creation items, got %d", phaseCounts[PhaseCreation])
	}

	// Phase 3: SBOM運用・管理 should have 5 items
	if phaseCounts[PhaseOperation] != 5 {
		t.Errorf("Expected 5 operation items, got %d", phaseCounts[PhaseOperation])
	}

	// Check auto-verify items
	autoVerifyItems := []string{
		"setup_07",   // SBOMツールを選定
		"create_01",  // コンポーネントを解析
		"create_05",  // 要件を満たすSBOMを作成
		"create_06",  // SBOMを共有
		"operate_01", // 脆弱性対応を実施
		"operate_02", // 脆弱性情報を特定
		"operate_03", // 脆弱性を優先付け
		"operate_04", // ライセンス違反を確認
		"operate_05", // SBOM情報を適切に管理
	}

	itemMap := make(map[string]ChecklistItem)
	for _, item := range items {
		itemMap[item.ID] = item
	}

	for _, id := range autoVerifyItems {
		item, ok := itemMap[id]
		if !ok {
			t.Errorf("Expected item %s to exist", id)
			continue
		}
		if !item.AutoVerify {
			t.Errorf("Expected item %s to have AutoVerify=true", id)
		}
	}
}

func TestGetChecklistPhaseLabels(t *testing.T) {
	labels := GetChecklistPhaseLabels()

	if len(labels) != 3 {
		t.Errorf("Expected 3 phase labels, got %d", len(labels))
	}

	// Check setup phase labels
	if labels[PhaseSetup].LabelJa != "環境構築・体制整備" {
		t.Errorf("Unexpected setup phase Japanese label: %s", labels[PhaseSetup].LabelJa)
	}

	// Check creation phase labels
	if labels[PhaseCreation].LabelJa != "SBOM作成・共有" {
		t.Errorf("Unexpected creation phase Japanese label: %s", labels[PhaseCreation].LabelJa)
	}

	// Check operation phase labels
	if labels[PhaseOperation].LabelJa != "SBOM運用・管理" {
		t.Errorf("Unexpected operation phase Japanese label: %s", labels[PhaseOperation].LabelJa)
	}
}
