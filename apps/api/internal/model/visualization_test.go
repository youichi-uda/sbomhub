package model

import (
	"testing"
)

func TestGetVisualizationOptions(t *testing.T) {
	options := GetVisualizationOptions()

	// Check SBOMAuthorScope options
	if len(options.SBOMAuthorScope) != 3 {
		t.Errorf("Expected 3 SBOMAuthorScope options, got %d", len(options.SBOMAuthorScope))
	}

	// Check DependencyScope options
	if len(options.DependencyScope) != 3 {
		t.Errorf("Expected 3 DependencyScope options, got %d", len(options.DependencyScope))
	}

	// Check GenerationMethod options
	if len(options.GenerationMethod) != 3 {
		t.Errorf("Expected 3 GenerationMethod options, got %d", len(options.GenerationMethod))
	}

	// Check DataFormat options
	if len(options.DataFormat) != 3 {
		t.Errorf("Expected 3 DataFormat options, got %d", len(options.DataFormat))
	}

	// Check UtilizationScope options
	if len(options.UtilizationScope) != 5 {
		t.Errorf("Expected 5 UtilizationScope options, got %d", len(options.UtilizationScope))
	}

	// Check UtilizationActor options
	if len(options.UtilizationActor) != 5 {
		t.Errorf("Expected 5 UtilizationActor options, got %d", len(options.UtilizationActor))
	}

	// Verify all options have both English and Japanese labels
	allOptions := [][]VisualizationOption{
		options.SBOMAuthorScope,
		options.DependencyScope,
		options.GenerationMethod,
		options.DataFormat,
		options.UtilizationScope,
		options.UtilizationActor,
	}

	for i, opts := range allOptions {
		for j, opt := range opts {
			if opt.Value == "" {
				t.Errorf("Option %d-%d has empty value", i, j)
			}
			if opt.Label == "" {
				t.Errorf("Option %d-%d has empty English label", i, j)
			}
			if opt.LabelJa == "" {
				t.Errorf("Option %d-%d has empty Japanese label", i, j)
			}
		}
	}
}
