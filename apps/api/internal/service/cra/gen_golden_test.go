//go:build genGolden

// This file is only compiled with `-tags genGolden` to regenerate the
// golden fixtures under testdata/golden/. It is not part of the normal
// test suite — see templates_test.go for the actual golden-file
// comparison.
//
// Run:
//
//   go test -tags genGolden ./internal/service/cra/ -run TestGenerateGoldens
//
// Then `git diff testdata/golden/` to review the regenerated fixtures.

package cra

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateGoldens(t *testing.T) {
	data := fixedGoldenInput()
	for _, rt := range SupportedReportTypes() {
		for _, lang := range SupportedLangs() {
			out, err := Render(rt, lang, data)
			if err != nil {
				t.Fatalf("render %s/%s: %v", rt, lang, err)
			}
			path := filepath.Join("testdata", "golden", string(rt)+"_"+string(lang)+".md")
			if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
				t.Fatalf("write %s: %v", path, err)
			}
			t.Logf("wrote %s (%d bytes)", path, len(out))
		}
	}
}
