//go:build integration

// Package cra — M75: the CRA runner, wired as production wires it (the real
// *repository.VulnerabilityRepository as VulnerabilityCVE, nothing else),
// prints the stored cvss_score and cvss_version in the draft's CVSS line.
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 -run 'M75CRA' ./internal/service/cra
package cra

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service/llm"
)

func TestM75CRARunner_DraftPrintsStoredCVSSScoreAndVersion(t *testing.T) {
	appURL, migURL := m47CRAEnv(t)
	migDB := m47CRAOpen(t, migURL)
	appDB := m47CRAOpen(t, appURL)

	cases := []struct {
		name    string
		score   any // nil = NULL
		version any
		lang    Lang
		want    string
		notWant string
	}{
		{"v3.1 en", 9.8, "3.1", LangEN, "- **CVSS score**: 9.8 (CVSS v3.1)\n", ""},
		{"v4.0 ja", 8.7, "4.0", LangJA, "- **CVSS スコア**: 8.7 (CVSS v4.0)\n", ""},
		{"version NULL", 7.5, nil, LangEN, "- **CVSS score**: 7.5\n", "CVSS v"},
		{"score NULL", nil, "3.1", LangEN, "", "CVSS score"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := m47CRASeed(t, migDB, "m75")
			if _, err := migDB.Exec(`UPDATE vulnerabilities SET cvss_score = $2, cvss_version = $3 WHERE id = $1`,
				f.linkedVuln, c.score, c.version); err != nil {
				t.Fatalf("set cvss: %v", err)
			}
			h := newTestHarness(t)
			h.sourceDraft.TenantID = f.tenantID
			h.sourceDraft.ProjectID = f.projectID
			h.sourceDraft.VulnerabilityID = f.linkedVuln
			h.sourceDraft.CVEID = f.linkedCVE
			h.drafts.byID[h.sourceDraft.ID] = h.sourceDraft

			runner := NewRunner(RunnerConfig{
				VEXDrafts:           h.drafts,
				AdvisoryExcerpts:    h.advisories,
				ReachabilityResults: h.reach,
				CRAReports:          h.craReports,
				LLMCalls:            h.llmCalls,
				VulnerabilityCVE:    repository.NewVulnerabilityRepository(appDB),
				Audit:               h.audit,
				Provider:            h.provider,
				GeneratedBy:         "SBOMHub/test",
			})
			in := m47CRARunInput(h, f, f.linkedVuln, f.linkedCVE)
			in.Lang = c.lang
			var runErr error
			m47CRARunTx(t, appDB, f.tenantID, func(ctx context.Context) {
				_, runErr = runner.Run(ctx, in)
			})
			if runErr != nil {
				t.Fatalf("Run: %v", runErr)
			}
			if len(h.craReports.inserted) != 1 {
				t.Fatalf("cra_reports = %d, want 1", len(h.craReports.inserted))
			}
			draft := h.craReports.inserted[0].DraftText
			if c.want != "" && !strings.Contains(draft, c.want) {
				t.Errorf("want %q in draft:\n%s", c.want, draft)
			}
			if c.notWant != "" && strings.Contains(draft, c.notWant) {
				t.Errorf("draft contains %q:\n%s", c.notWant, draft)
			}
		})
	}
}

// The CVSS read is scoped like the CVE re-resolve: another project's
// vulnerability is sql.ErrNoRows from the repository.
func TestM75CRARepository_GetCVSSByIDInProjectIsScoped(t *testing.T) {
	appURL, migURL := m47CRAEnv(t)
	migDB := m47CRAOpen(t, migURL)
	appDB := m47CRAOpen(t, appURL)

	f := m47CRASeed(t, migDB, "m75scope")
	if _, err := migDB.Exec(`UPDATE vulnerabilities SET cvss_version = '3.1' WHERE id = $1`, f.linkedVuln); err != nil {
		t.Fatal(err)
	}
	repo := repository.NewVulnerabilityRepository(appDB)
	m47CRARunTx(t, appDB, f.tenantID, func(ctx context.Context) {
		score, version, err := repo.GetCVSSByIDInProject(ctx, f.tenantID, f.projectID, f.linkedVuln)
		if err != nil || score == nil || *score != 7.5 || version == nil || *version != "3.1" {
			t.Errorf("linked: score=%v version=%v err=%v, want 7.5 / 3.1", score, version, err)
		}
		if _, _, err := repo.GetCVSSByIDInProject(ctx, f.tenantID, f.projectID, f.unlinkedVuln); !errors.Is(err, sql.ErrNoRows) {
			t.Errorf("unlinked vulnerability: err = %v, want sql.ErrNoRows", err)
		}
	})
}

// A CRA answer the provider reports as cut at its token limit leaves an
// llm_calls row (real repository, app role, RLS) holding the provider's
// finish reason, the error message and the partial response — and no draft.
func TestM75CRARunner_TruncatedAnswerRecordedInLLMCalls(t *testing.T) {
	appURL, migURL := m47CRAEnv(t)
	migDB := m47CRAOpen(t, migURL)
	appDB := m47CRAOpen(t, appURL)

	f := m47CRASeed(t, migDB, "m75trunc")
	h := newTestHarness(t)
	h.sourceDraft.TenantID = f.tenantID
	h.sourceDraft.ProjectID = f.projectID
	h.sourceDraft.VulnerabilityID = f.linkedVuln
	h.sourceDraft.CVEID = f.linkedCVE
	h.drafts.byID[h.sourceDraft.ID] = h.sourceDraft
	content := canonicalLLMResponse(t)
	h.provider.resp = &llm.CompleteResponse{Content: content, InputTokens: 5, OutputTokens: 4096, FinishReason: "max_tokens"}

	runner := NewRunner(RunnerConfig{
		VEXDrafts:           h.drafts,
		AdvisoryExcerpts:    h.advisories,
		ReachabilityResults: h.reach,
		CRAReports:          h.craReports,
		LLMCalls:            repository.NewLLMCallsRepository(appDB),
		VulnerabilityCVE:    repository.NewVulnerabilityRepository(appDB),
		Audit:               h.audit,
		Provider:            h.provider,
		GeneratedBy:         "SBOMHub/test",
	})
	m47CRARunTx(t, appDB, f.tenantID, func(ctx context.Context) {
		_, runErr := runner.Run(ctx, m47CRARunInput(h, f, f.linkedVuln, f.linkedCVE))
		if !errors.Is(runErr, llm.ErrTruncatedResponse) {
			t.Fatalf("Run err = %v, want ErrTruncatedResponse", runErr)
		}
		tx, _ := database.TxFromContext(ctx)
		var finish, errMsg, body sql.NullString
		var out int
		if err := tx.QueryRowContext(ctx, `
			SELECT finish_reason, error_message, response_body, output_tokens
			FROM llm_calls WHERE tenant_id = $1 AND purpose = 'cra_draft'`, f.tenantID).
			Scan(&finish, &errMsg, &body, &out); err != nil {
			t.Fatalf("read llm_calls: %v", err)
		}
		if finish.String != "max_tokens" || !strings.Contains(errMsg.String, "token limit") || out != 4096 {
			t.Errorf("llm_calls finish=%q error=%q output_tokens=%d", finish.String, errMsg.String, out)
		}
		if body.Valid && body.String != content {
			t.Errorf("response_body = %q, want the partial answer", body.String)
		}
	})
	if n := len(h.craReports.inserted); n != 0 {
		t.Errorf("cra_reports written for a truncated answer = %d, want 0", n)
	}
}
