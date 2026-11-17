package diff_summary

// M75 (Codex R1 High): POST /projects/:id/diff/summary runs under TenantTx,
// which rolls the request transaction back on any >=400 answer. A failed
// summary (provider error, truncated / filtered answer, parse failure)
// answers 500, so its llm_calls row and ai_failed audit row, written in the
// request transaction, were rolled back with it. Failure rows now go
// through Config.FailureTx in their own transaction, detached from the
// request one; success rows stay in the request transaction.

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service/llm"
)

type detachedKey struct{}

// fakeFailureTx stands in for triage.DBTxManager: it must be handed a ctx
// without the request tx, and marks the ctx it runs fn with.
type fakeFailureTx struct {
	t      *testing.T
	calls  int
	tenant uuid.UUID
}

func (f *fakeFailureTx) RunWrite(ctx context.Context, tenantID uuid.UUID, fn func(ctx context.Context) error) error {
	f.calls++
	f.tenant = tenantID
	if _, ok := database.TxFromContext(ctx); ok {
		f.t.Error("FailureTx got the request transaction; failure rows would roll back with it")
	}
	return fn(context.WithValue(ctx, detachedKey{}, true))
}

type ctxLLMCalls struct {
	rows     []repository.LLMCall
	detached []bool
}

func (f *ctxLLMCalls) Insert(ctx context.Context, c *repository.LLMCall) error {
	f.rows = append(f.rows, *c)
	f.detached = append(f.detached, ctx.Value(detachedKey{}) != nil)
	return nil
}

type ctxAudit struct {
	rows     []model.CreateAuditLogInput
	detached []bool
}

func (f *ctxAudit) Log(ctx context.Context, in *model.CreateAuditLogInput) error {
	f.rows = append(f.rows, *in)
	f.detached = append(f.detached, ctx.Value(detachedKey{}) != nil)
	return nil
}

func TestGenerate_FailureRowsAreWrittenOutsideTheRequestTx(t *testing.T) {
	cases := map[string]*fakeProvider{
		"truncated": {name: "openai", model: "m", resp: &llm.CompleteResponse{
			Content: `{"summary":"x","highlights":[],"confidence":0.9}`, FinishReason: "length"}},
		"provider error": {name: "openai", model: "m", err: errors.New("upstream 503")},
		"parse failure": {name: "openai", model: "m", resp: &llm.CompleteResponse{
			Content: `not json`, FinishReason: "stop"}},
	}
	for name, prov := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			calls, audit := &ctxLLMCalls{}, &ctxAudit{}
			ftx := &fakeFailureTx{t: t}
			svc := NewService(Config{Diff: f.diffSvc, Provider: prov, LLMCalls: calls, Audit: audit, FailureTx: ftx})
			ctx := database.WithTx(context.Background(), &sql.Tx{})
			if _, err := svc.Generate(ctx, Request{TenantID: f.tenantID, ProjectID: f.projectID, FromSbomID: f.fromID, ToSbomID: f.toID}); err == nil {
				t.Fatal("want an error")
			}
			if ftx.calls != 1 || ftx.tenant != f.tenantID {
				t.Fatalf("FailureTx calls=%d tenant=%v, want 1 / %v", ftx.calls, ftx.tenant, f.tenantID)
			}
			if len(calls.rows) != 1 || !calls.detached[0] || len(audit.rows) != 1 || !audit.detached[0] {
				t.Errorf("llm_calls detached=%v audit detached=%v, want both rows in the detached tx", calls.detached, audit.detached)
			}
		})
	}
}

func TestGenerate_SuccessRowsStayInTheRequestTx(t *testing.T) {
	f := newFixture(t)
	calls, audit := &ctxLLMCalls{}, &ctxAudit{}
	ftx := &fakeFailureTx{t: t}
	prov := &fakeProvider{name: "openai", model: "m", resp: &llm.CompleteResponse{
		Content: `{"summary":"ok","highlights":["a"],"confidence":0.9}`, FinishReason: "stop"}}
	svc := NewService(Config{Diff: f.diffSvc, Provider: prov, LLMCalls: calls, Audit: audit, FailureTx: ftx})
	if _, err := svc.Generate(context.Background(), Request{TenantID: f.tenantID, ProjectID: f.projectID, FromSbomID: f.fromID, ToSbomID: f.toID}); err != nil {
		t.Fatal(err)
	}
	if ftx.calls != 0 || len(calls.rows) != 1 || calls.detached[0] {
		t.Errorf("success: FailureTx calls=%d detached=%v, want 0 / request tx", ftx.calls, calls.detached)
	}
}

// Medium (Codex R1): the failure row keeps the whole partial answer, not
// only the 512-character preview.
func TestGenerate_FailureRowKeepsFullResponseBody(t *testing.T) {
	f := newFixture(t)
	long := `{"summary":"` + strings.Repeat("a", 2000)
	prov := &fakeProvider{name: "openai", model: "m", resp: &llm.CompleteResponse{Content: long, FinishReason: "length"}}
	svc := NewService(Config{Diff: f.diffSvc, Provider: prov, LLMCalls: f.llmCalls, Audit: f.audit})
	if _, err := svc.Generate(context.Background(), Request{TenantID: f.tenantID, ProjectID: f.projectID, FromSbomID: f.fromID, ToSbomID: f.toID}); err == nil {
		t.Fatal("want an error")
	}
	if got := f.llmCalls.rows[0].ResponseBody; got != long {
		t.Errorf("response_body len=%d, want the full %d-byte partial answer", len(got), len(long))
	}
}

// ctxCheckFailureTx records whether the ctx handed to FailureTx was live.
type ctxCheckFailureTx struct {
	errAtRun    error
	hasDeadline bool
}

func (f *ctxCheckFailureTx) RunWrite(ctx context.Context, _ uuid.UUID, fn func(ctx context.Context) error) error {
	f.errAtRun = ctx.Err()
	_, f.hasDeadline = ctx.Deadline()
	return fn(ctx)
}

// Codex integration R1 Medium: a client disconnect or upstream deadline
// while the LLM runs cancels the request ctx; the failure rows must still
// commit, so FailureTx gets a ctx detached from that cancellation (with its
// own bounded deadline), not the dead request ctx.
func TestPersistFailure_DetachesFromRequestCancellation(t *testing.T) {
	ftx := &ctxCheckFailureTx{}
	f := newFixture(t)
	svc := NewService(Config{Diff: f.diffSvc, Provider: &fakeProvider{name: "openai", model: "m"}, LLMCalls: f.llmCalls, Audit: f.audit, FailureTx: ftx})
	ctx, cancel := context.WithCancel(database.WithTx(context.Background(), &sql.Tx{}))
	cancel()
	ran := false
	if err := svc.persistFailure(ctx, uuid.New(), func(ctx context.Context) error { ran = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if !ran || ftx.errAtRun != nil {
		t.Fatalf("ran=%v ctx.Err()=%v at FailureTx, want a live ctx", ran, ftx.errAtRun)
	}
	if !ftx.hasDeadline {
		t.Error("detached ctx has no deadline; the failure write must stay bounded")
	}
}
