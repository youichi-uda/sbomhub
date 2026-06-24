package llm

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestDisabledProvider_Identifiers(t *testing.T) {
	p := &DisabledProvider{Reason: "test"}
	if p.Name() != "disabled" {
		t.Errorf("Name() = %q, want %q", p.Name(), "disabled")
	}
	if p.Model() != "" {
		t.Errorf("Model() = %q, want empty", p.Model())
	}
	if cap := p.Capabilities(); cap != (Capabilities{}) {
		t.Errorf("Capabilities() = %+v, want zero", cap)
	}
}

func TestDisabledProvider_CompleteReturnsDisabledError(t *testing.T) {
	p := &DisabledProvider{Reason: "BYOK not configured"}
	_, err := p.Complete(context.Background(), CompleteRequest{})
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	var de *DisabledError
	if !errors.As(err, &de) {
		t.Fatalf("error type = %T, want *DisabledError", err)
	}
	if de.HTTPStatus() != 503 {
		t.Errorf("HTTPStatus() = %d, want 503", de.HTTPStatus())
	}
	if !strings.Contains(de.Error(), "BYOK not configured") {
		t.Errorf("Error() = %q, want substring %q", de.Error(), "BYOK not configured")
	}
}

func TestDisabledProvider_EmbedReturnsDisabledError(t *testing.T) {
	p := &DisabledProvider{Reason: "test"}
	_, err := p.Embed(context.Background(), EmbedRequest{})
	if !IsDisabled(err) {
		t.Errorf("IsDisabled(err) = false, want true (err=%v)", err)
	}
}

func TestIsDisabled(t *testing.T) {
	if IsDisabled(nil) {
		t.Error("IsDisabled(nil) = true, want false")
	}
	if IsDisabled(errors.New("plain")) {
		t.Error("IsDisabled(plain) = true, want false")
	}
	if !IsDisabled(&DisabledError{Reason: "x"}) {
		t.Error("IsDisabled(&DisabledError) = false, want true")
	}
}

func TestDisabledError_EmptyReason(t *testing.T) {
	e := &DisabledError{}
	if !strings.Contains(e.Error(), "disabled") {
		t.Errorf("Error() = %q, want substring %q", e.Error(), "disabled")
	}
}
