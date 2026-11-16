package llm

// M74 — an Ollama answer that did not end with the final done:true message
// is incomplete, and must never be recorded (or consumed) as a finished
// "stop" draft.
//
//   - Transport-level truncation (the connection closes before the declared
//     Content-Length, a chunked body is cut, an EOF-delimited body ends
//     mid-JSON, or an NDJSON stream arrives although stream:false was sent)
//     already fails the call with an error and no response, exactly like
//     the other providers' truncated bodies. Pinned here.
//   - A well-formed envelope whose `done` is false or absent is answered
//     with an error wrapping ErrIncompleteResponse AND a response carrying
//     the partial content with FinishReason "incomplete", so the callers
//     (triage / CRA / diff summary all check the error first) fail the run
//     instead of saving a truncated draft, while the llm_calls row still
//     records what came back and why it was rejected.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func ollamaReq() CompleteRequest {
	return CompleteRequest{Messages: []Message{{Role: RoleUser, Content: "hi"}}}
}

func TestOllama_Complete_NotDoneIsIncompleteError(t *testing.T) {
	cases := []struct{ name, body string }{
		{"done false", `{"model":"m","message":{"role":"assistant","content":"partial"},"done":false}`},
		{"done absent", `{"model":"m","message":{"role":"assistant","content":"partial"}}`},
		{"done false with reason", `{"model":"m","message":{"role":"assistant","content":"partial"},"done":false,"done_reason":"stop"}`},
		{"wrong-type reason with done false", `{"model":"m","message":{"role":"assistant","content":"partial"},"done":false,"done_reason":3}`},
		{"done null", `{"model":"m","message":{"role":"assistant","content":"partial"},"done":null}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := m71RawServer(t, tc.body)
			out, err := NewOllama(srv.URL, "m").Complete(context.Background(), ollamaReq())
			if !errors.Is(err, ErrIncompleteResponse) {
				t.Fatalf("err = %v, want ErrIncompleteResponse", err)
			}
			if out == nil {
				t.Fatal("response must still be returned for the audit row")
			}
			if out.FinishReason != FinishReasonIncomplete {
				t.Errorf("FinishReason = %q, want %q", out.FinishReason, FinishReasonIncomplete)
			}
			if out.Content != "partial" || len(out.RawResponse) == 0 {
				t.Errorf("partial content / raw body not kept: %+v", out)
			}
		})
	}
}

// rawConnServer writes resp verbatim on the hijacked connection and closes
// it, simulating a server or proxy that dies mid-answer.
func rawConnServer(t *testing.T, resp string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Error("hijack unsupported")
			return
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer func(c net.Conn) { _ = c.Close() }(conn)
		_, _ = buf.WriteString(resp)
		_ = buf.Flush()
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestOllama_Complete_TruncatedTransportIsError(t *testing.T) {
	full := `{"model":"m","message":{"role":"assistant","content":"partial answer"},"done":true,"done_reason":"stop"}`
	half := full[:40]
	ndjson := `{"model":"m","message":{"role":"assistant","content":"par"},"done":false}` + "\n" +
		`{"model":"m","message":{"role":"assistant","content":"tial"},"done":false}` + "\n"
	cases := []struct{ name, resp string }{
		{"content-length cut", fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(full), half)},
		{"chunked cut", fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n", len(half), half)},
		{"eof-delimited cut", "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n" + half},
		{"ndjson stream without done", "HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nConnection: close\r\n\r\n" + ndjson},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := rawConnServer(t, tc.resp)
			out, err := NewOllama(srv.URL, "m").Complete(context.Background(), ollamaReq())
			if err == nil {
				t.Fatalf("truncated answer accepted: %+v", out)
			}
			if out != nil && out.FinishReason == "stop" {
				t.Fatalf("truncated answer recorded as stop: %+v", out)
			}
		})
	}
}

// The control case for the harness above: the same raw writer with the
// complete body succeeds as "stop".
func TestOllama_Complete_RawConnComplete(t *testing.T) {
	full := `{"model":"m","message":{"role":"assistant","content":"ok"},"done":true,"done_reason":"stop"}`
	srv := rawConnServer(t, fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(full), full))
	out, err := NewOllama(srv.URL, "m").Complete(context.Background(), ollamaReq())
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if out.FinishReason != "stop" || out.Content != "ok" {
		t.Fatalf("got %+v", out)
	}
}
