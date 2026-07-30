package diff_webhook

import "github.com/sbomhub/sbomhub/internal/egress"

// testEgress is the diff_webhook destination policy with internal addresses
// permitted.
//
// These tests point the service at httptest.Server instances, which bind
// 127.0.0.1 — a destination the production policy refuses. Everything else
// about the policy is kept identical (notably MaxRedirects=0, which several
// tests assert on), so what is relaxed here is exactly the address rule and
// nothing else.
func testEgress() *egress.Guard {
	return egress.NewSet(egress.Settings{AllowPrivate: true}).DiffWebhook
}
