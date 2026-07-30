package service

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/egress"
	"github.com/sbomhub/sbomhub/internal/model"
)

// notifServerOn starts an httptest server on a specific loopback address, so a
// test can tell "the host the policy permits" apart from "the host it must not
// reach". httptest.NewServer puts everything on 127.0.0.1.
func notifServerOn(t *testing.T, ip string, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Skipf("cannot bind %s: %v", ip, err)
	}
	srv := &httptest.Server{
		Listener: ln,
		Config:   &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second},
	}
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

// TestNotificationWebhook_DirectLoopbackURL is the M50 reproduction for the
// Slack / Discord notification sink.
//
// Measured before the fix (2026-07-30, go1.26.4): notification_settings
// .slack_webhook_url / .discord_webhook_url were written straight through from
// the API body — the handler binds and calls the service, and neither validated
// the URL at all — and NotificationService's http.Client was a bare
// &http.Client{Timeout: 10s}. A webhook URL naming a loopback address was
// delivered to, and the listener recorded 1 hit.
func TestNotificationWebhook_DirectLoopbackURL(t *testing.T) {
	var hits atomic.Int32
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer internal.Close()

	svc := NewNotificationService(nil, nil, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := svc.sendWebhook(ctx, internal.URL, map[string]string{"text": "x"},
		model.NotificationChannelSlack, uuid.New(), uuid.New())
	if err == nil {
		t.Error("expected the guarded client to refuse a loopback webhook URL")
	}
	if !errors.Is(err, egress.ErrBlockedDestination) {
		t.Errorf("expected ErrBlockedDestination, got %v", err)
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("loopback listener reached %d time(s)", n)
	}
}

// TestNotificationWebhook_RedirectDoesNotReachLoopback is the redirect half of
// the same gap.
//
// Measured before the fix: the service's http.Client had no CheckRedirect, so a
// 307 from a routable host retargeted the POST — method and body preserved —
// at loopback, and the loopback listener recorded 1 hit.
func TestNotificationWebhook_RedirectDoesNotReachLoopback(t *testing.T) {
	var internalHits atomic.Int32
	internal := notifServerOn(t, "127.0.0.1", func(w http.ResponseWriter, _ *http.Request) {
		internalHits.Add(1)
		w.WriteHeader(http.StatusOK)
	})

	var redirectorHits atomic.Int32
	redirector := notifServerOn(t, "127.0.0.2", func(w http.ResponseWriter, r *http.Request) {
		redirectorHits.Add(1)
		http.Redirect(w, r, internal.URL, http.StatusTemporaryRedirect)
	})

	// Exempt only the first hop, standing in for "a routable host the tenant is
	// allowed to configure".
	guard := egress.NewSet(egress.Settings{
		PrivateCIDRExemptions: []netip.Prefix{netip.MustParsePrefix("127.0.0.2/32")},
	}).NotificationWebhook

	svc := NewNotificationService(nil, nil, nil, guard)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_ = svc.sendWebhook(ctx, redirector.URL, map[string]string{"text": "x"},
		model.NotificationChannelSlack, uuid.New(), uuid.New())

	if redirectorHits.Load() == 0 {
		t.Fatal("the permitted first hop was never reached; the test is not exercising a redirect")
	}
	if n := internalHits.Load(); n != 0 {
		t.Errorf("redirect target %s was reached %d time(s)", internal.URL, n)
	}
}

// TestNotificationWebhook_MetadataRefusedEvenWithOptIn keeps the two policy
// tiers distinct for this sink: a self-hosted operator who opens internal
// destinations still does not get the cloud metadata service.
func TestNotificationWebhook_MetadataRefusedEvenWithOptIn(t *testing.T) {
	svc := NewNotificationService(nil, nil, nil,
		egress.NewSet(egress.Settings{AllowPrivate: true}).NotificationWebhook)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := svc.sendWebhook(ctx, "http://169.254.169.254/latest/meta-data/", map[string]string{"text": "x"},
		model.NotificationChannelSlack, uuid.New(), uuid.New())
	if !errors.Is(err, egress.ErrBlockedDestination) {
		t.Errorf("expected ErrBlockedDestination for the metadata address, got %v", err)
	}
}

// TestNotificationWebhook_AllowPrivateOptInDelivers is the other side of the
// same coin: the self-hosted opt-in has to actually restore delivery to an
// internal receiver, or the escape hatch documented in docs/UPGRADE.md is not
// one.
func TestNotificationWebhook_AllowPrivateOptInDelivers(t *testing.T) {
	var hits atomic.Int32
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer internal.Close()

	svc := NewNotificationService(nil, nil, nil,
		egress.NewSet(egress.Settings{AllowPrivate: true}).NotificationWebhook)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := svc.sendWebhook(ctx, internal.URL, map[string]string{"text": "x"},
		model.NotificationChannelSlack, uuid.New(), uuid.New()); err != nil {
		t.Fatalf("opt-in should permit an internal webhook receiver: %v", err)
	}
	if n := hits.Load(); n != 1 {
		t.Errorf("hits = %d, want 1", n)
	}
}
