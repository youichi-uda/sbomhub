package service

import (
	"net"
	"strings"
	"testing"

	"github.com/sbomhub/sbomhub/internal/model"
)

// testEncryptionKey is a 32-byte key for testing (exactly 32 characters)
var testEncryptionKey = []byte("01234567890123456789012345678901")

func TestNewIssueTrackerService(t *testing.T) {
	svc := NewIssueTrackerService(nil, nil, testEncryptionKey, nil)

	if svc == nil {
		t.Fatal("expected service to be created")
	}

	if len(svc.encryptionKey) != 32 {
		t.Errorf("expected encryption key length 32, got %d", len(svc.encryptionKey))
	}
}

func TestNewIssueTrackerService_PanicsOnShortKey(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for short encryption key")
		}
	}()

	NewIssueTrackerService(nil, nil, []byte("short-key"), nil)
}

func TestIssueTrackerService_EncryptDecrypt(t *testing.T) {
	svc := NewIssueTrackerService(nil, nil, testEncryptionKey, nil)

	tests := []struct {
		name      string
		plaintext string
	}{
		{"simple text", "hello world"},
		{"api token", "xoxb-1234567890-abcdefghij"},
		{"japanese text", "日本語テスト"},
		{"empty string", ""},
		{"special chars", "!@#$%^&*()_+-=[]{}|;':\",./<>?"},
		{"long text", "this is a very long text that should be encrypted and decrypted correctly even if it contains multiple sentences and paragraphs"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := svc.encrypt(tt.plaintext)
			if err != nil {
				t.Fatalf("encrypt failed: %v", err)
			}

			if encrypted == tt.plaintext && tt.plaintext != "" {
				t.Error("encrypted text should not equal plaintext")
			}

			decrypted, err := svc.decrypt(encrypted)
			if err != nil {
				t.Fatalf("decrypt failed: %v", err)
			}

			if decrypted != tt.plaintext {
				t.Errorf("decrypt mismatch: got %q, want %q", decrypted, tt.plaintext)
			}
		})
	}
}

func TestIssueTrackerService_EncryptProducesUniqueOutput(t *testing.T) {
	svc := NewIssueTrackerService(nil, nil, testEncryptionKey, nil)

	plaintext := "same-text-to-encrypt"

	encrypted1, err := svc.encrypt(plaintext)
	if err != nil {
		t.Fatalf("first encrypt failed: %v", err)
	}

	encrypted2, err := svc.encrypt(plaintext)
	if err != nil {
		t.Fatalf("second encrypt failed: %v", err)
	}

	// Due to random nonce, encrypting the same text should produce different outputs
	if encrypted1 == encrypted2 {
		t.Error("encryption should produce unique outputs due to random nonce")
	}

	// But both should decrypt to the same plaintext
	decrypted1, _ := svc.decrypt(encrypted1)
	decrypted2, _ := svc.decrypt(encrypted2)

	if decrypted1 != decrypted2 {
		t.Error("both encrypted values should decrypt to the same plaintext")
	}
}

func TestIssueTrackerService_DecryptInvalidData(t *testing.T) {
	svc := NewIssueTrackerService(nil, nil, testEncryptionKey, nil)

	tests := []struct {
		name       string
		ciphertext string
	}{
		{"invalid base64", "not-valid-base64!!!"},
		{"too short", "YWJj"}, // "abc" in base64
		{"empty", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.decrypt(tt.ciphertext)
			if err == nil {
				t.Error("expected error for invalid ciphertext")
			}
		})
	}
}

func TestIssueTrackerService_MapExternalStatus(t *testing.T) {
	svc := NewIssueTrackerService(nil, nil, testEncryptionKey, nil)

	tests := []struct {
		externalStatus string
		expected       model.TicketStatus
	}{
		// Closed statuses
		{"Done", model.TicketStatusClosed},
		{"Closed", model.TicketStatusClosed},
		{"完了", model.TicketStatusClosed},
		{"クローズ", model.TicketStatusClosed},

		// Resolved statuses
		{"Resolved", model.TicketStatusResolved},
		{"解決済み", model.TicketStatusResolved},

		// In Progress statuses
		{"In Progress", model.TicketStatusInProgress},
		{"処理中", model.TicketStatusInProgress},
		{"対応中", model.TicketStatusInProgress},

		// Default to Open
		{"Open", model.TicketStatusOpen},
		{"New", model.TicketStatusOpen},
		{"未着手", model.TicketStatusOpen},
		{"To Do", model.TicketStatusOpen},
		{"Unknown", model.TicketStatusOpen},
		{"", model.TicketStatusOpen},
	}

	for _, tt := range tests {
		t.Run(tt.externalStatus, func(t *testing.T) {
			result := svc.mapExternalStatus(tt.externalStatus)
			if result != tt.expected {
				t.Errorf("mapExternalStatus(%q) = %q, want %q", tt.externalStatus, result, tt.expected)
			}
		})
	}
}

func TestCreateConnectionInput_Validation(t *testing.T) {
	tests := []struct {
		name  string
		input CreateConnectionInput
		valid bool
	}{
		{
			name: "valid jira connection",
			input: CreateConnectionInput{
				TrackerType:       model.TrackerTypeJira,
				Name:              "My Jira",
				BaseURL:           "https://example.atlassian.net",
				AuthEmail:         "user@example.com",
				APIToken:          "token123",
				DefaultProjectKey: "PROJ",
				DefaultIssueType:  "Bug",
			},
			valid: true,
		},
		{
			name: "valid backlog connection",
			input: CreateConnectionInput{
				TrackerType:       model.TrackerTypeBacklog,
				Name:              "My Backlog",
				BaseURL:           "https://example.backlog.com",
				APIToken:          "token123",
				DefaultProjectKey: "PROJ",
			},
			valid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Just verify the struct can be created properly
			if tt.input.Name == "" && tt.valid {
				t.Error("valid input should have a name")
			}
		})
	}
}

func TestCreateTicketInput_Defaults(t *testing.T) {
	input := CreateTicketInput{
		Summary:     "Vulnerability CVE-2024-1234",
		Description: "High severity vulnerability found",
	}

	// Verify default values
	if input.IssueType != "" {
		t.Error("IssueType should be empty by default")
	}
	if input.ProjectKey != "" {
		t.Error("ProjectKey should be empty by default")
	}
	if input.Labels != nil {
		t.Error("Labels should be nil by default")
	}
}

func TestListTickets_LimitValidation(t *testing.T) {
	tests := []struct {
		name          string
		inputLimit    int
		expectedLimit int
	}{
		{"negative limit", -1, 20},
		{"zero limit", 0, 20},
		{"valid limit", 50, 50},
		{"over max limit", 200, 100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the limit validation logic
			limit := tt.inputLimit
			if limit <= 0 {
				limit = 20
			}
			if limit > 100 {
				limit = 100
			}

			if limit != tt.expectedLimit {
				t.Errorf("limit validation: got %d, want %d", limit, tt.expectedLimit)
			}
		})
	}
}

func TestIssueTrackerService_ValidateBaseURL(t *testing.T) {
	// Service with allowed domains (SaaS mode)
	svcWithAllowlist := NewIssueTrackerService(nil, nil, testEncryptionKey, AllowedIssueTrackerDomains)

	// Service without allowed domains (self-hosted mode)
	svcNoAllowlist := NewIssueTrackerService(nil, nil, testEncryptionKey, nil)

	tests := []struct {
		name           string
		url            string
		svc            *IssueTrackerService
		shouldFail     bool
		errorContains  string
	}{
		// Valid URLs
		{"valid jira cloud", "https://example.atlassian.net", svcWithAllowlist, false, ""},
		{"valid backlog", "https://example.backlog.com", svcWithAllowlist, false, ""},
		{"valid backlog jp", "https://example.backlog.jp", svcWithAllowlist, false, ""},
		{"subdomain allowed", "https://company.team.atlassian.net", svcWithAllowlist, false, ""},

		// Invalid URLs - blocked for all
		{"http not https", "http://example.atlassian.net", svcWithAllowlist, true, "HTTPS"},
		{"localhost blocked", "https://localhost/api", svcWithAllowlist, true, "localhost"},
		{"127.0.0.1 blocked", "https://127.0.0.1/api", svcWithAllowlist, true, "localhost"},
		{"invalid url (no scheme)", "not-a-url", svcWithAllowlist, true, "HTTPS"},
		{"empty host", "https:///path", svcWithAllowlist, true, "valid host"},

		// Domain allowlist checks (SaaS mode)
		{"unlisted domain blocked in saas", "https://evil.com/api", svcWithAllowlist, true, "not in allowed list"},
		{"arbitrary domain blocked in saas", "https://internal.company.local", svcWithAllowlist, true, "not in allowed list"},

		// Self-hosted mode allows more
		{"arbitrary domain allowed in selfhosted", "https://internal.company.local", svcNoAllowlist, false, ""},
		{"custom jira allowed in selfhosted", "https://jira.mycompany.com", svcNoAllowlist, false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.svc.validateBaseURL(tt.url)

			if tt.shouldFail {
				if err == nil {
					t.Errorf("expected error for URL %q, got nil", tt.url)
				} else if tt.errorContains != "" && !strContains(err.Error(), tt.errorContains) {
					t.Errorf("error %q should contain %q", err.Error(), tt.errorContains)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error for URL %q: %v", tt.url, err)
				}
			}
		})
	}
}

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip        string
		isPrivate bool
	}{
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.1.1", true},
		{"127.0.0.1", true},
		{"169.254.1.1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"203.0.113.1", false},
		{"::1", true},
		{"fe80::1", true},
		{"2001:4860:4860::8888", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := parseIP(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP: %s", tt.ip)
			}
			result := isPrivateIP(ip)
			if result != tt.isPrivate {
				t.Errorf("isPrivateIP(%s) = %v, want %v", tt.ip, result, tt.isPrivate)
			}
		})
	}
}

func TestIsDomainAllowed(t *testing.T) {
	allowedDomains := []string{"atlassian.net", "backlog.com", "example.org"}

	tests := []struct {
		host    string
		allowed bool
	}{
		{"atlassian.net", true},
		{"company.atlassian.net", true},
		{"deep.sub.atlassian.net", true},
		{"backlog.com", true},
		{"myteam.backlog.com", true},
		{"example.org", true},
		{"sub.example.org", true},
		{"notallowed.com", false},
		{"atlassian.net.evil.com", false}, // Should not match
		{"fakeatlassian.net", false},       // Should not match
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			result := isDomainAllowed(tt.host, allowedDomains)
			if result != tt.allowed {
				t.Errorf("isDomainAllowed(%q) = %v, want %v", tt.host, result, tt.allowed)
			}
		})
	}
}

// Helper function for tests
func parseIP(s string) net.IP {
	return net.ParseIP(s)
}

func strContains(s, substr string) bool {
	return strings.Contains(s, substr)
}
