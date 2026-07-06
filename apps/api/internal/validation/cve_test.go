package validation

import (
	"errors"
	"testing"
)

func TestValidateCVEID_Valid(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		// The \d{4,} sequence acceptance is the load-bearing property: 4, 5
		// and 7 digit sequences must ALL pass. A \d{4} (exactly-four) regex
		// would reject the 5- and 7-digit real-world IDs below.
		{"four-digit sequence", "CVE-2014-0160", "CVE-2014-0160"},
		{"five-digit sequence (log4shell)", "CVE-2021-44228", "CVE-2021-44228"},
		{"seven-digit sequence", "CVE-2023-1234567", "CVE-2023-1234567"},
		{"lowercase normalizes", "cve-2021-44228", "CVE-2021-44228"},
		{"mixed case normalizes", "Cve-2021-44228", "CVE-2021-44228"},
		{"surrounding whitespace trimmed", "  CVE-2021-44228  ", "CVE-2021-44228"},
		{"lowercase + whitespace", "  cve-2023-1234567 ", "CVE-2023-1234567"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ValidateCVEID(tc.input)
			if err != nil {
				t.Fatalf("ValidateCVEID(%q) returned error %v, want nil", tc.input, err)
			}
			if got != tc.want {
				t.Errorf("ValidateCVEID(%q) = %q, want %q", tc.input, got, tc.want)
			}
			if !IsValidCVEID(tc.input) {
				t.Errorf("IsValidCVEID(%q) = false, want true", tc.input)
			}
		})
	}
}

func TestValidateCVEID_Invalid(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"whitespace only", "   "},
		{"missing prefix", "2021-44228"},
		{"wrong prefix", "CWE-2021-44228"},
		{"non-numeric year", "CVE-20x1-44228"},
		{"non-numeric sequence", "CVE-2021-abcd"},
		{"three-digit year", "CVE-202-4444"},
		{"three-digit sequence (below \\d{4,} floor)", "CVE-2021-123"},
		{"injection chars", "CVE-2021-4&x"},
		{"sql injection tail", "CVE-2021-44228 OR 1=1"},
		{"trailing junk", "CVE-2021-44228x"},
		{"leading junk", "xCVE-2021-44228"},
		{"path traversal", "CVE-2021-44228/../../etc/passwd"},
		{"url-escape char", "CVE-2021-4%20"},
		{"comma batch (single-id validator rejects)", "CVE-2021-44228,CVE-2021-45046"},
		{"missing sequence", "CVE-2021-"},
		{"missing year", "CVE--44228"},
		{"just prefix", "CVE-"},
		{"embedded newline injection", "CVE-2021-44228\nCVE-0000-0000"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ValidateCVEID(tc.input)
			if !errors.Is(err, ErrInvalidCVEID) {
				t.Fatalf("ValidateCVEID(%q) err = %v, want ErrInvalidCVEID", tc.input, err)
			}
			if got != "" {
				t.Errorf("ValidateCVEID(%q) returned %q on failure, want empty string", tc.input, got)
			}
			if IsValidCVEID(tc.input) {
				t.Errorf("IsValidCVEID(%q) = true, want false", tc.input)
			}
		})
	}
}

// TestValidateCVEID_UnboundedSequence explicitly pins the \d{4,} contract:
// arbitrarily long numeric sequences (well past 7 digits) remain valid, so the
// validator never becomes a ceiling on future CVE sequence growth.
func TestValidateCVEID_UnboundedSequence(t *testing.T) {
	for _, id := range []string{
		"CVE-2025-1234",         // 4
		"CVE-2025-12345",        // 5
		"CVE-2025-123456",       // 6
		"CVE-2025-1234567",      // 7
		"CVE-2025-12345678",     // 8
		"CVE-2025-123456789012", // 12
	} {
		if _, err := ValidateCVEID(id); err != nil {
			t.Errorf("ValidateCVEID(%q) = %v, want valid (\\d{4,} must be unbounded)", id, err)
		}
	}
}
