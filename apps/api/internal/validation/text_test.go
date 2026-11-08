package validation

import (
	"errors"
	"strings"
	"testing"
)

func TestCheckJSONText(t *testing.T) {
	cases := []struct {
		name string
		in   string
		ok   bool
	}{
		{"plain", `{"name":"x"}`, true},
		{"japanese and emoji", `{"name":"日本語 🚀"}`, true},
		{"other escapes", `{"name":"a\u0001\n\u00e9"}`, true},
		{"escaped backslash then u0000 text", `{"name":"a\\u0000"}`, true},
		{"four backslashes then u0000 text", `{"name":"a\\\\u0000"}`, true},
		{"empty", ``, true},
		{"nul escape", `{"name":"a\u0000b"}`, false},
		{"nul escape after escaped backslash", `{"name":"a\\\u0000"}`, false},
		{"nul escape in key", `{"\u0000":1}`, false},
		{"nul escape second occurrence", `{"a":"\\u0000","b":"\u0000"}`, false},
		{"raw nul byte", "{\"name\":\"a\x00b\"}", false},
		{"invalid utf8", "{\"name\":\"a\xffb\"}", false},
		{"truncated utf8", "{\"name\":\"\xe3\x81\"}", false},
		{"utf8-encoded surrogate", "{\"name\":\"\xed\xa0\x80\"}", false},
		{"surrogate pair escape", `{"name":"\ud83d\ude80"}`, true},
		{"surrogate pair escape upper hex", `{"name":"\uD83D\uDE80"}`, true},
		{"escaped backslash then ud800 text", `{"name":"\\ud800"}`, true},
		{"lone high surrogate", `{"x":"\ud800"}`, false},
		{"lone high surrogate at end", `{"x":"a\uD800"}`, false},
		{"high surrogate then non-escape", `{"x":"\ud800x"}`, false},
		{"high surrogate then high", `{"x":"\ud800\ud800"}`, false},
		{"lone low surrogate", `{"x":"\udc00"}`, false},
		{"high then escaped-backslash u", `{"x":"\ud800\\udc00"}`, false},
		{"truncated escape", `{"x":"\ud8"}`, true}, // syntax error: left to the decoder
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckJSONText([]byte(tc.in))
			if tc.ok && err != nil {
				t.Fatalf("want ok, got %v", err)
			}
			if !tc.ok {
				if err == nil {
					t.Fatal("want error, got nil")
				}
				if !errors.Is(err, ErrInvalidText) {
					t.Fatalf("error %v does not wrap ErrInvalidText", err)
				}
			}
		})
	}
}

func TestCheckJSONText_MessageNamesOffsetNotInput(t *testing.T) {
	err := CheckJSONText([]byte(`{"secret":"hunter2\u0000"}`))
	if err == nil || strings.Contains(err.Error(), "hunter2") || !strings.Contains(err.Error(), "offset 18") {
		t.Fatalf("message = %v", err)
	}
	err = CheckJSONText([]byte("ab\xffc"))
	if err == nil || !strings.Contains(err.Error(), "offset 2") {
		t.Fatalf("message = %v", err)
	}
}

func TestCheckTextField(t *testing.T) {
	name := TextRule{Required: true, MaxChars: 255, SingleLine: true}
	desc := TextRule{MaxChars: 1000}
	cases := []struct {
		name  string
		value string
		rule  TextRule
		want  string // substring of the error; "" = ok
	}{
		{"name ok", "My Project", name, ""},
		{"name 255 multibyte chars", strings.Repeat("あ", 255), name, ""},
		{"name 256 chars", strings.Repeat("a", 256), name, "name must be at most 255 characters (got 256)"},
		{"name 300 chars", strings.Repeat("A", 300), name, "at most 255 characters (got 300)"},
		{"name empty", "", name, "name is required"},
		{"name blank", " \t ", name, "name is required"},
		{"name nul", "a\x00b", name, "must not contain a NUL"},
		{"name unit separator", "a\x1fb", name, "line-break characters (U+001F)"},
		{"name newline", "a\nb", name, "control characters (tab, newline)"},
		{"name del", "a\x7fb", name, "U+007F"},
		{"name invalid utf8", "a\xffb", name, "not valid UTF-8"},
		{"desc empty ok", "", desc, ""},
		{"desc multiline ok", "line1\nline2\ttab\r\n", desc, ""},
		{"desc 1000 ok", strings.Repeat("é", 1000), desc, ""},
		{"desc 1001", strings.Repeat("e", 1001), desc, "at most 1000 characters (got 1001)"},
		{"desc nul", "x\x00", desc, "NUL"},
		{"desc escape char allowed", "x\x1b[31m", desc, ""},
		{"desc form feed allowed", "page1\fpage2", desc, ""},
		{"name next line", "a\u0085b", name, "U+0085"},
		{"name line separator", "a\u2028b", name, "U+2028"},
		{"name paragraph separator", "a\u2029b", name, "U+2029"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			field := "name"
			if tc.rule == desc {
				field = "description"
			}
			err := CheckTextField(field, tc.value, tc.rule)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("want ok, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
			if !errors.Is(err, ErrInvalidText) {
				t.Fatalf("%v does not wrap ErrInvalidText", err)
			}
		})
	}
}
