package advisory

import "testing"

func TestExtractVulnFuncs(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{
			"explicit_vulnerable_function",
			"The vulnerable function `pkg.Foo` mishandles input.",
			[]string{"pkg.Foo"},
		},
		{
			"affected_function",
			"affected function `xml.Unmarshal`",
			[]string{"xml.Unmarshal"},
		},
		{
			"backtick_method_with_keyword",
			"This is vulnerable: `net/http.Server.Serve()` crashes when fed long headers.",
			[]string{"net/http.Server.Serve()"},
		},
		{
			"plain_backtick_without_keyword_ignored",
			"You can fix it by calling `runtime.Goexit()` afterwards.",
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractVulnFuncs(tt.in)
			if !equalStringSlice(got, tt.want) {
				t.Errorf("got %v want %v", got, tt.want)
			}
		})
	}
}

func TestExtractAffectedPaths(t *testing.T) {
	in := "See file `src/foo/bar.go` and also affects `cmd/server/main.go`."
	got := extractAffectedPaths(in)
	wantAny := []string{"src/foo/bar.go", "cmd/server/main.go"}
	for _, w := range wantAny {
		if !containsString(got, w) {
			t.Errorf("missing %q in %v", w, got)
		}
	}
}

func TestExtractRequiredEnv(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{
			"backtick_assignment",
			"Only triggers when the environment variable `DEBUG=1` is set.",
			[]string{"DEBUG"},
		},
		{
			"upper_snake_env_keyword",
			"This requires `GO_ENABLE_FOO` env variable.",
			[]string{"GO_ENABLE_FOO"},
		},
		{
			"lowercase_ignored",
			"Set `enable_admin` to true.",
			nil,
		},
		{
			"no_env_context",
			"`SOMETHING` is referenced but not as an env var.",
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractRequiredEnv(tt.in)
			if !equalStringSlice(got, tt.want) {
				t.Errorf("got %v want %v", got, tt.want)
			}
		})
	}
}

func TestExtractRequiredConfig(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantHit string
	}{
		{
			"by_setting",
			"by setting `allow_unsafe_html = true` you expose users",
			"allow_unsafe_html = true",
		},
		{
			"when_clause",
			"when `trusted_proxies` is set to wildcard",
			"trusted_proxies",
		},
		{
			"requires_flag",
			"requires the `--allow-root` flag",
			"--allow-root",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractRequiredConfig(tt.in)
			if !containsString(got, tt.wantHit) {
				t.Errorf("got %v want contains %q", got, tt.wantHit)
			}
		})
	}
}

func TestIsLikelyEnvVar(t *testing.T) {
	cases := map[string]bool{
		"DEBUG":      true,
		"GO_DEBUG":   true,
		"NODE_ENV":   true,
		"NODE_ENV=development": true,
		"camelCase":  false,
		"lower":      false,
		"AB":         false, // too short
		"":           false,
	}
	for in, want := range cases {
		if got := isLikelyEnvVar(in); got != want {
			t.Errorf("isLikelyEnvVar(%q) = %v want %v", in, got, want)
		}
	}
}

func TestDedupeStrings(t *testing.T) {
	in := []string{"a", "a", "", " b ", "b"}
	got := dedupeStrings(in)
	want := []string{"a", "b"}
	if !equalStringSlice(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
	if dedupeStrings(nil) != nil {
		t.Error("nil input should yield nil output")
	}
}

func equalStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
