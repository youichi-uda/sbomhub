// Package main is a reachability test fixture for go_analyzer_test.go.
//
// The fixture represents a project that BOTH imports the (fake) vulnerable
// module example.test/vulnpkg AND calls its vulnerable function Unmarshal,
// so the analyzer should report StatusReachable.
//
// The import resolves only inside the test harness, which parses this file
// directly via go/parser rather than packages.Load — that avoids needing a
// real module cache entry for example.test/vulnpkg. See go_analyzer_test.go
// for details.
package main

import (
	"fmt"

	vulnpkg "example.test/vulnpkg"
)

func main() {
	var out map[string]string
	if err := vulnpkg.Unmarshal([]byte("{}"), &out); err != nil {
		fmt.Println(err)
	}
}
