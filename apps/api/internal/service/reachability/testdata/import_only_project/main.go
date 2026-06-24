// Package main is a reachability test fixture for go_analyzer_test.go.
//
// The fixture imports example.test/vulnpkg transitively but never calls
// the vulnerable symbol (Unmarshal). The analyzer should report
// StatusImportOnly.
package main

import (
	"fmt"

	vulnpkg "example.test/vulnpkg"
)

func main() {
	// Safe is a non-vulnerable helper from the same package; touching it
	// keeps the import live without triggering the symbol-grep stage.
	safe := vulnpkg.Safe([]byte("hello"))
	fmt.Println(string(safe))
}
