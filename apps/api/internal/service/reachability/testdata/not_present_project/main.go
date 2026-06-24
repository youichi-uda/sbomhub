// Package main is a reachability test fixture for go_analyzer_test.go.
//
// The fixture does NOT require example.test/vulnpkg at all. The analyzer
// should report StatusNotPresent without even running the symbol-grep
// stage.
package main

import "fmt"

func main() {
	fmt.Println("safe and sound")
}
