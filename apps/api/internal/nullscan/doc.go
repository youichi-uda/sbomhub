// Package nullscan statically detects "nullable SQL column scanned into a
// NULL-intolerant Go type" bugs (the B1/B2 class: `sql: Scan error ...
// converting NULL to string is unsupported` turning reads into 500s).
package nullscan
