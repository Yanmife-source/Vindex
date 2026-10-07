package main

import (
	"fmt"
)

type Finding struct {
	Type      string // "XSS", "SQLi"
	URL       string
	Param     string
	Payload   string
	Signature string // empty for XSS
}

func printReport(findings []Finding) {
	fmt.Printf("\nScan complete — %d finding(s)\n\n", len(findings))
	for _, f := range findings {
		fmt.Printf("[%s] %s — param=%q\n", f.Type, f.URL, f.Param)
	}
}