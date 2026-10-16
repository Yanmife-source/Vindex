package main

import (
	"fmt"
	"sort"
)

type Finding struct {
	Type      string // "XSS", "SQLi"
	URL       string
	Param     string
	Payload   string
	Signature string // empty for XSS
}

var passiveTypes = map[string]bool{
	"Clickjacking": true, "Missing-Header": true, "Info-Disclosure": true,
}

func printReport(findings []Finding, pagesChecked int, detail bool) {
	var active, passive []Finding
	for _, f := range findings {
		if passiveTypes[f.Type] {
			passive = append(passive, f)
		} else {
			active = append(active, f)
		}
	}

	fmt.Printf("\n== Vulnerabilities (%d) ==\n", len(active))
	for _, f := range active {
		fmt.Printf("[%s] %s — param=%q\n", f.Type, f.URL, f.Param)
	}

	type key struct{ Type, Param string }
	groups := map[key][]string{}
	for _, f := range passive {
		k := key{f.Type, f.Param}
		groups[k] = append(groups[k], f.URL)
	}
	keys := make([]key, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if len(groups[keys[i]]) != len(groups[keys[j]]) {
			return len(groups[keys[i]]) > len(groups[keys[j]])
		}
		return keys[i].Param < keys[j].Param // stable output
	})

	fmt.Printf("\n== Passive findings (%d across %d pages) ==\n", len(passive), pagesChecked)
	for _, k := range keys {
		urls := groups[k]
		fmt.Printf("%-16s %s  (%d/%d pages)\n", k.Type, k.Param, len(urls), pagesChecked)
		if detail {
			for _, u := range urls {
				fmt.Printf("    %s\n", u)
			}
		}
	}
	if !detail {
		fmt.Println("(use -detail to list every URL)")
	}
}