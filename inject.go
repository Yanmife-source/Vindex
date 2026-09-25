package main

import (
	"fmt"
	"strings"
	"io"
	"golang.org/x/net/html"
	"net/http"
	"net/url"
)

// RunInjectionTests is the only function main.go needs to call.
// It handles finding the fields ONCE, then passes them to both XSS and SQLi.
func RunInjectionTests(url string, resp *http.Response) {
    // 1. Find fields once
	links:=crawl(url,resp)
    fields, err := find_input_fields(links)
    if err != nil {
        fmt.Println("[!] Could not parse input fields:", err)
        return // Stop here, no fields = no injection possible
    }

    // 2. Run XSS
    fmt.Println("Testing XSS...")
    xssResults, err := check_XSS_vuln(url, resp, fields)
	fmt.Println(xssResults)
    // handle xssResults...

    // 3. Run SQLi (using the exact same fields we already found!)
    // fmt.Println("Testing SQLi...")
    // sqliResults, err := check_SQLi_vuln(url, resp, fields)
	// fmt.Println(sqliResults)
    // handle sqliResults...
}

func find_input_fields(links []string) (map[string][]string,error) {
	fields:=make(map[string][]string)
	for _,link:=range links {
		resp,err:=http.Get(link)
		if err!=nil{
			continue
		}

		tokenizer := html.NewTokenizer(resp.Body)

		for {
			tt := tokenizer.Next()
			if tt == html.ErrorToken {
				break // reached end of document (io.EOF, expected)
			}

			if tt == html.StartTagToken || tt == html.SelfClosingTagToken {
				token := tokenizer.Token()
				if token.Data == "input" {
					for _, attr := range token.Attr {
						if attr.Key == "name" {
							fields[link]=[]string{}
							fields[link] = append(fields[link], attr.Val)
						}
					}
				}
			}
		}
	}
	return fields,nil
}


var xss_payloads = []string{
	`<script>alert('vindex_xss_test')</script>`,
	`"><script>alert('vindex_xss_test')</script>`,
	`<img src=x onerror="alert('vindex_xss_test')">`,
	`'><svg onload=alert('vindex_xss_test')>`,
} 



func check_XSS_vuln(base_url string,resp *http.Response,input_fields map[string][]string) ([]string,error) {
	var findings []string

	for _, param := range input_fields {
		for _, payload := range xss_payloads {
			test_url := fmt.Sprintf("%s?%s=%s", base_url, param, url.QueryEscape(payload))

			body, err := io.ReadAll(resp.Body)
			if err!=nil {
				continue
			}
			body_str := string(body)

			if strings.Contains(body_str, payload) {
				finding := fmt.Sprintf("[REFLECTED XSS] param=%q payload=%q at %s", param, payload, test_url)
				findings = append(findings, finding)
			}
		}
	}
	if len(findings) == 0 {
		return nil,fmt.Errorf("No reflected XSS found for URL: %s",base_url)
		
	}
	return findings,nil
}