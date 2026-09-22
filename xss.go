package main

import (
	"fmt"
	"strings"
	"io"
	"net/http"
	"net/url"
)

var xss_payloads = []string{
	`<script>alert('vindex_xss_test')</script>`,
	`"><script>alert('vindex_xss_test')</script>`,
	`<img src=x onerror="alert('vindex_xss_test')">`,
	`'><svg onload=alert('vindex_xss_test')>`,
} 

var commonParams = []string{"q", "search", "query", "id", "name", "input"}

func check_XSS_vuln(base_url string,resp *http.Response) ([]string) {
	var findings []string
	
	for _, param := range commonParams {
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
		fmt.Println("No reflected XSS found with current payload set")
		return  nil
	}
	return findings	
}