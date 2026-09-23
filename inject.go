package main

import (
	"fmt"
	"strings"
	"io"
	"golang.org/x/net/html"
	"net/http"
	"net/url"
)
func find_input_fields(resp *http.Response) ([]string,error) {
	var fields []string

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
						fields = append(fields, attr.Val)
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



func check_XSS_vuln(base_url string,resp *http.Response,input_fields []string) ([]string,error) {
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
		return nil,fmt.Errorf("No reflected XSS found with current payload set for URL: %q",base_url)
		
	}
	return findings,nil
}