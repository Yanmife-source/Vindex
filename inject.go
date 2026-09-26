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
    xssResults, xssErrs := check_XSS_vuln(fields)
	fmt.Println(xssResults)
	if len(xssErrs)==0 {
		fmt.Println("No reflected XSS found in URL: ",url,"or its subdomains")
	}
	
    // handle xssResults...

    // 3. Run SQLi (using the exact same fields we already found!)
    // fmt.Println("Testing SQLi...")
    // sqliResults, err := check_SQLi_vuln(url, resp, fields)
	// fmt.Println(sqliResults)
    // handle sqliResults...
}

func find_input_fields(links []string) (map[string][]string,error) {
	fields:=make(map[string][]string)
	init_iter:=true
	fmt.Println("Finding input fields... ")
	for _,link:=range links {
		resp,err:=fetchURL(link)
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
							if init_iter{
								fields[link]=[]string{}
								init_iter=false
							}
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



func check_XSS_vuln(input_fields map[string][]string) (map[string][]string,[]error) {
	var findings = map[string][]string{}
	var err []error

	fmt.Println("Checking XSS vulns...")
	for key, params := range input_fields {
		for _,param:=range params {
			for _, payload := range xss_payloads {
				test_url := fmt.Sprintf("%s?%s=%s", key, param, url.QueryEscape(payload))

				resp,error:=fetchURL(test_url)
				if error!=nil {
					continue
				}
				
				body, read_err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if read_err!=nil {
					continue
				}
				body_str := string(body)

				if strings.Contains(body_str, payload) {
					findings[key] = append(findings[key],fmt.Sprintf("[REFLECTED XSS] param=%q payload=%q at %s", param, payload, test_url))
				}
			}
		}
		if len(findings[key]) == 0 {
			err = append(err, fmt.Errorf("No reflected XSS found for URL: %s", key))
		}
	}
	return findings,err
}