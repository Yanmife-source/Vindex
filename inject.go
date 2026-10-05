package main

import (
	"fmt"
	"strings"
	"io"
	"golang.org/x/net/html"
	"net/url"
)
type InjectionResults struct {
	XSS map[string][]string
	SQLi map[string][]string
}

// RunInjectionTests is the only function main.go needs to call.
// It handles finding the fields ONCE, then passes them to both XSS and SQLi.
func RunInjectionTests(fields map[string][]field) (InjectionResults,[]error){
    // 1. Find fields once
	

	fmt.Printf("Discovered fields: %+v\n", fields)
	fmt.Println("Field count:", len(fields))

    // 2. Run XSS
	var allErrs []error
    fmt.Println("Testing XSS...")
    xssResults, xssErrs := check_XSS_vuln(fields)
	allErrs = append(allErrs, xssErrs...)
	
	for key := range fields {
		if len(xssResults[key]) == 0 {
			fmt.Println("No reflected XSS found for:", key)
		}
	}
	
    // handle xssResults...

    // 3. Run SQLi (using the exact same fields we already found!)
    // fmt.Println("Testing SQLi...")
    // sqliResults, err := check_SQLi_vuln(url, resp, fields)
	//allErrs = append(allErrs, xssErrs...)
	// fmt.Println(sqliResults)
    // handle sqliResults...
	return InjectionResults{XSS:xssResults,SQLi:sqliResults},allErrs
}


type field struct {
	Name  string
	Value string
}

func find_input_fields(links []string) (map[string][]field,error) {
	fields:=make(map[string][]field)
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
			//checks for inputs tags and stores their name and value attribultes
			if tt == html.StartTagToken || tt == html.SelfClosingTagToken {
				token := tokenizer.Token()
				if token.Data == "input" {
					var name, value string
					for _, attr := range token.Attr {
						if attr.Key == "name" {
							name = attr.Val   // the VALUE of the name attribute, not attr.Key
						}
						if attr.Key == "value" {
							value = attr.Val
						}
					}
					if name != "" {
						fields[link] = append(fields[link], field{Name: name, Value: value})
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



func check_XSS_vuln(input_fields map[string][]field) (map[string][]string,[]error) {
	var findings = map[string][]string{}
	var errs []error

	fmt.Println("Checking XSS vulns...")
	for key, params := range input_fields {
		for _,param:=range params {
			for _, payload := range xss_payloads {
				test_url := fmt.Sprintf("%s?%s=%s", key, param.Name, url.QueryEscape(payload))

				resp,error:=fetchURL(test_url)
				if error!=nil {
					errs = append(errs, fmt.Errorf("could not test %s: %w", test_url, error)) // REAL failure
					continue
				}
				
				body, readErr := io.ReadAll(resp.Body)
				resp.Body.Close()
				if readErr!=nil {
					errs = append(errs, fmt.Errorf("could not read response from %s: %w", test_url, readErr)) // REAL failure
					continue
				}
				body_str := string(body)

				// if param.Name == "name" {
				// 	fmt.Println("URL:", test_url)
				// 	fmt.Println("Status:", resp.StatusCode)
				// 	fmt.Println("Body length:", len(body_str))
				// }
				
				if strings.Contains(body_str, payload) {
					findings[key] = append(findings[key],fmt.Sprintf("[REFLECTED XSS] param=%q payload=%q at %s", param.Name, payload, test_url))
				}
			}
		
		}
	}
	return findings,errs
}