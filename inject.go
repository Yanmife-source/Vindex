package main

import (
	"fmt"
	"strings"
	"io"
	"golang.org/x/net/html"
	"net/url"
	"sync"
	"log/slog"
	"errors"
)
type InjectionResults struct {
	XSS map[string][]string
	SQLi map[string][]string
}

// RunInjectionTests is the only function main.go needs to call.
// It handles finding the fields ONCE, then passes them to both XSS and SQLi.
func RunInjectionTests(fields map[string][]field) (InjectionResults,[]error){

	fmt.Println("Field count:", len(fields))
	fmt.Println("Discovered fields: ",fields)

	var allErrs []error
	var wg sync.WaitGroup
	var xssResults,sqliResults map[string][]string
	var xssErrs,sqliErrs []error

	wg.Add(2)
	go func() {
		defer wg.Done()
		slog.Info("Testing XSS...")
		xssResults, xssErrs = check_XSS_vuln(fields)
	}()
	go func() {
		defer wg.Done()
		slog.Info("Testing SQLi...")
		sqliResults, sqliErrs = check_SQLi_vuln(fields)
	}()
	wg.Wait()
   
	

    
	allErrs = append(xssErrs, sqliErrs...)
	combinedErr:=errors.Join(allErrs...)
	for key := range fields {
		if len(xssResults[key]) == 0 {
			fmt.Println("No reflected XSS found for:", key)
		}
		if len(sqliResults[key]) == 0 {
			fmt.Println("No SQLi found for:", key)
		}
	
	}
	slog.Debug("Successfully ran Injection Vuln tests","error",combinedErr)
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
					break
				}
			}
		
		}
	}
	return findings,errs
}

var sqli_payloads = []string{
	`'`,
	`''`,
	`' OR '1'='1`,
	`' OR '1'='1' -- `,
	`" OR "1"="1`,
	`' UNION SELECT NULL-- `,
}

var sql_error_signatures = []string{
	"you have an error in your sql syntax",
	"warning: mysql",
	"unclosed quotation mark",
	"quoted string not properly terminated",
	"sqlstate",
	"mysql_fetch",
	"ora-01756", // Oracle
	"microsoft odbc",
}

func check_SQLi_vuln(input_fields map[string][]field) (map[string][]string,[]error) {
	var findings = map[string][]string{}
	var errs []error

	fmt.Println("Checking SQLi vulns...")
	for key, values := range input_fields {
		for _,param:=range values {
			for _, payload := range sqli_payloads {
				qs:=url.Values{}
				for _,f:=range values{
					if f.Name==param.Name{
						qs.Set(f.Name,payload)
					} else  {
						qs.Set(f.Name,f.Value)
					}
				}
				test_url := fmt.Sprintf("%s?%s", key, qs.Encode())

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
				bodyStr:=string(body)
				bodyLower := strings.ToLower(bodyStr)
				for _, sig := range sql_error_signatures {
					if strings.Contains(bodyLower, sig) {
						findings[key] = append(findings[key], fmt.Sprintf("[SQLi] param=%q payload=%q matched signature=%q at %s", param.Name, payload, sig, test_url))
						break
						 // one signature match is enough for this payload, don't log the same hit repeatedly
					}
				}
			}
		}
	}
	return findings,errs
}	