package main

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"golang.org/x/net/html"
)
type FormAtrr struct {
	URL *url.URL
	Action string
	Method string
}

func passive_CSRF_check(resp *http.Response) ([]FormAttr){
	var fields []FormAttr
	tokenizer := html.NewTokenizer(resp.Body)
	url:=resp.Request.URL

	for {
		tt := tokenizer.Next()
		if tt == html.ErrorToken {
			break // reached end of document (io.EOF, expected)
		}
		//checks for inputs tags and stores their name and value attribultes
		if tt == html.StartTagToken  {
			token := tokenizer.Token()
			if token.Data == "form" {
				var action,method string
				for _, attr := range token.Attr {
					if attr.Key == "action" {
						action = attr.Val   // the VALUE of the name attribute, not attr.Key
					}
					if attr.Key == "method" {
						method = attr.Val
					}
				}
				if action != "" || method !="" {
					fields = append(fields, FormAtrr{URL:url,Action: action, Method: method})
							}
			}
		}
	}
	return fields
}

func check_CSRF_vuln(fields map[string][]field) ([]Finding,[]error) {var findings []Finding
	var errs []error
	slog.Info(("Checking CSRF vulns..."))
	for key, field := range fields {
		tokenField, hasToken := findTokenField(field)
		if !hasToken {
			continue
		}

		finding, err := testCSRFOnPage(key, field, tokenField)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if finding != nil {
			findings = append(findings, *finding)
		}
	}
	return findings, errs
}
func testCSRFOnPage(link string,field []field,tokenfield string) (*Finding ,error){
	realParams := buildParams(field) // all fields including real token, as you already do for SQLi/XSS

	ogURL:=link + "?" + realParams.Encode()
	resp1, err := fetchURL(ogURL)
	if err != nil { 
		return nil, fmt.Errorf("Couldn't reach %s:%w",ogURL,err)
	}
	resp1.Body.Close()
	legit := responseIndicatesSuccess(resp1) // whatever marks "password changed" on DVWA

	if !legit {
		return nil,nil// form didn't even work normally, can't test meaningfully
	}

	// Step 2: same params, but strip/garble the token field
	tamperedParams := buildParams(field)
	tamperedParams.Set(tokenfield, "invalid_or_missing")

	tamperedURL:=link + "?" + tamperedParams.Encode()
	resp2, err := fetchURL(tamperedURL)
	if err != nil {
		return nil, fmt.Errorf("Couldn't reach %s:%w",tamperedURL,err)
		}
	resp2.Body.Close()
	stillWorks := responseIndicatesSuccess(resp2)

	if stillWorks {
		return &Finding{Type: "CSRF", URL: link, Param: tokenfield},nil
	}
	return nil,nil
}



func buildParams(fields []field) url.Values {
	qs := url.Values{}
	for _, f := range fields {
		qs.Set(f.Name, f.Value)
	}
	return qs
}

func responseIndicatesSuccess(response *http.Response) bool {
	body,err:=io.ReadAll(response.Body)
	if err!=nil{ return false}
	body_str:=string(body)
	return strings.Contains(strings.ToLower(body_str), "password changed")
}

func findTokenField(fields []field) (string, bool) {
	for _, f := range fields {
		if strings.Contains(strings.ToLower(f.Name), "token") {
			return f.Name, true
		}
	}
	return "", false
}