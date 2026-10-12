package main

import (
	"io"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

func check_CSRF_vuln(fields map[string][]field) ([]Finding,[]error) {var findings []Finding
	var errs []error

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
	var allErrs []error
	realParams := buildParams(field) // all fields including real token, as you already do for SQLi/XSS

	ogURL:=link + "?" + realParams.Encode()
	resp1, err := fetchURL(ogURL)
	if err != nil { 
		allErrs=append(allErrs, fmt.Errorf("Couldn't reach %s:%w",ogURL,err))
	}
	resp1.Body.Close()
	legit := responseIndicatesSuccess(resp1) // whatever marks "password changed" on DVWA

	if !legit {
		return nil,nil// form didn't even work normally, can't test meaningfully
	}

	// Step 2: same params, but strip/garble the token field
	tamperedParams := buildParams(field)
	tamperedParams.Set("tokenfield", "invalid_or_missing")

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