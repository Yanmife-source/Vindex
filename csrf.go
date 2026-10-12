package main

import (
	"io"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

func check_CSRF_vuln(fields map[string][]field) ([]Finding,[]error) {
	var findings []Finding
	var allErrs []error
	for link,field:=range fields {
		realParams := buildParams(field) // all fields including real token, as you already do for SQLi/XSS

		ogURL:=link + "?" + realParams.Encode()
		resp1, err := fetchURL(ogURL)
		if err != nil { 
			allErrs=append(allErrs, fmt.Errorf("Couldn't reach %s:%w",ogURL,err))
		}
		defer resp1.Body.Close()
		legit := responseIndicatesSuccess(resp1) // whatever marks "password changed" on DVWA

		if !legit {
			continue // form didn't even work normally, can't test meaningfully
		}

		// Step 2: same params, but strip/garble the token field
		tamperedParams := buildParams(field)
		tamperedParams.Set("user_token", "invalid_or_missing")

		tamperedURL:=link + "?" + tamperedParams.Encode()
		resp2, err := fetchURL(tamperedURL)
		if err != nil {
			allErrs=append(allErrs,  fmt.Errorf("Couldn't reach %s:%w",tamperedURL,err))
			}
		defer resp2.Body.Close()
		stillWorks := responseIndicatesSuccess(resp2)

		if stillWorks {
			findings=append(findings,Finding{Type: "CSRF", URL: link, Param: "user_token"})
		}
		
	}
	return findings,allErrs
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