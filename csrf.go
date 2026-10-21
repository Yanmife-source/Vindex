package main

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"github.com/PuerkitoBio/goquery"
)
type FormAttr struct {
	URL string
	Action string
	Method string
}

func checkPassiveCSRF(resp *http.Response) ([]FormAttr,error){
	var form_attr []FormAttr
	// 1. Parse the HTML document
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil,err
	}
	slog.Info("Checking for CSRF...")

	actionURL:=resp.Request.URL
	// 2. Find every <form> on the page and loop through them
	doc.Find("form").Each(func(index int, form *goquery.Selection) {
		
		// 3. Extract the Action and Method
		action, _ := form.Attr("action")
		method, _ := form.Attr("method")
		
			
		resolved,err:=actionURL.Parse(action);	
		if err!=nil{
			slog.Debug("Couldn't parse URL","action",action,"error",err)
			return 
		}
		action=resolved.String()
		
		if method == "" {
			method = "GET" // Browsers default to GET if it's missing
		}

		hasToken := false
		passwordCount := 0
		// 4. Find all <input> tags INSIDE this specific form
		form.Find("input").Each(func(i int, input *goquery.Selection) {
			inputType, _ := input.Attr("type")
			inputName, _ := input.Attr("name")

			// Check if this input is a hidden CSRF token
			if strings.ToLower(inputType) == "hidden" {
				nameLower := strings.ToLower(inputName)
				if strings.Contains(nameLower, "csrf") || strings.Contains(nameLower, "token") {
					hasToken = true
				}
			}
		
		
			if typeAttr, exists := input.Attr("type"); exists {
				// Use EqualFold to safely catch case-insensitive variants like "PASSWORD"
				if strings.EqualFold(typeAttr, "password") {
					passwordCount++
				}
			}
		})
		
		// 5. The Verdict: State-changing form with no token? Flag it.
		if !hasToken && (strings.ToUpper(method) == "POST" || passwordCount>=2) {
			form_attr =append(form_attr,FormAttr{URL:actionURL.String(),Action:action,Method:method})
		}
	})
	return form_attr,nil
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
	realParams := buildParams(field) // all fields including real token

	ogURL:=link + "?" + realParams.Encode()
	resp1, err := fetchURL(client,ogURL)
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
	resp2, err := fetchURL(client,tamperedURL)
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