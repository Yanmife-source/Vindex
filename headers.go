package main

import ( 
	"fmt"
	"net/http"
	"strings"
)
type Doer interface {
    Do(req *http.Request) (*http.Response, error)
}

func fetchURL(d Doer,url string) (*http.Response,error) {
	req, err := http.NewRequest("GET",url,nil)
    if err!=nil{
		return nil, fmt.Errorf("could not reach %s: %w", url, err)
	}
	return d.Do(req)

}

type ScanResult struct {
	ClickjackingVuln bool
    MissingCSP       bool
    MissingHSTS      bool
	MissingXCTO      bool
	MissingReferrerPolicy bool
	ServerInfo string
	Cookies []string
}

func runPassiveChecks(links []string) ([]Finding,[]error) {
	var errs []error
	 var out []Finding
	for _, link := range links {          // same crawled links used elsewhere
		
		response,err:=fetchURL(client,link)
		if err!=nil{
			errs=append(errs,fmt.Errorf("Could not reach URL %s:%w",link,err))
			continue
		}
		defer response.Body.Close()
		result := check_header(response)
		if result.ClickjackingVuln {
			out = append(out, Finding{Type: "Clickjacking", URL: link, Param: "X-Frame-Options/CSP frame-ancestors"})
		}
		if result.MissingCSP {
			out = append(out, Finding{Type: "Missing-Header", URL: link, Param: "Content-Security-Policy"})
		}
		if result.MissingHSTS {
			out = append(out, Finding{Type: "Missing-Header", URL: link, Param: "Strict-Transport-Security"})
		}
		if result.MissingXCTO {
			out = append(out, Finding{Type: "Missing-Header", URL: link, Param: "X-Content-Type-Options"})
		}
		if result.MissingReferrerPolicy {
			out = append(out, Finding{Type: "Missing-Header", URL: link, Param: "Referrer-Policy"})
		}
		if result.ServerInfo != "" {
			out = append(out, Finding{Type: "Info-Disclosure", URL: link, Param: "Server: " + result.ServerInfo})
		}
		for _, c := range result.Cookies {
			out = append(out, Finding{Type: "Cookie-Flag", URL: link, Param: c})
		}
		
		form_attrs,err:=checkPassiveCSRF(response)
		if err!=nil{
			errs=append(errs,fmt.Errorf("could not check %s for CSRF:%w",link,err))
			continue
		}
		for _,form_attr:=range form_attrs{
				param:=fmt.Sprintf("No-Token (%s -> %s)",strings.ToUpper(form_attr.Method),form_attr.Action)
				out=append(out,Finding{Type:"Potential-CSRF",URL:link,Param:param})
		}
	}
	return out,errs

}

// Checks the  headers if the important secrutiy  headers are present or permissive 
func check_header(resp *http.Response) ScanResult {
	xfo := resp.Header.Get("X-Frame-Options")
	csp := resp.Header.Get("Content-Security-Policy")
	sts := resp.Header.Get("Strict-Transport-Security")
	xct := resp.Header.Get("X-Content-Type-Options")
	rp := resp.Header.Get("Referrer-Policy")
	si:=resp.Header.Get("Server")
	hasFrameAncestors := strings.Contains(csp, "frame-ancestors")

	var insecureCookies []string
	for _, c := range resp.Cookies() {
		if !c.Secure || !c.HttpOnly {
			insecureCookies = append(insecureCookies, c.Name)
		}
	}

	return ScanResult{
		ClickjackingVuln:      xfo == "" && !hasFrameAncestors,
		MissingCSP:            csp == "",
		MissingHSTS:           sts == "",
		MissingXCTO:           xct == "",
		MissingReferrerPolicy: rp == "",
		ServerInfo: si,
		Cookies: insecureCookies,
	}
}



