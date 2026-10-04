package main

import ( 
	"fmt"
	"net/http"
	"strings"
)


func fetchURL(url string) (*http.Response,error) {
	req, err := http.NewRequest("GET",url,nil)
    if err!=nil{
		return nil, fmt.Errorf("could not reach %s: %w", url, err)
	}
	resp,err:=client.Do(req)
	if err!=nil {
		return nil,err
	}
	return resp,nil

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


// Checks the  headers if the important secrutiy  headers are present or permissive 
func check_headers(resp *http.Response) ScanResult {
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
