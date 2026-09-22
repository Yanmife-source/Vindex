package main

import ( 
	"fmt"
	"net/http"
	"strings"
)


func fetchURL(url string) (*http.Response,error) {
	resp, err := http.Get(url)
    if err != nil {
        return nil, fmt.Errorf("could not reach %s: %w\nStatus code: %s", url, err,resp.Status)
    }
    return resp, nil
}

type ScanResult struct {
	ClickjackingVuln bool
    MissingCSP       bool
    MissingHSTS      bool
}


// Checks the  headers if the important secrutiy  headers are present or permissive 
func check_headers(resp *http.Response) ScanResult {
	xfo := resp.Header.Get("X-Frame-Options")
	csp := resp.Header.Get("Content-Security-Policy")
	sts:=resp.Header.Get("Strict-Transport-Security")
	hasFrameAncestors := strings.Contains(csp, "frame-ancestors")

	return ScanResult{
        ClickjackingVuln: xfo == "" && !hasFrameAncestors,
        MissingCSP:       csp == "",
        MissingHSTS:	  sts == "",
    }

}