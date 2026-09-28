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
	return client.Do(req)
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