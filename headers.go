package main

import ( 
	"fmt"
	"net/http"
	"os"
	"strings"
)

func main(){
	if len(os.Args) <2 {
		fmt.Println("Usage: go run main.go <url>")
		return
	}
	url:=os.Args[1]
	resp,err:=fetchURL(url)
	if err!=nil {
		fmt.Print("Error: ",err)
		return
	}
	defer resp.Body.Close()

	check_headers(resp)

	
}

type ScanResult struct {
	ClickjackingVuln bool
    MissingCSP       bool
    MissingHSTS      bool
}

func fetchURL(url string) (*http.Response,error) {
	resp, err := http.Get(url)
    if err != nil {
        return nil, fmt.Errorf("could not reach %s: %w", url, err)
    }
    return resp, nil
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