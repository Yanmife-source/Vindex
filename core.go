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

func fetchURL(url string) (*http.Response,error) {
	resp, err := http.Get(url)
    if err != nil {
        return nil, fmt.Errorf("could not reach %s: %w", url, err)
    }
    return resp, nil
}

// Checks the  headers if the important secrutiy  headers are present or permissive 
func check_headers(resp *http.Response) {
	xfo := resp.Header.Get("X-Frame-Options")
	csp := resp.Header.Get("Content-Security-Policy")
	sts:=resp.Header.Get("Strict-Transport-Security")
	hasFrameAncestors := strings.Contains(csp, "frame-ancestors")

	if xfo == "" && !hasFrameAncestors {
		fmt.Println("[VULNERABLE] No clickjacking protection")
	}
	if csp=="" {
		fmt.Println("[FINDING] No Content-Security-Policy header - no defense-in-depth against XSS if an injection point exists")
	}

	if sts == "" {
		fmt.Println("[VULNERABLE] Missing HSTS - vulnerable to SSL stripping")
	}

}