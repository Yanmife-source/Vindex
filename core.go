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
	required_headers:=[]string{"Content-Security-Policy", "X-Frame-Options", "Strict-Transport-Security"}
	fmt.Println("== Important Security headers ==")
	for _,header:=range required_headers {
		if resp.Header.Get(header)==""{
			fmt.Println("[MISSING]", header)
		} else {
			fmt.Println("[OK]", header, "-", resp.Header.Get(header))
		}
	}

	xfo := resp.Header.Get("X-Frame-Options")
	csp := resp.Header.Get("Content-Security-Policy")
	sts:=resp.Header.Get("Strict-Transport-Security")
	hasFrameAncestors := strings.Contains(csp, "frame-ancestors")

	if xfo == "" && !hasFrameAncestors {
		fmt.Println("[VULNERABLE] No clickjacking protection")
	}
	if csp=="" {
		fmt.Println("[VULNERABLE] vulnerable to Reflected and Stored XSS attacks")
	}

	if sts == "" {
		fmt.Println("[VULNERABLE] Missing HSTS - vulnerable to SSL stripping")
	}

}
