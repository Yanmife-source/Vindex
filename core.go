package main

import ( 
	"fmt"
	"net/http"
	"os"
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

	// //To print the headers found and the status code of the website at the url
	// fmt.Println("Status code:", resp.Status)
	// fmt.Println("Headers: ")
	// for key,values := range resp.Header {
	// 	for _,value:=range values {
	// 		fmt.Printf("%s: %s\n",key,value)
	// 	}

	// }

	// Checks the  headers if the improtant secrutiy  headers are present or permissive 
	
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
	for _,header:=range required_headers {
		fmt.Println("== Important Security headers ==")
		if resp.Header.Get(header)==""{
			fmt.Println("[MISSING]", header)
		} else {
			fmt.Println("[OK]", header, "-", resp.Header.Get(header))
		}
	}

}
