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
	resp,err:=http.Get(url)
	if err!=nil{
		fmt.Println("Could not reach target:", url)
    	fmt.Println("(is the server running? try again in a few seconds)")
		//fmt.Println("Error fetching URL:", err)
		return
	}
	defer resp.Body.Close()

	//To print the headers found and the status code of the website at the url
	fmt.Println("Status code:", resp.Status)
	fmt.Println("Headers: ")
	for key,values := range resp.Header {
		for _,value:=range values {
			fmt.Printf("%s: %s\n",key,value)
		}

	}

	// Checks the  headers if the improtant secrutiy  headers are present or permissive 
	required_headers:=[]string{"Content-Security-Policy", "X-Frame-Options", "Strict-Transport-Security"}
	missing_headers:=[]string{}
	for _,header:=range required_headers {
		if resp.Header.Get(header)==""{
			fmt.Println("[MISSING]", header)
			missing_headers=append(missing_headers,header)
		} else {
			fmt.Println("[OK]", header, "-", resp.Header.Get(header))
		
		}
	}
	

}

