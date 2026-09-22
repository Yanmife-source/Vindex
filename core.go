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

	// 
	required_headers:=[]string{"Content-Security-Policy", "X-Frame-Options", "Strict-Transport-Security"}
	for _,header:=range required_headers {
		if resp.Header.Get(header)==""{
			fmt.Println("[MISSING]", header)
		} else {
			fmt.Println("[OK]", header, "-", resp.Header.Get(header))
		
		}
	}
	
	fmt.Println("Status code:", resp.Status)
	fmt.Println("Headers: ")
	for key,values := range resp.Header {
		for _,value:=range values {
			fmt.Printf("%s: %s\n",key,value)
		}

	}

}

