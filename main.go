package main

import (
	"os"
	"fmt"
	"flag"
	"io"
	"strings"
	"net/url"
)

const (
	loginURL    = "http://localhost:8080/login.php"
	securityURL = "http://localhost:8080/security.php"
	dvwaUser    = "admin"
	dvwaPass    = "password"
)
func main(){
	// This creates a boolean flag "-e". It defaults to false.
	exploit:=flag.Bool("e",false,"attempt active exploitation of detected vulnerabilities")

	//Parse the terminal input
	flag.Parse() 

	//Grab the URL
	args := flag.Args() 
	if len(args) < 1 {
		fmt.Println("Usage: vindex [flags] <url>")
		fmt.Println("Example: vindex -e http://localhost:3000")
		fmt.Println("\nAvailable flags:")
		flag.PrintDefaults() // Automatically prints a professional help menu for your flags!
		os.Exit(1)
	}
	targetURL := args[0]

	err:=initSession(loginURL,dvwaUser,dvwaPass)
	if err!=nil{
		fmt.Println("Error: ",err)
		return
	}


		
	secErr:=setSecurityLevel(securityURL)
	if secErr!=nil{
		fmt.Println("Error setting the security level: ",secErr)
		return
	}
	fmt.Println("Security level set successfully")
	secResp, _ := fetchURL(securityURL)
	body, _ := io.ReadAll(secResp.Body)
	secResp.Body.Close()
	fmt.Println(strings.Contains(string(body), `value="low" selected`))

	u, _ := url.Parse(loginURL)
	cookies := client.Jar.Cookies(u)
	for _, c := range cookies {
		fmt.Println(c.Name, "=", c.Value)
	}

	//Fetch the url and checks for errors
	resp,err:=fetchURL(targetURL)
	fmt.Println("Fetching the URL... ")
	if err!=nil {
		fmt.Print("Error: ",err)
		return
	}
	defer resp.Body.Close()//closes the http request jsut before main() closes

	res_struct:=check_headers(resp)//Checks Important security headers for 

	//Crawls the webpage and finds input fields there
	links:=crawl(targetURL,resp)
    fields, err := find_input_fields(links)
    if err != nil {
        fmt.Println("[!] Could not parse input fields:", err)
    }

	fmt.Printf("Starting scan on: %s\n", targetURL)
	if *exploit {
		fmt.Println("[WARNING] Active exploitation mode enabled.")
		RunInjectionTests(links)
		// if err!=nil {
		// 	fmt.Println("Error occurred:", err)
		// }
		// for _,result:=range results {
		// 	fmt.Println(result)
		// } 
	} else if res_struct.MissingCSP {
		fmt.Println("[INFO] Rerun with -e to attempt active XSS testing")
	}

	
	fmt.Println(res_struct.Cookies)
	
}