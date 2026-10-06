package main

import (
	"os"
	"fmt"
	"flag"
	"io"
	"strings"
	"log/slog"
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
	verbose:=flag.Bool("v",false,"Enables verbose output")

	//Parse the terminal input
	flag.Parse() 

	//Set the default log level to INFO
	logLevel := &slog.LevelVar{}
	logLevel.Set(slog.LevelInfo)

	if *verbose {
		logLevel.Set(slog.LevelDebug)
	}

	//Grab the URL
	args := flag.Args() 
	flag.Usage = func() {
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
		slog.Error("Failed to set security level","error",secErr)
		return
	} 
	slog.Info("Security level set successfully")
	secResp, _ := fetchURL(securityURL)
	body, _ := io.ReadAll(secResp.Body)
	secResp.Body.Close()
	slog.Debug("Security level set","value",strings.Contains(string(body), `value="low" selected`))

	//Prints all the cookies in a single clean log entry
	u, _ := url.Parse(loginURL)
	slog.Debug("Session cookie active","name",u.Host, "value", client.Jar.Cookies(u))

	//Fetch the url and checks for errors
	slog.Info("Fetching the URL... ")
	resp,err:=fetchURL(targetURL)
	if err!=nil {
		slog.Error("Failed the fetch target url","error",err)
		return
	}
	defer resp.Body.Close()//closes the http request jsut before main() closes

	res_struct:=check_headers(resp)//Checks Important security headers for 

	
	if *verbose {
		logLevel.Set(slog.LevelDebug)
	}
	//Crawls the webpage and finds input fields there
	links:=crawl(targetURL,resp)
	//Include paths found in robots.txt
	disallowedPaths, _ := checkRobots(targetURL)
	slog.Info("Checking robots.txt... ")
	for _, path := range disallowedPaths {
		fullURL :=  targetURL+ path
		links=append(links,fullURL)
		
	}
    fields, err := find_input_fields(links)
    if err != nil {
        slog.Error("Failed to parse input fields","error", err)
    }

	fmt.Printf("Starting scan on: %s\n", targetURL)
	if *exploit {
		fmt.Println(" Active exploitation mode enabled.")
		results,err:=RunInjectionTests(fields)
		fmt.Println(results.XSS)
		fmt.Println(results.SQLi)
		if err!=nil{
			slog.Error("Failed to run Injection Vuln tests","error",err)
		}
		// if err!=nil {
		// 	fmt.Println("Error occurred:", err)
		// }
		// for _,result:=range results {
		// 	fmt.Println(result)
		// } 
	} 
	
	fmt.Println(res_struct.Cookies)
	
}