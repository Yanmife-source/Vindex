package main

import (
	"os"
	"fmt"
	"flag"
	"io"
	"strings"
	"log/slog"
	"net/url"
	"errors"
)

const (
	loginURL    = "http://localhost:8080/login.php"
	securityURL = "http://localhost:8080/security.php"
	dvwaUser    = "admin"
	dvwaPass    = "password"
)

var allFindings []Finding

func main(){
	// This creates a boolean flag "-e". It defaults to false.
	exploit:=flag.Bool("e",false,"attempt active exploitation of detected vulnerabilities")
	verbose:=flag.Bool("v",false,"Enables verbose output")
	depth:=flag.Int("depth",3,"Maximum depth for recursive crawling")

	//Parse the terminal input
	flag.Parse() 

	//Set the default log level to INFO
	logLevel := &slog.LevelVar{}
	logLevel.Set(slog.LevelInfo)

	if *verbose {
		logLevel.Set(slog.LevelDebug)
	}

	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})
	slog.SetDefault(slog.New(handler))

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
		slog.Error("Failed to log in","error",err)
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

	
	//Crawls the webpage and finds input fields there
	links:=crawlSite(targetURL,*depth)
	//Include paths found in robots.txt
	slog.Info("Checking robots.txt... ")
	disallowedPaths, err := checkRobots(targetURL)
	if err!=nil {
		slog.Error("Couldn't check robots.txt","error",err)
	}

	for _, path := range disallowedPaths {
		fullURL :=  targetURL+ path
		links=append(links,fullURL)
		
	}
    fields, err := find_input_fields(links)
    if err != nil {
        slog.Error("Failed to parse input fields","error", err)
    }

	slog.Info("Starting scan on: ","url", targetURL)
	allHeaderResults,errs:=checkPageHeaders((links))
	if errs!=nil{
		allErrs:=errors.Join(errs...)
		slog.Error("Failed to Check Headers","error",allErrs)
	}
	if *exploit {
		slog.Warn("ACTIVE EXPLOITATION MODE ENABLED. Payloads will be sent to the target.")
		results,err:=RunVulnTests(fields)
		slog.Debug("XSS vuln results","results",results.XSS)
		slog.Debug("SQLi vuln results","results",results.SQLi)
		slog.Debug("CSRF vuln results","results",results.CSRF)
		if err!=nil{
			combinedErr:=errors.Join(err...)
			slog.Error("Failed to run Injection Vuln tests","error",combinedErr)
		}
		allFindings = append(allFindings, results.XSS...)
		allFindings = append(allFindings, results.SQLi...)
		allFindings = append(allFindings, results.CSRF...)
		// if err!=nil {
		// 	fmt.Println("Error occurred:", err)
		// }
		// for _,result:=range results {
		// 	fmt.Println(result)
		// } 
	}  else {
		slog.Info("Running in passive mode. No payloads will be sent.")
	}
	for url, result := range allHeaderResults { // whatever check_headers returned per-page
		allFindings = append(allFindings, headerFindings(url, result)...)
	}

	printReport(allFindings,len(links),true)
	
	
}