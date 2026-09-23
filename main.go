package main

import (
	"os"
	"fmt"
	"flag"
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
	url := args[0]

	resp,err:=fetchURL(url)
	fmt.Println("Fetching the URL... ")
	if err!=nil {
		fmt.Print("Error: ",err)
		return
	}
	defer resp.Body.Close()

	fmt.Printf("Starting scan on: %s\n", url)
	if *exploit {
		fmt.Println("[WARNING] Active exploitation mode enabled.")
		results,err:=check_XSS_vuln(url,resp)
		if err!=nil {
			fmt.Println("Error occurred:", err)
		}
		for _,result:=range results {
			fmt.Println(result)
		}
	}

	

	res_struct:=check_headers(resp)
	if res_struct.ClickjackingVuln{}
	if res_struct.MissingCSP{
		fmt.Println("")
	}
}