package main

import {
	"os"
	"fmt"
	"flag"
}

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
}