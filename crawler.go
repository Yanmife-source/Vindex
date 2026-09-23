package main

import (
	"net/http"
	"net/url"
	"golang.org/x/net/html"
)


func find_links(resp *http.Response) ([]string, error) {
	var domains []string

	tokenizers:=html.NewTokenizer(resp.Body)

	for {
		tt:=tokenizers.Next()
		if tt==html.ErrorToken {
			break
		}
		if tt==html.StartTagToken {
			token := tokenizers.Token()
			if token.Data=="a" {
				for _,attr:=range token.Attr {
					if attr.Key=="href"{
						domains=append(domains,attr.Val)
					}
				}
			}
		}
	}
	return domains,nil
}

func is_same_links(base_url string,link_url string) (bool) {
	parsed_base,err:=url.Parse(base_url)
	if err!=nil{
		return false
	}
	parsed_link,err:=url.Parse(link_url)
	if err!=nil{
		return false
	}
	return parsed_base.Hostname()==parsed_link.Hostname()
}
