package main

import (
	"fmt"
	"net/http"
	"net/url"
	"golang.org/x/net/html"
)
func crawl(base_url string,resp *http.Response) ([]string) {
	var res_links []string
	var all_links []string
	links,_:=find_links(resp)
	base, _ := url.Parse(base_url)

	fmt.Println("Crawling...")
	for _,link:=range links {
		resolved, err := base.Parse(link) // handles both relative and absolute hrefs correctly
		if err != nil {
    		continue// skip malformed links
		}
		full_url := resolved.String()
		if is_same_links(base_url,full_url) {
			res_links=append(res_links,full_url)
		}
	}
	all_links = append([]string{base_url}, res_links...)
	return all_links
}

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
