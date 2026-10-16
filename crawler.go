package main

import (
	"fmt"
	"strings"
	"io"
	"net/http"
	"net/url"
	"golang.org/x/net/html"
	"log/slog"
)
func crawlSite(startURL string, maxDepth int) []string {
	type queueItem struct {
		url   string
		depth int
	}
	queue := []queueItem{{startURL, 0}}
	seen := map[string]bool{startURL: true}
	var allLinks []string
	
	slog.Info("Crawling...")
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		allLinks = append(allLinks, current.url)

		if current.depth >= maxDepth {
			continue
		}

		resp, err := fetchURL(current.url)
		if err != nil {
			continue
		}
		pageLinks := crawl(resp) // your existing single-page logic, reused as-is
		resp.Body.Close()

		for _, link := range pageLinks {
			if !seen[link] {
				seen[link] = true
				queue = append(queue, queueItem{link, current.depth + 1})
			}
		}
	}
	return allLinks
}
func crawl(resp *http.Response) ([]string) {
	var res_links []string
	var all_links []string
	var skipList=[]string{"logout","setup","phpids="}
	var seen=make(map[string]bool)
	links,base_url,_:=find_links(resp)
	base:=resp.Request.URL
	

	if base_url != "" {
		if parsedBase, err := base.Parse(base_url); err == nil {
			base = parsedBase
		}
	}
	pageURL:=base.String()
	Loop:
	for _,link:=range links {
		resolved, err := base.Parse(link) // handles both relative and absolute hrefs correctly
		if err != nil {
    		continue// skip malformed links
		}
		full_url := resolved.String()
		for _,s :=range skipList {
			if strings.Contains(full_url,s){
			continue Loop 
			}// never follow logout links — it kills the session for everything after it
		}
		
		if is_same_links(pageURL,full_url) && !seen[full_url] {
			res_links=append(res_links,full_url)
			seen[full_url]=true
		}
	}
	all_links = append([]string{pageURL}, res_links...)
	slog.Debug("Successfully crawled the target URL","url",pageURL)
	return all_links
}

func find_links(resp *http.Response) ([]string,string ,error) {
	var domains []string
	var baseURL string

	tokenizers:=html.NewTokenizer(resp.Body)

	for {
		tt:=tokenizers.Next()
		if tt==html.ErrorToken {
			break
		}
		if tt==html.StartTagToken {
			token := tokenizers.Token()
			switch token.Data {
			case "a":
				for _,attr:=range token.Attr {
					if attr.Key=="href"{
						domains=append(domains,attr.Val)
					}
				}
			case "base": 
				for _,attr:=range token.Attr {
					if attr.Key=="href"{
						baseURL=attr.Val
					}
				}
				
			} 
		}
	}	
	return domains,baseURL,nil
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


func findCSRFToken (resp *http.Response) (string,error) {
	tokenizers:=html.NewTokenizer(resp.Body)
	var res_token string
	var foundHidden bool

	for {
		tt:=tokenizers.Next()
		if tt==html.ErrorToken {
			break
		}
		if tt==html.StartTagToken || tt == html.SelfClosingTagToken {
			token := tokenizers.Token()
			if token.Data=="input" {
				for _,attr:=range token.Attr {
					if attr.Key=="type" && attr.Val=="hidden"{
						foundHidden=true
					}
					if attr.Key=="value"  {
						res_token=attr.Val
					}
				}
				if res_token!="" && foundHidden {
					return res_token,nil
				}
			}
		}
	}
	return "", fmt.Errorf("no hidden CSRF token field found")
}


func checkRobots(baseURL string) ([]string,error){
	robotsURL := baseURL + "/robots.txt"
	resp, err := fetchURL(robotsURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		slog.Info("No robots.txt found", "status_code", resp.StatusCode)
		return nil, nil // no robots.txt present, nothing to report
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var disallowed []string
	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Disallow:") {
			path := strings.TrimSpace(strings.TrimPrefix(line, "Disallow:"))
			if path != "" {
				disallowed = append(disallowed, path)
			}
		}
	}
	return disallowed, nil
}