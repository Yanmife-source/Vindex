package main
import (
	"net/http/cookiejar"
	"net/http"
	"net/url"
	"fmt"
)

var client *http.Client

func initSession(loginURL, username, password string) error {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return err
	}
	client = &http.Client{Jar: jar}
	loginPage, err := client.Get(loginURL)
	if err != nil {
		return err
	}
	defer loginPage.Body.Close()
	csrfToken,err:=findCSRFToken(loginPage)
	if err!=nil{
		fmt.Println("Error: ",err)
		return err
	}

	resp, err := client.PostForm(loginURL, url.Values{
		"username": {username},
		"password": {password},
		"Login":    {"Login"},
		"user_token": {csrfToken},
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func setSecurityLevel(secURL string) error {
	secPage, err := client.Get(secURL)
	if err != nil {
		return err
	}
	secToken,err:=findCSRFToken(secPage)
	if err!=nil{
		return err
	}

	resp,err:=client.PostForm(secURL,url.Values{
		"security":{"low"},
		"seclev_submit": {"Submit"},
		"user_token": {secToken},
	})
	if err!=nil{
		return err
	}
	defer resp.Body.Close()
	return nil

}