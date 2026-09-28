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
	}

	resp, err := client.PostForm("http://localhost:8080/login.php", url.Values{
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