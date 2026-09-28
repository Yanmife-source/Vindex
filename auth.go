package main
import (
	"net/http/cookiejar"
	"net/http"
	"net/url"
)

var client *http.Client

func initSession() error {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return err
	}
	client = &http.Client{Jar: jar}

	resp, err := client.PostForm("http://localhost:8080/login.php", url.Values{
		"username": {"admin"},
		"password": {"password"},
		"Login":    {"Login"},
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}