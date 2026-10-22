package main

import (
	"os"
	"gopkg.in/yaml.v3"
)
type Config struct {
	Target string `yaml:"target"`
	Scope struct {
		AllowedHosts []string  `yaml:"allowed_hosts"`
	}`yaml:"scope"`
	Crawl struct {
        Depth   int      `yaml:"depth"`
        Exclude []string `yaml:"exclude"`
    } `yaml:"crawl"`
	Auth Auth `yaml:"auth"`
	Checks struct {
		Enabled []string `yaml:"enabled"`
	}`yaml:"checks"`
	Limits struct {
		Workers int `yaml:"workers"`
		RequestsPerSecond int `yaml:"request_per_second"`
	} `yaml:"limits"`
	Output struct{
		Detail bool `yaml:"detail"`
	}`yaml:"output"`
}

type Auth struct {
    Type        string `yaml:"type"`
    LoginURL    string `yaml:"login_url"`
    Username    string `yaml:"username"`
    PasswordEnv string `yaml:"password_env"`
}

