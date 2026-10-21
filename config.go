package main

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
}

type Auth struct {
    Type        string `yaml:"type"`
    LoginURL    string `yaml:"login_url"`
    Username    string `yaml:"username"`
    PasswordEnv string `yaml:"password_env"`
}

