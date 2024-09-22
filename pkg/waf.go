package waf

import (
	"fmt"
	"log/slog"
	"os"
)

type Waf struct {
	logger *slog.Logger
	Cnf    Config
}

type Config struct {
	AllowedHTTPMethods []string `yaml:"allowedhttpmethods"`
	dryMode            bool     `yaml:"drymode"`
	ipBlackList        []string `yaml:"ipblacklist"`
	ipWhiteList        []string `yaml:"ipwhitelist"`
	queryUrlWhitelist  []string `yaml:"queryurlwhitelist"`
	blockedPatterns    []string `yaml:"blockedpatterns"`
}

func NewWaf(args ...string) (*Waf, error) {
	filePath := "config.yaml"
	if len(args) > 0 {
		filePath = args[0]
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	config, err := parseIntoConfig(filePath)
	if err != nil {
		return &Waf{}, fmt.Errorf("could not create waf: %v", err)
	}
	return &Waf{
		logger,
		config,
	}, nil
}

//func checkHTTPMethod
