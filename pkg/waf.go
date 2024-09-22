package waf

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"slices"
)

type Waf struct {
	logger *slog.Logger
	Cnf    Config
}

type Config struct {
	allowedHTTPMethods []string `yaml:"allowedhttpmethods"`
	// dryMode            bool     `yaml:"drymode"`
	ipBlackList       []string `yaml:"ipblacklist"`
	queryUrlWhitelist []string `yaml:"queryurlwhitelist"`
	blockedPatterns   []string `yaml:"blockedpatterns"`
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

func (wf *Waf) checkHTTPMethod(w http.ResponseWriter, r *http.Request) error {
	if slices.Contains(wf.Cnf.allowedHTTPMethods, r.Method) {
		wf.logger.Info("http method is supported",
			"method", r.Method,
			"ip", r.RemoteAddr,
			"url", r.URL)
		return nil
	}
	wf.logger.Warn("unsupported HTTP method ",
		"method", r.Method,
		"ip", r.RemoteAddr,
		"url", r.URL)
	w.WriteHeader(http.StatusBadRequest)
	w.Write([]byte("unsupported HTTP method"))
	return fmt.Errorf("http method: %s for request: %v is unsupported", r.Method, r)
}

func (wf *Waf) checkIP(w http.ResponseWriter, r *http.Request) error {
	if !slices.Contains(wf.Cnf.ipBlackList, r.RemoteAddr) {
		wf.logger.Info("Ip isn't blacklisted ",
			"method", r.Method,
			"ip", r.RemoteAddr,
			"url", r.URL)
		return nil
	}
	wf.logger.Warn("IP addres is Blacklisted",
		"method", r.Method,
		"ip", r.RemoteAddr,
		"url", r.URL)
	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte("IP addres is Blacklisted"))
	return fmt.Errorf("ip: %s for request: %v is blacklisted", r.RemoteAddr, r)
}

func (wf *Waf) checkUrl(w http.ResponseWriter, r *http.Request) error {
	if slices.Contains(wf.Cnf.queryUrlWhitelist, r.URL.String()) {
		wf.logger.Info("allowed url ",
			"method", r.Method,
			"ip", r.RemoteAddr,
			"url", r.URL)
		return nil
	}
	w.WriteHeader(http.StatusForbidden)
	wf.logger.Warn("not allowed url",
		"method", r.Method,
		"ip", r.RemoteAddr,
		"url", r.URL)
	w.Write([]byte("not allowed url"))
	return fmt.Errorf("url: %s for request: %v is not allowed", r.URL.String(), r)
}

// func (wf *Waf) checkSQLInjection(w http.ResponseWriter, r *http.Request)error{

// 	if r.Method == "GET"{
// 		for _, value := range r.URL.Query(){

// 		}
// 	}
// }
