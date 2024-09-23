package waf

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
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
	if _, err := w.Write([]byte("unsupported HTTP method")); err != nil {
		return err
	}
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
	if _, err := w.Write([]byte("IP addres is Blacklisted")); err != nil {
		return err
	}
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
	if _, err := w.Write([]byte("not allowed url")); err != nil {
		return err
	}
	return fmt.Errorf("url: %s for request: %v is not allowed", r.URL.String(), r)
}
func sqlInjectionHelper(str string) bool {
	sqlInjectPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)--`),
		regexp.MustCompile(`(?i)\/\*`),
		regexp.MustCompile(`(?i)\'`),
		regexp.MustCompile(`(?i)\"`),
		regexp.MustCompile(`(?i)OR\s+1=1`),
		regexp.MustCompile(`(?i)AND\s+1=1`),
		regexp.MustCompile(`(?i)UNION\s+SELECT`),
		regexp.MustCompile(`(?i)SELECT\s+.*FROM`),
	}
	for _, regex := range sqlInjectPatterns {
		if regex.MatchString(str) {
			return true
		}
	}
	return false
}
func (wf *Waf) checkSQLInjection(w http.ResponseWriter, r *http.Request) error {
	if r.Method == "GET" {
		query := r.URL.RequestURI()
		slicedQuery := strings.Split(query, "&")
		for _, param := range slicedQuery {
			keyValuePair := strings.Split(param, "=")
			if len(keyValuePair) != 2 {
				continue
			}
			if sqlInjectionHelper(keyValuePair[1]) {
				wf.logger.Warn("sql injection detected",
					"method", r.Method,
					"ip", r.RemoteAddr,
					"url", r.URL)
				if _, err := w.Write([]byte("sql injection detected")); err != nil {
					return err
				}
				return fmt.Errorf("url: %s for request: %v contains sql injection", r.URL.String(), r)
			}
		}

	} else if r.Method == "POST" {
		buf := new(strings.Builder)
		_, err := io.Copy(buf, r.Body)
		if err != nil {
			return err
		}
		bufString := buf.String()
		if sqlInjectionHelper(bufString) {
			wf.logger.Warn("sql injection detected",
				"method", r.Method,
				"ip", r.RemoteAddr,
				"url", r.URL)
			if _, err = w.Write([]byte("sql injection detected")); err != nil {
				return err
			}
			return fmt.Errorf("body: %s for request: %v contains sql injection", r.URL.String(), r)
		}
	}
	return nil
}

func (wf *Waf) checkXSSInjection(w http.ResponseWriter, r *http.Request) error {
	scriptTagPattern := regexp.MustCompile(`(?i)<\s*script[^>]*\s*>(.|\s)*?<\s*/\s*script\s*>`)
	if r.Method == "POST" {
		buf := new(strings.Builder)
		_, err := io.Copy(buf, r.Body)
		if err != nil {
			return err
		}
		bufString := buf.String()
		if scriptTagPattern.MatchString(bufString) {
			wf.logger.Info("Requst contain XSS injection in the body",
				"method", r.Method,
				"ip", r.RemoteAddr,
				"url", r.URL,
				"body", bufString)
			w.WriteHeader(http.StatusForbidden)
			if _, err := w.Write([]byte("xss injectin found")); err != nil {
				return err
			}
			return fmt.Errorf("body: %s for request: %v is not allowed", bufString, r)
		}

	} else if r.Method == "GET" {
		if scriptTagPattern.MatchString(r.URL.RequestURI()) {
			wf.logger.Info("Requst contain XSS injection in the body",
				"method", r.Method,
				"ip", r.RemoteAddr,
				"url", r.URL)
			w.WriteHeader(http.StatusForbidden)
			if _, err := w.Write([]byte("xss injectin found")); err != nil {
				return err
			}
			return fmt.Errorf("url: %s for request: %v is not allowed", r.URL.String(), r)
		}
	}
	return nil
}

func (wf *Waf) checkCustomPatterns(w http.ResponseWriter, r *http.Request) error {
	foundPatterns := []string{}
	for _, patterns := range wf.Cnf.blockedPatterns {
		scriptTagPattern := regexp.MustCompile(patterns)
		if r.Method == "GET" {
			if scriptTagPattern.MatchString(r.URL.RequestURI()) {
				foundPatterns = append(foundPatterns, patterns)
			}
		} else if r.Method == "POST" {
			buf := new(strings.Builder)
			_, err := io.Copy(buf, r.Body)
			if err != nil {
				return err
			}
			bufString := buf.String()
			if scriptTagPattern.MatchString(bufString) {
				foundPatterns = append(foundPatterns, patterns)
			}
		}
	}
	if len(foundPatterns) == 0 {
		return nil
	}
	wf.logger.Info("Requst contains user custom patterns injected.",
		"method", r.Method,
		"ip", r.RemoteAddr,
		"url", r.URL,
		"breaked custom patterns", foundPatterns)
	w.WriteHeader(http.StatusForbidden)
	if _, err := w.Write([]byte("custom pattern injectin found")); err != nil {
		return err
	}
	return fmt.Errorf("request: %v contains custom patterns injected: %v", r, foundPatterns)
}

func (wf *Waf) WebAppFirewall(w http.ResponseWriter, r *http.Request) error {
	if len(wf.Cnf.allowedHTTPMethods) > 0 {
		if err := wf.checkHTTPMethod(w, r); err != nil {
			return err
		}
	}
	if len(wf.Cnf.ipBlackList) > 0 {
		if err := wf.checkIP(w, r); err != nil {
			return err
		}
	}
	if len(wf.Cnf.queryUrlWhitelist) > 0 {
		if err := wf.checkUrl(w, r); err != nil {
			return err
		}
	}
	if len(wf.Cnf.blockedPatterns) > 0 {
		if err := wf.checkCustomPatterns(w, r); err != nil {
			return err
		}
	}
	if err := wf.checkSQLInjection(w, r); err != nil {
		return err
	}
	if err := wf.checkXSSInjection(w, r); err != nil {
		return err
	}
	proxyReq, err := http.NewRequest(r.Method, r.URL.String(), r.Body)
	if err != nil {
		wf.logger.Error("error creating request")
		w.WriteHeader(http.StatusInternalServerError)
		if _, err := w.Write([]byte("Internal Server Error")); err != nil {
			return err
		}
		return err
	}
	proxyReq.Header = r.Header
	client := &http.Client{}
	resp, err := client.Do(proxyReq)
	if err != nil {
		wf.logger.Error("error forwarding request")
		w.WriteHeader(http.StatusInternalServerError)
		if _, err := w.Write([]byte("Internal Server Error")); err != nil {
			return err
		}
		return err
	}
	defer resp.Body.Close()
	w.WriteHeader(resp.StatusCode)
	if _, err = io.Copy(w, resp.Body); err != nil {
		return err
	}
	return nil
}
