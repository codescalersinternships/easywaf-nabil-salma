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

	"github.com/prometheus/client_golang/prometheus"
)

type Waf struct {
	logger         *slog.Logger
	Cnf            Config
	backendAddress string
	Promethues	*Metrics
}
type Metrics struct{
	numberOfRequests prometheus.Counter
	numberOfSQlInj prometheus.Counter
	numberOfXSS prometheus.Counter
	numberOfBlockedIp prometheus.Counter
}
type Config struct {
	AllowedHTTPMethods []string `yaml:"allowedhttpmethods"`
	IpBlackList        []string `yaml:"ipblacklist"`
	QueryUrlWhitelist  []string `yaml:"queryurlwhitelist"`
	BlockedPatterns    []string `yaml:"blockedpatterns"`
}

func newMetrics()( *Metrics, error){
	numOfReq := prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "total_request_count",
			Help: "No of request handled handled by waf",
		},
	)
	numberOfSQl := prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "sql_injections_count",
			Help: "No of requests containing sql injection",
		},
	)
	numberOfXSS := prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "xss_count",
			Help: "No of requests containing XSS",
		},
	)

	numberOfBlockedIp := prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "ips_blocked_count",
			Help: "No of requests containing blocked ips",
		},
	)
	reg:= prometheus.NewRegistry()
	if err :=reg.Register(numOfReq); err != nil{
		return &Metrics{}, fmt.Errorf("could not register total number of request: %v", err)
	}
	if err := reg.Register(numberOfSQl); err != nil {
		return &Metrics{}, fmt.Errorf("could not register number of sql injections: %v", err)
	}
	if err := reg.Register(numberOfXSS); err != nil {
		return &Metrics{}, fmt.Errorf("could not register number of xss injections: %v", err)
	}
	if err := reg.Register(numberOfBlockedIp); err != nil {
		return &Metrics{}, fmt.Errorf("could not register number of blocked ips: %v", err)
	}
	return &Metrics{
		numberOfRequests: numOfReq, numberOfSQlInj: numberOfSQl,numberOfXSS: numberOfXSS,numberOfBlockedIp: numberOfBlockedIp,
	}, nil
}
func NewWaf(backendAddress string, args ...string) (*Waf, error) {
	filePath := "config.yaml"
	if len(args) > 0 {
		filePath = args[0]
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	config, err := parseIntoConfig(filePath)
	if err != nil {
		return &Waf{}, fmt.Errorf("could not create waf: %v", err)
	}
	metrics, err:= newMetrics()
	if err!=nil{
		return &Waf{}, err
	}
	return &Waf{
		logger,
		config,
		backendAddress,
		metrics,
	}, nil
}

func (wf *Waf) checkHTTPMethod(w http.ResponseWriter, r *http.Request) (bool, error) {
	if slices.Contains(wf.Cnf.AllowedHTTPMethods, r.Method) {
		wf.logger.Info("http method is supported",
			"method", r.Method,
			"ip", r.RemoteAddr,
			"url", r.URL)
		return false, nil
	}
	wf.logger.Warn("unsupported HTTP method ",
		"method", r.Method,
		"ip", r.RemoteAddr,
		"url", r.URL)
	w.WriteHeader(http.StatusBadRequest)
	if _, err := w.Write([]byte("unsupported HTTP method")); err != nil {
		return true, err
	}
	return true, nil
}

func (wf *Waf) checkIP(w http.ResponseWriter, r *http.Request) (bool, error) {
	if !slices.Contains(wf.Cnf.IpBlackList, r.RemoteAddr) {
		wf.logger.Info("Ip isn't blacklisted ",
			"method", r.Method,
			"ip", r.RemoteAddr,
			"url", r.URL)
		return false, nil
	}
	wf.Promethues.numberOfBlockedIp.Inc()
	wf.logger.Warn("IP addres is Blacklisted",
		"method", r.Method,
		"ip", r.RemoteAddr,
		"url", r.URL)
	w.WriteHeader(http.StatusForbidden)
	if _, err := w.Write([]byte("IP addres is Blacklisted")); err != nil {
		return true, err
	}
	return true, nil
}

func (wf *Waf) checkUrl(w http.ResponseWriter, r *http.Request) (bool, error) {
	if slices.Contains(wf.Cnf.QueryUrlWhitelist, r.URL.Path) {
		wf.logger.Info("allowed url ",
			"method", r.Method,
			"ip", r.RemoteAddr,
			"url", r.URL)
		return false, nil
	}
	w.WriteHeader(http.StatusForbidden)
	wf.logger.Warn("not allowed url",
		"method", r.Method,
		"ip", r.RemoteAddr,
		"url", r.URL)
	if _, err := w.Write([]byte("not allowed url")); err != nil {
		return true, err
	}
	return true, nil
}
func sqlInjectionHelper(str string) bool {
	sqlInjectPatterns := []*regexp.Regexp{
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
func (wf *Waf) checkSQLInjection(w http.ResponseWriter, r *http.Request) (bool, error) {
	if r.Method == "GET" {
		query := r.URL.RequestURI()
		slicedQuery := strings.Split(query, "&")
		for _, param := range slicedQuery {
			keyValuePair := strings.Split(param, "=")
			if len(keyValuePair) != 2 {
				continue
			}
			if sqlInjectionHelper(keyValuePair[1]) {
				wf.Promethues.numberOfSQlInj.Inc()
				wf.logger.Warn("sql injection detected",
					"method", r.Method,
					"ip", r.RemoteAddr,
					"url", r.URL)
				if _, err := w.Write([]byte("sql injection detected")); err != nil {
					return true, err
				}
				return true, nil
			}
		}

	} else if r.Method == "POST" {
		buf := new(strings.Builder)
		_, err := io.Copy(buf, r.Body)
		if err != nil {
			return false, err
		}
		bufString := buf.String()
		r.Body = io.NopCloser(strings.NewReader(bufString))
		if sqlInjectionHelper(bufString) {
			wf.Promethues.numberOfSQlInj.Inc()
			wf.logger.Warn("sql injection detected",
				"method", r.Method,
				"ip", r.RemoteAddr,
				"url", r.URL)
			if _, err = w.Write([]byte("sql injection detected")); err != nil {
				return true, err
			}
			return true, nil
		}
	}
	return false, nil
}

func (wf *Waf) checkXSSInjection(w http.ResponseWriter, r *http.Request) (bool, error) {
	scriptTagPattern := regexp.MustCompile(`(?i)<\s*script[^>]*\s*>(.|\s)*?<\s*/\s*script\s*>`)
	if r.Method == "POST" {
		buf := new(strings.Builder)
		_, err := io.Copy(buf, r.Body)
		if err != nil {
			return false, err
		}
		bufString := buf.String()
		r.Body = io.NopCloser(strings.NewReader(bufString))

		if scriptTagPattern.MatchString(bufString) {
			wf.Promethues.numberOfXSS.Inc()
			wf.logger.Warn("Requst contain XSS injection in the body",
				"method", r.Method,
				"ip", r.RemoteAddr,
				"url", r.URL,
				"body", bufString)
			w.WriteHeader(http.StatusForbidden)
			if _, err := w.Write([]byte("xss injectin found")); err != nil {
				return true, err
			}
			return true, nil
		}

	} else if r.Method == "GET" {
		if scriptTagPattern.MatchString(r.URL.RequestURI()) {
			wf.Promethues.numberOfXSS.Inc()
			wf.logger.Warn("Requst contain XSS injection in the body",
				"method", r.Method,
				"ip", r.RemoteAddr,
				"url", r.URL)
			w.WriteHeader(http.StatusForbidden)
			if _, err := w.Write([]byte("xss injectin found")); err != nil {
				return true, err
			}
			return true, nil
		}
	}
	return false, nil
}

func (wf *Waf) checkCustomPatterns(w http.ResponseWriter, r *http.Request) (bool, error) {
	foundPatterns := []string{}
	for _, patterns := range wf.Cnf.BlockedPatterns {
		scriptTagPattern := regexp.MustCompile(patterns)
		if r.Method == "GET" {
			if scriptTagPattern.MatchString(r.URL.RequestURI()) {
				foundPatterns = append(foundPatterns, patterns)
			}
		} else if r.Method == "POST" {
			buf := new(strings.Builder)
			_, err := io.Copy(buf, r.Body)
			if err != nil {
				return false, err
			}
			bufString := buf.String()
			r.Body = io.NopCloser(strings.NewReader(bufString))
			if scriptTagPattern.MatchString(bufString) {
				foundPatterns = append(foundPatterns, patterns)
			}
		}
	}
	if len(foundPatterns) == 0 {
		return false, nil
	}
	wf.logger.Info("Requst contains user custom patterns injected.",
		"method", r.Method,
		"ip", r.RemoteAddr,
		"url", r.URL,
		"breaked custom patterns", foundPatterns)
	w.WriteHeader(http.StatusForbidden)
	if _, err := w.Write([]byte("custom pattern injectin found")); err != nil {
		return true, err
	}
	return true, nil
}

func (wf *Waf) WebAppFirewall(w http.ResponseWriter, r *http.Request) {
	wf.Promethues.numberOfRequests.Inc()
	if len(wf.Cnf.AllowedHTTPMethods) > 0 {
		if notSafe, err := wf.checkHTTPMethod(w, r); err != nil || notSafe {
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				wf.logger.Error(err.Error())
			}
			return
		}
	}
	if len(wf.Cnf.IpBlackList) > 0 {
		if notSafe, err := wf.checkIP(w, r); err != nil || notSafe {
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				wf.logger.Error(err.Error())
			}
			return

		}
	}
	if len(wf.Cnf.QueryUrlWhitelist) > 0 {
		if notSafe, err := wf.checkUrl(w, r); err != nil || notSafe {
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				wf.logger.Error(err.Error())
			}
			return
		}
	}
	if len(wf.Cnf.BlockedPatterns) > 0 {
		if notSafe, err := wf.checkCustomPatterns(w, r); err != nil || notSafe {
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				wf.logger.Error(err.Error())
			}
			return
		}
	}
	if notSafe, err := wf.checkSQLInjection(w, r); err != nil || notSafe {
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			wf.logger.Error(err.Error())
		}
		return
	}
	if notSafe, err := wf.checkXSSInjection(w, r); err != nil || notSafe {
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			wf.logger.Error(err.Error())
		}
		return
	}

	proxyReq, err := http.NewRequest(r.Method, wf.backendAddress+r.URL.Path, r.Body)
	if err != nil {
		wf.logger.Error("error creating request")
		w.WriteHeader(http.StatusInternalServerError)
		if _, err := w.Write([]byte("Internal Server Error")); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			wf.logger.Error(err.Error())
			return
		}
		wf.logger.Error(err.Error())
		return
	}
	proxyReq.Header = r.Header
	client := &http.Client{}
	resp, err := client.Do(proxyReq)
	if err != nil {
		wf.logger.Error("error forwarding request")
		w.WriteHeader(http.StatusInternalServerError)
		if _, err := w.Write([]byte("Internal Server Error")); err != nil {
			wf.logger.Error(err.Error())
			return
		}
		wf.logger.Error(err.Error())
		return
	}
	defer resp.Body.Close()
	w.WriteHeader(resp.StatusCode)
	if _, err = io.Copy(w, resp.Body); err != nil {
		wf.logger.Error(err.Error())
	}

}
