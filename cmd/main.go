package main

import (
	"log"
	"net/http"

	waf "github.com/codescalersinternships/easywaf-nabil-salma/pkg"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	wf, registry, err := waf.NewWaf("http://localhost:8090")
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{
		Addr: ":8080",
	}
	http.HandleFunc("/",wf.WebAppFirewall)
	http.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	
	if err := server.ListenAndServe(); err != nil{
		log.Fatalf("error running server: %v", err)
	}
	
}
