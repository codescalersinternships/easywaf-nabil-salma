package main

import (
	"log"

	waf "github.com/codescalersinternships/easywaf-nabil-salma/pkg"
)

func main() {
	_, err := waf.NewWaf()
	if err != nil {
		log.Fatal(err)
	}
	//println(w.Cnf.AllowedHTTPMethods[0])
}
