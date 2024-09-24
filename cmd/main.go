package main

import (
	"log"

	waf "github.com/codescalersinternships/easywaf-nabil-salma/pkg"
)

func main() {
	_, err := waf.NewWaf("http://localhost:8090")
	if err != nil {
		log.Fatal(err)
	}
}
