# Basic Web Application Firewall (WAF) in Go

## Overview

The Basic Web Application Firewall (WAF) is designed to act as a protective layer between a web application and incoming traffic. It filters and blocks potentially malicious requests based on predefined rules, primarily focusing on detecting and mitigating common web application attacks, such as SQL injection and XSS (Cross-Site Scripting), while allowing safe traffic to pass through.

## Features

- **Basic Request Filtering**
  - **Pattern Matching**: Detects and blocks common web attack vectors like SQL injection (`';--`, `OR 1=1`) and XSS (`<script>` tags).
  - **Request Inspection**: Inspects incoming HTTP requests for suspicious patterns in query parameters, headers, and body content.
  - **Action on Match**: Blocks requests that match malicious patterns and returns an appropriate HTTP status code (e.g., `403 Forbidden`).

- **Custom Rules**
  - **Static Rules**: Define static rules in a configuration file (YAML or JSON) specifying patterns to detect and actions to take.
  - **IP Disallow List**: Allows administrators to block requests from specific IP addresses.

- **Request Logging**
  - **Log Malicious Requests**: Logs details of blocked requests, including client IP, request URL, and the detected pattern for monitoring and auditing.
  - **Basic Log Format**: Uses a simple text-based log format and ensures log rotation to prevent excessive disk usage.

- **Prometheus Integration**: Integrates with Prometheus for monitoring metrics related to WAF performance.

- **HTTP Forward Proxy**
  - **Proxy Mode**: Functions as an HTTP proxy that forwards legitimate requests to the backend web application.
  - **Simple HTTP Server**: Utilizes Go’s built-in `net/http` package to handle incoming requests and forward them if they pass filtering rules.

- **Configuration Management**
  - **Config File**: Allows configuration via a simple config file defining rules, IP blacklists, and other settings.

## Getting Started

### Prerequisites

- Go 1.18 or later
- Docker (optional, for containerization)

### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/codescalersinternships/easywaf-nabil-salma/tree/development/pkg/
   
2. Use it in your project like this 


    ```go
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
    ```
