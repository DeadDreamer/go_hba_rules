package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"go_hba_rules/pkg/hba"
)

func main() {
	var hbaPath string
	var identPath string
	var sslOn bool
	var wideV4 int
	var wideV6 int
	flag.StringVar(&hbaPath, "hba", "", "path to pg_hba.conf")
	flag.StringVar(&identPath, "ident", "", "path to pg_ident.conf")
	flag.BoolVar(&sslOn, "ssl", true, "set to false if server SSL is off")
	flag.IntVar(&wideV4, "wide4", 16, "IPv4 prefix threshold for wide networks")
	flag.IntVar(&wideV6, "wide6", 48, "IPv6 prefix threshold for wide networks")
	flag.Parse()

	if hbaPath == "" {
		fmt.Fprintln(os.Stderr, "missing -hba")
		os.Exit(2)
	}
	if identPath == "" {
		identPath = filepath.Join(filepath.Dir(hbaPath), "pg_ident.conf")
	}

	hbaFile, err := os.Open(hbaPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open hba: %v\n", err)
		os.Exit(2)
	}
	defer hbaFile.Close()

	rules, err := hba.ParseHBA(hbaFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse hba: %v\n", err)
		os.Exit(2)
	}

	ident := hba.IdentMap{}
	if f, err := os.Open(identPath); err == nil {
		ident = hba.ParseIdent(f)
		f.Close()
	}

	issues := hba.CheckAll(rules, hba.Config{
		SSLOn:  sslOn,
		Ident:  ident,
		WideV4: wideV4,
		WideV6: wideV6,
	})
	for _, is := range issues {
		fmt.Printf("%s %s line=%d %s\n", is.Severity, is.Code, is.Line, is.Message)
	}

	if hasError(issues) {
		os.Exit(1)
	}
}

func hasError(issues []hba.Issue) bool {
	for _, is := range issues {
		if is.Severity == hba.SeverityError {
			return true
		}
	}
	return false
}
