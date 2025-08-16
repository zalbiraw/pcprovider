//go:build preview
// +build preview

// Package main provides a small preview tool to run the provider and print one configuration snapshot.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"os"
	"strings"

	"pcprovider"
)

func main() {
	// Flags (optional, envs are primary)
	var (
		name  = flag.String("name", "preview", "provider instance name")
		pcURL = flag.String("pc-url", envOr("PC_URL", ""), "Prism Central base URL (or PC_URL)")
		user  = flag.String("username", envOr("PC_USERNAME", ""), "Prism Central username (or PC_USERNAME)")
		pass  = flag.String("password", envOr("PC_PASSWORD", ""), "Prism Central password (or PC_PASSWORD)")
		token = flag.String("token", envOr("PC_BEARER_TOKEN", ""), "Prism Central bearer token (or PC_BEARER_TOKEN)")
		insec = flag.Bool("insecure-skip-verify", envBool("INSECURE_SKIP_VERIFY"), "skip TLS verification (or INSECURE_SKIP_VERIFY)")
		key   = flag.String("category-key", envOr("CATEGORY_KEY", "TraefikServiceName"), "category key to group by (or CATEGORY_KEY)")
	)
	flag.Parse()

	cfg := pcprovider.CreateConfig()
	cfg.PCURL = firstNonEmpty(*pcURL, cfg.PCURL)
	cfg.Username = *user
	cfg.Password = *pass
	cfg.BearerToken = *token
	cfg.InsecureSkipVerify = *insec
	cfg.CategoryKey = firstNonEmpty(*key, cfg.CategoryKey)

	p, err := pcprovider.New(context.Background(), cfg, *name)
	if err != nil {
		log.Fatalf("init error: %v", err)
	}

	cfgChan := make(chan json.Marshaler, 1)
	if err := p.Provide(cfgChan); err != nil {
		log.Fatalf("provide error: %v", err)
	}
	// Read a single configuration snapshot and print it.
	marshaled := <-cfgChan
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(marshaled); err != nil {
		log.Fatalf("encode error: %v", err)
	}
	_ = p.Stop()
}

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func envBool(k string) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(k)))
	return v == "1" || v == "true" || v == "yes"
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
