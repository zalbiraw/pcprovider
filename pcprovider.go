// Package pcprovider provides a Traefik provider that discovers VMs from
// Nutanix Prism Central and builds HTTP services grouped by a category
// key (default: "TraefikServiceName").
package pcprovider

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/traefik/genconf/dynamic"
)

const (
	schemeHTTP        = "http"
	schemeHTTPS       = "https"
	categorySchemeKey = "traefikServiceScheme"
)

// Config the plugin configuration.
type Config struct {
	// PollInterval is how often to refresh from Prism Central, e.g. "30s".
	PollInterval string `json:"pollInterval,omitempty"`

	// PCURL is the base URL to Prism Central, e.g. "https://pc.example.com".
	PCURL string `json:"pcUrl,omitempty"`

	// Username and Password for basic auth. If a BearerToken is provided, it takes precedence.
	Username    string `json:"username,omitempty"`
	Password    string `json:"password,omitempty"`
	BearerToken string `json:"bearerToken,omitempty"`

	// InsecureSkipVerify allows skipping TLS verification for self-signed PC certs.
	InsecureSkipVerify bool `json:"insecureSkipVerify,omitempty"`

	// CategoryKey is the category key to group services by.
	// Services will be created per category value, e.g. "<key>-<value>".
	// Default: "TraefikServiceName".
	CategoryKey string `json:"categoryKey,omitempty"`
}

// CategoryInfo represents a Prism Central category with key/value and extId.
type CategoryInfo struct {
	ExtID string
	Key   string
	Value string
}

// fetchCategories retrieves category entries and returns an index by extId.
// Only categories whose key is present in allowedKeys are included.
func (p *Provider) fetchCategories(key string) (map[string]CategoryInfo, error) {
	path := "/api/prism/v4.1/config/categories"
	payload, _, err := p.fetchGET(path, nil)
	if err != nil {
		return nil, err
	}
	items := extractArray(payload, "data")

	out := make(map[string]CategoryInfo, len(items))
	for _, it := range items {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		v, ok := m["key"].(string)
		if !ok || v != key {
			continue
		}

		ext, _ := m["extId"].(string)
		val, _ := m["value"].(string)
		if ext == "" || val == "" {
			// Skip incomplete entries.
			continue
		}

		out[ext] = CategoryInfo{ExtID: ext, Key: key, Value: val}
	}

	return out, nil
}

// groupByCategories groups VMs by configured category keys using category extIds.
// Returns a nested map: key -> (category value -> []serverTarget).
//
//nolint:gocyclo // readability favored; logic split elsewhere would add overhead
func groupByCategories(vms []map[string]any, keys []string, catIndex map[string]CategoryInfo) map[string]map[string][]serverTarget {
	// Build a set of keys for quick membership checks.
	keySet := map[string]struct{}{}
	for _, k := range keys {
		if strings.TrimSpace(k) != "" {
			keySet[k] = struct{}{}
		}
	}

	groups := map[string]map[string][]serverTarget{}
	initGroup := func(ci CategoryInfo) {
		if _, ok := keySet[ci.Key]; !ok {
			return
		}
		if _, exists := groups[ci.Key]; !exists {
			groups[ci.Key] = map[string][]serverTarget{}
		}
		if _, exists := groups[ci.Key][ci.Value]; !exists {
			groups[ci.Key][ci.Value] = []serverTarget{}
		}
	}
	// Initialize outer map with known keys from index to ensure deterministic presence.
	for _, ci := range catIndex {
		initGroup(ci)
	}

	for _, vm := range vms {
		// Extract category extIds.
		vmCatExts := extractCategoryExtIDs(vm)

		ips := collectIPs(vm)
		if len(ips) == 0 {
			continue
		}
		// For each VM category extId, resolve and match configured keys.
		for _, ext := range vmCatExts {
			ci, ok := catIndex[ext]
			if !ok {
				continue
			}
			if _, want := keySet[ci.Key]; !want {
				continue
			}
			initGroup(ci)
			for _, ip := range ips {
				groups[ci.Key][ci.Value] = appendServerUnique(groups[ci.Key][ci.Value], serverTarget{IP: ip})
			}
		}
	}
	return groups
}

// extractCategoryExtIDs extracts category extIds from a VM object where categories is an array of references.
func extractCategoryExtIDs(vm map[string]any) []string {
	var exts []string
	// Primary field name used by our $select
	if catsAny, ok := vm["categories"].([]any); ok {
		for _, c := range catsAny {
			if cm, ok := c.(map[string]any); ok {
				if s, ok := cm["extId"].(string); ok && s != "" {
					exts = append(exts, s)
				}
			}
		}
	}
	// Compatibility: some payloads may expose category references under a different field name.
	if catsAny, ok := vm["categoryReferences"].([]any); ok {
		for _, c := range catsAny {
			if cm, ok := c.(map[string]any); ok {
				if s, ok := cm["extId"].(string); ok && s != "" {
					exts = append(exts, s)
				}
			}
		}
	}
	return unique(exts)
}

func appendServerUnique(base []serverTarget, more ...serverTarget) []serverTarget {
	seen := map[string]struct{}{}
	for _, s := range base {
		seen[s.Scheme+"|"+s.IP] = struct{}{}
	}
	for _, s := range more {
		key := s.Scheme + "|" + s.IP
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			base = append(base, s)
		}
	}
	return base
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		PollInterval:       "30s",
		CategoryKey:        "TraefikServiceName",
		InsecureSkipVerify: false,
	}
}

// Provider queries Prism Central and produces Traefik dynamic services.
type Provider struct {
	name         string
	pollInterval time.Duration

	client      *http.Client
	baseURL     string
	authToken   string
	username    string
	password    string
	categoryKey string

	cancel func()
}

// New creates a new Provider plugin.
func New(ctx context.Context, config *Config, name string) (*Provider, error) {
	if config == nil {
		return nil, errors.New("config is nil")
	}

	// Use only provided config values; do not read from environment here.
	pcURL := strings.TrimSpace(config.PCURL)
	username := strings.TrimSpace(config.Username)
	password := strings.TrimSpace(config.Password)
	bearer := strings.TrimSpace(config.BearerToken)

	if pcURL == "" {
		return nil, errors.New("pcURL is required")
	}

	// Auth validation: require either bearer token OR both username and password.
	if bearer == "" {
		if username == "" || password == "" {
			return nil, errors.New("authentication required: set bearerToken or both username and password")
		}
	}

	pi, err := time.ParseDuration(firstNonEmpty(config.PollInterval, "30s"))
	if err != nil {
		return nil, fmt.Errorf("invalid poll interval: %w", err)
	}

	// HTTP client with optional TLS skip-verify.
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: config.InsecureSkipVerify}} //nolint:gosec
	httpClient := &http.Client{Timeout: 30 * time.Second, Transport: transport}

	// Default category key if not provided
	catKey := strings.TrimSpace(config.CategoryKey)
	if catKey == "" {
		catKey = "TraefikServiceName"
	}

	return &Provider{
		name:         name,
		pollInterval: pi,
		client:       httpClient,
		baseURL:      strings.TrimRight(pcURL, "/"),
		authToken:    bearer,
		username:     username,
		password:     password,
		categoryKey:  catKey,
	}, nil
}

// Init the provider.
func (p *Provider) Init() error {
	if p.pollInterval <= 0 {
		return fmt.Errorf("poll interval must be greater than 0")
	}
	return nil
}

// Provide creates and sends dynamic configuration.
func (p *Provider) Provide(cfgChan chan<- json.Marshaler) error {
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel

	go func() {
		defer func() {
			if err := recover(); err != nil {
				log.Print(err)
			}
		}()

		p.loadConfiguration(ctx, cfgChan)
	}()

	return nil
}

func (p *Provider) loadConfiguration(ctx context.Context, cfgChan chan<- json.Marshaler) {
	// Immediately load once, then on ticker.
	p.pushOnce(cfgChan)

	ticker := time.NewTicker(p.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.pushOnce(cfgChan)
		case <-ctx.Done():
			return
		}
	}
}

func (p *Provider) pushOnce(cfgChan chan<- json.Marshaler) {
	configuration := &dynamic.Configuration{
		HTTP: &dynamic.HTTPConfiguration{
			Routers:           make(map[string]*dynamic.Router),
			Middlewares:       make(map[string]*dynamic.Middleware),
			Services:          make(map[string]*dynamic.Service),
			ServersTransports: make(map[string]*dynamic.ServersTransport),
		},
	}

	groups, err := p.fetchServiceGroups(p.categoryKey)
	if err != nil {
		log.Printf("pcprovider: fetch error: %v", err)
		// still push empty configuration to avoid blocking Traefik
		cfgChan <- &dynamic.JSONPayload{Configuration: configuration}
		return
	}

	for key, targets := range groups {
		if len(targets) == 0 {
			continue
		}

		servers := make([]dynamic.Server, 0, len(targets))
		for _, t := range targets {
			scheme := t.Scheme
			if scheme == "" {
				scheme = schemeHTTP
			}
			servers = append(servers, dynamic.Server{URL: fmt.Sprintf("%s://%s", scheme, t.IP)})
		}
		configuration.HTTP.Services[key] = &dynamic.Service{
			LoadBalancer: &dynamic.ServersLoadBalancer{
				Servers:        servers,
				PassHostHeader: boolPtr(true),
			},
		}
	}

	cfgChan <- &dynamic.JSONPayload{Configuration: configuration}
}

// Stop to stop the provider and the related go routines.
func (p *Provider) Stop() error {
	if p.cancel != nil {
		p.cancel()
	}
	return nil
}

// fetchServiceGroups queries Prism Central for VMs and returns a nested map of
// key -> (category value -> list of IPs) for VMs where each key has a value.
type serverTarget struct {
	IP     string `json:"ip"`
	Scheme string `json:"scheme"`
}

func (p *Provider) fetchServiceGroups(key string) (map[string][]serverTarget, error) {
	// Build category extId index first (for resolving VM category references).
	catIndex, err := p.fetchCategories(key)
	if err != nil {
		return nil, err
	}

	payload, err := p.fetchVMsPayload()
	if err != nil {
		return nil, err
	}
	items := extractArray(payload, "entities")
	if len(items) == 0 {
		items = extractArray(payload, "data")
	}
	// Normalize items into []map[string]any representing VMs.
	vms := make([]map[string]any, 0, len(items))
	for _, it := range items {
		if m, ok := it.(map[string]any); ok {
			vms = append(vms, m)
		}
	}

	all := groupByCategories(vms, []string{p.categoryKey}, catIndex)
	// Ensure we always return a non-nil map for the requested key.
	if out, ok := all[p.categoryKey]; ok {
		return out, nil
	}
	return map[string][]serverTarget{}, nil
}

func (p *Provider) fetchVMsPayload() (map[string]any, error) {
	// Simplified: fetch from a single v4.1 endpoint that returns VM configs.
	path := "/api/vmm/v4.1/ahv/config/vms"
	// Keep server-side power filter, but do not restrict fields to ensure NIC IPs are present.
	q := map[string]string{
		"$filter": "powerState eq Vmm.Ahv.Config.PowerState'ON'",
		"$select": "name,nics,categories",
	}
	payload, _, err := p.fetchGET(path, q)
	if err != nil {
		return nil, err
	}
	return payload, nil
}

//nolint:unparam // status code can be useful for future callers; keep signature.
func (p *Provider) fetchGET(path string, qparams map[string]string) (map[string]any, int, error) {
	u, err := url.Parse(p.baseURL + path)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid URL: %w", err)
	}
	q := u.Query()
	for k, v := range qparams {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, 0, err
	}
	p.applyAuth(req)
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return nil, resp.StatusCode, fmt.Errorf("PC API status %d: %s", resp.StatusCode, string(body))
	}
	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, resp.StatusCode, err
	}
	return payload, resp.StatusCode, nil
}

func (p *Provider) applyAuth(req *http.Request) {
	if p.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+p.authToken)
	} else if p.username != "" || p.password != "" {
		req.SetBasicAuth(p.username, p.password)
	}
}

func collectIPs(vm map[string]any) []string {
	nicsAny, ok := vm["nics"].([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, n := range nicsAny {
		if nic, ok := n.(map[string]any); ok {
			out = append(out, collectIPsFromAddresses(nic)...)
		}
	}
	return unique(out)
}

//nolint:gocognit,gocyclo // supports multiple payload shapes; kept together intentionally
func collectIPsFromAddresses(nic map[string]any) []string {
	var out []string
	collectFromEndpoints := func() {
		eps, ok := nic["ip_endpoint_list"].([]any)
		if !ok {
			return
		}
		for _, e := range eps {
			m, ok := e.(map[string]any)
			if !ok {
				continue
			}
			ip, ok := m["ip"].(string)
			if ok && strings.TrimSpace(ip) != "" {
				out = append(out, strings.TrimSpace(ip))
			}
		}
	}
	collectFromStrings := func() {
		arr, ok := nic["ipAddresses"].([]any)
		if !ok {
			return
		}
		for _, v := range arr {
			s, ok := v.(string)
			if ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
	}
	collectFromNested := func() {
		for _, netKey := range []string{"nicNetworkInfo", "networkInfo"} {
			netInfo, ok := nic[netKey].(map[string]any)
			if !ok {
				continue
			}
			ipv4, ok := netInfo["ipv4Config"].(map[string]any)
			if !ok {
				continue
			}
			ipObj, ok := ipv4["ipAddress"].(map[string]any)
			if !ok {
				continue
			}
			ip, ok := ipObj["value"].(string)
			if ok && strings.TrimSpace(ip) != "" {
				out = append(out, strings.TrimSpace(ip))
			}
		}
	}

	collectFromEndpoints()
	collectFromStrings()
	collectFromNested()
	return out
}

func unique(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

func extractArray(m map[string]any, key string) []any {
	if v, ok := m[key]; ok {
		if arr, ok := v.([]any); ok {
			return arr
		}
	}
	return nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// boolPtr returns a pointer to the provided bool value.
func boolPtr(b bool) *bool { return &b }
