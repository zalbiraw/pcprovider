package pcprovider

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestCreateConfigDefaults(t *testing.T) {
	cfg := CreateConfig()
	if strings.TrimSpace(cfg.CategoryKey) == "" {
		t.Fatalf("expected default CategoryKey, got %#v", cfg.CategoryKey)
	}
	if cfg.PollInterval == "" {
		t.Fatalf("expected default PollInterval, got empty")
	}
}

func TestNewRequiresPCURL(t *testing.T) {
	cfg := CreateConfig()
	cfg.PCURL = "" // ensure missing
	if _, err := New(context.Background(), cfg, "test"); err == nil {
		t.Fatal("expected error when pcURL is missing")
	}
}

func TestCollectIPs(t *testing.T) {
	vm := map[string]any{
		"nics": []any{
			map[string]any{
				"ip_endpoint_list": []any{
					map[string]any{"ip": "10.0.0.1"},
				},
				"ipAddresses": []any{"10.0.0.2", ""},
			},
		},
	}
	ips := collectIPs(vm)
	want := []string{"10.0.0.1", "10.0.0.2"}
	if !reflect.DeepEqual(ips, want) {
		t.Fatalf("collectIPs got %#v want %#v", ips, want)
	}
}

func TestGroupByCategories(t *testing.T) {
	// Build a fake category index as returned by /api/prism/v4.1/config/categories
	catIndex := map[string]CategoryInfo{
		"ext-foo":   {ExtID: "ext-foo", Key: "TraefikServiceName", Value: "foo"},
		"ext-other": {ExtID: "ext-other", Key: "other", Value: "bar"},
	}

	vms := []map[string]any{
		{
			"categories": []any{
				map[string]any{"extId": "ext-foo"},
			},
			"nics": []any{map[string]any{"ipAddresses": []any{"10.0.0.1"}}},
		},
		{
			"categories": []any{
				map[string]any{"extId": "ext-foo"},
			},
			"nics": []any{map[string]any{"ip_endpoint_list": []any{map[string]any{"ip": "10.0.0.2"}}}},
		},
		{
			"categories": []any{
				map[string]any{"extId": "ext-other"},
			},
			"nics": []any{map[string]any{"ipAddresses": []any{"10.0.0.3"}}},
		},
	}

	groups := groupByCategories(vms, []string{"TraefikServiceName", "other"}, catIndex)
	if got := groups["TraefikServiceName"]["foo"]; !reflect.DeepEqual(got, []serverTarget{{IP: "10.0.0.1"}, {IP: "10.0.0.2"}}) {
		t.Fatalf("grouping mismatch for TraefikServiceName=foo: %#v", got)
	}
	if got := groups["other"]["bar"]; !reflect.DeepEqual(got, []serverTarget{{IP: "10.0.0.3"}}) {
		t.Fatalf("grouping mismatch for other=bar: %#v", got)
	}
}

// Scheme derivation is not tested here; scheme defaults are applied in pushOnce when building servers.
