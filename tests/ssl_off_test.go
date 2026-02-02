package tests

import (
	"strings"
	"testing"

	"go_hba_rules/pkg/hba"
)

func TestSSLDisabledCases(t *testing.T) {
	input := `host all all 10.0.0.0/16 password
hostssl all all 10.0.0.0/16 scram-sha-256
`
	rules, err := hba.ParseHBA(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	issues := hba.CheckSimpleRules(rules, hba.Config{SSLOn: false, WideV4: 16, WideV6: 48})

	for _, code := range []string{"passwordNoSSL", "hostsslNoSSL"} {
		if !hasCode(issues, code) {
			t.Fatalf("expected code %s", code)
		}
	}
}
