package tests

import (
	"strings"
	"testing"

	"go_hba_rules/pkg/hba"
)

func TestParseHBA(t *testing.T) {
	input := `# comment
host all all 10.0.0.0/16 md5
local all all peer
hostssl mydb app_user 10.0.0.5/32 scram-sha-256 clientcert=verify-full
`
	rules, err := hba.ParseHBA(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(rules))
	}
	if rules[0].Type != "host" || rules[0].Method != "md5" {
		t.Fatalf("unexpected rule[0]: %+v", rules[0])
	}
	if rules[1].Type != "local" || rules[1].Method != "peer" {
		t.Fatalf("unexpected rule[1]: %+v", rules[1])
	}
	if rules[2].Opts["clientcert"] != "verify-full" {
		t.Fatalf("expected clientcert option")
	}
}
