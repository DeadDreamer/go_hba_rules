package tests

import (
	"strings"
	"testing"

	"go_hba_rules/pkg/hba"
)

func TestOverlapChecks(t *testing.T) {
	input := `host all all 0.0.0.0/0 trust
host mydb app 10.0.0.5/32 scram-sha-256
host all all 10.0.0.0/16 reject
host mydb app 10.0.0.5/32 scram-sha-256
host all all 0.0.0.0/0 md5
hostssl all all 0.0.0.0/0 scram-sha-256
host all all 10.0.0.0/16 scram-sha-256
host mydb app 10.0.0.5/32 scram-sha-256
host all all 10.0.0.0/24 scram-sha-256
host all all 10.0.0.0/16 scram-sha-256
`
	rules, err := hba.ParseHBA(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	issues := hba.CheckOverlaps(rules)

	want := []string{
		"overlyBroadRule",
		"shadowedByBroadRule",
		"shadowedByReject",
		"shadowedByHost",
		"redundantRule",
		"partialOverlap",
	}
	for _, code := range want {
		if !hasCode(issues, code) {
			t.Fatalf("expected code %s", code)
		}
	}
}
