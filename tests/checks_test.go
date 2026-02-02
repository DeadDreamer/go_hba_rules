package tests

import (
	"strings"
	"testing"

	"go_hba_rules/pkg/hba"
)

func TestSimpleChecks(t *testing.T) {
	input := `host all all 0.0.0.0/0 trust
host all all 10.0.0.0/16 password
hostssl all all 10.0.0.5/32 password
host all all 10.0.0.0/16 md5
host all all 0.0.0.0/0 scram-sha-256
host all all 10.0.0.0/16 scram-sha-256
host replication all 0.0.0.0/0 scram-sha-256
host all all 10.0.0.0/16 ident
host all all 10.0.0.0/16 ident map=missingmap
host all all 10.0.0.0/16 peer
local all all trust
host all all 10.0.0.0/16 scram-sha-256 clientcert=verify-ca
hostssl all all 10.0.0.0/16 scram-sha-256 clientcert=bad
`
	rules, err := hba.ParseHBA(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	ident := hba.ParseIdent(strings.NewReader("validmap osuser dbuser\n"))
	issues := hba.CheckSimpleRules(rules, hba.Config{SSLOn: true, Ident: ident, WideV4: 16, WideV6: 48})

	want := []string{
		"trustNetwork",
		"passwordNoTLS",
		"passwordWithTLS",
		"md5Deprecated",
		"wideAddress",
		"allDbAllUser",
		"replicationWideAccess",
		"identNoMap",
		"identMapMissing",
		"peerNonLocal",
		"localAllAll",
		"clientcertNonHostssl",
		"clientcertInvalid",
		"nonTLSPath",
	}
	for _, code := range want {
		if !hasCode(issues, code) {
			t.Fatalf("expected code %s", code)
		}
	}
}

func hasCode(issues []hba.Issue, code string) bool {
	for _, is := range issues {
		if is.Code == code {
			return true
		}
	}
	return false
}
