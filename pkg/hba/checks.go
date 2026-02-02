package hba

import (
	"fmt"
	"strings"
)

// Config — контекст для проверок (глобальные настройки инстанса).
// Значения могут приходить из CLI или интеграции с postgres.conf.
type Config struct {
	SSLOn  bool     // ssl=on|off
	Ident  IdentMap // содержимое pg_ident для проверки map
	WideV4 int      // порог «широкой» сети IPv4 (префикс <=)
	WideV6 int      // порог «широкой» сети IPv6 (префикс <=)
}

// CheckAll запускает все проверки: простые (по отдельной строке) и перекрытия.
func CheckAll(rules []Rule, cfg Config) []Issue {
	var issues []Issue
	issues = append(issues, CheckSimpleRules(rules, cfg)...)
	issues = append(issues, CheckOverlaps(rules)...)
	return issues
}

// CheckSimpleRules реализует «простые» проверки из readme: небезопасные методы,
// широкие сети, replication, ident/peer/clientcert и т.д.
func CheckSimpleRules(rules []Rule, cfg Config) []Issue {
	var issues []Issue
	if cfg.WideV4 == 0 {
		cfg.WideV4 = 16
	}
	if cfg.WideV6 == 0 {
		cfg.WideV6 = 48
	}
	for _, r := range rules {
		// trust по сети — прямое отключение аутентификации.
		if r.IsHost() && r.Method == "trust" {
			issues = append(issues, Issue{
				Severity: SeverityError,
				Code:     "trustNetwork",
				Line:     r.Line,
				Message:  "Unsafe: trust for network connections. Any client can log in as any user without a password.",
			})
		}

		// method=password: при ssl=off всегда ошибка; при ssl=on ошибка, если не hostssl.
		if r.Method == "password" {
			if cfg.SSLOn {
				if r.Type == "hostssl" {
					issues = append(issues, Issue{
						Severity: SeverityWarn,
						Code:     "passwordWithTLS",
						Line:     r.Line,
						Message:  "Password method sends cleartext password. Use scram-sha-256 or stronger.",
					})
				} else {
					issues = append(issues, Issue{
						Severity: SeverityError,
						Code:     "passwordNoTLS",
						Line:     r.Line,
						Message:  "Unsafe: password method without guaranteed TLS. Use hostssl + scram-sha-256.",
					})
				}
			} else { // ssl=off
				issues = append(issues, Issue{
					Severity: SeverityError,
					Code:     "passwordNoSSL",
					Line:     r.Line,
					Message:  "SSL is off; method=password always sends credentials in cleartext.",
				})
			}
		}

		if cfg.SSLOn {
			if (r.Type == "host" || r.Type == "hostnossl") && !r.Addr.IsLoopbackOnly() {
				issues = append(issues, Issue{
					Severity: SeverityWarn,
					Code:     "nonTLSPath",
					Line:     r.Line,
					Message:  "Non-TLS path exists (host/hostnossl). If TLS is required, switch to hostssl.",
				})
			}
		} else {
			// ssl=off: любые hostssl правила никогда не сработают.
			if r.Type == "hostssl" {
				issues = append(issues, Issue{
					Severity: SeverityError,
					Code:     "hostsslNoSSL",
					Line:     r.Line,
					Message:  "Server ssl=off: hostssl rule will never match. Enable ssl or change to host with proper security.",
				})
			}
		}

		// md5 — deprecated, подсказка на миграцию.
		if r.Method == "md5" {
			issues = append(issues, Issue{
				Severity: SeverityWarn,
				Code:     "md5Deprecated",
				Line:     r.Line,
				Message:  "MD5 auth is deprecated. Migrate to scram-sha-256.",
			})
		}

		// Широкие сети подсвечиваем, чтобы стянуть диапазон.
		if r.IsHost() && r.Addr.IsWideWith(cfg.WideV4, cfg.WideV6) {
			issues = append(issues, Issue{
				Severity: SeverityWarn,
				Code:     "wideAddress",
				Line:     r.Line,
				Message:  fmt.Sprintf("Address range is too wide: %s.", r.Addr.OrigToken),
			})
		}

		// all/all — отсутствие сегментации.
		if containsToken(r.DBs, "all") && containsToken(r.Users, "all") {
			issues = append(issues, Issue{
				Severity: SeverityWarn,
				Code:     "allDbAllUser",
				Line:     r.Line,
				Message:  "Overly broad access: database=all and user=all.",
			})
		}

		// replication должна быть максимально узкой.
		if r.HasDB("replication") && r.Method != "reject" {
			if r.Addr.IsWideWith(cfg.WideV4, cfg.WideV6) || r.HasUser("all") {
				issues = append(issues, Issue{
					Severity: SeverityError,
					Code:     "replicationWideAccess",
					Line:     r.Line,
					Message:  "Replication access from wide network or all users. Restrict to replica IPs and dedicated user.",
				})
			}
		}

		// ident без map — предупреждение; с несуществующим map — ошибка.
		if r.Method == "ident" {
			mapName := strings.ToLower(r.Opts["map"])
			if mapName == "" {
				issues = append(issues, Issue{
					Severity: SeverityWarn,
					Code:     "identNoMap",
					Line:     r.Line,
					Message:  "Ident used without map=. Add a map and ensure pg_ident entries exist.",
				})
			} else if !cfg.Ident.Has(mapName) {
				issues = append(issues, Issue{
					Severity: SeverityError,
					Code:     "identMapMissing",
					Line:     r.Line,
					Message:  "Ident map is missing in pg_ident.",
				})
			}
		}

		// peer допустим только для local.
		if r.Method == "peer" && r.Type != "local" {
			issues = append(issues, Issue{
				Severity: SeverityError,
				Code:     "peerNonLocal",
				Line:     r.Line,
				Message:  "Peer auth is valid only for local connections.",
			})
		}
		// local trust/peer all/all — слишком общий локальный доступ.
		if r.Type == "local" && (r.Method == "trust" || r.Method == "peer") && containsToken(r.DBs, "all") && containsToken(r.Users, "all") {
			issues = append(issues, Issue{
				Severity: SeverityWarn,
				Code:     "localAllAll",
				Line:     r.Line,
				Message:  "Local all/all with trust or peer is overly broad.",
			})
		}

		if v, ok := r.Opts["clientcert"]; ok {
			if r.Type != "hostssl" {
				issues = append(issues, Issue{
					Severity: SeverityError,
					Code:     "clientcertNonHostssl",
					Line:     r.Line,
					Message:  "clientcert is allowed only for hostssl.",
				})
			} else {
				val := strings.ToLower(v)
				if val != "verify-ca" && val != "verify-full" {
					issues = append(issues, Issue{
						Severity: SeverityError,
						Code:     "clientcertInvalid",
						Line:     r.Line,
						Message:  "clientcert must be verify-ca or verify-full.",
					})
				}
			}
		}
	}
	return issues
}
