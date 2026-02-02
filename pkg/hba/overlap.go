package hba

import "fmt"

// CheckOverlaps проверяет перекрытия правил в порядке файла и помечает затенённые.
// Упрощения: не анализируем спец-значения sameuser/samerole, но ловим частые кейсы:
// ранний reject, host перекрывает hostssl, более широкое менее строгое правило, дубликаты.
func CheckOverlaps(rules []Rule) []Issue {
	var issues []Issue
	for j := 0; j < len(rules); j++ {
		rj := rules[j]
		for i := 0; i < j; i++ {
			ri := rules[i]
			if !compatibleType(ri.Type, rj.Type) {
				continue
			}
			if ri.Type == "local" && rj.Type == "local" {
				// ok
			}
			if !ri.Addr.Covers(rj.Addr) && !ri.Addr.Intersects(rj.Addr) {
				continue
			}
			if !dbCovers(ri.DBs, rj.DBs) && !dbIntersects(ri.DBs, rj.DBs) {
				continue
			}
			if !userCovers(ri.Users, rj.Users) && !userIntersects(ri.Users, rj.Users) {
				continue
			}

			covers := ri.Addr.Covers(rj.Addr) && dbCovers(ri.DBs, rj.DBs) && userCovers(ri.Users, rj.Users) && optsNotStricter(ri.Opts, rj.Opts)
			intersects := ri.Addr.Intersects(rj.Addr) && dbIntersects(ri.DBs, rj.DBs) && userIntersects(ri.Users, rj.Users)

			if covers {
				issues = append(issues, overlapIssues(ri, rj)...)
				continue
			}
			if intersects {
				issues = append(issues, Issue{
					Severity: SeverityWarn,
					Code:     "partialOverlap",
					Line:     rj.Line,
					Message:  fmt.Sprintf("Rule partially overlaps with line %d.", ri.Line),
				})
				continue
			}
		}
	}
	return issues
}

// overlapIssues формирует список предупреждений/ошибок для пары (верхнее, нижнее) правил,
// когда верхнее полностью покрывает нижнее.
func overlapIssues(upper Rule, lower Rule) []Issue {
	var issues []Issue
	if upper.Method == "reject" && lower.Method != "reject" {
		issues = append(issues, Issue{
			Severity: SeverityError,
			Code:     "shadowedByReject",
			Line:     lower.Line,
			Message:  fmt.Sprintf("Rule is shadowed by reject at line %d.", upper.Line),
		})
		return issues
	}

	if upper.Type == "host" && (lower.Type == "hostssl" || lower.Type == "hostnossl") {
		issues = append(issues, Issue{
			Severity: SeverityWarn,
			Code:     "shadowedByHost",
			Line:     lower.Line,
			Message:  fmt.Sprintf("host rule at line %d shadows this rule.", upper.Line),
		})
	}

	if isWeaker(upper.Method, lower.Method) {
		issues = append(issues, Issue{
			Severity: SeverityWarn,
			Code:     "overlyBroadRule",
			Line:     upper.Line,
			Message:  fmt.Sprintf("Broad rule shadows stricter rule at line %d.", lower.Line),
		})
		issues = append(issues, Issue{
			Severity: SeverityWarn,
			Code:     "shadowedByBroadRule",
			Line:     lower.Line,
			Message:  fmt.Sprintf("Rule is shadowed by broader rule at line %d.", upper.Line),
		})
		return issues
	}

	if upper.Method == lower.Method && optsEqual(upper.Opts, lower.Opts) {
		issues = append(issues, Issue{
			Severity: SeverityInfo,
			Code:     "redundantRule",
			Line:     lower.Line,
			Message:  fmt.Sprintf("Rule is redundant due to line %d.", upper.Line),
		})
		return issues
	}

	issues = append(issues, Issue{
		Severity: SeverityWarn,
		Code:     "shadowedRule",
		Line:     lower.Line,
		Message:  fmt.Sprintf("Rule is fully shadowed by line %d.", upper.Line),
	})
	return issues
}

func compatibleType(a, b string) bool {
	if a == b {
		return true
	}
	// host считается супером для hostssl/hostnossl/...
	if a == "host" && (b == "host" || b == "hostssl" || b == "hostnossl" || b == "hostgssenc" || b == "hostnogssenc") {
		return true
	}
	if b == "host" && (a == "host" || a == "hostssl" || a == "hostnossl" || a == "hostgssenc" || a == "hostnogssenc") {
		return true
	}
	return false
}

func dbCovers(a, b []string) bool {
	if containsToken(a, "all") {
		return true
	}
	if containsToken(b, "all") {
		return false
	}
	for _, v := range b {
		if !containsToken(a, v) {
			return false
		}
	}
	return true
}

func dbIntersects(a, b []string) bool {
	if containsToken(a, "all") || containsToken(b, "all") {
		return true
	}
	for _, v := range a {
		if containsToken(b, v) {
			return true
		}
	}
	return false
}

func userCovers(a, b []string) bool {
	if containsToken(a, "all") {
		return true
	}
	if containsToken(b, "all") {
		return false
	}
	for _, v := range b {
		if !containsToken(a, v) {
			return false
		}
	}
	return true
}

func userIntersects(a, b []string) bool {
	if containsToken(a, "all") || containsToken(b, "all") {
		return true
	}
	for _, v := range a {
		if containsToken(b, v) {
			return true
		}
	}
	return false
}

func optsNotStricter(a, b map[string]string) bool {
	// Проверяем, что набор опций верхнего правила не строже нижнего.
	// Если верхнее требует что-то (clientcert=verify-full), а нижнее — нет,
	// то верхнее не считается перекрывающим (возвращаем false).
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}

func optsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func isWeaker(upper, lower string) bool {
	// Очень грубая шкала «слабых»/«сильных» методов для подсветки перекрытия.
	// Если нужно точнее, расширяем списки или вводим веса.
	weak := map[string]bool{
		"trust":    true,
		"md5":      true,
		"password": true,
	}
	strong := map[string]bool{
		"scram-sha-256": true,
		"cert":          true,
		"gss":           true,
		"sspi":          true,
		"ldap":          true,
		"pam":           true,
		"radius":        true,
		"peer":          true,
		"ident":         true,
	}
	if weak[upper] && strong[lower] {
		return true
	}
	return false
}
