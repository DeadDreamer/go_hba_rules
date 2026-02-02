package hba

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// ParseHBA читает pg_hba.conf-подобный поток, отбрасывает комментарии/пустые строки
// и возвращает нормализованный список правил. Минимальные валидации: количество полей,
// корректность адреса для host*, распознавание метода и опций.
// Задача функции — не «строгий парсер postgres», а быстрый и безопасный разбор для статанализа.
func ParseHBA(r io.Reader) ([]Rule, error) {
	var rules []Rule
	scanner := bufio.NewScanner(r)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		raw := scanner.Text()
		line := stripComment(raw)
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			return nil, fmt.Errorf("line %d: not enough fields", lineNo)
		}

		var rule Rule
		rule.Line = lineNo
		rule.Raw = raw
		rule.Type = strings.ToLower(fields[0])
		idx := 1
		rule.DBs = parseList(fields[idx])
		idx++
		rule.Users = parseList(fields[idx])
		idx++

		if rule.IsHost() {
			// host* правила обязаны иметь адрес и метод.
			if len(fields) < idx+2 {
				return nil, fmt.Errorf("line %d: not enough fields for host rule", lineNo)
			}
			addr, err := ParseAddr(fields[idx])
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", lineNo, err)
			}
			rule.Addr = addr
			idx++
		} else {
			// local не имеет адреса; считаем покрывающим только сокеты (Any=true для упрощения покрытий).
			rule.Addr.Any = true
			rule.Addr.OrigToken = "local"
		}

		rule.Method = strings.ToLower(fields[idx])
		idx++
		rule.Opts = parseOptions(fields[idx:])

		rules = append(rules, rule)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return rules, nil
}

func stripComment(line string) string {
	if i := strings.Index(line, "#"); i >= 0 {
		return line[:i]
	}
	return line
}

// parseList разбирает поля database/user, разделённые запятой, приводит к lowercase.
func parseList(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(strings.ToLower(p))
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

// parseOptions разбирает auth-options формата key=value, игнорируя одиночные токены.
func parseOptions(parts []string) map[string]string {
	if len(parts) == 0 {
		return map[string]string{}
	}
	opts := map[string]string{}
	for _, p := range parts {
		if !strings.Contains(p, "=") {
			continue
		}
		kv := strings.SplitN(p, "=", 2)
		key := strings.ToLower(strings.TrimSpace(kv[0]))
		val := strings.TrimSpace(kv[1])
		if key == "" || val == "" {
			continue
		}
		opts[key] = val
	}
	return opts
}

// containsToken проверяет вхождение с учётом точного совпадения (списки уже lowercase).
func containsToken(list []string, token string) bool {
	for _, v := range list {
		if v == token {
			return true
		}
	}
	return false
}
