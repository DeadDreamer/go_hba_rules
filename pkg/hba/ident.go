package hba

import (
	"bufio"
	"io"
	"strings"
)

// IdentMap хранит список map-ов из pg_ident для проверки наличия map=...
type IdentMap struct {
	Maps map[string]bool
}

// ParseIdent парсит pg_ident.conf, собирая имена map (первый столбец).
// Остальные колонки нам не нужны для текущих проверок (только факт существования map).
func ParseIdent(r io.Reader) IdentMap {
	maps := map[string]bool{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		line = stripComment(line)
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		name := strings.ToLower(fields[0])
		if name != "" {
			maps[name] = true
		}
	}
	return IdentMap{Maps: maps}
}

func (m IdentMap) Has(name string) bool {
	if name == "" {
		return false
	}
	return m.Maps[strings.ToLower(name)]
}
