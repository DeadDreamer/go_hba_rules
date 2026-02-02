package hba

// Severity фиксирует уровень проблемы, чтобы CLI мог выйти с ошибкой на ERROR.
type Severity string

const (
	SeverityError Severity = "ERROR"
	SeverityWarn  Severity = "WARN"
	SeverityInfo  Severity = "INFO"
)

// Issue — единичная найденная проблема/предупреждение по строке pg_hba.
// Code без пробелов, чтобы удобно парсить/фильтровать в скриптах.
type Issue struct {
	Severity Severity // уровень: ERROR/WARN/INFO
	Code     string   // машинно-читаемый код проблемы
	Line     int      // номер строки в файле
	Message  string   // человекочитаемое описание
}

// Rule — нормализованное представление строки pg_hba.conf
// (без комментариев и пустых строк). Минимальный набор полей
// для всех реализованных проверок.
type Rule struct {
	Line   int               // номер строки в оригинальном файле
	Raw    string            // исходная строка (для отладки)
	Type   string            // type: local/host/hostssl/...
	DBs    []string          // список БД (lowercase)
	Users  []string          // список пользователей (lowercase)
	Addr   AddrSet           // нормализованный адрес/сеть
	Method string            // метод аутентификации (lowercase)
	Opts   map[string]string // параметры auth-options
}

func (r Rule) HasDB(token string) bool {
	return containsToken(r.DBs, token)
}

func (r Rule) HasUser(token string) bool {
	return containsToken(r.Users, token)
}

func (r Rule) IsLocal() bool {
	return r.Type == "local"
}

func (r Rule) IsHost() bool {
	return r.Type == "host" || r.Type == "hostssl" || r.Type == "hostnossl" || r.Type == "hostgssenc" || r.Type == "hostnogssenc"
}
