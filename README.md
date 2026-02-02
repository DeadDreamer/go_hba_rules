# go_hba_rules

CLI‑утилита для подсветки проблем в `pg_hba.conf` (PostgreSQL) и базовой проверки перекрытий правил (когда более широкое правило перекрывает более узкое).

## Что делает
- Проверяет «простые» правила безопасности:
  - небезопасные методы (`trust` в сети, `password` без TLS, `md5` как deprecated, `peer` вне `local`, `ident` без/с неверным map, `clientcert` не в hostssl или с плохим значением и т.д.);
  - слишком широкие сети (пороги IPv4 `/16`, IPv6 `/48` по умолчанию);
  - `database=all` + `user=all` слишком общий доступ;
  - репликация из широкой сети или для всех пользователей;
  - наличие не-TLS пути при `ssl=on` для всей СУБД (host/hostnossl);
  - неработающие `hostssl` при `ssl=off` (опционально, если выставить `-ssl=false`).
- Анализирует перекрытия правил сверху вниз: широкое правило перекрывает узкое, ранний `reject`, `host` затеняет `hostssl/hostnossl`, дубликаты и частичные пересечения.
- Выводит текстовые строки вида `SEVERITY CODE line=N message`, а при наличии `ERROR` возвращает exit code 1.

## Структура проекта
- `cmd/hba-check` — CLI входная точка.
- `pkg/hba` — основная логика: парсер, проверки, перекрытия, типы.
- `tests/` — unit‑тесты (используют публичное API из `pkg/hba`).
- `testdata/` — примерные `pg_hba.conf` и `pg_ident.conf`, плюс кейсы `case1.conf`–`case5.conf`.

## Быстрый старт
```bash
# Запуск проверок на примере
go run ./cmd/hba-check -hba testdata/pg_hba.conf -ident testdata/pg_ident.conf

# Запуск тестов
go test ./...
```

## Флаги
- `-hba <path>` — путь к `pg_hba.conf` (обязателен).
- `-ident <path>` — путь к `pg_ident.conf` (по умолчанию рядом с hba).
- `-ssl` — `true/false`, состояние `ssl` инстанса (влияет на проверки password/hostssl/non-TLS). По умолчанию `true`.
- `-wide4` — порог широких IPv4 сетей (префикс <= N), по умолчанию 16.
- `-wide6` — порог широких IPv6 сетей (префикс <= N), по умолчанию 48.

## Примеры правил и ожидаемые срабатывания
- `host all all 0.0.0.0/0 trust`
  - ERROR `trustNetwork`, WARN `nonTLSPath`, WARN `wideAddress`, WARN `allDbAllUser`.
- `host all all 10.0.0.0/16 password` (ssl=on)
  - ERROR `passwordNoTLS`, WARN `nonTLSPath`, WARN `wideAddress`, WARN `allDbAllUser`.
- `hostssl all all 10.0.0.0/16 password`
  - WARN `passwordWithTLS`, WARN `wideAddress`, WARN `allDbAllUser`.
- `host replication all 0.0.0.0/0 scram-sha-256`
  - ERROR `replicationWideAccess` (широкая сеть или user=all).
- Перекрытие: 
  - верх `host all all 0.0.0.0/0 md5`, ниже `hostssl all all 0.0.0.0/0 scram-sha-256`
    - нижнее получит WARN `shadowedByHost`, верх — WARN `overlyBroadRule`.

## Коды ошибок/предупреждений (Error codes reference)
| Code | Уровень | Описание (RU) | Description (EN) |
|------|---------|---------------|-------------------|
| trustNetwork | ERROR | Сетевое правило с методом `trust` любой, кто дотянется до порта, зайдёт как суперпользователь без пароля. | Network rule with `trust`: anyone reaching the port can log in as any user without a password. |
| passwordNoTLS | ERROR | `password` без TLS (ssl=on, но не `hostssl`): пароль уйдёт в открытом виде. | `password` without guaranteed TLS (ssl=on but not `hostssl`): password sent in cleartext. |
| passwordNoSSL | ERROR | SSL выключен, метод `password` всегда шлёт пароль в открытую — небезопасно. | SSL is off; `password` always sends credentials in cleartext. |
| passwordWithTLS | WARN | Даже в `hostssl` метод `password` передаёт пароль в открытом виде, лучше `scram/cert`. | Even over TLS, `password` sends cleartext; prefer `scram`/`cert`. |
| md5Deprecated | WARN | `md5` устарел и будет удалён, переходите на `scram-sha-256`. | `md5` is deprecated; migrate to `scram-sha-256`. |
| nonTLSPath | WARN | При `ssl=on` есть `host/hostnossl` для внешних адресов — можно подключиться без шифрования. | With ssl=on, `host/hostnossl` allows non-TLS connections from non-loopback addresses. |
| hostsslNoSSL | ERROR | При `ssl=off` правила `hostssl` никогда не сработают. | When ssl=off, `hostssl` rules never match. |
| wideAddress | WARN | Диапазон адресов шире порога (IPv4 ≤ /16, IPv6 ≤ /48 по умолчанию) — сократите сеть. | Address range wider than threshold (IPv4 ≤ /16, IPv6 ≤ /48) — narrow it down. |
| allDbAllUser | WARN | `database=all` и `user=all`: нет сегментации БД и пользователей. | `database=all` and `user=all`: no access segmentation. |
| replicationWideAccess | ERROR | Репликация разрешена из широкой сети или для всех пользователей — высокий риск компрометации. | Replication allowed from wide network or all users — high risk. |
| identNoMap | WARN | Метод `ident` без `map=`: сопоставление не определено, возможны неожиданные логины. | `ident` without `map=`: mapping undefined, may allow unexpected logins. |
| identMapMissing | ERROR | Указанный `map` отсутствует в `pg_ident.conf`, правило не сработает. | Referenced `map` is missing in `pg_ident.conf`; rule will not work. |
| peerNonLocal | ERROR | Метод `peer` допустим только для `local`, в сетевых правилах ошибка. | `peer` allowed only for `local`; invalid in host rules. |
| localAllAll | WARN | `local` с `trust/peer` и `all/all`: любой локальный пользователь зайдёт в любую БД. | `local` trust/peer with all/all: any local OS user can access any DB. |
| clientcertNonHostssl | ERROR | Опция `clientcert` допустима только в `hostssl` — иначе синтаксическая ошибка. | `clientcert` is valid only in `hostssl` rules. |
| clientcertInvalid | ERROR | `clientcert` должен быть `verify-ca` или `verify-full`, другие значения некорректны. | `clientcert` must be `verify-ca` or `verify-full`; other values invalid. |
| shadowedByReject | ERROR | Правило ниже никогда не сработает из‑за верхнего `reject` — функциональная ошибка. | Lower rule never matches because of upper `reject` (logic error). |
| shadowedByHost | WARN | Верхний `host` перехватывает и TLS, и non-TLS, затеняя `hostssl/hostnossl` ниже. | Upper `host` shadows lower `hostssl/hostnossl` rules. |
| overlyBroadRule | WARN | Более широкое и более слабое правило выше перекрывает более строгое ниже. | Broader/weaker upper rule shadows a stricter lower rule. |
| shadowedByBroadRule | WARN | Текущее правило затенено более широким/слабым выше и не достигнется. | Current rule is shadowed by a broader/weaker upper rule. |
| redundantRule | INFO | Полный дубликат по условиям и методу — можно безопасно удалить. | Full duplicate (conditions+method); safe to remove. |
| shadowedRule | WARN | Полностью перекрыто верхним правилом (условия совпадают, метод может отличаться). | Fully shadowed by an upper rule (conditions covered). |
| partialOverlap | WARN | Частичное пересечение диапазонов/БД/пользователей — порядок правил может влиять. | Partial overlap of address/DB/user sets; order may affect behavior. |

## Как читать вывод
Формат строки: `SEVERITY CODE line=<num> <message>`
- `SEVERITY`: ERROR | WARN | INFO.
- `CODE`: без пробелов, удобно фильтровать grep/awk.
- `line`: номер строки в исходном файле.

Exit codes:
- `0` — нет ошибок (могут быть WARN/INFO).
- `1` — есть хотя бы один `ERROR`.
- `2` — ошибки ввода (не найден файл, неверный формат строки и т.п.).

## Добавление новых правил проверки
- Расширяйте функции в `pkg/hba/checks.go` или `pkg/hba/overlap.go`.
- При необходимости добавляйте парсинг дополнительных опций в `pkg/hba/parser.go`.
- Пороговые значения/флаги — через структуру `Config` и CLI флаги.
- Пишите тесты в `tests/`, используя публичные функции из `pkg/hba`.

## Известные упрощения
- Спец-значения `sameuser/samerole/samegroup` и т.п. обрабатываются как строки (без полнотой семантики покрытий).
- Для `samenet` не вычисляем реальную сеть интерфейсов — считаем «широко».
- Парсер не поддерживает `include`/`@file` и многострочные комментарии — только базовый формат.
