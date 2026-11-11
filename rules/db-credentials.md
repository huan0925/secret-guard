---
id: psql-invocation
match_against: [command]
pattern: (^|[;&|(`]\s*)(sudo\s+)?(\w+=\S*\s+)*(psql|pg_dump|pg_dumpall)\b|\bexec\s[^;&|\n]*\s(psql|pg_dump|pg_dumpall)\b
action: ask
---

⚠️ 這是直接連線或匯出資料庫的指令，可能暴露連線密碼或資料。

---
id: pgpassword-env
match_against: [command]
pattern: PGPASSWORD=
action: ask
---

⚠️ 指令中直接帶有資料庫密碼環境變數（PGPASSWORD）。

---
id: mysql-inline-password
match_against: [command]
pattern: \bmysql\s+(.*\s)?(-p\S|--password=)
action: ask
---

⚠️ 指令中直接帶有 MySQL 密碼參數。

---
id: mongodb-uri-with-credentials
match_against: [command, content]
pattern: mongodb(\+srv)?://[^:/\s]+:[^@/\s]+@
action: ask
---

⚠️ 偵測到 MongoDB 連線字串中直接帶有帳號密碼。

---
id: env-dump
match_against: [command]
pattern: (^|[;&|(`]\s*)(printenv\b|env\s*($|[|>]))|\bexec\s[^;&|\n]*\s(printenv|env)\s*($|[|>])
action: ask
---

⚠️ 這個指令會印出整組環境變數，其中可能包含機密值。

---
id: config-secret-print
match_against: [command]
pattern: (tinker|php\s+-r)\b.*(config|env|getenv)\(\s*["'][^"']*(password|secret|_key|token)
action: ask
---

⚠️ 這個指令會印出設定中的密碼、金鑰或 token。

---
id: db-connection-string-tool
match_against: [tool]
pattern: (get_connection_string|reset_postgres_role_password)$
action: ask
---

⚠️ 這個工具會回傳含密碼的資料庫連線字串，或重設資料庫密碼。
