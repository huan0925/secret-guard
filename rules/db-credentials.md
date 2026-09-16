---
id: psql-invocation
match_against: [command]
pattern: \bpsql\b
action: deny
---

⚠️ 這是直接連線資料庫的指令，可能暴露連線密碼。請自行在終端機執行。

---
id: pgpassword-env
match_against: [command]
pattern: PGPASSWORD=
action: deny
---

⚠️ 指令中直接帶有資料庫密碼環境變數（PGPASSWORD）。請自行在終端機執行。

---
id: mysql-inline-password
match_against: [command]
pattern: mysql\s+.*-p\S
action: deny
---

⚠️ 指令中直接帶有 MySQL 密碼參數。請自行在終端機執行。

---
id: mongodb-uri-with-credentials
match_against: [command, content]
pattern: mongodb(\+srv)?://[^:/\s]+:[^@/\s]+@
action: deny
---

⚠️ 偵測到 MongoDB 連線字串中直接帶有帳號密碼。
