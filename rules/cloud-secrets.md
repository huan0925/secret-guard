---
id: gcloud-secret-access
match_against: [command]
pattern: \bgcloud\b[^;&|\n]*\bsecrets\b[^;&|\n]*\bversions\b[^;&|\n]*\b(access|add)\b
action: ask
---

⚠️ 此指令會讀取或寫入 Google Secret Manager 的機密值。

---
id: gcloud-iam-key-create
match_against: [command]
pattern: gcloud\s+iam\s+service-accounts\s+keys\s+create
action: deny
---

⚠️ 此指令會建立一組新的 GCP 服務帳戶金鑰檔（長期憑證）。請自行在終端機執行。

---
id: aws-secretsmanager-access
match_against: [command]
pattern: aws\s+secretsmanager\s+(get-secret-value|create-secret|put-secret-value)
action: ask
---

⚠️ 此指令會讀取或寫入 AWS Secrets Manager 的機密值。

---
id: azure-keyvault-access
match_against: [command]
pattern: az\s+keyvault\s+secret\s+show
action: ask
---

⚠️ 此指令會讀取 Azure Key Vault 的機密值。

---
id: cli-auth-token
match_against: [command]
pattern: \bgcloud\s+auth\s+(application-default\s+)?print-(access|identity)-token|\bgh\s+auth\s+token\b
action: ask
---

⚠️ 此指令會印出目前登入帳號的存取 token。

---
id: data-file-flag
match_against: [command]
pattern: (?=.*\bgcloud\b)(?=.*--data-file)
action: ask
---

⚠️ 此指令使用 --data-file 參數，通常用於傳遞機密檔案內容（例如建立/更新 Secret 或金鑰）。
