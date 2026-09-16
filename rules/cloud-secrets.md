---
id: gcloud-secret-access
match_against: [command]
pattern: gcloud\s+secrets\s+versions\s+(access|add)
action: deny
---

⚠️ 此指令會讀取或寫入 Google Secret Manager 的機密值。若確定要執行，請自行在終端機執行。

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
action: deny
---

⚠️ 此指令會讀取或寫入 AWS Secrets Manager 的機密值。請自行在終端機執行。

---
id: azure-keyvault-access
match_against: [command]
pattern: az\s+keyvault\s+secret\s+show
action: deny
---

⚠️ 此指令會讀取 Azure Key Vault 的機密值。請自行在終端機執行。

---
id: gcloud-run-describe
match_against: [command]
pattern: gcloud\s+run\s+services\s+describe
action: deny
---

⚠️ 此指令可能顯示 Cloud Run 服務的環境變數，其中可能包含機密值。

---
id: data-file-flag
match_against: [command]
pattern: --data-file
action: deny
---

⚠️ 此指令使用 --data-file 參數，通常用於傳遞機密檔案內容（例如建立/更新 Secret 或金鑰）。
