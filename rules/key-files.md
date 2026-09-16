---
id: dotenv-file
match_against: [command, file_path]
pattern: (^|[/\s"'])\.env(\.[a-zA-Z0-9_-]+)?($|[\s"'])
action: deny
---

⚠️ 這牽涉到 .env 環境變數檔案，可能包含機密值。

---
id: private-key-file-extension
match_against: [file_path, command]
pattern: \.(pem|pfx|key)($|[\s"'])
action: deny
---

⚠️ 這是常見的私鑰/憑證檔案格式（.pem/.pfx/.key）。

---
id: ssh-private-key-filename
match_against: [file_path, command]
pattern: (id_rsa|id_ed25519|id_ecdsa)($|[\s"'])
action: deny
---

⚠️ 這看起來是 SSH 私鑰檔案。

---
id: aws-credentials-file
match_against: [file_path, command]
pattern: \.aws/credentials
action: deny
---

⚠️ 這是 AWS CLI 的機密憑證檔（~/.aws/credentials）。

---
id: kube-config-file
match_against: [file_path, command]
pattern: \.kube/config
action: deny
---

⚠️ 這是 Kubernetes 的 kubeconfig 檔案，通常內嵌叢集存取憑證。
