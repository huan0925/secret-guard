---
id: kubectl-get-secret
match_against: [command]
pattern: kubectl\s+(get|describe)\s+secret
action: deny
---

⚠️ 這會讀取 Kubernetes Secret 的內容。

---
id: kubectl-secret-base64-decode
match_against: [command]
pattern: kubectl\s+get\s+secret.*base64\s+(-d|--decode)
action: deny
---

⚠️ 這個指令會把 Kubernetes Secret 的值解碼成明文。
