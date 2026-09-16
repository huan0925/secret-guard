---
id: aws-access-key-literal
match_against: [command, content]
pattern: AKIA[0-9A-Z]{16}
action: deny
---

⚠️ 偵測到文字中出現 AWS Access Key ID 格式的字串。

---
id: github-token-literal
match_against: [command, content]
pattern: gh[ps]_[0-9A-Za-z]{36}
action: deny
---

⚠️ 偵測到文字中出現 GitHub Token 格式的字串（ghp_/ghs_ 開頭）。

---
id: openai-stripe-style-key-literal
match_against: [command, content]
pattern: sk-[A-Za-z0-9]{20,}
action: deny
---

⚠️ 偵測到文字中出現 sk- 開頭的 API Key 格式字串（常見於 OpenAI/Stripe）。

---
id: slack-token-literal
match_against: [command, content]
pattern: xox[baprs]-[0-9A-Za-z-]+
action: deny
---

⚠️ 偵測到文字中出現 Slack Token 格式的字串。

---
id: google-api-key-literal
match_against: [command, content]
pattern: AIza[0-9A-Za-z_-]{35}
action: deny
---

⚠️ 偵測到文字中出現 Google API Key 格式的字串。

---
id: pem-private-key-block
match_against: [command, content]
pattern: -----BEGIN\s?(RSA |EC |OPENSSH )?PRIVATE KEY-----
action: deny
---

⚠️ 偵測到文字中包含 PEM 格式私鑰區塊。
