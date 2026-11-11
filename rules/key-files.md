---
id: dotenv-file
match_against: [file_path]
pattern: (^|[/*])\.env(?!\.(example|sample|template|dist)$)(\.[\w-]+)?$
action: ask
---

⚠️ 這牽涉到 .env 環境變數檔案，可能包含機密值。

---
id: dotenv-file-command
match_against: [command]
pattern: (\b(cat|less|more|head|tail|bat|nl|xxd|od|strings|base64|source|grep|rg|awk|sed|cut|sort|cp|mv|scp|rsync|tar|zip|open|code|vim?|nano|python3?|php|node|ruby|curl)\b|(^|[\s;&|(])\.(?=\s))[^;&|\n]*?[\s/"'=<@(]\.e(nv|n[?*]|[?*])(?!\.(example|sample|template|dist)\b)(\.[\w-]+)?($|[\s"';|)<>&])
action: ask
---

⚠️ 這個指令會讀取或複製 .env 環境變數檔案，可能包含機密值。

---
id: private-key-file-extension
match_against: [file_path]
pattern: \.(pem|pfx|p12|key)$
action: ask
---

⚠️ 這是常見的私鑰/憑證檔案格式（.pem/.pfx/.p12/.key）。

---
id: private-key-file-command
match_against: [command]
pattern: \b(cat|less|more|head|tail|bat|nl|xxd|od|strings|base64|cp|mv|scp|rsync|tar|zip|openssl\s+(rsa|pkey|ec|pkcs12|pkcs8))\b[^;&|\n]*?[\w~*-]\.(pem|pfx|p12|key)($|[\s"';|)<>&])
action: ask
---

⚠️ 這個指令會讀取或複製私鑰/憑證檔案（.pem/.pfx/.p12/.key）。

---
id: ssh-private-key-filename
match_against: [file_path]
pattern: (id_rsa|id_ed25519|id_ecdsa)$
action: deny
---

⚠️ 這看起來是 SSH 私鑰檔案。

---
id: ssh-private-key-command
match_against: [command]
pattern: \b(cat|less|more|head|tail|bat|nl|xxd|od|strings|base64|cp|mv|scp|rsync|tar|zip)\b[^;&|\n]*?(id_rsa|id_ed25519|id_ecdsa)(?!\.pub)($|[\s"';|)<>&])
action: deny
---

⚠️ 這個指令會讀取或複製 SSH 私鑰檔案。

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
action: ask
---

⚠️ 這是 Kubernetes 的 kubeconfig 檔案，通常內嵌叢集存取憑證。
