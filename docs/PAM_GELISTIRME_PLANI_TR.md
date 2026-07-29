# OpenIDX PAM — Geliştirme Araştırması & İmplementasyon Planı

> **Amaç.** OpenIDX'in PAM (Ayrıcalıklı Erişim Yönetimi) sütununu 2026 pazar
> liderleriyle (CyberArk, BeyondTrust, Delinea, Teleport, StrongDM) rekabet
> edebilecek — ve birleşik mimarisiyle onları geçebilecek — seviyeye taşımak
> için kod-doğrulanmış, önceliklendirilmiş bir implementasyon planı.
>
> **Yöntem.** (1) Canlı kodun taranması (`internal/access/pam_*`,
> `internal/vault/`, `internal/credentials/`, `internal/governance/`), (2)
> Temmuz 2026 pazar araştırması (modern-PAM differentiator'ları), (3) mevcut
> `MARKET_GAP_ANALYSIS_2026.md` Pillar-3 register'ının güncel koda karşı
> yeniden doğrulanması. **Not:** Gap register'ın (10 Temmuz) "eksik" dediği
> birçok madde son commit'lerde **kapatılmış**; bu plan gerçek boşluklara odaklanır.

---

## 1. Mevcut durum — kod-doğrulanmış envanter

### ✅ Zaten gerçek ve üretim-kalitesinde (koddan doğrulandı)
| Yetenek | Kanıt |
|---|---|
| Zarf-şifreli kasa + KEK rotasyon | `internal/vault/crypto.go`, `store.go`, sweeper |
| 8 rotasyon konnektörü | `internal/credentials/{ssh,ssh_key,gcp_sa,postgres,aws_iam,directory,generate,mysql}_rotator.go` + `engine.go` scheduler |
| Guacamole SSH/RDP/VNC/telnet broker + kimlik enjeksiyonu | `internal/access/guacamole.go`, `pam_launch.go` |
| Oturum kaydı, transkript, legal hold, saklama | `recording_crypto.go`, `remote_support_recording.go` |
| **SSH CA + `openidx connect` (kısa-ömürlü sertifika)** | `internal/access/ssh_ca.go` (464 satır) + migration **v109** |
| **Break-glass / acil erişim** | `pam_checkout_control.go:handlePamBreakGlass` + migration **v105** |
| **Ayrıcalıklı hesap keşfi + auto-onboarding** | `internal/governance/privileged_discovery.go` (380 satır) |
| **MCP gateway (AI-agent erişimi)** | `internal/access/mcp_gateway.go` (296 satır) |
| JIT checkout + onay + kill-switch | `pam_checkout_control.go`, governance workflows |
| Ayrıcalıklı oturumlar OpenZiti overlay üzerinden | `pam_ziti.go` (bu oturumda düzeltildi) |
| Oturum özeti / güvenlik iç görüsü | `internal/portal/security_insights.go` |

**Sonuç:** PAM sütunu, gap register'ın önerdiğinden **çok daha olgun**. Modern-PAM
frontier'ının büyük kısmı (ephemeral cert, discovery, break-glass, AI-agent)
temelde mevcut. Kalan boşluklar **derinlik ve genişlik**tir.

### ❌ Gerçekten eksik (dosya yok — doğrulandı)
| Boşluk | 2026 pazar kanıtı | Kim satıyor |
|---|---|---|
| **DB oturum brokerı + sorgu-seviyesi denetim** | Native `psql`/`mysql` istemcisi, sorgu logu | StrongDM, Teleport, CyberArk SIA |
| **Kubernetes erişim brokerı** | `kubectl` impersonation, kısa-ömürlü kubeconfig, verb/resource denetim | Teleport, StrongDM, Boundary |
| **Cloud konsol/CLI JIT yükseltme** | `AssumeRole` → federe konsol URL'i, süre dolunca iptal | CyberArk SCA, Entra PIM, AWS TEAM |
| **Moderated (denetimli) oturumlar** | İkinci kullanıcı onaylayana kadar oturum bekler; SOX/PCI | Teleport moderated sessions |
| **Windows/WinRM rotasyonu + bağımlılık** | Servis/task/IIS pool bağımlılıkları | CyberArk, Delinea (300+ konnektör) |
| **ChatOps onayları + ticket doğrulama** | Slack/Teams imzalı onay, ServiceNow/Jira ticket no | Tüm liderler |
| **Ayrıcalık grafiği / etkin-yetki analizi** | "X sırrına kim, hangi yolla ulaşır" | BeyondTrust True Privilege |
| **Oturum risk skoru + otomatik askıya alma** | Canlı oturumu risk skoruna göre kes | CyberArk PTA, StrongDM |
| **Konnektör genişliği** (MSSQL/Oracle/Mongo/Redis) | Liderler 300-400+; OpenIDX 8 | CyberArk, Delinea |
| **Terraform provider (access-as-code)** | Bulut PAM için table-stakes | Teleport, StrongDM |
| **Cloud vault federasyonu** (AWS SM/Azure KV/GCP SM) | İki-yönlü sır senkronu | CyberArk Secrets Hub |

### ⚠️ Var ama sağlamlaştırılmalı
- **guacd kayıtları düz-metin diskte** — WebRTC kayıtları şifreli ama guacd
  kayıtları `recording_crypto.go` keyring'inden geçmiyor (denetim-kanıt bütünlüğü).
- **PAM olaylarının SIEM'e CEF/syslog akışı** — birleşik ingestion + CSV var,
  ama syslog/HEC forwarder yok.

---

## 2. 2026 pazar tezi: "Zero Standing Privileges" (ZSP)

Pazar araştırması net bir yön gösteriyor: **modern PAM'in geleceği vault'lanmış
statik kimlik-bilgisi değil, kimlik-farkında kısa-ömürlü sertifika + hiç-kalıcı-
yetki (ZSP)**. Teleport "%95 kimlik-bilgisi azaltma", StrongDM "sıfır kalıcı
yetki", SSH.com "ZSP yeni zorunluluk", Gartner "ephemeral identity" oturumları.

**OpenIDX'in avantajı:** SSH CA (v109) + `openidx connect` + OpenZiti overlay
zaten bu mimarinin **omurgasına** sahip. Statik-kimlik-bilgisi PAM'inden
ZSP-native PAM'e geçiş için altyapı hazır; eksik olan **protokol genişliği**
(DB, K8s, cloud) ve **derinlik** (moderated, graph, risk).

**Birleşik mimari moat'ı:** OpenIDX IdP + IGA + PAM + ZTNA tablolarını tek
Postgres'te tuttuğu için, rakiplerin M&A ile kuramadığı iki şeyi **native**
yapabilir: (1) **ayrıcalık grafiği** (tek DB'de transitif yetki hesabı), (2)
**tek kill-switch** (token→oturum→kasa→ağ ≤30 sn — zaten var).

---

## 3. İmplementasyon planı — dalgalar

Efor: **S** ≈ ≤1 hafta · **M** ≈ 1–3 hafta · **L** ≈ 1–2 ay · **XL** ≈ çeyrek+.
Sıra: önce **sağlamlaştırma + hızlı kazanımlar**, sonra **ZSP protokol genişliği**,
sonra **derinlik/differentiator**.

### Dalga A — Sağlamlaştırma & denetim-kanıt bütünlüğü (P0, 2–3 hafta)
Küçük, yüksek-güven, uyum-kritik işler. Demo/pentest öncesi kapatılmalı.

| # | İş | Efor | Dosya / yaklaşım |
|---|---|---|---|
| A1 | **guacd kayıtlarını şifrele** — oturum sonunda kaydı mevcut keyring'den geçir + SHA-256 hash-zincirini denetime yaz | S | `remote_support_recording.go` + `recording_crypto.go` post-session hook |
| A2 | **PAM olay SIEM forwarder** — CEF/TLS-syslog + Splunk HEC worker (webhooks retry pattern'i) | S | `internal/audit` yeni forwarder worker |
| A3 | **Checkout exclusivity + dual-control reveal** — `exclusive`/`require_dual_control` bayrakları; atomik `UPDATE…RETURNING` ile eşzamanlı checkout engeli; reveal'ı onaylı access-request'e bağla | S | `pam_checkout_control.go`, `pam_entries.go` şema bayrağı |
| A4 | **Step-up MFA'yı checkout/session-launch'ta zorla** — `require_step_up` bayrağı reveal/retrieve/session handler'larında enforce (step-up doğrulama zaten #593'te düzeltildi) | S | `vault/handlers.go`, `guacamole.go` |

### Dalga B — ZSP protokol genişliği (P0/P1, 6–10 hafta) — EN YÜKSEK DEĞER
Native-client erişimi ve DB/K8s brokerı; dev-platform değerlendirmelerini kazandırır.

| # | İş | Efor | Dosya / yaklaşım |
|---|---|---|---|
| B1 | **DB oturum brokerı (Postgres wire-protocol proxy)** — forward-auth/OIDC ile kimlik doğrula, vault kimlik-bilgisini sunucu-tarafı enjekte et (guacamole.go pattern'i), parse edilmiş sorguları denetime yaz. Native `psql` çalışır. | XL | Yeni `internal/access/dbproxy/` — pgproto3 kütüphanesi |
| B2 | **`openidx connect` CLI'yi genişlet** — SSH CA zaten var; CLI'yi paketle (session-request→onay→kısa-ömürlü Ziti kimlik→yerel listener). Native `ssh` değişmeden çalışır. | L | `cmd/openidx-cli/` + mevcut `ssh_ca.go` + `pam_ziti.go` |
| B3 | **Kubernetes erişim brokerı** — OpenIDX oturumunu K8s impersonation'a maplayan authenticating reverse-proxy; JIT grant'tan kısa-ömürlü kubeconfig; verb/resource denetim | L | Yeni `internal/access/k8sproxy/` |
| B4 | **Cloud konsol/CLI JIT yükseltme** — `cloud_role` grant tipi: onayda `AssumeRole` (STS client zaten import) → federe konsol URL'i; süre dolunca iptal | M | `pam_entries.go` yeni grant tipi + `internal/credentials` STS |

### Dalga C — Differentiator derinlik (P1/P2, 8–12 hafta)
Birleşik mimarinin leapfrog fırsatları + SOX/PCI derinliği.

| # | İş | Efor | Dosya / yaklaşım |
|---|---|---|---|
| C1 | **Ayrıcalık grafiği / etkin-yetki** (MOAT) — mevcut tablolar üzerinde recursive CTE materyalizer; `GET /pam/privilege-graph` "X sırrına kim, hangi yolla". IdP+IGA+PAM tek DB'de olduğu için native. | L | Yeni `internal/access/privgraph.go` |
| C2 | **Oturum risk skoru + otomatik askıya alma** — `continuous_verify.go`'yu Guacamole oturumlarına genişlet (login-risk + transkript keyword + mesai-dışı); orphan `internal/risk` mantığını dirilt | M | `continuous_verify.go` + `internal/risk` |
| C3 | **Moderated oturumlar** — `require_moderator` bayrağı; ikinci kullanıcı bağlanana kadar oturum "bekliyor"; Guacamole 1.3+ interaktif paylaşım | M | `guacamole.go` + şema bayrağı |
| C4 | **ChatOps onayları + ticket zorlaması** — `internal/webhooks`'a imzalı interaktif Slack/Teams payload; `required_ticket` politikası ServiceNow/Jira'ya karşı doğrulanır | M | `internal/webhooks` genişletme |
| C5 | **AI-agent ayrıcalıklı erişim derinliği** — MCP gateway var; her tool-call'ı OPA'ya karşı değerlendir + HITL onayı (CIBA) + tam denetim | M | `mcp_gateway.go` + OPA + `internal/governance` |

### Dalga D — Genişlik & ekosistem (P1/P2, sürekli)
Kaybedilen "8-vs-300 konnektör" algısını kapat + IaC.

| # | İş | Efor | Dosya / yaklaşım |
|---|---|---|---|
| D1 | **Windows/WinRM rotasyonu + bağımlılıklar** — WinRM client ile rotator; servis/task/IIS pool bağımlılıkları post-rotate hook | L | `internal/credentials/windows_rotator.go` |
| D2 | **Konnektör genişliği** — `pkg/rotator` arayüzlerini test harness'iyle şablon olarak yayınla; MSSQL/Oracle/MongoDB/Redis/network-SSH tohumla; uzun kuyruğu topluluğa bırak | M | `internal/credentials/` + `pkg/rotator` |
| D3 | **Terraform provider (access-as-code)** — OpenAPI spec'lerinden `terraform-provider-openidx`: vault sırları (sadece metadata), rotasyon politikaları, route'lar, uygulamalar | M | Yeni repo/modül |
| D4 | **AAPM SDK'ları + dinamik per-lease sır** — servis-hesabı auth + `/use` saran ince Go/Python SDK; connector arayüzüne `Issue()` dinamik mod (AWS Minter pattern'i zaten var) | M | `pkg/sdk` + `credentials/engine.go` |
| D5 | **Cloud vault federasyonu** — promote adımında yeni versiyonu AWS SM/Azure KV/GCP SM'e de push et; pull-mode keşif | L | `credentials/engine.go` sync worker |

---

## 4. Önerilen sıra ve gerekçe

**İlk 90 gün (MVP→rekabetçi):**
1. **Dalga A tamamı** (2–3 hafta) — uyum/denetim-kanıt bütünlüğü; pentest öncesi.
2. **B1 (DB proxy) + B2 (`openidx connect` CLI)** — en yüksek değer. Dev-platform
   değerlendirmelerini bunlar kazandırır ("native `psql`/`ssh` değişmeden çalışır").
   B2 için altyapı (SSH CA) zaten var; hızlı kazanım.
3. **C1 (ayrıcalık grafiği)** — birleşik-mimari moat'ı; rakiplerin kuramadığı özellik.

**90–180 gün (differentiator):**
4. **B3 (K8s) + B4 (cloud JIT)** — bulut-native işgücünü kazan.
5. **C2 (oturum risk) + C3 (moderated)** — SOX/PCI derinliği.
6. **C4 (ChatOps) + C5 (AI-agent derinliği)** — modern iş akışı.

**Sürekli:**
7. **Dalga D** — konnektör genişliği + IaC; topluluk kaldıracıyla.

---

## 5. Ölçüm — "başardık" nasıl anlaşılır

| Hedef | Metrik |
|---|---|
| ZSP mimarisi | Statik-kimlik-bilgisi checkout'ların oranı ↓, kısa-ömürlü sertifika/token ↑ |
| Native-client erişimi | `psql`/`ssh`/`kubectl` değişmeden çalışan hedef sayısı |
| Denetim-kanıt bütünlüğü | Tüm kayıtlar şifreli + hash-zincirli; SIEM'e %100 akış |
| Differentiator | Ayrıcalık grafiği canlı sorgu; risk-tabanlı oturum askıya alma çalışıyor |
| Genişlik algısı | Konnektör sayısı 8 → 15+ (çekirdek) + topluluk şablonu |
| Rekabet | Teleport/StrongDM değerlendirmesinde "native client + DB/K8s + graph + tek kill-switch" ile fark |

---

## 6. Riskler ve notlar

- **DB/K8s proxy (B1/B3)** en yüksek eforlu ve en yüksek değerli; wire-protocol
  doğruluğu kritik. Küçük başla (Postgres, salt-okunur denetim), sonra genişlet.
- **Gap register eskimiş** — bu plan koda karşı yeniden doğrulandı; başlamadan
  önce her maddeyi tekrar `grep` ile teyit et (bazıları ek olarak kapatılmış olabilir).
- **Moat'a yatırım yap:** Ayrıcalık grafiği (C1) ve tek kill-switch, rakiplerin
  M&A ile kuramadığı, OpenIDX'in tek-DB mimarisinin native verdiği farklar. Pazarlama
  bunları öne çıkarmalı.
- **Topluluk kaldıracı:** Konnektör uzun-kuyruğu (D2) ve Terraform provider (D3)
  OSS topluluğuyla ölçeklenir; çekirdek ekip sadece şablon + ilk 5-6 konnektörü verir.
