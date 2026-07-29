# OpenIDX — Kuruma Kullandırma Yol Haritası, Pazarlanabilir Kısımlar ve Pazar Araştırması

> **Amaç.** Bu doküman OpenIDX'in bir kuruma nasıl konumlandırılıp
> kullandırılabileceğini, hangi bileşenlerinin pazarlanabilir olduğunu ve
> güncel (2026) pazar araştırmasına dayanan gerekçelerini tek yerde toplar.
> Kaynak: repo içi kod-doğrulanmış analizler
> (`MARKET_GAP_ANALYSIS_2026.md`, `MARKET_REANALYSIS_AND_GTM_2026-07.md`,
> `README.md`) + Temmuz 2026 web pazar araştırması.
>
> **Dürüstlük notu.** OpenIDX olgunluk seviyesi **"MVP–erken GA"**: çekirdek
> gerçek ve büyük ölçüde üretim kalitesinde; tasarım ortağı (design partner) ve
> ücretli pilotlar için hazır. Kayıtsız şartsız "genel kullanıma açık (GA)"
> değil. Broşür/satış dilinde güçlü yönleri öne çıkarırken bu çizgiyi koruyun.

---

## 1. Tek cümlelik ürün tezi

OpenIDX, normalde **dört ayrı ürün** olarak satın alınan yeteneği — **kimlik
(IAM), yönetişim (IGA), ayrıcalıklı erişim (PAM) ve sıfır-güven ağ katmanı
(ZTNA)** — **tek self-host edilebilir platformda, tek PostgreSQL üzerinde**
birleştirir. Microsoft Entra ID + Okta + SailPoint + CyberArk + Zscaler
yığınının yerini, **stacked (üst üste binen) kullanıcı-başı fiyatların
%70–80 altında** bir maliyetle almak için tasarlanmıştır.

**Asıl fark (moat):** Dört sütun tek kod tabanı ve tek veritabanını paylaştığı
için, bir karar uçtan uca yayılır. Bir erişim-iptali ya da yönetici
"kill-switch"i; kullanıcının **token'larını, oturumlarını, vault check-out'larını,
canlı ayrıcalıklı oturumlarını VE ağ devrelerini** saniyeler içinde keser —
çok-konnektörlü bir entegrasyon projesi olarak değil, tek işlemle.

---

## 2. Pazar araştırması özeti (2026)

### 2.1 Pazarın acı noktası: fiyat

Her kategori kullanıcı-başı / kimlik-başı / MAU-başı fiyatlı ve ağır SKU
yığınlamalı. Belgelenmiş alıcı isyanı var:

| Rakip | Gerçek fiyat (2026) | Not |
|---|---|---|
| **Okta Workforce** | SSO-only $2/kullanıcı/ay → Essentials Suite $17/kullanıcı/ay (~$204/kullanıcı/yıl); Professional/Enterprise teklif-bazlı | Governance SKU'su ana lisans kadar tutabiliyor |
| **Auth0** | MAU-bazlı | Belgelenmiş: 1.67× kullanıcı artışında **15× fatura** |
| **CyberArk** | $1.8K–12K/kullanıcı/yıl, teklif-bazlı | Palo Alto **$25 milyar**a satın aldı (Şub 2026) |
| **PAM (genel)** | $9–400/kullanıcı/yıl | CyberArk/BeyondTrust/Delinea çoğu teklif-bazlı, çok-yıl taahhüt |
| **Teleport** | Kaynak-başı metering | Otomatik ölçeklenmeyi cezalandırır, Community Edition kısıtlı |
| **NHI (makine kimliği)** | Kimlik-başı | Makine:insan oranı 50–82:1'e ulaşırken fiyat patlıyor |

**Sonuç:** Gerçekten açık, self-host edilebilir, **sabit-maliyetli birleşik**
bir platform tam da bu acıya nişan alır — yeter ki reklamını yaptığı özellikler
çalışsın.

### 2.2 Rekabet ortamı: konsolidasyon dalgası

2026'da her lider "kimlikten ağ paketine kadar" sözünü **M&A ile** kuruyor:
- **$25 milyar** PANW × CyberArk (kapanış Şub 2026)
- Okta × Axiom
- Delinea × StrongDM
- SailPoint IPO oldu

**OpenIDX zaten bu birleşmiş üründür** — tek kod tabanında, tek Postgres
üzerinde. Rakipler entegrasyon borcu biriktirirken OpenIDX tek karar =
tek yazma + ≤30 sn reconcile sağlar.

### 2.3 Açık kaynak IAM ortamı ve boşluk

- **Keycloak / Authentik / Zitadel:** self-host SSO/IdP'de olgun ama
  **sadece IAM** (kimlik). IGA, PAM, ZTNA yok.
- **OpenZiti ekosistemi:** upstream v2.0 GA controller HA getirdi ama resmi
  konsol vestijyal (**37 GitHub yıldızı**), NetFoundry teklif-bazlı ve OSS'i
  "üretim değil" diye konumluyor.
- **Headscale (42K yıldız)** açık control-plane'lerin zihin payı kazandığını
  kanıtlıyor.

**OpenIDX'in sahiplenebileceği boşluk:** çok-kiracılı, delege-RBAC'li,
SCIM→Ziti kimlik yaşam döngülü, ölçüm/geri-faturalamalı, uyum-zarflı
(SOC2/FIPS) bir **OpenZiti yönetim düzlemi** — kimse doldurmadı.

---

## 3. OpenIDX'in gerçek yetenekleri (kod-doğrulanmış)

### Kimlik ve Erişim Yönetimi (IAM)
- Yerel OAuth 2.0 / OIDC sağlayıcı (auth code + PKCE, refresh rotation,
  client credentials, token exchange RFC 8693, JWKS + anahtar rotasyonu)
- SAML 2.0 Identity Provider (XML-DSig imzalama, SP metadata, SLO)
- SSO — uygulama-başı onay ekranı
- Çok Faktörlü Kimlik Doğrulama — TOTP, WebAuthn/passkey, push, donanım
  token, e-posta/SMS OTP
- Passwordless & magic-link
- Uyarlanabilir / risk-tabanlı kimlik doğrulama + step-up
- Dizin entegrasyonu & senkron (LDAP, Active Directory, Azure AD)
- SCIM 2.0 provisioning (kullanıcı & grup, filtre, PATCH)
- Sosyal / harici IdP federasyonu

### Kimlik Yönetişimi (IGA)
- Erişim gözden geçirmeleri & sertifikasyon kampanyaları (iptal enforce edilir)
- Erişim-talebi & çok-adımlı onay iş akışları
- Görevler Ayrılığı (SoD) — önleyici, fail-closed enforce
- Just-in-Time (JIT) yükseltme + otomatik süre dolumu
- Yetki kataloğu, delegasyonlar, yaşam döngüsü politikaları
- RBAC, ABAC ve OPA politika-tabanlı erişim
- **HR-tetikli Joiner/Mover/Leaver** (BambooHR bugün; Workday/SuccessFactors modeli)

### Ayrıcalıklı Erişim Yönetimi (PAM)
- Zarf-şifreli kimlik-bilgisi kasası (KEK rotasyonlu)
- Otomatik kimlik-bilgisi rotasyonu (SSH, AWS IAM, GCP SA, Postgres, MySQL, LDAP)
- Guacamole üzerinden brokerlı SSH/RDP/VNC — sunucu-tarafı kimlik enjeksiyonu
- Oturum kaydı (at-rest şifreli), transkript, legal hold, saklama
- Kullanıcı-başı broker kimlikleri + RDM-eşdeğeri bağlantı yöneticisi
- **Ayrıcalıklı oturumlar OpenZiti overlay üzerinden — hedefte açık port yok**

### Sıfır Güven Ağ (OpenZiti üzerinde ZTNA)
- Kimlik-tetikli "karanlık" servisler (açık inbound port yok)
- BrowZer clientless tarayıcı erişimi (ajan kurulumu yok)
- Masaüstü (Windows, imzalı) ve mobil/Android uç-nokta ajanları + posture
- İstenen-durum reconciler (OpenIDX politikasını Ziti controller'a senkronlar)
- **Sütunlar-arası kill switch:** token + oturum + vault + ağ devresini tek işlemde iptal

### Platform, güvenlik ve uyum
- APISIX API gateway + rate limiting, mTLS & sertifika yönetimi
- **Çok-kiracılılık: PostgreSQL FORCE row-level security, CI-enforced**
  (`tools/orgscope` linter'ı org_id eksik sorguda build'i kırar)
- Kurcalama-belirtir denetim günlüğü (HMAC hash-zinciri) + Elasticsearch arama
- SIEM entegrasyonu, uyum raporları (SOC 2, ISO 27001, GDPR)
- Gözlemlenebilirlik: Prometheus, OpenTelemetry, SLO'lar
- Otomatik yedekleme + test edilmiş geri yükleme

---

## 4. Pazarlanabilir kısımlar (paketleme haritası)

OpenIDX'i tek dev SKU olarak değil, alıcı-katmanına göre **paketlenebilir
modüller** olarak konumlayın. Çekirdek Apache-2.0 kalır; para kazandıran
katmanlar yeni-alıcı özellikleridir.

| # | Paketlenebilir modül | Kime satılır | Değer önermesi | Ticari katman |
|---|---|---|---|---|
| 1 | **IAM/SSO çekirdeği** (OIDC/SAML/MFA/SCIM/dizin) | Her kurum | Okta/Auth0 yerine sabit-maliyet, self-host | Açık kaynak (funnel) |
| 2 | **PAM Suite** (kasa, rotasyon, oturum kaydı, JIT) | Regüle sektör, IT ops | CyberArk/Delinea alternatifi, %90+ ucuz | Enterprise |
| 3 | **ZTNA / OpenZiti yönetim düzlemi** | Dağıtık işgücü, OT/IoT, MSP | "Karanlık" servisler, VPN yok, clientless | Enterprise / MSP |
| 4 | **IGA / Yönetişim** (access review, SoD, onay, JML) | Uyum ekipleri, denetim | SailPoint alternatifi, denetim kanıtı | Enterprise |
| 5 | **Birleşik Kill-Switch & Access 360** | CISO, SOC | Tek işlemle uçtan-uca iptal ≤30 sn | Enterprise (moat) |
| 6 | **Uyum Paketleri** (SOC2/ISO/KVKK/DORA kanıtı) | Regüle sektör | Denetime hazır çıktı | Ücretli eklenti |
| 7 | **Premium konnektörler** (Workday, ServiceNow, ek rotasyon) | Kurumsal entegrasyon | Hazır entegrasyon | Ücretli eklenti |
| 8 | **MSP orkestrasyon + ölçüm/geri-faturalama** | Servis sağlayıcılar | White-label çok-kiracı | MSP katmanı |
| 9 | **FIPS / hava-boşluklu (air-gap) build** | Savunma, kamu | Sertifikalı dağıtım | Ücretli eklenti |
| 10 | **SLA + destek + yönetilen kurulum** | Her ücretli müşteri | Güven & operasyon | Abonelik |

---

## 5. Bir kuruma kullandırma yol haritası (uygulama)

### Faz 0 — Keşif & kapsam (1–2 hafta)
- Kurumun mevcut yığını (Entra/Okta/AD, PAM var mı, VPN/ZTNA) çıkarılır.
- İlk değer noktası seçilir: genelde **SSO+MFA** (hızlı kazanım) veya
  **PAM/SSH-RDP erişim** (yüksek acı).
- Başarı kriteri + pilot kapsamı yazılır (örn. "50 kullanıcı, 3 uygulama SSO,
  10 sunucu PAM, 30 günde").

### Faz 1 — Temel kurulum (2–4 hafta)
- Self-host kurulum (Docker/K8s), tek Postgres, TLS/sertifika.
- Dizin senkronu (LDAP/AD/Azure AD) → kullanıcılar OpenIDX'e akar.
- OIDC/SAML SSO ilk 2–3 uygulamaya bağlanır; MFA politikası (TOTP/passkey).
- Denetim günlüğü + SIEM akışı + yedekleme doğrulanır.

### Faz 2 — Ayrıcalıklı erişim (2–4 hafta)
- Kritik sunucular PAM kasasına alınır; SSH/RDP/VNC brokerı + oturum kaydı.
- Rotasyon konnektörleri (SSH/AWS/GCP/DB) devreye alınır.
- JIT yükseltme + onay iş akışı; legal hold/saklama politikası.

### Faz 3 — Sıfır güven ağ (3–6 hafta)
- OpenZiti overlay; kritik iç servisler "karanlık" hale getirilir (port kapanır).
- BrowZer ile clientless erişim veya masaüstü/mobil ajan + posture.
- PAM hedefleri overlay üzerine taşınır (inbound port sıfırlanır).

### Faz 4 — Yönetişim & uyum (paralel/sürekli)
- Erişim gözden geçirme kampanyaları, SoD kuralları, HR-tetikli JML.
- Kill-switch + Access 360 devrede; uyum raporları üretilir.
- Pentest → düzeltme → SOC2/ISO hazırlığı.

### Faz 5 — Devreye alma & büyütme
- Pilot → üretim; kullanıcı/sunucu kademeli genişletme.
- Destek/SLA sözleşmesi; ücretli katman eklentileri (uyum paketi, konnektör).

---

## 6. Hedef segmentler (Go-To-Market)

Sıra, "regülasyonun self-host'u zorunlu kıldığı" yerlerden başlar (en kolay
kazanım), sonra maliyet-hassas OSS-öncelikli kurumlara genişler.

### Segment 1 — Türkiye regüle sektör (ÖNCELİK)
- **BDDK** Bilgi Sistemleri Yönetmeliği + Bulut Tebliği: bankalar, sigorta,
  aracı kurumlar veri yerelleştirme ve dış-hizmet kurallarına tabi; çekirdek
  bankacılık için SaaS IdP kullanımı ağır kısıtlı → **self-host zorunlu**.
- **KVKK md. 9** veri lokalizasyonu.
- **Yerli malı belgesi → kamu ihalelerinde %15 fiyat avantajı.**
- Gerçek rakip "ücretsiz Keycloak + sistem entegratörü" — bu yüzden
  **sertifikalı, destekli, dört-sütunlu paket** olarak satılır.

### Segment 2 — AB NIS2 / DORA orta ölçek
- DORA'nın RTS'i pratikte bir PAM zorunluluğu; NIS2 kimlik + ayrıcalıklı
  erişim + denetim ister.
- Egemen (sovereign), self-host, dört-sütunlu tek satıcı yok → boşluk.

### Segment 3 — MSP'ler (Yönetilen Hizmet Sağlayıcılar)
- White-label çok-kiracılı ZTNA OSS'te hiç servis edilmiyor.
- OpenIDX'in FORCE-RLS çok-kiracılılığı + ölçüm/geri-faturalama tam oturur.

### Segment 4 — OSS-öncelikli mühendislik kurumları
- Auth0-yenileme ve Teleport-lisans "mültecileri".
- Show HN / r/selfhosted funnel'ı (Infisical/Authentik modeli).

---

## 7. Fiyatlandırma modeli

| Katman | Fiyat | Kapsam |
|---|---|---|
| **Community** | Ücretsiz (Apache-2.0) | Tüm çekirdek: IAM+IGA+PAM+ZTNA, self-host, topluluk desteği |
| **Enterprise** | **$4–6/kullanıcı/ay** (taban ~$6–8K/yıl) | SLA, uyum paketleri, premium konnektör, öncelikli destek |
| **MSP** | Kiracı + ölçüm bazlı | White-label, çok-kiracı orkestrasyon, geri-faturalama |
| **Kamu/Savunma** | Proje-bazlı | FIPS/air-gap build, yerinde kurulum, yerli malı |

**Karşılaştırma:** Yığılmış rakip faturası **$33–65/kullanıcı/ay**. OpenIDX
Enterprise ~$4–6 → README'nin **"%70–80 tasarruf"** iddiası üçüncü-taraf
fiyat verisiyle doğrulanmış durumda.

**Lisans stratejisi:** Çekirdek sonsuza dek Apache-2.0. Sadece yeni alıcı-katmanı
özellikleri (uyum, MSP, FIPS, SLA) para kazandırır — 2023–26 lisans savaşları
tepkinin "geriye dönük alma"yı izlediğini kanıtlıyor.

---

## 8. Gerçekçi hedef ve önündeki engeller

**Yıl-2 hedefi:** 30–60 müşteri ≈ **$1–2M ARR** — Zitadel, NetBird, Infisical'ın
fon aldığı / sürdürülebilirliğe ulaştığı su hattı. (Self-host kurumların
%0.2–1'i dönüşür.)

**Kapatılması gereken güven/uyum takvimi:**
1. Pentest (hemen)
2. **CRA açık-bildirim hazırlığı 2026-09-11** (kimlik/PAM yazılımı CRA "Önemli
   Sınıf I")
3. ISO 27001 (Q4)
4. SOC 2 Type II (ilk ABD orta-ölçek anlaşmasından önce)

**Demo öncesi kapatılacak "mayınlar"** (repo GTM dokümanından, birkaç gün–hafta):
push-MFA teslimatı, magic-link e-posta, SAML kripto sağlamlaştırma, onay ekranı,
test-yardımcısı temizliği. Bu oturumda benzer sınıf hatalar (CORS, şema
uyuşmazlıkları, güvenlik başlıkları, açık DCR) zaten düzeltildi.

---

## 9. Özet: neden OpenIDX

1. **Dört ürün, tek platform, tek veritabanı** — entegrasyon borcu yok.
2. **%70–80 daha ucuz** — sabit maliyet, kullanıcı-başı fiyat cezası yok.
3. **Veri egemenliği** — tamamen self-host, verin senin altyapında.
4. **Regülasyona hazır konumlanma** — BDDK/KVKK/DORA/NIS2 self-host'u zorluyor.
5. **Benzersiz moat** — kill-switch token→oturum→vault→ağ devresini ≤30 sn'de keser.
6. **Açık kaynak, kilitlenme yok** — Apache-2.0 çekirdek, açık standartlar.
