# OpenIDX Küresel Ölçek Mimarisi — Hücre Modeli, Servis Düzlemleri ve DDoS Dayanıklılığı

> **⚠️ DONDURULDU — 2026-09-23.** Bu program, proje sahibinin kararıyla ([ADR 0001](../adr/0001-product-focus-and-trusted-core.md))
> **dondurulmuştur.** Buradaki fazlar, takvim ve açık maddeler şu an uygulanmıyor. Öncelikler
> [ROADMAP.md](../../ROADMAP.md)'dedir: M1 "Güvenilir Çekirdek" (v2.0 LTS). **Yeniden başlatma
> tetikleyicisi:** birden fazla bölgeye ihtiyaç duyan ilk müşteri ya da MSP. Belge, tasarım
> referansı olarak korunur; yeni iş eklenmez.
>
> **Tarih:** 2026-09-13 · **Sürüm tabanı:** v1.35.0 (`VERSION`), 8 Go servisi, 187 migrasyon
> **Soru:** *"Proje tüm dünyaya açılacak ve çok kullanıcıya hizmet edecek. Tasarımı buna göre
> gözden geçir; mikroservise dönüş yapılmalı. Ağır DDoS altında yanıt dönen bir sistem
> istiyorum."*
> **Kapsam:** Kenar (edge) ağı, trafik akışı, servis sınırları, veri katmanı, saldırı
> altında bozulma davranışı. Ürün özellikleri kapsam dışı.
> **Sözleşme:** Her iddia bir dosyaya işaret eder. Kod ile bu belge çelişirse kod haklıdır,
> belge çürümüştür; belgeyi düzelt (bkz. `docs/PROJECT-READINESS-GUIDE.md` §7).
> **Uygulama planı:** `docs/plans/2026-09-13-global-scale-cell-architecture-plan.md` · **Takvim:** `docs/plans/2026-09-13-global-scale-roadmap.md`

---

## 0. Özet — beş cümlede karar

1. **OpenIDX zaten 8 ayrı süreçtir; eksik olan "daha çok servis" değil, "doğru sınırlar"dır.**
   Servisler tek PostgreSQL'de buluşur (`docs/architecture/system-design-review-2026-07-14.md` §2);
   bugün sınırlar deploy sınırıdır, arıza sınırı değildir.
2. **Mikroservis dönüşümünü "kullanılabilirlik sınıfı" ekseninde yapıyoruz, "tablo başına servis"
   ekseninde değil.** Doğrulama düzlemi (token verify), yayınlama düzlemi (login/token),
   yönetim düzlemi (admin/IGA/SCIM), olay düzlemi (audit/webhook/SIEM) ve ağ düzlemi (Ziti)
   ayrı ayrı ölçeklenir, ayrı ayrı bozulur, ayrı ayrı korunur (§4.3).
3. **Küresel ölçeğin birimi "hücre"dir (cell).** Bir hücre = tam bir yığın (kenar + servisler +
   PG + Redis), sınırlı sayıda kiracıya hizmet eder; kiracılar hücreye sabitlenir. Dünya
   "tek büyük küme" ile değil, "çok sayıda küçük, birbirinden yalıtılmış hücre" ile
   ölçeklenir (§4.2).
4. **DDoS'u satın alırız, yazmayız.** L3/L4 ve hacimsel L7 saldırılar anycast bir kenar
   sağlayıcısında emilir; origin gizlenir; APISIX ve Go katmanı yalnızca
   *uygulama-farkında* kabul kontrolü ve yük atma yapar (§5).
5. **Veri katmanında iki yapısal engel kaldırılmalıdır:** RLS'in oturum-kapsamlı GUC ile
   kurulması bağlantı çoğullamayı yasaklıyor (`internal/common/database/rls.go:59`),
   tek Redis ise hız sınırı, oturum, iptal ve kilitleri aynı bellekte tutuyor. İkisi de
   saldırı altında "kendini DDoS etme" üretir (§3, B1–B3).

---

## 1. Hedefler ve ölçütler

### 1.1 Ölçek hedefleri (tasarım zarfı)

| Boyut | Hedef (tasarım zarfı) | Neden bu sayı |
|---|---|---|
| Kiracı (org) | 10.000+ / bölge, hücre başına ≤ 500 | RLS + tek PG'nin makul kiracı yoğunluğu; blast radius |
| Kayıtlı kullanıcı | 50M+ toplam | Kimlik verisi hücre içinde kalır, küresel indeks yalnız kiracı→hücre |
| Verify (token doğrulama) | 200k rps / hücre, p99 < 30 ms | Durumsuz, JWKS önbellekli, PG'ye dokunmaz |
| Issue (`/oauth/token`, login) | 5k rps / hücre, p99 < 300 ms | PG + Redis'e dokunur; kabul kontrolü burada |
| Admin/IGA/SCIM | 500 rps / hücre | İlk atılan yük |
| Audit ingest | 50k olay/sn / hücre, asenkron | Outbox → olay omurgası → ayrı depo |

### 1.2 Kullanılabilirlik ve bozulma hedefleri

| Düzlem | SLO | Saldırı altında beklenen davranış |
|---|---|---|
| Verify | 99.99 % | Hiç bozulmaz; kenar + APISIX'te sonuçlanır |
| Issue | 99.95 % | Kiracı başına kota; kota aşan kiracı **kendi** hatasını görür, komşusu görmez |
| Admin | 99.9 % | Yük atma ilk burada; UI "yavaş" der, verify sürer |
| Event | 99.9 % (at-least-once) | Gecikir, kaybolmaz (outbox) |
| Network (Ziti) | Veri düzlemi 99.99 %, kontrol 99.9 % | Kurulu tüneller sürer; yeni kayıt/dial gecikir |

### 1.3 DDoS tehdit zarfı

| Katman | Vektör | Nerede emilir |
|---|---|---|
| L3/L4 | SYN/UDP/ampl. flood, Tbps | Anycast kenar sağlayıcısı (satın alınır) |
| TLS | Handshake flood, renegotiation | Kenar sağlayıcısı TLS sonlandırma |
| L7 hacimsel | HTTP flood `/`, `/.well-known/*`, statik SPA | Kenar önbelleği + WAF hız kuralları |
| L7 uygulama | `/oauth/token`, `/oauth/login`, SCIM, `/api/*` | APISIX kabul kontrolü + Go yük atma + kiracı kotası |
| L7 yavaş | Slowloris, slow body, HTTP/2 rapid reset | Kenar sağlayıcısı + APISIX zaman aşımı + Go `ReadHeaderTimeout` |
| Uygulama mantığı | Credential stuffing, OTP spray, SCIM bulk, arama | Hesap/IP/kiracı sayaçları, challenge, maliyet-tabanlı kota |
| Veri | Pahalı sorgu, derin sayfalama, ES arama | Keyset sayfalama, sorgu zaman aşımı, ayrı ES havuzu |
| Kontrol düzlemi | Ziti enrollment/dial flood, APISIX admin | Ayrı hostname, mTLS, kota, admin API yalnız iç ağ |

---

## 2. Mevcut durumun fotoğrafı

Bu bölüm övgü de eleştiri de değildir; planın üzerine kurulduğu zemindir.

### 2.1 Zaten var olan ve korunacak

| Alan | Kanıt |
|---|---|
| 8 bağımsız süreç, ayrı Deployment, replika 2, PDB, anti-affinity, NetworkPolicy default-deny | `deployments/kubernetes/helm/openidx/values.yaml`, `templates/networkpolicy.yaml` |
| Ingress HA: ≥2 controller, HPA, AZ yayılımı, NLB, `externalTrafficPolicy: Local` | `deployments/kubernetes/ingress-nginx-values.yaml` |
| Tek L7 kenar (APISIX), gateway-service istek yolundan çıkarıldı | `docs/architecture/edge.md` |
| Durumsuz verify: RS256 + JWKS, bayat-servis (`JWKS_MAX_STALE`), PG'den bağımsız | `internal/common/jwksverify/`, `cmd/verify-service/`, `docs/architecture/always-available-auth-plan.md` Tier 0 |
| Redis tabanlı dağıtık hız sınırı; auth yolları Redis yokken **kapalı-başarısız** | `internal/common/middleware/ratelimit.go` |
| Kiracı yalıtımı DB'de: FORCE RLS + `orgscope` CI kapısı | `docs/SECURITY-TENANCY.md`, `tools/orgscope` |
| Lider seçimi (Redis SET NX) ile arka plan işleri tek kopyada | `internal/common/leader/leader.go` |
| Okuma replikası havuzu (`Reader()`), RDS Multi-AZ prod | `internal/common/database/database.go`, `deployments/terraform/main.tf` |
| Outbox deseni iki yerde var: SCIM outbound, SSF transmitter | `internal/provisioning/outbound_worker.go`, `internal/oauth/ssf_transmitter.go` |
| Ziti: controller Raft ×3, router ×2 (prod Helm) | `docs/openidx-k8s-always-on.md` §2.4 |
| Zarif kapanma, preStop, `maxUnavailable: 0` güncellemeler | `docs/openidx-k8s-always-on.md` §2.1–2.2 |
| Tehdit modeli, güvenlik kapıları (`ValidateProduction`) | `docs/THREAT-MODEL.md`, `internal/common/config/security_check.go` |

### 2.2 Önceki incelemelerin vardığı yer

Depo bu soruyu daha önce iki kez tartıştı ve **"daha fazla servis bölme, veri katmanını
yedekle"** dedi (`system-design-review-2026-07-14.md` §5, `always-available-auth-plan.md` §0).
O tavsiyeler **tek VM / tek bölge** hedefi için doğruydu. Bu belge hedefi değiştiriyor:
**küresel, çok kiracılı, saldırı altında bir SaaS**. Bu hedefte iki önceki tavsiye korunur
(tabloya göre servis bölmeyin; tek PG'yi kiracı sınırı olarak koruyun), ikisi güncellenir
(CDN/anycast artık hedef *dışı* değil, önkoşuldur; olay omurgası artık ertelenemez).

---

## 3. Bulgular — küresel ölçekte kıracak noktalar

Öncelik sırasına göre. **B** = bloke edici (küresel açılıştan önce şart), **Y** = yüksek,
**O** = orta.

### B1 — RLS oturum GUC'u bağlantı çoğullamayı yasaklıyor

`internal/common/database/rls.go:59` her havuz çıkışında
`set_config('app.org_id', $1, false)` çalıştırır; `false` = **oturum** kapsamı.
`docs/architecture/db-pooling.md` bu yüzden transaction-mode pgbouncer'ı doğru olarak
yasaklıyor. Sonuç: PG'ye açık bağlantı sayısı = servis × replika × `DB_MAX_CONNS`. HPA ile
8 servis × 10 replika × 10 = 800 bağlantı; PG bunun altında `max_connections` ile boğulur.
**Ölçek tavanı sabit ve düşüktür.** Çözüm: GUC'u işlem içinde `SET LOCAL` ile kurmak
(db-pooling.md'nin kendi 3. seçeneği), sonra pgbouncer/pgcat transaction modu (§4.4.1).

### B2 — Tek Redis, dört farklı işi aynı bellekte yapıyor

> **Durum (2026-09-13):** Kod düzeyinde kapandı (görev 0.1): üç rol istemcisi, `RevocationDB()`/`RateLimitDB()`, census testi, compose'da üç örnek, Helm `redis.roles`/`externalSecrets.redisRoles`. Staging ölçümü bekliyor.

Hız sınırı sayaçları (`ratelimit.go`), login/MFA/authcode oturum durumu
(`internal/oauth/handlers_passwordless.go:216`, `authorize.go:548`), iptal işaretleri
(`internal/revocation`), lider kilitleri (`internal/common/leader`) aynı örnekte.
Compose'da `maxmemory-policy` **yok** (`deployments/docker/docker-compose.yml:86`), yani
varsayılan `noeviction`. Bir IP/kiracı floodu milyonlarca `ratelimit:*` anahtarı üretir →
Redis OOM döner → hız sınırı auth yollarında **kapalı-başarısız** çalışır (tasarım gereği)
→ **saldırgan tüm login'i kapatır**. Bu, savunmanın saldırıya dönüşmesidir.
Çözüm: rol başına ayrı Redis (§4.4.2), sayaç Redis'i `allkeys-lru` + sıkı TTL.

### B3 — Kenar arkasında gerçek istemci IP'si kaybolur; hız sınırı tek kovaya çöker

> **Durum (2026-09-13):** Kod düzeyinde kapandı (görev 0.2): `OIDX_EDGE_TRUSTED_CIDRS` birleşimi, prod'da `*` reddi, APISIX `real-ip` (compose + edge seed), `edge-cidr-sync` CronJob. Staging ölçümü bekliyor.

APISIX `limit-req` `key: remote_addr` kullanıyor (`deployments/docker/apisix/apisix.yaml`).
Go tarafı `ConfigureTrustedProxies` varsayılan olarak yalnız loopback'e güvenir
(`internal/common/middleware/trustedproxies.go:32`). Bir CDN/anycast katmanı öne
konduğunda `remote_addr` = CDN IP'si olur: **tüm dünya tek kovayı paylaşır**, meşru
kullanıcılar birbirini sınırlar, saldırgan bir tuşla herkesi 429'a düşürür.
Çözüm: kenar sağlayıcısının imzalı gerçek-IP başlığı + APISIX `real-ip` eklentisi +
`OIDX_TRUSTED_PROXIES` = sağlayıcı CIDR listesi, sağlayıcı dışından gelen bağlantı **red**
(origin gizleme, §5.2).

### B4 — Olay omurgası yok; servisler arası iletişim "aynı tabloya yaz" ile oluyor

`internal/common/events` **süreç içi** bir bus taşıyordu; başka süreçteki hiçbir servis
duymazdı. *(3.1'de silindi: 346 satırlık `bus.go` ve testlerini ağaçta **hiçbir şey import
etmiyordu** — ne bir yayıncı ne bir abone. Yerine `internal/common/events/outbox.go` geldi:
olayı, anlattığı durum değişikliğinin işlemine yazan tek yayın yolu. İkisini yan yana
bırakmak, kullanılmamış olmasından kötüydü — "olay bus'ı" arayan biri hangisi daha kolay
okunuyorsa onu seçerdi ve aradaki fark, birinin süreç ölünce her şeyi kaybetmesi.)* Audit çift yazımı en-iyi-çaba (`internal/audit/service.go:325`) ve bir uzlaştırıcı
ile telafi ediliyor (`:351`). Webhook'lar satır içi ateşleniyor. Küresel ölçekte audit yazma
hacmi PG birincilini kilitler; kiracı silme, iptal, kill-switch gibi çapraz-servis olaylar
kaybolabilir. Çözüm: outbox'ı platform ilkelini yap, NATS JetStream ile taşı (§4.4.4).

### B5 — Kenar savunması IaC'de yok

> **Durum (2026-09-13):** Kısmen kapandı: nginx/APISIX/Go zaman aşımı ve bağlantı tavanları (görev 0.3), health/metrics kenarda 404 (0.4). WAF/Shield/CDN modülleri Faz 1.1'de.

`deployments/terraform` içinde WAF, Shield, CloudFront, Front Door veya herhangi bir
DDoS kaynağı **yok** (grep sonucu boş). nginx'te `limit_conn`/`limit_req`/`client_body_timeout`
yok (`deployments/docker/nginx/nginx.conf`); APISIX'te `limit-conn` yok; etcd tek
örnek (compose). Bugün L3/L4'te ilk paket bulutu yutan NLB'dir, arkası çıplaktır.

### Y1 — HPA varsayılan kapalı ve yalnız CPU'ya bakıyor

> **Durum (2026-09-13):** Kod düzeyinde kapandı (görev 0.5): access ve gateway HPA/PDB kapsamına alındı (eksikti), `behavior` blokları, CPU hedefi %60. KEDA Faz 3.6'da.

`values.yaml`'da `autoscaling.enabled: false`, hedef CPU %80. Kimlik trafiği CPU'dan önce
**bağlantı ve PG bekleme** ile boğulur; CPU %80'e geldiğinde p99 çoktan patlamıştır.
Çözüm: RPS/gecikme/kuyruk derinliği tabanlı ölçekleme (KEDA veya custom metrics, §7).

### Y2 — Servis içinde yük atma ve öncelik yok

> **Durum (2026-09-13):** Kısmen: `server.NewHTTP` başlık zaman aşımı/boyut/HTTP2 akış sınırı ve gövde tavanları (0.3). Kabul denetleyicisi ve öncelik sınıfları Faz 3.5'te.

Go sunucularda `ReadTimeout` var (`cmd/oauth-service/main.go:299`) ama eşzamanlılık
sınırı, kuyruk, öncelik sınıfı yok. `/oauth/token` ile `/api/v1/audit/search` aynı
goroutine havuzunda yarışır. Saldırı admin API'ye gelirse login de düşer.
Çözüm: düzlem başına ayrı Deployment + kabul denetleyicisi (§5.4).

### Y3 — İssue yoluna bot/otomasyon direnci yok

Depoda CAPTCHA/Turnstile/PoW/cihaz-parmak-izi yok (grep boş). Credential stuffing
yalnız IP/kiracı sayacıyla karşılanıyor; dağıtık botnet her IP'den 3 deneme yapar, sayaç
hiç dolmaz. Çözüm: hesap-başına sayaç, kenar "managed challenge", risk skoru → step-up
(mevcut `internal/risk` ve `internal/stepup` ile birleşir, §5.3).

### Y4 — Ziti kontrol düzlemi kamuya açık ve kota yok

Agent'lar controller edge API'sine (1280) mTLS ile dial eder; enrollment JWT'leri
kamuya açık uçtan tüketilir. Bir enrollment floodu controller Raft'ını yorar; veri düzlemi
sürer ama yeni kullanıcı katılamaz. Çözüm: ayrı hostname/LB, kenar hız kuralı, enrollment
uçlarının OpenIDX üzerinden ön-onaylı token ile açılması (§6.4).

### O1 — CORS `*` oauth-service'te satır içi ve koşulsuz

> **Durum (2026-09-13):** Kapandı (görev 0.6): `middleware.OAuthCORS` — protokol uçları `*` (tasarım gereği, çerez taşımaz), UI yolları yapılandırılan liste; tehdit modeli TB1 güncellendi.

`cmd/oauth-service/main.go:159-170` her yanıta `Access-Control-Allow-Origin: *` yazar;
tehdit modeli `ValidateProduction()`'ın joker CORS'u reddettiğini söyler
(`docs/THREAT-MODEL.md` TB1). İkisi çelişiyor; belge veya kod düzelmeli. OAuth uçları için
`*` kabul edilebilir olabilir (kimlik bilgisi taşımayan uçlar) ama **bilinçli** olmalı.

### O2 — APISIX rota tablosunda CORS listesi 9 kez kopyalanmış

> **Durum (2026-09-13):** Kapandı (görev 0.6): compose ve loader'da tek global `cors` kuralı; protokol rotalarında `*` override; test liste sayısını 1'e sabitler.

Kiracı alan adları çoğaldığında bu liste yönetilemez. Global plugin + kiracı bazlı
origin çözümü gerekir (kiracı→izinli origin tablosu zaten `orgs` ile modellenebilir).

### O3 — Tek etcd APISIX arkasında

Compose'da etcd tek; K8s'te APISIX chart'a dahil değil. Rota tablosu kaybı = kenar sağır.
Hücre başına 3 etcd veya APISIX standalone (yaml) modu.

---

## 4. Hedef mimari

### 4.1 Katmanlar

```
              ┌───────────────────────────────────────────────────────────────┐
  İnternet    │  KÜRESEL KENAR (satın alınır): anycast PoP ağı, L3/4 emilim,   │
  ─────────►  │  TLS 1.3 / HTTP/3, WAF, bot yönetimi, önbellek, kiracı→hücre   │
              │  yönlendirme (subdomain → hücre origin), imzalı gerçek-IP      │
              └──────────────┬───────────────────────────┬────────────────────┘
                             │ yalnız kenar CIDR + mTLS   │
                 ┌───────────▼───────────┐   ┌───────────▼───────────┐
                 │  HÜCRE eu-1 (bölge A)  │   │  HÜCRE us-1 (bölge B)  │   ... hücre N
                 │  NLB → APISIX ×N       │   │                        │
                 │  ├ VERIFY düzlemi      │   │  aynı yapı, farklı      │
                 │  ├ ISSUE düzlemi       │   │  kiracı kümesi,         │
                 │  ├ ADMIN düzlemi       │   │  bağımsız PG/Redis      │
                 │  ├ EVENT düzlemi       │   │                        │
                 │  └ NETWORK düzlemi     │   │                        │
                 │  PG(+pgcat) Redis×3 ES │   │                        │
                 └───────────┬───────────┘   └───────────────────────┘
                             │
              ┌──────────────▼──────────────────────────────────────────────┐
              │  KÜRESEL KONTROL DÜZLEMİ (küçük, salt-okunur ağır):           │
              │  kiracı dizini (org → hücre, durum, residency), yayın/sürüm,  │
              │  merkezi gözlemlenebilirlik, DR koordinasyonu                 │
              └─────────────────────────────────────────────────────────────┘
```

Üç ilke:

1. **İstek yolunda küresel bileşen yoktur.** Kenar, kiracı→hücre eşlemesini önbelleğinden
   çözer; küresel kontrol düzlemi çökse trafik akar (`docs/openidx-trafik-mimarisi.md` K2
   ilkesinin küresel ölçeğe genellenmesi).
2. **Hücreler birbirini görmez.** Bir hücrenin PG'si, Redis'i, Ziti fabric'i kendine aittir.
   Kiracı verisi hücre dışına yalnız DR replikasyonu için çıkar.
3. **Kenar dışından origin'e paket girmez.** Origin yalnız kenar sağlayıcısının IP
   bloklarından ve mTLS ile kabul eder (§5.2).

### 4.2 Hücre (cell) modeli

| Özellik | Karar |
|---|---|
| Hücre boyutu | ≤ 500 kiracı veya ≤ 2M kullanıcı veya ≤ 5k issue rps (hangisi önce) |
| Kiracı yerleşimi | Kayıtta seçilir (residency + kapasite); taşıma nadir ve planlı |
| Yönlendirme anahtarı | `{tenant}.{base_domain}` → hücre origin; mevcut `TENANT_BASE_DOMAIN` çözümü aynen kullanılır (`internal/common/middleware/tenant_resolver.go`) |
| Yönlendirme kaynağı | Kiracı dizini → kenar KV/worker'a itilir; TTL 60 s; hücre etiketi JWT `cell` claim'inde de taşınır |
| Hücre içi yığın | Bugünkü Helm chart, bir hücre = bir release |
| Hücre kimliği | Her olay/audit kaydı `cell_id` taşır; küresel arama hücre-federe |
| Blast radius | Bir hücrenin çökmesi o hücrenin kiracılarını etkiler, dünyayı değil |
| Kanarya | Yeni sürüm önce "kanarya hücre"ye; dünya genelinde dalga dalga yayılır |

Hücre modelinin OpenIDX için ekstra kazancı: **RLS'i korur.** Kiracı sınırı hücre içinde tek
PG + FORCE RLS olarak kalır; kiracı başına DB gibi maliyetli bir modele gidilmez.

### 4.3 Servis düzlemleri — mikroservis sınırlarının yeniden çizilmesi

Mevcut 8 servis, veri sahipliğine göre değil **kullanılabilirlik sınıfına** göre
gruplanır. Bir düzlem = ayrı Deployment seti, ayrı HPA, ayrı NetworkPolicy, ayrı PG
bağlantı bütçesi, ayrı Redis, ayrı APISIX upstream, ayrı öncelik sınıfı.

| Düzlem | İçerik (bugünkü koddan) | Durum | Veri erişimi | Yük atma sırası |
|---|---|---|---|---|
| **VERIFY** | JWKS (`/.well-known/*`), introspection, forward-auth (`access-service` `/access/.auth/*`), iptal kontrolü | Durumsuz + Redis(iptal) salt-okur | PG **yok** | En son (hiç) |
| **ISSUE** | `oauth-service` authorize/token/login/MFA/passwordless, `identity-service` kimlik doğrulama uçları | Durumlu | PG birincil + Redis(oturum) | 3. |
| **ADMIN** | `admin-api`, `governance-service` API, `provisioning-service` SCIM API, identity CRUD | Durumlu | PG birincil + replika | 1. (ilk atılır) |
| **EVENT** | `audit-service` ingest, webhook teslimi, SIEM, SSF, uzlaştırıcılar, tüm `leader.RunPeriodic` işleri | Asenkron worker | Outbox → NATS → ES/PG | Kuyruklanır |
| **NETWORK** | Ziti controller/router, `access-service` proxy/kill-switch, PAM broker | Durumlu (Ziti Raft) | Kendi deposu + PG | Kurulu tünel korunur |

Bu ne demek, ne demek değil:

- **Bölünen:** `identity-service` ikiye ayrılır (auth uçları → ISSUE, CRUD → ADMIN);
  `governance`/`provisioning`/`audit` içindeki ticker/worker döngüleri API binary'sinden
  çıkarılır (`cmd/*-worker`), API pod'ları salt istek servis eder. Verify için küçük bir
  `verify-service` (JWKS sunumu + introspection + forward-auth) ayrılır; `oauth-service`
  yalnız issue yapar.
- **Bölünmeyen:** Tablo başına servis, kiracı başına DB, hücre içi servisler arası
  senkron RPC ağı. Aynı PG, aynı RLS.
- **Neden bu eksen:** Saldırı yükü hangi düzleme gelirse ona bağlı bozulma isteriz; kimlik
  ürününde "login çalışıyor, admin paneli yavaş" kabul edilir, tersi kabul edilmez.

### 4.4 Veri mimarisi

#### 4.4.1 PostgreSQL: hücre başına tek PG, `SET LOCAL` RLS, transaction pooler

1. `rls.go` `beforeAcquire` kancası yerine, tüm sorguların geçtiği tek bir işlem sarmalayıcısı
   (`database.WithTx(ctx, fn)`) işlemin ilk ifadesi olarak `SET LOCAL app.org_id = ...` koşar.
   Autocommit tek-ifade sorgular `BEGIN; SET LOCAL; <stmt>; COMMIT` olarak paketlenir
   (pgx `Batch`). `orgscope` linter'ı "işlem dışı sorgu" için de kapı olur.
2. Sonra **pgcat/pgbouncer transaction modu** öne konur: servis havuzları küçülür, PG'ye
   giden bağlantı hücre başına sabit bir bütçedir (ör. 200), HPA replika sayısından
   bağımsızlaşır.
3. Okuma replikası `Reader()` ADMIN düzleminde varsayılan olur (`values-prod.yaml`
   `readReplica: true`).
4. Sorgu zaman aşımı düzlem başına: VERIFY 200 ms (zaten PG yok), ISSUE 2 s, ADMIN 10 s,
   EVENT 30 s (`statement_timeout` rolde).
5. Derin `OFFSET` sayfalama audit/SCIM listelerinde keyset'e çevrilir (önceki inceleme #11).

#### 4.4.2 Redis: rol başına ayrı örnek

| Rol | Örnek | Politika | Kayıpta davranış |
|---|---|---|---|
| `redis-ratelimit` | Cluster/Sentinel, küçük | `allkeys-lru`, TTL ≤ pencere | Auth yolları kapalı-başarısız (bugünkü davranış), **ama** yalnız bu örnek hedef alınabilir; oturumlar etkilenmez |
| `redis-session` | Sentinel, AOF | `noeviction`, TTL'li anahtarlar | Login oturumları kaybolur, mevcut JWT'ler sürer |
| `redis-revocation` | Sentinel, AOF, çoğaltılır | `noeviction` | Verify **fail-closed değil**: son bilinen iptal kümesi yerel Bloom filtreden okunur (JWKS bayat-servis ile aynı felsefe) |
| Lider kilitleri | `redis-session` üzerinde | — | Redis hatasında iş **çalışmaz** (mevcut davranış, doğru) |

Uygulama yolu: `NewRedisFromConfig` zaten Sentinel destekliyor; yalnız üç URL
(`REDIS_RATELIMIT_URL`, `REDIS_SESSION_URL`, `REDIS_REVOCATION_URL`) ve her tüketicinin
doğru istemciyi alması.

#### 4.4.3 Audit: ilk gerçek depo ayrımı

Audit yazımı PG birincilinden çıkar: servis → outbox (aynı işlem) → relay → NATS JetStream
`audit.<cell>.<org>` → tüketici → ES/OpenSearch (arama) + soğuk depo (S3/Parquet, yasal
saklama). HMAC zinciri (`internal/audit/chain.go`) tüketici tarafında hücre-org dizisi
üzerinden korunur. PG'de yalnız son N gün "sıcak" kopya kalır (uyumluluk raporları için).

#### 4.4.4 Olay omurgası: outbox → NATS JetStream

- `internal/common/events` arayüzü korunur; `MemoryBus` yanına `OutboxBus` gelir:
  `Publish` = aynı `pgx.Tx` içinde `outbox` tablosuna INSERT. Relay worker (EVENT düzlemi,
  lider seçimli) yayınlar, at-least-once, idempotency anahtarı = `event.ID`.
- Neden NATS JetStream, Kafka değil: tek binary, hücre başına 3 pod, düşük işletme
  maliyeti, konu bazlı kiracı ayrımı. Kafka ölçeği burada gerekmez; ihtiyaç doğarsa arayüz aynı.
- Tüketiciler: audit indexer, webhook deliverer (satır içi ateşleme kalkar), SIEM
  forwarder, SSF transmitter (mevcut outbox'ı bu ilkele göç eder), Ziti reconciler
  (kill-switch olayı), cache invalidation (izin/rol değişimi → `redis-session`).

### 4.5 Trafik akışları

**Verify (her API isteği):**
kenar (WAF, kota) → APISIX `jwt-auth`/`forward-auth` → verify-service (JWKS yerel, iptal
Bloom + `redis-revocation`) → 200/401. PG yok, ISSUE düzlemi yok. Kenar önbelleği
`/.well-known/jwks.json`'ı 5 dk saklar (`Cache-Control`), JWKS floodu origin'e ulaşmaz.

**Issue (login/token):**
kenar (bot challenge, IP itibarı, kiracı kotası) → APISIX (`limit-count` anahtar =
`tenant + client_id + gerçek IP`, `limit-conn`) → oauth-service kabul denetleyicisi
(eşzamanlılık N, kuyruk M, 50 ms üstü bekleyen 503+`Retry-After`) → `redis-session` +
PG (pgcat) → outbox olay → yanıt.

**Admin:**
kenar (yalnız oturumlu, WAF sıkı) → APISIX (düşük kota) → ADMIN düzlemi → PG replika/birincil.
Aşırı yükte ilk 503 alan bu düzlemdir; alarm eşiği burada düşük tutulur.

---

## 5. DDoS savunma mimarisi

Savunma ilkesi: **her katman kendi altındakinin göremeyeceği bilgiyle karar verir, üstüne
yük geçirmez.** Kenar IP/ASN/TLS parmak izini bilir; APISIX rotayı ve kiracıyı bilir;
Go kullanıcıyı, riski ve maliyeti bilir.

### 5.1 Katman 0 — Kenar sağlayıcısı (satın alınır)

> **Durum (2026-09-13):** Görev 1.1 kodlandı: `deployments/terraform/edge` kökü + `modules/edge-{cloudflare,aws,azure}`, ortak arayüz ve tek kural kaynağı `modules/edge-common/rules.json` (bu tablo). Üçü de `terraform validate` geçer; CI'da. Sağlayıcı seçimi (K1) hâlâ açık — kök tek değişkenle seçer.

- Anycast PoP ağı, L3/L4 otomatik emilim, TLS 1.3 + HTTP/3 sonlandırma, HTTP/2 rapid
  reset koruması, WAF (OWASP CRS + kimlik ürününe özel kurallar), bot yönetimi
  ("managed challenge"), hız kuralları (IP, ASN, JA4, ülke), önbellek.
- Sağlayıcı seçimi IaC ile soyutlanır: `deployments/terraform/modules/edge-{cloudflare,aws,azure}`
  aynı girdi/çıktıyı verir. AWS yolunda: CloudFront + Shield Advanced + WAFv2; Azure
  yolunda: Front Door Premium + DDoS Network Protection; sağlayıcı-bağımsız yolda: Cloudflare.
- **Kabul ölçütü:** Origin NLB'nin güvenlik grubu yalnız sağlayıcı IP bloklarına açık;
  sağlayıcı dışından `curl` origin'e → bağlantı reddi.

### 5.2 Katman 1 — Origin gizleme ve gerçek IP

- Origin hostname'i kamuya yayınlanmaz; sertifika CT log'unda görünür, bu yüzden IP
  filtre + **origin mTLS** (sağlayıcı istemci sertifikası doğrulanır) birlikte şarttır.
- Gerçek IP yalnız sağlayıcının başlığından (`CF-Connecting-IP` / `X-Forwarded-For` ilk
  güvenilir hop) alınır: APISIX `real-ip` eklentisi `trusted_addresses` = sağlayıcı CIDR;
  Go tarafında `OIDX_TRUSTED_PROXIES` aynı liste (asla `*`).
- Sağlayıcı CIDR listesi bir CronJob ile çekilir, `ConfigMap` + APISIX global rule
  güncellenir; liste alınamazsa eski liste korunur, alarm üretilir.

### 5.3 Katman 2 — Kenar kuralları (uygulama-farkında ama durumsuz)

| Hedef | Kural |
|---|---|
| Statik SPA, `/.well-known/*`, JWKS | Önbellekten servis; origin'e dakikada 1 |
| `/oauth/login`, `/oauth/mfa-*`, `/oauth/passwordless/*` | IP başına 30/dk; ASN anomalisi → managed challenge; risk başlığı ile Go'ya `X-Edge-Bot-Score` |
| `/oauth/token` | Kaynak başına 300/dk (kenar POST gövdesini ayrıştırmaz; client_id bütçesi APISIX'te); `grant_type=password` yok |
| `/scim/` | Kaynak başına 600/dk (kenar); Bearer olmadan gelen → 401 APISIX'te |
| `/api/v1/audit/events/search` | Kaynak başına 60/dk (kenar); kiracı başına bütçe APISIX'te |
| Tüm | Gövde 1 MB (SCIM bulk 5 MB istisna), URL 8 KB, başlık 16 KB, `Content-Type` beyaz liste |
| Ziti controller hostname | Yalnız mTLS; HTTP kuralı yok, L4 hız sınırı (yeni bağlantı/sn) |

### 5.4 Katman 3 — APISIX kabul kontrolü

- `limit-conn` (rota başına eşzamanlı bağlantı) + `limit-count` (Redis-cluster politikası,
  anahtar `$tenant_host|$remote_addr(real)`), `client_max_body_size`, `proxy_read_timeout`
  düzlem başına (VERIFY 2 s, ISSUE 10 s, ADMIN 30 s).
- **Öncelik:** APISIX upstream'leri düzlem başına ayrı; ISSUE upstream'i için
  `retries: 0` (yeniden deneme çarpanı saldırıyı büyütür), ADMIN için `retries: 1`.
- Pasif sağlık kontrolü: 5xx oranı %20 → upstream düğümü 10 s dışarı.
- `/health/ready` **dışa kapalı** (bugün `skipPaths` ile hız sınırından muaf; kenarda 404).
- etcd ×3 veya APISIX standalone yaml (Helm `apisix.deployment.mode: standalone`, rota
  tablosu ConfigMap). Standalone tercih: bir bağımlılık eksik, rota tablosu Git'te.

### 5.5 Katman 4 — Go servislerinde yük atma ve maliyet kotası

- **Kabul denetleyicisi middleware** (`internal/common/middleware/admission.go`, yeni):
  düzlem başına eşzamanlılık sınırı (`ADMISSION_MAX_INFLIGHT`), kısa kuyruk
  (`ADMISSION_QUEUE_TIMEOUT`, ISSUE için 100 ms), aşımda `503` + `Retry-After` +
  `openidx_admission_rejected_total{plane,route}`. Uyarlanabilir sınır (gradient/AIMD)
  ikinci aşamada.
- **Maliyet-tabanlı kota:** `ratelimit.go`'ya rota maliyeti eklenir: `/oauth/token` = 5
  birim, `/oauth/login` = 10, `/api/v1/audit/search` = 20, okuma = 1. Kiracı bütçesi
  birim/dk. Böylece pahalı uç ucuz uçla aynı kovadan yenmez.
- **Hesap-başına sayaç** (credential stuffing): `login_fail:{org}:{username_hash}` →
  N hatada o hesap için challenge/step-up zorunlu; IP'den bağımsız. Mevcut
  `internal/risk` skoruna girdi.
- **Redis kaybı:** hız sınırı `redis-ratelimit` yokken ISSUE için yerel token-bucket'a
  (replika başına kota/N) 60 s süreyle düşer, alarm üretir; 60 s sonra kapalı-başarısız.
  Bugünkü "anında 503" davranışı bir Redis restart'ını login kesintisine çeviriyor.
- HTTP sunucu: `ReadHeaderTimeout: 5s`, `MaxHeaderBytes: 16<<10`, `http.MaxBytesReader`
  rota başına; HTTP/2 `MaxConcurrentStreams` 100.
- Pahalı iş asla istek içinde: rapor üretimi, CSV export, SCIM bulk → EVENT düzlemine
  iş kuyruğu, istemciye `202 + job_id`.

### 5.6 Bozulma matrisi (ne kaybolur, ne kalır)

| Kaybedilen | Verify | Issue | Admin | Event | Network |
|---|---|---|---|---|---|
| Kenar sağlayıcısı PoP'u | Anycast yeniden yönlendirir | aynı | aynı | — | Ziti ayrı yol |
| Bir hücre tamamen | O hücrenin kiracıları için her şey düşer; diğerleri etkilenmez | | | | |
| PG birincil (failover 30–60 s) | **Sürer** | Kesilir, sonra döner | Kesilir | Kuyruklanır | Tüneller sürer |
| `redis-ratelimit` | Sürer | 60 s yerel kota, sonra 503 | 60 s yerel kota | — | — |
| `redis-session` | Sürer | Yeni login bozulur, JWT sürer | Sürer | Lider kilidi yok → işler durur | — |
| `redis-revocation` | Bloom'dan **bayat** okur, alarm | Sürer | Sürer | — | — |
| NATS | Sürer | Sürer (outbox PG'de birikir) | Sürer | Gecikir | Kill-switch gecikir → alarm |
| ES/OpenSearch | Sürer | Sürer | Arama 503 | Kuyruklanır | — |
| Ziti controller quorum | Sürer | Sürer | Sürer | — | Yeni dial yok, kurulu sürer |

### 5.7 Saldırı anı runbook'u (özet; tam sürüm planda)

1. Alarm: `edge_requests_total` baseline ×5 veya `admission_rejected_total` > 0 ISSUE'da.
2. Kenarda "Under Attack" modu: tüm ISSUE uçları managed challenge; statik önbellek TTL ↑.
3. Kaynak kiracı/ASN/ülke belirle; kiracı bazlı kotayı düşür (kiracı **kendi** hatasını
   görür, komşusu görmez).
4. ADMIN düzlemini `minReplicas`'a çek (kaynakları ISSUE'ya ver); VERIFY'a dokunma.
5. PG bağlantı bütçesini kontrol et (pgcat gauge); ISSUE kuyruğu > 100 ms ise ISSUE
   HPA maks ↑.
6. Kayıt: `cell_id`, kural değişimleri, süre → audit; geri alma adımları aynı sırada ters.

---

## 6. Ağ ve güvenlik mimarisi

### 6.1 Kuzey–güney

İnternet → kenar sağlayıcısı (anycast, TLS) → origin mTLS → NLB (yalnız kenar CIDR) →
APISIX → düzlemler. Hiçbir servis pod'unun `LoadBalancer`/`NodePort`'u yok (bugün de öyle).

### 6.2 Doğu–batı: mTLS ve kimlik

- `serviceTLS.enabled` bugün `false` (`docs/architecture-and-ha-review.md` §5). Hedef:
  SPIFFE kimlikli mTLS. Seçenek A: mesh (Linkerd; hafif, Go ile uyumlu). Seçenek B:
  mevcut `internal/common/tlsutil` + cert-manager ile servis sertifikaları. **Karar:**
  Linkerd; gerekçe: yeniden deneme bütçesi, mTLS ve altın metrikler tek yerde, kod değişimi
  sıfır. Ziti pod'ları mesh dışı (kendi PKI'sı var).
- NetworkPolicy default-deny **egress** de eklenir (bugün yalnız ingress): servis pod'ları
  yalnız PG/Redis/NATS/OPA/Ziti ve kenar CIDR'lerine çıkar; SMTP/SMS/webhook egress'i
  yalnız EVENT düzleminden.
- OPA sidecar veya OPA pod'u düzlem başına; ADMIN'de fail-closed, VERIFY'da OPA yok.

### 6.3 Sırlar ve anahtarlar

- Hücre başına ayrı JWT imzalama anahtarı, `kid` içinde `cell`; küresel JWKS yok
  (her kiracı kendi hücresinin JWKS'ini görür; bugünkü `PUBLIC_BASE_URL` kiracı-alt-alan
  modeliyle uyumlu).
- KEK'ler OpenBao/KMS'te hücre başına; `cmd/rekey` hücre kapsamında.
- APISIX admin API kapalı (standalone) veya yalnız iç ağ + anahtar rotasyonu.

### 6.4 Ziti kontrol düzlemi koruması

- Controller/router için ayrı hostname ve ayrı L4 LB; HTTP kenarından geçmez.
- Enrollment JWT'leri kısa ömürlü (15 dk), tek kullanımlık, yalnız OpenIDX'in onayladığı
  cihaz için üretilir (bugün `access-service` üretiyor; kota eklenir: kiracı başına saatte N).
- Controller edge API'sine yeni bağlantı/sn L4 kuralı; Raft ×3 + router ×2 korunur.
- Router'lar hücre içidir; bölgeler arası fabric kurulmaz (hücre yalıtımı).

### 6.5 Tedarik zinciri

Mevcut: cosign imzalı Helm, CodeQL, Trivy, gitleaks (`.github/workflows/`). Eklenir:
imaj digest pin'i Helm değerlerinde zorunlu (`tag: latest` yasak, CI kapısı), SBOM
yayımı, kenar sağlayıcı kural setinin de Git'te ve imzalı olması.

---

## 7. Ölçekleme

| Düzlem | Sinyal | Hedef | Min/Maks (hücre) |
|---|---|---|---|
| VERIFY | RPS / pod, p99 | 5k rps/pod, p99 < 30 ms | 3 / 40 |
| ISSUE | Kabul kuyruğu bekleme p95, PG bekleme | kuyruk < 20 ms | 3 / 30 |
| ADMIN | CPU + p99 | p99 < 500 ms | 2 / 10 |
| EVENT worker | NATS consumer lag | lag < 10 s | 2 / 20 |
| APISIX | Bağlantı sayısı, CPU | %60 | 3 / 20 |

- KEDA ile Prometheus tetikleyicileri; HPA `behavior.scaleDown.stabilizationWindowSeconds: 300`
  (saldırı dalgalanmasında flap etmesin), `scaleUp` agresif (60 s'de ×2).
- Küme düzeyinde: Karpenter/cluster-autoscaler, ISSUE için ayrı düğüm havuzu
  (`nodeSelector: plane=issue`) — ADMIN'in bellek sızıntısı ISSUE'nun düğümünü yemesin.
- Kapasite modeli tabloları yük testinden çıkar; **sayı tahmin edilmez, ölçülür**
  (`k6` senaryoları planda).

---

## 8. Gözlemlenebilirlik ve SLO'lar

- Her metrik `cell`, `plane`, `org_id` (kardinalite için hash'li) etiketli.
- Altın sinyaller düzlem başına; SLO'lar §1.2. Hata bütçesi yanınca özellik sürümü durur.
- Saldırı panosu: kenar istek/blok oranı, APISIX 429/503, kabul reddi, PG bağlantı bütçesi,
  Redis bellek (3 örnek ayrı), NATS lag, Ziti dial başarı oranı.
- İzleme: OTel zaten var (`otelgin`); `traceparent` kenardan itibaren taşınır, kenar
  `Ray-ID` eşdeğerini `X-Edge-Request-ID` ile Go log'una geçirir.
- Tatbikat: `make k8s-chaos` canlı modu her hücrede aylık; DDoS oyun günü çeyreklik
  (planda tanımlı senaryolar).

---

## 9. Mimari karar kayıtları (ADR)

| # | Karar | Reddedilen alternatif | Gerekçe |
|---|---|---|---|
| ADR-1 | Hücre tabanlı bölgesel mimari | Tek küresel küme + küresel PG | Blast radius, residency, RLS'i koruma |
| ADR-2 | Servis sınırı = kullanılabilirlik sınıfı | Tablo/alan başına servis | Saldırıda bağlı bozulma; RLS tek DB'de kalır |
| ADR-3 | Kenar/DDoS satın alınır, IaC ile soyutlanır. **Seçilen sağlayıcı (2026-09-13): Azure Front Door Premium** — yığın zaten Azure'da; WAF + Bot Manager aynı abonelikte; origin `X-Azure-FDID` + `AzureFrontDoor.Backend` servis etiketiyle gizlenir | Kendi anycast/scrubbing; Cloudflare/CloudFront modülleri korunur (taşınabilirlik) | Altyapı yatırımı, yazılımla taklit edilemez (`openidx-trafik-mimarisi.md` K3) |
| ADR-4 | RLS `SET LOCAL` + pgcat transaction modu | Oturum GUC + büyük `max_connections` | Bağlantı = ölçek tavanı; HPA ile çarpan patlar |
| ADR-5 | Rol başına üç Redis | Tek Redis, `maxmemory` ayarı | Savunmanın saldırıya dönüşmesini keser |
| ADR-6 | Outbox → NATS JetStream | Kafka; doğrudan HTTP webhook | İşletme maliyeti; at-least-once; hücre içi |
| ADR-7 | Audit ayrı depo (ES + soğuk) | PG'de kalsın | Yazma hacmi birincili kilitler |
| ADR-8 | Linkerd mTLS | Uygulama seviyesi TLS | Kod değişimi sıfır, gözlem hediye |
| ADR-9 | APISIX standalone (rota tablosu Git'te) | etcd ×3 | Bir bağımlılık eksik, drift yok |
| ADR-10 | Kabul denetleyicisi + maliyet kotası Go'da | Yalnız kenar kotası | Kenar kullanıcıyı/maliyeti bilmez |
| ADR-11 | Kill-switch olayı NATS ile, hedef p95 < 2 s | Senkron çağrı zinciri | Çapraz-düzlem, at-least-once, hücre içinde |

---

## 10. Yapmayacaklarımız

- ❌ Kiracı başına veritabanı. RLS + hücre yeter; işletme maliyeti patlar.
- ❌ Hücreler arası senkron çağrı veya paylaşılan Redis/PG.
- ❌ Kendi L3/L4 scrubbing merkezi, kendi anycast'i.
- ❌ Go içinde yük dengeleyici veya WAF yazmak.
- ❌ İstek yolunda küresel kontrol düzlemi.
- ❌ Bir "hızlı düzeltme" için transaction-mode pgbouncer'ı `SET LOCAL` refactor'undan
  **önce** açmak — kiracı sızıntısı (`db-pooling.md` uyarısı geçerli).
- ❌ Verify yolunda fail-closed Redis bağımlılığı.

---

## 11. Riskler

| Risk | Etki | Azaltım |
|---|---|---|
| `SET LOCAL` refactor'u 158 KLOC'ta sorgu yolu kaçırır | Kiracı sızıntısı | `orgscope` genişletilir; RLS entegrasyon testleri (`rls_enforcement_test.go`) pgcat arkasında koşar; kanarya hücre |
| Kenar sağlayıcısı kilitlenmesi | Taşıma maliyeti | Terraform modül arayüzü sabit; iki sağlayıcı ile CI'da `terraform validate` |
| Hücre yönlendirme önbelleği bayatlar | Kiracı yanlış hücreye gider | Hücre yanlış kiracıyı tanımaz → 421 + doğru hücre; kenar yeniden çözer |
| NATS öğrenme eğrisi | Olay kaybı korkusu | Outbox PG'de kalır; NATS düşse birikir |
| Maliyet | Hücre başına sabit taban | Küçük hücre profili (tek AZ, 3 pod) ilk pazarlar için |

---

## 12. Bu belge yanlışsa

Belge dosya atıflarıyla yazıldı ki yeniden doğrulanabilsin. Bir bulgu düzeltildiğinde aynı
PR'da ilgili satırı güncelle veya çiz. Plan dosyası (`docs/plans/...`) görev durumunu tutar;
bu belge **niyeti** tutar.
