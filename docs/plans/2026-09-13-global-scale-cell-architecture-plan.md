# Küresel Ölçek Dönüşümü — Uygulama Planı

> **Tasarım:** `docs/architecture/2026-09-13-global-scale-cell-architecture-and-ddos.md`
> (önce onu oku; bu plan oradan argüman alır, tekrar etmez).
> **Takvim ve kilometre taşları:** `docs/plans/2026-09-13-global-scale-roadmap.md` (fazların haftalara, sprintlere ve karar noktalarına bağlanması).
> **Biçim:** Her görev dosya adı, kabul ölçütü ve onay kutusu taşır. Bir görev
> "bitti" sayılmak için kabul ölçütünün **ölçülmüş** olması gerekir; "yaptım" yetmez
> (`docs/openidx-k8s-always-on.md` §4'ün dersi).
> **Sıra:** Fazlar bağımlılık sırasındadır. Faz 0 ve Faz 1 paralel gidebilir; Faz 2,
> Faz 3'ün önkoşuludur; Faz 4 hepsini bekler.

---

## Küresel kısıtlar

- Her davranış değişikliği bir bayrak arkasında, varsayılan bugünkü davranış
  (depo geleneği: `ACCESS_ASSIGNMENT_ENFORCE`, `STEPUP_GATE` tri-state modeli).
- Migrasyon yüksek su çizgisi **v187**; bu plan v188'den başlar, numaralar görevlerde.
  `DO $$` blokları yok.
- `orgscope` yeşil kalır; RLS entegrasyon testleri (`internal/common/database/rls_enforcement_test.go`)
  her faz sonunda **pgcat arkasında** da koşar.
- `make lint`, `make test`, `make k8s-chaos` (statik) her PR'da; canlı kaos faz kapısında.
- Hiçbir görev PR'ı "kenar sağlayıcı seçimi" gibi ürün kararını sessizce almaz;
  karar ADR'de, PR onu uygular.

## Roller

| Rol | Sahip olduğu fazlar |
|---|---|
| Kenar / Ağ mimarı | Faz 1, Faz 4 yönlendirme |
| Platform / Veri | Faz 0 (Redis, PG), Faz 2 |
| Servis mühendisliği | Faz 3 |
| SRE / Güvenlik | Faz 0 (zaman aşımı, kota), Faz 5, tüm oyun günleri |

---

## Faz 0 — Sızdırmazlık (2 hafta, kod değişikliği küçük, etki büyük)

Amaç: bugün bir kenar sağlayıcısı öne konduğunda **kendini DDoS eden** noktaları kapatmak.
Hepsi tasarım §3 bulgularının doğrudan karşılığıdır.

### 0.1 Redis'i rollere ayır (B2)

**Dosyalar:** `internal/common/config/config.go`, `internal/common/database/database.go`,
`cmd/*/main.go`, `deployments/docker/docker-compose.yml`, Helm `values*.yaml`, `templates/configmap.yaml`
- [x] `REDIS_RATELIMIT_URL`, `REDIS_SESSION_URL`, `REDIS_REVOCATION_URL` konfig alanları; boşsa `REDIS_URL`'e düşer (geri uyumlu).
- [x] `DistributedRateLimit` yalnız ratelimit istemcisini alır; `internal/revocation` tüketicileri revocation istemcisini; `leader` ve login/MFA oturum anahtarları session istemcisini.
- [x] Compose: üç `redis` servisi; ratelimit örneğinde `--maxmemory 256mb --maxmemory-policy allkeys-lru`; diğerlerinde `noeviction` + AOF.
- [x] Helm: `redis.ratelimit/session/revocation` alt-değerleri; prod'da üç ElastiCache/Azure Cache uç noktası (Terraform `modules/elasticache` üç kez).
- **Kabul:** `redis-cli -h ratelimit DEBUG POPULATE 5000000` ile bellek doldurulduğunda login **çalışmaya devam eder** (session Redis etkilenmez); test `internal/common/middleware/ratelimit_isolation_test.go`.

### 0.2 Gerçek IP zinciri (B3)

**Dosyalar:** `deployments/docker/apisix/apisix.yaml`, `deployments/apisix-edge/seed-edge-routes.sh`,
`internal/common/middleware/trustedproxies.go`, Helm `configmap.yaml`
- [x] APISIX global rule: `real-ip` eklentisi, `source: http_x_forwarded_for` **yalnız** `trusted_addresses` içinden; `limit-req`/`limit-count` anahtarı `$remote_addr` (real-ip sonrası).
- [x] `OIDX_TRUSTED_PROXIES` Helm'de kenar CIDR listesini alan bir değerden üretilir (`edge.trustedCidrs` → `OIDX_EDGE_TRUSTED_CIDRS`, servislerde birleştirilir); `*` değeri `ValidateProduction()`'da **reddedilir**.
- [x] CronJob `edge-cidr-sync`: sağlayıcı CIDR listesini çeker, ConfigMap'i günceller, alınamazsa eskiyi korur. *(Sayaç yerine Job başarısızlığı kullanılır: `OpenIDXEdgeCidrSyncFailed` kuralı `kube_job_status_failed` üzerinden; bir CronJob Prometheus sayacı yayamaz.)*
- **Kabul:** İki farklı `X-Forwarded-For` ile aynı kenar IP'sinden gelen istekler **ayrı** kovalara düşer (test `ratelimit_realip_test.go`); güvenilmeyen kaynaktan sahte XFF yok sayılır.

### 0.3 Zaman aşımı ve boyut sertleştirme (B5, Y2)

**Dosyalar:** `cmd/*/main.go` (http.Server), `internal/server/graceful.go`, `deployments/docker/nginx/nginx.conf`, APISIX rotaları
- [x] Tüm servislerde `ReadHeaderTimeout: 5s`, `MaxHeaderBytes: 16<<10`; ortak yapıcı `server.NewHTTP(cfg)` ile tek yerde (bugün her `main.go` kendi yazıyor).
- [x] `http.MaxBytesReader` rota gruplarına: oauth/governance/audit 1 MB, admin-api ve provisioning (SCIM bulk) 5 MB, identity (CSV import) 10 MB; access ve gateway kenara bırakıldı (yayınlanan uygulamaları proxy'ler). *(Audit search GET'tir; gövde sınırı yerine sorgu zaman aşımı Faz 2.4'te.)*
- [x] HTTP/2: `http2.Server{MaxConcurrentStreams: 100}`.
- [x] nginx: `client_body_timeout 10s; client_header_timeout 10s; limit_conn_zone ... limit_conn perip 50; http2 on`.
- [x] APISIX: her rotada `limit-conn` (ISSUE 200, ADMIN 100, VERIFY 1000 eşzamanlı), `proxy_read_timeout` düzlem başına; ISSUE `retries: 0`.
- **Kabul:** `slowhttptest -c 2000 -H` origin'e karşı: sağlıklı istek p99 < 2× baseline. *(Uygulamada `openidx_http_header_timeout_total` sayacı eklenmedi: Go `http.Server` başlık zaman aşımını olay olarak dışa vermez; birim testi bunun yerine yavaş başlığın `ReadHeaderTimeout` içinde kesildiğini ölçer — `internal/server/http_test.go`.)*

### 0.4 `/health/ready` ve `/metrics` dışa kapansın

- [x] APISIX'te `/health/*`, `/metrics`, `/ready` için `priority: 100` rota → 404; iç ağdan probe'lar doğrudan pod'a.
- **Kabul:** Kenar üzerinden `GET /health/ready` → 404; K8s probe'ları yeşil.

### 0.5 HPA açık ve doğru sinyal (Y1)

**Dosyalar:** Helm `values-prod.yaml`, `templates/hpa.yaml`
- [x] `autoscaling.enabled: true` tüm servislerde; `behavior.scaleUp` 60 s'de ×2, `scaleDown` 300 s stabilizasyon.
- [x] Geçici: CPU %60 (KEDA Faz 3'te gelir).
- **Kabul:** `k6` ile 3× baseline yük → 2 dk içinde replika artar, p99 SLO içinde kalır.

### 0.6 CORS tutarlılığı (O1, O2)

- [x] `cmd/oauth-service/main.go:159-170` satır içi CORS kaldırılır; `ValidateProduction()`'ın izin verdiği ortak CORS middleware'i kullanılır; OAuth için `*` **bilinçli** istisna ise `OAUTH_CORS_WILDCARD=true` bayrağı ve belgede gerekçe.
- [x] APISIX rotalarındaki CORS kopyaları (compose 11, loader 7) tek global rule'a; protokol uçları (token, introspect, revoke, userinfo, discovery) rota seviyesinde `*` — tasarım gereği, çerez taşımaz. *(Kiracı alan adlarından dinamik üretim Faz 4.1 kiracı dizini ile gelir.)*
- **Kabul:** `docs/THREAT-MODEL.md` TB1 satırı kodla uyuşur; kiracı origin listesi `apisix.yaml`'da **tam bir kez** geçer (test: `deployments/docker/apisix_test.go`).

### 0.7 Redis kaybında ISSUE için kademeli düşüş

**Dosya:** `internal/common/middleware/ratelimit.go`
- [x] Redis hatasında auth yolları için replika-yerel sayaç (kota/`RATE_LIMIT_REPLICA_HINT`), süre `RATE_LIMIT_LOCAL_FALLBACK_MAX` (varsayılan 60 s), sonra kapalı-başarısız; `openidx_rate_limit_local_fallback_seconds` gauge; `OpenIDXRateLimitOnLocalFallback` uyarısı 10 s'de.
- **Kabul:** Redis restart (10 s) sırasında login başarı oranı > %99; 60 s'ten uzun kesintide 503 (test `ratelimit_fallback_window_test.go`).

**Faz 0 çıkış kapısı:** Yukarıdaki yedi kabul ölçütü staging hücresinde ölçülmüş;
`docs/architecture/...-ddos.md` §3'te B2, B3, B5, Y1, Y2, O1, O2 satırları "kapandı" işaretli.

**Durum (2026-09-13):** Yedi görevin kodu birleşti; her biri kendi commit'inde ve
birim/entegrasyon düzeyinde ölçüldü (testler: `internal/common/database/redis_roles_test.go`,
`internal/common/middleware/ratelimit_{isolation,realip,fallback_window}_test.go`,
`internal/server/http_test.go`, `deployments/docker/{apisix,nginx,routes,config}_test.go`,
`deployments/apisix-edge/seed-edge-routes.test.sh`; Helm: lint + kubeconform 64/0).
**Staging ölçüm günü henüz yapılmadı** — k6/slowhttptest/`DEBUG POPULATE` ölçümleri bir
hücre gerektirir. M0 bu ölçüm yapılıp `docs/evidence/` altına yazılınca ilan edilir;
kod bitmiş olması M0 değildir.

---

## Faz 1 — Küresel kenar ve origin gizleme (4–6 hafta)

### 1.1 Kenar sağlayıcı modülü (ADR-3)

**Dosyalar:** `deployments/terraform/modules/edge-cloudflare/`, `modules/edge-aws/` (CloudFront + Shield Advanced + WAFv2), `modules/edge-azure/` (Front Door Premium)
- [x] Ortak arayüz: girdi `edge_hostnames[]`, `zone_domain`, `origin_hostname`, `rules_file`; çıktı `edge_cidrs[]`, `origin_verification` (mTLS CA / gizli başlık / `X-Azure-FDID`), `edge_hostname`. Kök: `deployments/terraform/edge` tek `edge_provider` değişkeniyle seçer.
- [x] Her modül `terraform validate` ile CI'da (`.github/workflows/terraform.yml`): kök + cloudflare + azure; aws kök üzerinden (us-east-1 alias gerektirir).
- [x] Kural seti Git'te: `modules/edge-common/rules.json` (§5.3 tablosu); `deployments/terraform/edge_rules_test.go` her kuralın tabloda adlandırıldığını ve boyut sınırlarının Go tabanıyla eşit olduğunu doğrular.
- **Kabul:** Üç modül aynı kök girdisiyle `terraform validate` geçer (ölçüldü: 3/3); kural seti belgede ve kodda aynı (test). *`terraform plan` gerçek hesap ister — K1 verilince.*

### 1.2 Origin gizleme (§5.2)

**K1 = Azure Front Door Premium** olduğu için origin gizleme mTLS ile değil, **iki katman** ile yapılır (Cloudflare seçilseydi Authenticated Origin Pulls tek başına yeterdi):

- [x] **Ağ katmanı:** AKS alt ağına NSG — yalnız `AzureFrontDoor.Backend` servis etiketi 80/443'e girebilir, `Internet` açıkça reddedilir (`deployments/terraform/azure/main.tf`). Servis etiketi, elle kopyalanmış CIDR listesinin aksine Azure tarafından güncel tutulur. Çıktı: `origin_locked_to_front_door`.
- [x] **Uygulama katmanı:** servis etiketi **her kiracının** Front Door'unu kabul eder, bu yüzden origin ayrıca "hangi Front Door" sorusunu sorar: `X-Azure-FDID` = profil GUID'i. Ingress `configuration-snippet` ile 403 döner (`edge.originVerify.*`; yarı yapılandırma render'ı düşürür), APISIX kenarı için `EDGE_ORIGIN_VERIFY_HEADER/VALUE` global `request-validation` kuralı. Controller'da `allow-snippet-annotations: "true"` (1.9'dan beri varsayılan kapalı — açılmazsa annotation sessizce yok sayılırdı).
- [x] Origin hostname'i kamuya yayınlanmaz; **ama** CT log'u hostname'leri yayınladığı için "kimse bilmiyor" bir kontrol sayılmaz — kontrol yukarıdaki iki katmandır.
- **Kabul:** Sağlayıcı dışı IP'den origin'e istek → NSG'de reddedilir; servis etiketinden gelen ama `X-Azure-FDID` taşımayan istek → **403**. *(Render ve seed düzeyinde ölçüldü: annotation üç durumda da doğru — kapalı/açık/yarı; canlı `curl` ölçümü M1 oyun gününde.)*

### 1.3 Önbellek ve statik yük

- [x] SPA hash'li varlıklar `Cache-Control: public, immutable` + 1 yıl (üç nginx yapılandırmasında: üretim imajı, geliştirme imajı, kenar kutusu); `index.html` `no-cache` (güvenlik başlıkları tekrarlanarak — nginx `add_header` birleştirmez); `/.well-known/openid-configuration` 3600 s ve `jwks.json` 300 s başlıkları zaten handler'larda vardı. **Bulgu:** compose TLS proxy'sindeki `proxy_cache_valid` yıllardır zone'suzdu — hiçbir şey önbelleklenmiyordu; `openidx_edge` zone'u tanımlandı, `proxy_cache_lock` + `use_stale` eklendi.
- **Kabul:** 100k rps JWKS floodu → origin'e ≤ 10 rps. *(Kenar sağlayıcısı önbelleği `edge-common/rules.json` `cache_rules` ile geldi; ölçüm oyun günü #1'de.)*

### 1.4 Bot direnci ve hesap-başına sayaç (Y3)

**Dosyalar:** `internal/common/middleware/ratelimit.go`, `internal/risk`, `internal/oauth/service.go` (handleLogin), `internal/stepup`
- [x] `login_fail:{org}:{sha256(username)}` sayacı (session Redis, `internal/botgate`); eşik `LOGIN_FAIL_CHALLENGE_AFTER` (5) / `LOGIN_FAIL_WINDOW_SECONDS` (900) → `403 challenge_required`; kenar skoru `X-Edge-Bot-Score` (eşik altı → ilk hatadan önce challenge); Cloudflare Turnstile doğrulayıcı (`TURNSTILE_SECRET`), `challenge_token` ile yeniden gönderim.
- [x] Bayrak `BOT_GATE=off|observe|enforce`; observe modunda karar `unified_audit_events`'e `bot_gate` eylemiyle (`would_challenge`); `ReportModeGates` sayımına eklendi.
- [ ] **Kalan:** admin-console login sayfası `challenge_required` yanıtında Turnstile widget'ını gösterip `challenge_token` ile yeniden göndermeli (frontend işi; K1 Cloudflare ise). Şimdilik enforce modunda challenge = pencere sonuna kadar yumuşak kilit.
- **Kabul:** 10.000 IP'den hesap başına 3 deneme simülasyonu (k6) → 5. denemede challenge; meşru kullanıcı (doğru parola) challenge görmez. *(Birim testte ölçüldü: `internal/botgate/botgate_test.go` — adres bağımsız 6. deneme challenge, doğru parola sayaç sıfırlar; k6 senaryosu 1.5'te.)*

### 1.5 DDoS oyun günü #1

- [x] `test/load/ddos/` altında altı k6 senaryosu: JWKS flood, token flood (geçersiz client), login spray, slowloris, SCIM bulk, audit search; ortak `common.js` VERIFY p99 (<30 ms) ve ISSUE meşru başarı (>%99) eşiklerini paylaşır. `scripts/ddos-drill.sh` (`--check` kümesiz sözdizimi+yapı doğrular, canlı koşu STAGING url'sine karşı, üretim/loopback reddedilir), `scripts/ddos-drill.test.sh`, `make ddos-drill`, CI adımı.
- [x] Runbook `docs/runbooks/ddos-under-attack.md` (tasarım §5.7'nin tam sürümü: alarm sinyalleri, kenar "under attack", dar kaynak kesimi, ADMIN'den ISSUE'ya kaynak, hücre hedefi, ters sırayla stand-down).
- [ ] **Kalan (canlı koşu):** k6 + STAGING hücresi gerektirir. `--check` ve self-test CI'da yeşil; gerçek "VERIFY p99 değişmedi / ISSUE > %99" ölçümü **oyun günü M1'de** `docs/evidence/`'e yazılır.
- **Kabul:** Her senaryoda VERIFY p99 < 30 ms **değişmez**; ISSUE meşru trafik başarı > %99; olay zaman çizelgesi belgelenir. *(Senaryolar ve eşikler kodda; ölçüm oyun günü M1.)*

---

## Faz 2 — Veri katmanı (6–8 hafta)

### 2.1 RLS `SET LOCAL` refactor (B1, ADR-4)

**Dosyalar:** `internal/common/database/rls.go`, `database.go`, yeni `tx.go`, `tools/orgscope`
- [x] `database.WithTx(ctx, fn)`: `BEGIN` → `set_config(..., true)` (SET LOCAL; `SET LOCAL app.org_id = $1` geçerli SQL değil, parametreli `set_config` kullanılır) → fn → `COMMIT`. Tek-ifade sorgular için `db.Exec/Query/QueryRow` sarmalayıcıları; `Query`/`QueryRow` işlemi satırların ömrü boyunca açık tutar ve `Close`/`Scan` ile kapatır.
- [x] `beforeAcquire` kancası bayrakla kapatılır: `RLS_MODE=session|local` (varsayılan `session`); yedi servis başlangıçta `SetRLSMode` çağırır (migrate hariç: DDL, tek bağlantı, bypass).
- [x] **Tasarım değişti — daha güvenli ve çok daha küçük.** Plan 1.950 çağrı yerinin elle taşınmasını öngörüyordu; **her atlanan satır sessizce kapsamsız bir sorgu** olurdu (FORCE RLS altında sıfır satır döner, test kırmızıya dönmez). Bunun yerine kapsam **tipe** taşındı: `database.ScopedPool` (`scopedpool.go`), `PostgresDB.Pool`'un tipi. Metot kümesi `*pgxpool.Pool` ile aynı olduğu için **1.933 çağrı yeri tek karakter değişmeden** kapsamlı hale geldi; soru "bu satırı hatırladık mı?" yerine "derleniyor mu?" oldu. Derleyici 11 değer-geçişi yerini buldu; her biri tek tek incelendi (`Raw()` = kurulum-geneli/istatistik, arayüz = kiracı tablosu okuyanlar). **Bulgu:** `audit.CrossOrgAuditor` bypass bağlamıyla yazıyor — `Raw()` verilseydi local modda hiç işaret taşımaz ve zorunlu çapraz-org denetim satırı `WITH CHECK` tarafından reddedilirdi; arayüze çevrildi.
- [x] **`orgscope` `Raw()` kuralı** (`tools/orgscope/rawpool.go`). Üç bulgu: (1) `Raw()` üzerinden erişilen kiracı tablosu — **SQL'de `org_id` yazması bulguyu temizlemez**, çünkü politika onu `current_setting('app.org_id')` ile karşılaştırır, kapsam yoksa satır görünmez; (2) `Raw()` üzerinden yapılan, SQL'i okunamayan bir çağrı (bu depoda sorgular çoğunlukla değişkende) → **kapalı düşer**, `Begin()` dahil; (3) vetlenmemiş bir fonksiyona verilen kapsamsız havuz — `rawHandoffAllowed` kaydı, her girdi gerekçesiyle (`installWideTables` ile aynı desen). Kaçış yolu aynı `//orgscope:ignore <gerekçe>`. CI kapısı artık `./internal ./cmd` (meşru handoff'lar `cmd/`'de yaşıyor). 16 test; ayrıca gerçek ağaçta mutasyonla doğrulandı.
- [x] **Bulgu — 2.1b'nin bıraktığı gerçek delik: `Reader()`.** Tip değişimi `db.Pool`'u kapsamlı yaptı ama `Reader()` çıplak `*pgxpool.Pool` döndürmeye devam ediyordu. Replika yapılandırılmadığında `Reader()` birincile düşer, yani **hiçbir şey bozulmadı, hiçbir şey derlenmedi bile denemedi** — ve local modda ~12 okuma yolu sorgusu (kullanıcı id/kullanıcı adı/e-posta ile, oturumlar, gruplar, oauth istemcileri) hiç `app.org_id` taşımayacaktı. FORCE RLS altında bu hata değil, **sıfır satır**: login "böyle bir kullanıcı yok" derdi. `Reader()` artık `*ScopedPool` döndürüyor; **tek bir üretim çağrı yeri** (`WithReadTx`) derlemeyi kırdı, kalan ~12'si değişmeden kapsamlı hale geldi. Gerçek Postgres'e karşı ölçüldü (`TestScopedPool_ReaderIsScopedToo`) ve `Reader().Raw()` mutasyonuyla kırmızıya döndüğü (`no rows in result set`) doğrulandı.
- [x] `rls_local_test.go` iki modda da koşar, **tek bağlantılı** havuzda (pooler'ın yarattığı şekil): iki kiracı dönüşümlü 25 tur, 200 eşzamanlı okuma, sızıntı = 0; commit sonrası kapsam bağlantıda kalmıyor (pooling'i güvenli kılan özellik); çapraz-kiracı yazma `WITH CHECK` ile reddediliyor; hata yollarında bağlantı sızıntısı yok. Süit **superuser rolü reddeder** (Postgres superuser'ı her politikadan muaf tutar — aksi halde kemer kesikken de yeşil yanardı) ve iki mutasyonla kırmızıya döndüğü doğrulandı. CI işi: `rls-isolation`.
- **Kabul:** Kanarya hücrede `RLS_MODE=local` 2 hafta; `orgscope` yeşil; sızıntı testi 0.

### 2.2 pgcat transaction pooler

**Dosyalar:** Helm `templates/pgcat.yaml`, `_helpers.tpl`, sekiz servis şablonu, `prometheus-rules.yaml`, `values.yaml`, `.github/workflows/helm.yml`
- [x] pgcat ×2, `pool_mode = "transaction"`, `maxUnavailable: 0`, PDB `minAvailable: 1`, düğümler arası anti-affinity. **Varsayılan kapalı.**
- [x] **Kilit (override yok):** `pgcat.enabled=true` iken `config.rlsMode != "local"` ise chart **render olmayı reddeder**. Gerekçe ölçüm: kenar durumu değil, `docs/evidence/2026-09-13-rls-transaction-pooling.md` §1. İkinci ret: `preparedStatementsCacheSize = 0` (pgcat'in **kendi varsayılanı**) → tek sorgu koşturamayan bir filo.
- [x] **Yönlendirme chart'ın işi, operatörün değil.** Sekiz istek-sunan Deployment `DATABASE_URL`'ı `<release>-pgcat:6432`'ye çevirir (`env`, `envFrom`'u yener); **migrate Job'ı, bootstrap hook'u ve backup CronJob'ı doğrudan DSN'de kalır** — hiçbiri transaction pooling'de yaşamaz (migrasyonun advisory lock'u session kapsamlı, `pg_dump` tek oturumda tek anlık görüntü ister). Plan bunu "operatör `DATABASE_URL`'ı çevirir" diye bırakıyordu; bu, hiçbir şeyin kullanmadığı ya da yarısının kullandığı bir pooler demekti.
- [x] Bağlantı bütçesi `replicaCount × poolSize` = 2 × 40 = **80, sabit** (poolerʼsız: `8 × replika × DB_MAX_CONNS`, HPA ile çarpılır).
- [x] Görünürlük: pgcat Prometheus exporter'ı açık + kendi ServiceMonitor'ı; `OpenIDXPoolerClientsWaiting` (havuz tükendi → istek kuyrukta) `OpenIDXDBPoolSaturation`'ın yerini alır, `OpenIDXPoolerNoRedundancy` veritabanının önündeki yeni tek hata noktasını korur. Metrik adları pgcat v1.2.0 kaynağından doğrulandı (`pgcat_pools_*`).
- [x] CI: "The transaction pooler is safe by construction" — beş iddia (varsayılan kapalı, iki ret, sekiz servis yönlendirildi, Job'lar yönlendirilmedi, `pgcat.toml` TOML olarak ayrışır ve `prepared_statements_cache_size` **pool** bölümünde). **Her biri koruduğu şey kırılarak** kırmızıya döndürüldü.
- [x] **Plan'dan sapma — `DB_MAX_CONNS` 10 → 4 yapılmadı.** Pooler'ın arkasında bu sayı artık Postgres'i korumuyor; pooler'a açılan *ucuz istemci* bağlantılarını boyutluyor. Düşürmek yalnızca servis içi eşzamanlılığı kısardı, backend sayısını değil. Gerekçe koda ve `values.yaml`'a yazıldı.
- [x] **Bulgular (hepsi kaynak/registry denetiminden, çalışan pgcat'ten değil):** `1.1.1` etiketi **yok** (registry'de tek sürüm etiketi `v1.2.0`); `prepared_statements` diye bir `[general]` anahtarı yok ve pgcat bilinmeyen anahtarları **sessizce yok sayıyor**; imajda `ENTRYPOINT` yok (`CMD ["pgcat"]`), yani yalnız `args` vermek binary'yi TOML dosyasıyla değiştiriyordu. Üçü de `helm lint`, `helm template` ve kubeconform'dan geçiyordu.
- [ ] **Kalan:** `values-prod.yaml`'da açılması, Terraform RDS `max_connections`, ve asıl ölçüm.
- **Kabul:** ISSUE HPA 30 replikaya çıkarken PG bağlantı sayısı sabit. *(Ölçülmedi — kanarya kapısı geçerli: `RLS_MODE=local` 2 hafta + `orgscope` bitmiş olmalı. `docs/architecture/db-pooling.md` "the chart ships the pooler" notuyla güncellendi.)*

### 2.3 Okuma replikası varsayılan (ADMIN)

- [x] **Önce kabul kriterinin kendisi yalandı, onu düzelttik.** Üç yerde (`Reader()` yorumu, sağlık denetleyicisi, `values-prod.yaml`) "replika kaybında trafik şeffafça birincile düşer" yazıyordu. Bu **yalnızca açılışta** doğruydu: `NewPostgres` replika havuzunu açamazsa `readPool` nil kalır ve `Reader()` sonsuza dek birincili döndürür. Havuz bir kez açıldıktan sonra `Reader()` onu koşulsuz veriyordu — saat 03:00'te ölen bir replika (failover, yeniden başlatma, ağ bölünmesi, RDS bakım penceresi) o replikaya yönlenmiş **her okumayı, süreç yeniden başlatılana kadar** düşürürdü. Replika denetleyicisi tasarımı gereği kritik olmadığı için readiness bu süre boyunca yeşil kalırdı.
- [x] **Gerçek geri düşüş** (`internal/common/database/readerfallback.go`): replika havuzu birincile bir referans ve bir devre kesici taşır. **Altyapı hatası** (bağlantı reddi, kırık boru, havuz tükendi) → çağrı birincide yeniden denenir; `Reader()` sözleşme gereği salt-okunur olduğu için yeniden deneme güvenli. **`PgError`** → sunucu *cevap verdi*; sorgu hatalı ve birincide de aynı şekilde hatalı olurdu — buna **25006 (salt-okunur işlemde yazma)** dahil, ki bu "`Reader()`'ı asla yazma için kullanma" kuralını uygulanabilir tutan şeydir (aksi halde yazma sessizce birincile yönlenirdi). Üç ardışık altyapı hatasından sonra kesici 30 sn açılır; kesinti başına istek başına bir başarısız çevirme değil, soğuma başına bir tane maliyeti olur. Soğuma bitince kesici kapanmaz, **tek bir yoklama** geçirir.
- [x] **Ölçüldü, iddia edilmedi:** gerçekten dinlenmeyen bir porta bakan replika havuzuyla `QueryRow`/`Query`/`Begin` hepsi cevap vermeye devam ediyor — birinciden, ve **hâlâ kiracı-kapsamlı**; kesicinin açıldığı da doğrulanıyor (`TestReaderFallback_deadReplicaStillServesReads`). Ters yön de: cevap veren bir replika kendi okumasını sunuyor, etrafından dolaşılmıyor. Üç mutasyonla kırmızıya döndürüldü (bağlama yok, kesici hiç açılmıyor, `PgError` altyapı hatası sayılıyor).
- [x] Görünürlük: `openidx_db_replica_fallback_total{reason}` ve `openidx_db_replica_breaker_open`; `OpenIDXReadReplicaOffloadLost` (kesici 5 dk açık → offload kayıp, istekler iyi) ve `OpenIDXReadReplicaFlapping` (kesici oturmadan sürekli geri düşüş → her istek yolunda boşa bir çevirme). `make ha-drill` yeni bir bölüm kazandı.
- [x] **Bulgu — `rls-isolation` CI işi `-run 'RLS'` çalıştırıyordu**, ve `TestScopedPool_*` bu üç harfi içermiyor: 2.1b'nin ~1.950 çağrı yerinin kapsamlı olduğunu kanıtlayan süit **CI'da hiç koşmamıştı**. Regex genişletildi ve dört testin adı tek tek "PASS etti mi" diye denetleniyor (`-run` hiçbir şeyle eşleşmezse 0 ile çıkar — sessiz yeşil).
- [ ] **Kalan — `values-prod.yaml` `readReplica: true` YAPILMADI.** Adım 1 (mağazaya `database-read-url` yazmak) olmadan bayrağı açmak, ExternalSecret'ı var olmayan bir anahtara referans verdirir ve **tüm gizin** senkronizasyonunu düşürür — taze bir cutover'da her bağlantı dizesini. Varsayılan, kurulabilen olmalı; açma adımı runbook'ta.
- [ ] **ADMIN düzlemi sorgularının `Reader()`'a taşınması — 1. parti yapıldı (2026-09-13).** Analitik/pano yüzeyi: `analytics_enhanced.go`, `risk_analytics.go`, `predictive_analytics.go`, `dashboard.go` — **26 okuma**, sıfır yazma. Hepsi `audit_events`, `login_history`, `user_sessions` ve `users` üzerinde gün/saat/hafta kovalarına göre toplulaştırma; bir konsol grafiği bir saniyelik gecikmeyi gösteremez. Bunlar aynı zamanda **en pahalı** ADMIN sorguları, yani offload'ın var olma sebebi.
  - **Varsayılanda davranış değişmiyor:** `Reader()` replika yapılandırılmamışken `db.Pool` döndürüyor, yani `readReplica` kapalı her kurulumda çağrı birebir aynı havuza gidiyor.
  - **Muhafaza iki yönlü** (`internal/admin/replica_offload_test.go`), çünkü yalnız biri akla geliyor: (a) bildirilen bir dosya **yalnız** replikayı kullanmalı ve **yazmamalı** — `Reader()` üzerinden yazma sunucuda 25006 ile reddedilir, yani hata üretimde çıkar, CI'da değil; (b) bildirilmemiş bir dosya `Reader()`'a **hiç dokunamaz** — bir sorgunun, gecikmeye dayanıp dayanmadığına kimse karar vermeden geçişte offload edilmesini durduran şey bu.
  - Her girdi **neden** gecikmeye dayandığını yazmak zorunda; "bu bir okuma" gerekçe sayılmıyor (bir oku-yazdıktan-sonra da okumadır) ve test 30 karakterden kısa gerekçeyi reddediyor.
  - **Kanıt:** dört mutasyon kırmızı — bir okumayı birincile geri almak, offload edilmiş dosyaya yazma sızdırmak, bildirilmemiş bir dosyayı replikaya geçirmek, gerekçeyi boşaltmak.
  - **2. parti (aynı gün):** `ai_intelligence.go` (8) ve `pam_overview.go` (7) — 15 okuma daha. İkisi de tam okuma: risk ortalamaları, uyarı sayıları, sır/rotasyon/erişim-talebi sayaçları. Hepsi geçmişin özeti, hiçbiri bir şeye karar vermiyor.
  - **Sayımın ikinci yarısı eklendi: `stayOnPrimary`.** Okuması olup yazması olmayan bir dosya, yukarıdaki testlerin aynısını geçtiği için *offload edilebilir görünüyor* — ama hepsi değil. `dsar_processor.go` bir **worker**: `data_subject_requests`'i birazdan üzerinde işlem yapacağı iş için yokluyor, yani gecikmeli bir replika ona başka bir replikanın aldığı talebi verir ya da bekleyen birini gizler — ders kitabı oku-yazdıktan-sonra. `tilequery.go` ise **çağıranın verdiği SQL'i** koşan genel bir yardımcı; onu offload etmek bütün çağıranları aynı anda, kimsenin okumadıkları dahil, offload etmek olurdu. Gerekçeler yazıldı ki bir sonraki parti bunları yeniden türetmek zorunda kalmasın.
  - **Yeni muhafız — karar verilmemiş dosya kalamaz** (`TestEveryReadOnlyFileIsDecided`): okuması olup yazması olmayan her dosya iki listeden **tam birinde** olmak zorunda. Hiçbirinde olmayan dosya, karar verilmemiş dosyadır; bir sonraki kişinin tahmin etmesi böyle başlar.
  - **Kanıt (2. parti):** iki mutasyon daha kırmızı — offload edilmiş bir dosyayı listeden düşürmek, ve birincide kalması gereken worker'ı replikaya geçirmek (bu ikisi *iki ayrı testten* birden yakalanıyor).
  - **3. parti: sayım tamamlandı, ve sınır ölçülerek bulundu (aynı gün).** Kalan 22 dosyanın **hepsinde yazma var** ve hepsi CRUD yüzeyi. Bu önemli, çünkü konsol yazmadan sonra ne yapıyor: TanStack Query uygulaması ve değiştirdiği listeyi **anında geçersiz kılıyor**. Sayıldı: **384 `invalidateQueries` çağrısı, 81 dosyada** — mutasyon yapan 90 dosyanın neredeyse tamamı. Yani bu ekranlarda "liste" gecikmeye dayanan bir okuma **değil**; POST döndükten milisaniyeler sonra yapılan bir oku-yazdıktan-sonra. Bir yönlendirme kuralı oluşturup tazelenen listede göremeyen yönetici beklemez, bir daha oluşturur.
  - **Dosya düzeyinde 2.3 burada bitiyor:** 1. ve 2. parti sınırın diğer tarafındaki her şeyi aldı; geriye dosya düzeyinde aday kalmadı. Yirmi iki dosyanın her biri gerekçesiyle `stayOnPrimary`'de, ve sayım artık **okuması olan her dosyanın** iki listeden tam birinde olmasını şart koşuyor (yalnız salt-okuma olanların değil). Bir yazması da olan dosya yine de bir karar gerektiriyor; karar neredeyse hep aynı, ve onu yazmak bir sonraki kişinin yeniden türetmesini engelliyor.
  - **Sıradaki adım "fonksiyon düzeyi sayım" sanılmıştı; ölçüm onu çürüttü.** Bu dosyalarda okuyup hiç yazmayan **132 fonksiyon** ve onlarda **194 sorgu** var — kalan fırsat gibi görünüyor, ta ki adları okunana kadar: `handleListAIAgents`, `handleGetAttestationCampaign`, `handleListRecommendations`. Bunlar tam da oku-yazdıktan-sonra olan okumalar. Yazma aynı fonksiyonda değil, `handleCreateX`'te; ilişki konsolun **oluştur-sonra-tazele** akışında kuruluyor ve iki işleyiciye yayılıyor. Yani "bu fonksiyon yazmıyor" ölçütü, yapılmaması gereken hamlelere tam olarak izin verirdi.
  - **Ölçüt yapısal değil, anlamsal:** mesele *ekranın* ne yaptığı ve bunu Go kaynağının hiçbir şekli karara bağlayamaz. Gerçekten kalan (kimsenin az önce yazmadığı tarihsel toplamlar üzerindeki işleyiciler — `ispm GetPostureTrends`, `mfa_management MFAEnrollmentStats` gibi) ekran ekran, konsola bakarak, o kartın bir mutasyondan sonra tazelenip tazelenmediğini söyleyebilecek biri tarafından karara bağlanmalı. Daha fazla makine yardımcı olmaz; yalnızca yanlış cevaba ulaşmayı kolaylaştırır.
  - **Kanıt (3. parti):** iki mutasyon daha kırmızı — bir CRUD dosyasını karar listesinden düşürmek, ve güvenlik-kritik `settings_repository.go`'yu replikaya geçirmek (ikincisi yine iki ayrı testten yakalanıyor).
- **Kabul:** `make ha-drill` replika kaybında ADMIN birincile düşer, ISSUE etkilenmez. *(Geri düşüşün kendisi ölçüldü ve drill'e eklendi; "ADMIN" kısmı yukarıdaki iki kalem bitince tamamlanır.)*

### 2.4 Düzlem başına PG rolü ve `statement_timeout`

- [x] **Migrasyon v189** (plan v188 diyordu; o numarayı `temp_link_pam_entry` almış): `openidx_issue` (2 s), `openidx_admin` (10 s), `openidx_event` (30 s). Hepsi `IN ROLE openidx_app` ile yaratılıyor — v53'ün DML izinlerini **ve onlarla birlikte v37 FORCE RLS politikalarını** miras alıyorlar (politikalar `TO openidx_app` verildiği için, o ayrıcalıklara sahip her role uygulanır). Yani bir düzlem rolü `openidx_app` kadar kiracı-kapsamlı; daha az yetkili olabilir, daha fazla asla. `NOBYPASSRLS` yine de tek tek yazılı: kemeri sessizce atlayan bir rol **hata vermez, her kiracının satırını döndürür**.
- [x] **Neden rol, neden DSN parametresi değil.** `statement_timeout` bağlantı başına da verilebilirdi (`options=-c statement_timeout=2000`) ve daha küçük bir değişiklik olurdu — ama o zaman DSN'de yaşar, yani kimsenin diff'lemediği bir values dosyasında yanlış olmaya bir kopyala-yapıştır uzaklıktadır ve veritabanına "bu servis ne yapabilir" diye sormanın yolu yoktur. Role bağlıyken **sunucunun bir özelliği**: `\drds` listeler, operatör bir gizi düzenleyerek kaybedemez, gece 3'te o rolle açılan bir psql oturumunda da yürürlüktedir.
- [x] **Neden uygulama zaman aşımı yetmez.** Context iptali Go çağrısını terk eder; backend CPU'yu yakmaya ve kilitleri tutmaya devam eder. Sorgu *çalışırken* onu durdurabilecek tek katman veritabanıdır.
- [x] **Plandan sapma — `idle_in_transaction_session_timeout` da eklendi** (60 s/120 s/300 s). Yalnız `statement_timeout` önemsizce atlatılır: `BEGIN`, bir hızlı sorgu, sonra işlemi açık tut — backend çivilenir, kilitleri durur, vacuum en eski anlık görüntüyü geçemez. Değerler bilerek çok daha gevşek, ki yalnızca gerçekten takılmış işi yakalasın.
- [x] **Ölçüldü:** gerçek PostgreSQL'e karşı üç rol de kendi kiracısını görüyor, diğerini görmüyor, çapraz-kiracı yazma reddediliyor ve hiçbiri `BYPASSRLS` taşımıyor; ADMIN rolünde 15 s'lik sorgu **sunucu tarafından ~10 s'de iptal ediliyor** (test 10,05 s sürüyor) ve bağlantı iptalden sağ çıkıyor; ISSUE bağımsız (kendi girişi, kendi 2 s'si). Dört mutasyonla kırmızıya döndü — en önemlisi `BYPASSRLS`: rol o anda **iki kiracının da satırlarını görüyor**.
- [x] CI: `rls-isolation` işine yeni adım (süperuser DSN'i gerektirir — `CREATE ROLE` tam da uygulamanın kendi rolünün yapamadığı şey, ki v53'ün amacı bu). Üç testin adı tek tek "PASS etti mi" diye denetleniyor.
- [x] **Bulgu — roller migrasyona ait değil, bootstrap hook'una ait.** İlk hâli `CREATE ROLE` yapan düz bir migrasyondu; `TestMigrationsRunAsLeastPrivilegedOwner` onu **`permission denied to create role` ile düşürdü** ve haklıydı: migrasyon Job'ı veritabanı *sahibi* olarak bağlanır, Bitnami alt-chart'ının yarattığı düz `NOCREATEROLE` bir login rolüdür — `CREATE ROLE`, `GRANT` ve `ALTER ROLE ... SET`'in üçü de orada reddedilir. Bu yüzden roller v53'ün `openidx_app`'i gibi **süperuser bootstrap hook'unda** yaratılıyor; v189'un her ayrıcalıklı ifadesi "zaten öyle mi?" ile korunuyor, yani hook koştuktan sonra migrasyon yalnızca `pg_roles` ve `pg_db_role_setting` okuyup hiçbir şey değiştirmiyor. Ayrıcalıklı DSN'li harici veritabanında işi kendisi yapar; ayrıcalıksız ve ön-yaratımsız bir kurulumda **yüksek sesle düşer** — v53'ün belgelediği sözleşmenin aynısı. Ayrıca önceden var olan bir düzlem rolü `BYPASSRLS` taşıyorsa migrasyon **sessizce onarmaz, istisna fırlatır**: bu kaymış bir ayar değil, orada olmayan bir kiracı sınırıdır.
- [x] **Dağıtım yarısı — `database.planeRoles` (2026-09-13).** Varsayılan kapalı; açıldığında sekiz servisin her biri kendi düzleminin rolüyle bağlanıyor. Atama tabloda (`database.planeRoles.assignments`), yani şablon düzenlemeden değiştirilebiliyor: oauth→ISSUE, audit→EVENT, kalan altısı→ADMIN.
  - **Açık kalan iki soru cevaplandı, birincisi kabul edilerek:** (a) `identity-service` hâlâ iki düzleme birden hizmet ettiği için **ADMIN (10 s)** alıyor — daha sıkısı konsol sorgularını keserdi; `SERVICE_PROFILE` süreci ikiye böldüğünde auth yarısı `issue`'ya geçecek. (b) pgcat ile birlikte açılamıyor: chart **render etmeyi reddediyor** ve nedenini söylüyor — ikisi de `DATABASE_URL`'ı `env` olarak enjekte ediyor, *ve* asıl mesele bir transaction pooler'ın sunucu bağlantılarını kendi havuz kullanıcısıyla açması; bütçeleri geri almak pgcat'e üç havuz kullanıcısı vermek, yani hücrenin backend bütçesini üçe bölmek demek. Bu bir bayrak değil, maliyeti olan bir boyutlandırma kararı.
  - **Sessiz olacak olan etkileşim yakalandı ve ölçüldü.** `DB_STATEMENT_TIMEOUT` bağlantı *runtime parametresi* olarak gönderiliyor ve runtime parametresi, role iliştirilmiş `ALTER ROLE ... SET` değerini **ezer**. `values-prod.yaml` `statementTimeout: "30s"` ayarlıyor — yani bayrağı çevirmek üç düzleme de 30 saniye verirdi, her serviste, hiçbir logda tek satır olmadan. Ölçüm: `DB_STATEMENT_TIMEOUT=45s` ile test üç rol için de 45 000 ms raporluyor. Chart bu bileşimi de reddediyor ve temizlenecek dosyayı adıyla söylüyor.
  - **Asıl açık soru buydu ve ölçüldü:** roller izinlerini *miras alıyor*, kendileri hiçbirine sahip değil — 220 tablo 190 küsur migrasyona yayılmış, kimi `openidx_app`'e açıkça GRANT veriyor, kalanı v53'ün default privileges'ına güveniyor. İkisini de almayan tek bir tablo, ayağa kalkan, sağlık kontrolünü geçen ve tek bir uçta `permission denied for table` diyen bir servis demek. Tam zinciri en az ayrıcalıklı sahiple uygulayıp ölçtük: **üç rol de 220 tablonun tamamına ve her sequence'a erişiyor** (`TestV189PlaneRolesReachEveryTableAfterTheFullChain`), ve bütçeler `database.NewPostgres`'in açtığı havuzda hayatta kalıyor (`...BudgetsSurviveTheApplicationPool`).
  - **Altı kilit**, her biri çözecek düğmeyi adıyla söylüyor: pgcat ile birlikte; `statementTimeout` doluyken; kimlik bilgisi yokken; üç URL'den yalnız ikisi verilmişken; harici veritabanına `password` verilmişken; atama tablosunda düzlem olmayan bir ad varken. Hepsi CI'da (`helm.yml`, "Each plane connects as its own role, or none of them does") ve her biri koruduğu şey kırılarak doğrulandı — atamayı değiştirmek ve bir servisin bağlantısını kaldırmak dahil.
- **Kabul:** ADMIN'de 15 s'lik yapay sorgu → iptal; ISSUE etkilenmez. *(Ölçüldü ve CI'da koşuyor.)* Düzlemler artık gerçekten o rollerle bağlanıyor — ama hiçbiri üretim trafiği görmedi: chart desteğini göndermek onu çalıştırmış olmakla aynı şey değil.

### 2.5 Keyset sayfalama

- [x] **Audit olay listesi**: `?cursor=` ile keyset. İmleç `(timestamp, id)` konumunu taşıyan, sürüm önekli, opak bir değer; `X-Next-Cursor` başlığıyla dönüyor. Bozuk imleç **400**, sessizce ilk sayfaya düşmüyor — düşseydi çağırana zaten okuduğu sayfayı "sonraki" diye verirdi, ki denetim kaydında bu hatadan beter. `OFFSET` yolu aynen duruyor (`X-Total-Count` yayınlanmış bir başlık ve konsol onu okuyor).
- [x] **Migrasyon v190:** `(org_id, timestamp DESC, id DESC)`. Mevcut iki indeks bu sorguyu karşılayamıyordu: `idx_audit_events_timestamp` tek sütunlu ve **kurulum geneli** (yani taraması her kiracının olaylarını gezip sizinkiler dışındakileri atıyor — v176'nın `(org_id, event_type)` için düzelttiği kusur), `(org_id, event_type)` ise sıralama sorgusu için yanlış ikinci sütunla başlıyor. İki sütunda da `DESC` süs değil: bileşik bir indeks geriye okunurken **her** sütunu ters çevirmek zorundadır.
- [x] **Bulgu — `ORDER BY timestamp DESC` tek başına tam sıralama değil.** Sütunun varsayılanı `NOW()` ve bir patlama aynı mikrosaniyede birkaç satır yazıyor; eşit satırlar herhangi bir sırada ve her seferinde aynı sırada gelmek zorunda değil. `OFFSET` sayfalamasıyla bu, bir satırın **iki ardışık sayfada birden ya da hiçbirinde** görünmesi demek — denetim kaydında mevcut en kötü yanlış cevap. Yani `id` ile eşitlik bozma, imlecin zaten ihtiyaç duyduğu bir **doğruluk düzeltmesi**.
- [x] **Bulgu — asıl maliyetin yarısı `COUNT(*)` ve keyset ona dokunmuyor.** Aynı filtrelerle sayım her eşleşen satırı okur: sayfa numarası ne olursa olsun bu fonksiyondaki pahalı ifade odur, dolayısıyla yalnız `OFFSET`'i düzelten bir imleç derin-sayfa bütçesini yine patlatırdı. İmleç yolunda sayım **hiç çalıştırılmıyor** (imleçle gezen çağıran 1000. sayfaya atlamıyor, kaydı yürüyor) ve sayım yapılmadığı için `X-Total-Count` sıfır gönderilmek yerine **hiç gönderilmiyor** — satır döndürürken "toplam 0" diyen bir liste, başlıksız olandan daha kötü.
- [x] Ölçüldü: gerçek Postgres'e karşı imleçle sayfalama **her satırı tam bir kez**, sırayla, eşitlik patlaması dahil geziyor; başka kiracının satırı hiç gelmiyor; `EXPLAIN` v190 indeksini kullanıyor ve **sıralama yapmıyor**. Üç mutasyon kırmızıya döndü (sayım imleç yolunda da koşuyor, karşılaştırma yönü ters, indeks `org_id` ile başlamıyor).
- [x] **Dördüncü mutasyon tutmadı, bu yüzden testin şekli değişti.** Eşitlik bozmayı kaldırmak davranış testlerini **yeşil bırakıyor**: Postgres eşit satırları seçtiği indeksin sırasında döndürüyor ve v190'ın indeksi `id` taşıyor, yani tehlike gizli kalıyor. Garanti `ORDER BY`'dan gelmek zorunda — planlayıcı sıralama seçmekte özgür ve o gün eşitler yığın sırasında gelir. Sıralama tek bir yerde (`eventOrdering`) ve **bir karar olarak** sabitlendi; mutasyonu artık kırmızı.
- [x] **Kalan iş yapıldı (2026-09-13) — ama beklenen şekilde değil, ve nedeni önemli.** SCIM **imleç olamaz**: RFC 7644 §3.4.2.4 bir ListResponse'u `startIndex` ile sayfalıyor ve `totalResults`'ı **zorunlu** kılıyor, yani offset'i istemci seçiyor ve sayım hesaplanmak zorunda — ikisinden birini bırakmak taramayı kurtarmıyor, protokolü bozuyor. Düzeltilebilecek olan sıralamaydı, ve o zaten indeks gerekmeden önce **doğruluk** gerekçesiyle düzeltilmeliydi.
  - **Eşitlikler burada garanti, nadir değil.** `created_at` varsayılanı `NOW()`, ve Postgres'te `NOW()` **işlem** zaman damgası: bir işlemin yazdığı her satır birebir aynı değeri taşır. Ölçüldü: *tek işlemde 200 satır → 1 farklı `created_at`*. Bir SCIM toplu oluşturma, bir dizin senkronu, bir CSV içe aktarma — her biri tam eşitlenen bir blok indiriyor.
  - Sıralama artık `(created_at, id)` ve tek bir yerde (`internal/provisioning/scim_ordering.go`), `TestSCIMOrderingIsTotal` ile bir **karar** olarak sabitli. **Migrasyon v191** `users` ve `groups` üzerine `(org_id, created_at, id)` ekliyor: `org_id` ile başlıyor çünkü her SCIM okuması önce kiracı-kapsamlı — `(created_at)` indeksi kurulum geneli olur ve sizinkini bulmak için her kiracının satırını gezerdi (v176'nın `audit_events` için düzelttiği, v190'ın kaçındığı kusur).
  - `internal/audit/reports.go` ve `service.go` rapor listeleri aynı sınıf kusuru taşıyordu; eşitlik bozma eklendi. **İmleç eklenmedi ve nedeni yazıldı:** bunlar kiracı başına onlarca satırlık rapor listeleri — 2.5'in hedeflediği derin-sayfa maliyetini ödeyecek kimse yok, imleç karşılıksız karmaşıklık olurdu.
  - **Protokolün izin vermediği kısım açıkça yazıldı:** iki sayfa arasında istemcinin konumunun önüne bir satır girerse sonraki her `OFFSET` bir kayıyor ve sınırdaki satır hiç dönmüyor. Aynı şekilde ölçüldü: *tek bir eşzamanlı eklemeden sonra 200 kullanıcının 1'i sessizce kayıp*. Bu, indeks tabanlı sayfalamanın bir özelliği; kaldıran şey imleç ve SCIM'in imleci koyacak yeri yok.
- [x] **Sıralamayı test ederken bulunan üretim hatası — SCIM listesi isimsiz kullanıcıları sessizce düşürüyordu.** `users.first_name`, `last_name` ve `email` nullable; liste ise düz `string`'lere tarıyordu, yani soyadı olmayan her kullanıcıda `rows.Scan` düşüyordu — ve döngü buna **`continue`** ile cevap veriyordu. Cevap `totalResults = N` taşıyor, içinde N kullanıcının **hiçbiri** yok, HTTP 200, hiçbir logda iz yok. SCIM istemcisi kısa sayfayı tam dizin olarak okur: o hesaplar her alt uygulama açısından **yoktur**. Eşzamanlılık ya da eşitlik gerektirmediği için sayfalama kusurundan da beter. `COALESCE` + tarama hatasını döndürme ile düzeltildi (gruplarda da).
  - **İki düzeltme üst üste biniyor ve biri diğerini gizliyor:** `COALESCE` varken hiçbir tarama düşmüyor, yani `continue`'yu geri koymak davranış testlerini **yeşil** bırakıyor. Bu yüzden `continue` kaynakta ayrıca sabitlendi (`TestSCIMListLoopsDoNotSwallowScanErrors`) — mutasyonu artık kırmızı.
  - **Kanıt:** beş mutasyon kırmızı — eşitlik bozmayı kaldırmak (1 kullanıcı iki sayfada, 2 kullanıcı hiçbirinde), sıralama sabitini SQL'de kullanmamak, `COALESCE`'u geri almak, `continue`'yu geri koymak, ve premisin kendisi (tek işlem → tek zaman damgası) ölçüldü.
- **Kabul:** 50M satırda sayfa 1000 → p99 < 100 ms. *(50M satırlık ölçüm yapılmadı — bu bir yük ortamı işi. Test edilen, iddianın mekanizması: plan indekse **seek** ediyor, tarama yapmıyor, ve sayım imleç yolunda hiç koşmuyor. Zamanlama iddiası bu makineyi ölçerdi, değişikliği değil.)*

---

## Faz 3 — Olay omurgası ve servis düzlemleri (6–8 hafta)

### 3.1 Outbox platform ilkeli (B4, ADR-6)

**Dosyalar:** `internal/common/events/outbox.go`, migrasyon **v192** (`outbox` tablosu, `org_id`, RLS), `cmd/event-relay/`

> Migrasyon numarası **v189 → v192**: v189 bu arada düzlem rollerine gitti (2.4), v190 audit keyset indeksi, v191 SCIM sıralama indeksi.

- [x] `OutboxBus.Publish(ctx, ev)` aktif `pgx.Tx`'i context'ten alır; yoksa hata (yayın işlem dışında yapılamaz). **(2026-09-13)**
  - **Tek garanti atomiklik.** Satırı yaz sonra yayınla: aradaki çökme olayı kaybeder ve veritabanında onu borçlu olduğumuzu söyleyen hiçbir şey kalmaz. Yayınla sonra yaz: platform olmamış bir şeyi duyurmuş olur. İkisi de yeniden denemeyle kapanmaz, çünkü yeniden denemesi gereken süreç ölen süreçtir. Olayı **aynı işleme** yazmak pencereyi tamamen kaldırıyor: ya iki taahhüt birden ya hiçbiri.
  - **İşlem context'te taşınıyor** (`PostgresDB.WithTxCtx`), elle aşağı geçirilmiyor. Elle geçirmeyi zahmetli bulan ilk çağrı yeri olayı işlem dışına yazar — ve bu kod okurken aynı görünür. Kapanışın yakaladığı **dış** context ile yayın yapmak da aynı sebeple gürültülü biçimde hata veriyor; yanlışın gitmesi gereken yön bu.
  - **id bir imleç değil ve bu ölçüldü.** `bigserial` numarayı INSERT anında verir, işlem COMMIT anında görünür olur; bunlar farklı anlardır ve sırası ters olabilir. İki eşzamanlı işlem elle sürüldü: **düşük id ikinci taahhüt etti**, `id > lastSeen` ile sayfalayan bir röle o satırı **kalıcı olarak kaybetti**, durum tabanlı talep (`published_at IS NULL ... FOR UPDATE SKIP LOCKED` — v95'ten beri SCIM kuyruğunun kullandığı şekil) ikisini de teslim etti.
  - **v192 bu ölçümün etrafında şekillendi:** geri kalan iş indeksi **kısmi** (`WHERE published_at IS NULL`), yani tablonun değil birikmiş işin boyunda kalıyor; `org_id` doğuştan `NOT NULL` + gerçek foreign key ve FORCE RLS kemeri tabloyla **birlikte** geliyor (sonraki bir migrasyona bırakılan kemer, aradaki her satırı denetlenmiş değil güvenilmiş yapar); `UNIQUE (org_id, event_id)` tüketicinin yeniden teslimi tanımasını sağlıyor — kiracı bazında, çünkü kiracılar arası çakışma bir rastlantıdır ve bir kiracının yazmasını başkasının yüzünden düşürmemeli.
  - **Teslim en-az-bir-kez ve bunu söylüyor.** Röle satırı, broker kabul ettikten *sonra* işaretliyor; iki olgu arasındaki çökme yeniden teslim eder. Tam-bir-kez, broker ile bu veritabanının birlikte taahhüt etmesini gerektirirdi; edemezler.
  - **Kanıt:** altı mutasyon kırmızı — işlemsiz yayını sessizce başarılı saymak, kiracı şartını kaldırmak, `WithTxCtx`'in dış context'i vermesi, tablonun `FORCE` olmaması, geri-kalan-iş indeksinin kısmi olmaması, `event_id`'nin kiracı yerine küresel tekil olması.
- [x] **Süreç içi bus silindi.** `internal/common/events` bir `Bus` arayüzü, `MemoryBus`, abonelikler ve paket düzeyinde global `Publish`/`Subscribe` taşıyordu — 346 satır artı 315 satır test — ve ağaçta **kendi dosyası dışında tek bir yayıncı ya da abone yoktu**. Outbox'ın yanında bırakmak, kullanılmamış bırakmaktan kötüydü: "olay bus'ı" arayan biri hangisi daha kolay okunuyorsa onu seçerdi ve aradaki fark, birinin süreç ölünce her şeyi kaybetmesi. Olay zarfı ve olay-tipi sözlüğü kaldı; bir outbox satırı onlardan yapılıyor.
- [x] Relay worker: 100'lük batch, `Sink` arayüzüne teslim, başarıda `published_at`. **(2026-09-13)** — *NATS JetStream ve `events.<cell>.<org>.<type>` konu şeması 3.2'de; `Sink` tam da bunun için bir arayüz, böylece rölenin garantileri broker olmadan ölçülebiliyor.*
  - **Lider seçimi YOK ve bu plandan kasıtlı bir sapma.** `FOR UPDATE SKIP LOCKED` zaten koordinasyonun kendisi: başka bir rölenin tuttuğu satır bu röleye görünmüyor. Lider, bir kiralama (lease) getirir; kiralama ise bu tasarımda olmayan bir başarısızlık kipi ekler — lider öldüğü an ile kiralaması dolduğu an arasında **hiç kimse** röle yapmaz ve biriken iş tam o süre kadar büyür. Liderin satın alacağı şey küresel sıralamadır; bu outbox küresel sıralama **vaat etmiyor** (id bir dizi değeri, taahhüt sırası değil). Vermediğimiz bir garanti için erişilebilirlik boşluğu ödemek yanlış takas. **Ölçüldü: eşzamanlı dört röle 60 olayı tam 60 kez teslim etti**, hiçbir satır iki kez talep edilmedi.
  - **Talep, yayın ve işaretleme tek işlem.** SKIP LOCKED'ın aldığı satır kilidi işlem bitene kadar sürüyor; bu yüzden ne bir `claim` sütunu var, ne `processing` durumu, ne de ölü rölenin bıraktığı satırları toplayan bir süpürücü — ölmek işlemi geri alır ve satır yeniden serbest kalır. Bedeli, işlemin ağ yayını boyunca açık kalması: EVENT düzleminin `idle_in_transaction` bütçesi (300 s, 2.4) tam bunun için boyutlandırılmış, ve o bütçeyi aşacak kadar yavaş bir sink, uğruna sessizce işlem tutulacak değil bağırılacak bir sink.
  - **Zehirli olay** `MaxAttempts`'te duruyor ve **tabloda kalıyor**, son hatasıyla: araştırılacak bir şey, silinecek bir şey değil.
  - **Kanıt:** beş mutasyon kırmızı — sink kabul etmeden önce işaretlemek (en-fazla-bir-kez'e çevirir), `SKIP LOCKED`'ı kaldırmak, deneme sınırını kaldırmak, reddedilen teslimi yine de yayınlanmış saymak, rölenin çapraz-kiracı bypass'ını kaldırmak.
- [x] **Saklama süpürücüsü (`SweepPublished`).** v192 süpürücü için bir indeks ekliyordu; kullanıcısı olmayan indeks tam da bu deponun kovaladığı kusur, o yüzden süpürücü de burada. Teslim edilmiş satır bir makbuz — bir olaydan sonra ilk soru "bu olay yayınlandı mı, ne zaman" — ama tablo her servisin yazma yolunda, dolayısıyla sonsuza kadar saklamak haftalar önce bitmiş bir fayda için her vacuum'u yavaşlatır. Silme **sınırlı gruplar** hâlinde: bir aylık olayı tek `DELETE` ile silmek, her servisin yazdığı tabloda uzun bir kilit demek — bu programın tekrar tekrar bulduğu şeklin ta kendisi. Yüklem `published_at IS NOT NULL` içeriyor, yani teslim edilmemiş bir olay **hiçbir zaman** yaşlandırılamaz; dikkatsiz bir yüklemin yanlış yaptığı vaka ölçüldü: **sink'in reddettiği doksan günlük bir olay** her turdan sağ çıkıyor, kırk günlük teslim edilmiş satırlar gidiyor. `KeepFor` sıfırken kapalı. **Üç mutasyon kırmızı:** yüklemi `created_at`'e çevirmek, sıfır `KeepFor`'u "hepsini sil"e çevirmek, grup sınırını kaldırmak.
- [ ] Mevcut SSF ve SCIM outbound outbox'ları bu ilkele göç eder (iki ayrı tablo kalkar).
- [ ] **Açık ve altı çizilerek yazılıyor: bu outbox'a henüz hiçbir üretim kodu yazmıyor ve röleyi hiçbir süreç koşturmuyor.** İlkel, röle ve saklama gerçek bir PostgreSQL'e karşı ölçüldü; ama bir mekanizmanın *gönderilmiş* olması *çalıştırılmış* olmakla aynı şey değil — 2.4'te düzlem rolleri için yazılan cümlenin aynısı. Üretici tarafı (oturum iptali, kiracı silme, kill-switch) 3.3'ün işi; `cmd/event-relay/` binary'si ise bir Sink gerektiriyor, o da 3.2. **Bu durum, az önce sildiğim süreç-içi bus'ın kusurunun aynısına bir adım mesafede:** hiçbir şeyin yazmadığı bir tablo, hiçbir şeyin import etmediği bir paketten yalnızca niyetiyle ayrılır. Fark, sıralamanın planlı olması ve burada yazılı olması; o yüzden ilk üretici gelene kadar bu madde açık kalıyor.
- **Kabul:** Relay 10 dk kapalı → olay kaybı 0, kuyruğa alınan sayı = üretilen sayı; idempotent tüketici çift teslimi yutar (test `outbox_relay_test.go`). *(Karşılandı. Kesinti, uyumak yerine her denemeyi reddeden bir sink ile kuruldu — kesintiyi kesinti yapan şey her denemenin başarısız olması ve röle on dakikalık bir reddedişle on saniyelik olanı ayırt edemez. Beş tam drain boyunca sink her seferinde reddetti: teslim 0, birikmiş iş bozulmadan 25 satır. Sink dönünce 25'inin hepsi, her biri **bir kez** geldi. Kabulden sonra zorlanan bir çökme üç olayın üçünü de yeniden teslim etti ve aynı üç `event_id` ikişer kez göründü — idempotent tüketici altı teslimde üç olay sayıyor.)*

### 3.2 NATS JetStream (hücre içi)

- [ ] Helm `templates/nats.yaml` ×3, stream retention 7 gün, kiracı bazlı konu izinleri.
- **Kabul:** Bir NATS pod kaybı → yayın sürer; `make k8s-chaos` canlı moda eklenir.

### 3.3 Tüketiciler

- [ ] Audit indexer (PG sıcak + ES); `internal/audit/service.go` çift yazımı kalkar, `StartESReconciler` emekli.
- [ ] Webhook deliverer: satır içi ateşleme kalkar; `internal/webhooks` tüketici olur.
- [ ] Kill-switch olayı → Ziti reconciler + session revoker; hedef p95 < 2 s (ADR-11).
- [ ] Cache invalidation: rol/izin değişimi → session Redis anahtarları.
- **Kabul:** Kill-switch uçtan uca p95 ölçülür ve panoda; audit olayı ES'te ≤ 5 s.

### 3.4 Düzlem ayrımı (ADR-2)

**Dosyalar:** `cmd/verify-service/`, `cmd/identity-auth/` (veya identity-service bayrakla iki profil), `cmd/*-worker/`, Helm şablonları, `networkpolicy.yaml`
- [ ] `verify-service`: JWKS sunumu, introspection, `/access/.auth/*` forward-auth; PG bağımlılığı **yok** (import guard testi: `internal/common/importguard` deseniyle `pgx` importu yasak).
- [x] identity-service `SERVICE_PROFILE=auth|admin`: auth profili yalnız login/MFA/passwordless rotalarını kaydeder. **(2026-09-13)**
  - Sınıflandırma *tipte*: `internal/identity/profile.go` içindeki `planeGroup`, `*gin.RouterGroup` yerine geçer ve düzlemi servis edilmeyen rotayı kaydetmez — 182 kayıt satırı olduğu gibi kaldı (2.1b'deki `ScopedPool` hamlesinin aynısı).
  - 182 rotanın tamamı `routePlanes` tablosunda: 71 ISSUE, 111 ADMIN. Tabloda olmayan bir rota **her iki profilde de** servis edilir (üretimde sessiz kaybolma yok) ve `TestEveryIdentityRouteIsClassified` kırmızıya döner.
  - `SERVICE_PROFILE` yazım hatası **ölümcül**: bayrağın işi rota *kaldırmak*; sessizce hepsini servis eden bir süreç, uğruna bölündüğü yalıtımı geri verirdi.
  - Portal ve bildirim grupları (`cmd/identity-service/main.go`) ADMIN'e bağlandı; arka plan worker'ları bu adımda değişmedi (aşağıdaki `cmd/*-worker` maddesi).
  - Sınıflandırma veri olarak da yayımlanıyor: `files/identity-planes.json`, `go run ./tools/identityplanes` ile üretilir ve `TestPlaneManifestMatchesTheRouteTable` tabloyla senkron tutar — kenar yönlendirme kuralları bunun üzerinden üretilecek.
  - **Kanıt:** dört mutasyon kırmızı — login rotasını ADMIN'e taşımak, bir rotayı sınıflandırma dışı bırakmak, bilinmeyen profili sessizce `all` yapmak, filtreyi tamamen devre dışı bırakmak. Manifest için iki mutasyon daha.
  - **Helm yarısı ve kenar yönlendirmesi de tamam (`identityService.planeSplit`).** Kapalıyken tek Deployment — render **bayt bayt** eskisiyle aynı. Açıkken `-identity-auth` (`SERVICE_PROFILE=auth`) ve `-identity-admin` (`SERVICE_PROFILE=admin`), Ingress ISSUE yollarını birinciye, kalan her şeyi ikinciye gönderiyor.
  - **Bileşen etiketi bilerek `identity-service` kaldı** iki yarıda da: NetworkPolicy, ServiceMonitor ve PDB onun üzerinden seçiyor; yeniden adlandırmak pod'ları üçünden birden sessizce düşürürdü — önemlisi NetworkPolicy. Yarılar ek `openidx.io/plane` etiketiyle ayrılıyor, ki bu etiket split kapalıyken hiç yok: mevcut Deployment'ın (değiştirilemez) selector'ı aynı kalıyor.
  - **Kenar kuralları manifestten üretiliyor**, elle yazılmıyor: 77 ISSUE rotası 65 kurala indirgeniyor (61 Exact + 4 Prefix), geri kalan her şey catch-all ile ADMIN'e düşüyor. Sınıflandırılmamış yeni bir rota da ADMIN'e düşer ve **cevaplanır** (`ProfileAdmin` sınıflandırılmamış her rotayı sunar), 404 almaz.
  - **Yönlendirilebilirlik bir kısıt olarak yazıldı** (`TestThePlaneSplitIsRoutable`): aynı yolu iki düzlem sunamaz (Ingress metoda bakamaz) ve bir ISSUE öneki bir ADMIN rotasının üzerine uzanamaz. Altı giriş kurala uymuyor ve nedeni tabloda yazılı; hepsi ISSUE'ya kaydı, çünkü maliyetler simetrik değil — yanlışlıkla ISSUE'da olan rota ucuz düzleme biraz yük ekler, yanlışlıkla ADMIN'de olan rota düzlem atıldığı anda çalışmaz.
  - **CI'daki render simülasyonu Go testindeki bir hatayı buldu:** Kubernetes `Prefix` eşleşmesi *eleman bazlı*, string öneki değil — yani `/invitations` kuralı `/invitations`'ın kendisini de talep ediyor. İlk sürüm bunu `strings.HasPrefix` sanmıştı ve `GET|POST /invitations`'ı ADMIN'de bırakmıştı; gerçek Ingress kurallarını 182 rotanın somut yoluyla süren adım itiraz etti. Artık iki taraf da aynı semantiği kullanıyor.
- [x] **Süpürücü sayımı ve üç düzeltme (2026-09-13).** Bu maddenin gerekçesi ölçülürken **üç canlı kusur** çıktı: bir servisin `main`'inde başlatılan süpürücü o Deployment'ın **her pod'unda** koşuyor; `access-service` iki replika ile geliyor ve üretimde sekize, `audit-service` üç ile gelip ona ölçekleniyor. Ağaçtaki **on iki** süpürücü zaten `leader.RunPeriodic` üzerinden geçiyordu; üçü geçmiyordu ve özel bir yanları yoktu.
  - **EDR yoklayıcısı müşterinin CrowdStrike / Intune / Jamf kiracısını replika başına bir kez arıyordu.** Süpürücü hiçbir şeyi talep etmiyor: `last_sync_at`'i aralığından eski olan kaynakları seçiyor ve `last_sync_at` yalnız senkron **bittiğinde** yazılıyor — yani her replika aynı dakikada aynı kaynağı "zamanı gelmiş" görüyor. Beş dakikada bir yoklaması istenen bir kaynak o pencerede iki ila sekiz kez, **müşterinin kendi rate limit'i üzerinden** yokladı; üstelik her senkron, Ziti zorlama yolunun erişimi iptal etmek için okuduğu posture sonuçlarını yazıyor.
  - **Guacamole dış denetim senkronu** her uzak oturumu **taze bir uuid** birincil anahtarıyla ekliyor, dolayısıyla `ON CONFLICT DO NOTHING` mantıksal bir kopya için **asla** tetiklenemiyor: aynı pencereyi yoklayan iki replika, bir kayıtlı oturum için iki denetim satırı yazdı. Bir uyumluluk ürününde bu israf değil, **yanlış cevap** — ayrıcalıklı uzak oturumları sayan bir denetçi gerçeğin replika sayısı katını görür. Ayrıca hiçbir replikanın kilitlemediği tek bir ortak imleci ilerletiyor.
  - **Elasticsearch uzlaştırıcısı** aynı 500 belgeyi replika başına bir kez indeksliyor ve `indexed_at`'i replika başına bir kez damgalıyordu. ES yazımları belge kimliğiyle idempotent olduğu için bozulma yok; bedeli, ürünün **en yüksek hacimli** yolunda N kat yazma yükü — hem de tam ES'in zaten geride olduğu anda, ki uzlaştırıcının yapacak işi olduğu tek an o.
  - **Dördüncüsü ve en pahalısı: kullanım ölçümü (faturalama).** Rollup tekil bir imleç satırını okuyor, sonrasındaki olayları çekiyor, her biri için `count = count + 1` yapıyor — **artırma**, idempotent yazma değil — ve imleci ilerletiyor. İmleç **kilitsiz** okunuyordu; üç `audit-service` replikası aynı imleci okudu, aynı grubu çekti, her sayacı artırdı ve imleci aynı yere taşıdı. Rollup'ın üstündeki yorum "imleç her olayın en fazla bir kez toplanmasını garantiler" diyordu: tek süreç için doğru, üç süreç için yanlış. **Müşterinin faturalandığı günlük kullanım replika sayısı kadar şişiyordu.**
    - Düzeltme, imleç satırına tüm grup boyunca tutulan bir `FOR UPDATE SKIP LOCKED` — **lider kapısı değil.** Lider seçimi Redis üzerinde koşuyor ve istemci yokken "her replika koşar"a düşüyor; yalnızca işi tekrarlayan bir süpürücü için kabul edilebilir, çift saymaması gereken bir sayaç için değil. Kilit, koruduğu sayının bulunduğu veritabanında duruyor.
    - **Ölçüldü:** 40 olay üzerinde dört eşzamanlı toplayıcı 40 fatura ediyor; kilit kaldırıldığında daha fazlasını ediyor. **Eksik imleç satırı** artık sessizlik değil, hata kaydı — hiçbir şeyi toplamamak, çift faturalamanın yanlış yaptığı kadar geliri kaybettirir ve sağlıklı boş bir worker gibi görünür.
    - **Bir mutasyon yeşil kaldı ve kalması doğru:** `SKIP LOCKED` yerine düz `FOR UPDATE` de doğru — beklemek çift saymıyor, sadece replikayı beş yüz satırlık bir grubun arkasına kuyruğa sokuyor. Bu bir doğruluk değil işletme tercihi ve testin kırmızıya dönmemesi gerekiyor; tercih kaynakta yazılı.
  - **Beşincisi: SIEM iletici.** Ölçüm imleciyle aynı şekil — kilitsiz okuma, grup, teslim, ilerlet. Aşağı akıştaki veri yanlış değil (SIEM olay kimliğiyle tekilleştiriyor; kodun imleç ilerletme hatasını zaten tolere etmesinin sebebi de bu) ama SIEM ürünleri **alım hacmi üzerinden faturalandırıyor**: müşteri tek bir denetim akışı için replika sayısı kadar ödedi ve karşı taraftaki her korelasyon kuralı her olayı üç kez gördü. Aynı şekilde düzeltildi — imleç satırı tüm grup boyunca `FOR UPDATE SKIP LOCKED` ile tutuluyor, çünkü "Redis her düştüğünde müşterinin SIEM faturası üçe katlanıyor" kimsenin onaylayacağı bir bozulma değil. Eksik imleç satırı artık sessizce duran bir akış değil, hata kaydı.
  - **Denetim zinciri mühürleyicisi zaten güvenliydi ve artık öyle kayıtlı:** org başına `pg_advisory_xact_lock` alıyor — iş talep edilebilir bir *satır kümesi* değil, yalnızca tek bir yazarın uzatabileceği bir dizi olduğunda doğru ilkel budur. Sayım, bunu olmadığı bir şekle zorlamak yerine dördüncü geçerli cevap olarak `advisory-lock`'u kazandı.
  - Üçü de artık `leader.RunPeriodic` üzerinden geçiyor. **Türetilmiş bir sayım** (`internal/common/leader/sweeps_census_test.go`) `internal/` ve `cmd/` altındaki her `time.NewTicker`'ı kendisi buluyor ve hiçbir kaydın adlandırmadığı biri varsa kırmızıya dönüyor; böylece dördüncüsü sessizce eklenemiyor — yazan kişi hangi cevabın geçerli olduğunu söylemek zorunda: lider, `FOR UPDATE SKIP LOCKED` talebi, ya da gerçekten süreç-başına. `SKIP LOCKED` içermeyen bir `claim` kaydı ve artık ticker'ı olmayan bir dosya için kalan kayıt da kırmızı. **On bir ticker açıkça "karar verilmedi" olarak duruyor** — sayılıyor ve adlandırılıyor, sessizce geçirilmiyor; orgscope'un `needsScoping` kütüğüyle aynı şekil, aynı sebeple.
  - **Kanıt:** üç mutasyon kırmızı — EDR süpürücüsünü çıplak ticker'a geri döndürmek, talep etmeyen bir dosyayı `claim` olarak kaydetmek, ticker'ı olmayan bir dosya için kayıt bırakmak.
- [x] **Sayımdan bir kalem karara bağlandı: `lifecycle_sweep.go` → "idempotent" (2026-09-14).** Bu süpürücü her replikada koşuyor ve kendi yorumu bunun sorun olmadığını söylüyordu: "her ifade yalnızca hâlâ etkin satırlara dokunur, tekrar eden tur'lar (ya da yarışan replikalar) zararsızdır." Bu, eşzamanlılık altındaki SQL hakkında bir iddia — yani bu programın tekrar tekrar "tek süreç için doğru, birkaç süreç için yanlış" bulduğu türden. **Doğru çıktı ve artık ölçümü var: sekiz eşzamanlı süpürücü tek bir süpürücüyle aynı duruma iniyor, üstelik oturmuş bir duruma** — sonrasında atılan bir tur daha hiçbir şeyi değiştirmiyor.
  - **Sebebi adlandırmaya değer:** süpürücünün yazmaları `UPDATE ... WHERE <hâlâ etkin>` şeklinde ve READ COMMITTED altında ikinci güncelleyici satır kilidinde bekleyip yüklemini *taahhüt edilmiş* satıra karşı yeniden değerlendiriyor — dolayısıyla hiçbir şeyle eşleşmiyor. **Koordinasyonu veritabanı yapıyor**; burada ne lider ne talep gerekmesinin sebebi bu.
  - **Sayım beşinci bir cevap kazandı (`idempotent`).** Bu cevap bir mekanizmaya değil gerekçesine dayandığı için, bekçi bu ağaçta *gerçekten yanlış çıkmış* iki şekli kontrol ediyor: tur başına bir `INSERT` (Guacamole denetim senkronu replika başına bir kopya satır yazıyordu) ve oku-değiştir-yaz artırma (ölçüm rollup'ı müşteriyi replika başına bir kez faturalandırıyordu). İkisi de idempotentliği kanıtlamıyor; ikisi de onun en yaygın yokluğunu yakalıyor. "Karar verilmedi" listesi 11'den 10'a indi.
  - **Kanıt:** dört mutasyon kırmızı — hibe bitişini şimdi yerine geleceğe itmek, çekiliş iptalinden "hâlâ etkin" yüklemini düşürmek, etkin kullanıcıları da iptal etmek, yükseltme işaretlemesinden id filtresini düşürmek.
  - **Testin ilk taslağı bunlardan ikincisini kaçırdı** ve bu kayda değer: satır *sayıyordu* — "kaç çekilişte `returned_at` var" — yani her turda o damgayı taze bir `NOW()` ile yeniden yazan bir süpürücü hiçbir sayacı oynatmıyordu. Oysa idempotentliği sağlayan şey tam da o yüklem. Test artık sayıları değil, yeniden yazılacak **değerleri** özetliyor.
- [x] **Sayımdan ikinci kalem: `posture.go` → "idempotent" (2026-09-14).** 15 dakikalık ticker'ın gövdesi tek bir ifade: `DELETE FROM device_posture_results WHERE expires_at < NOW()`. Tekrar etme yarısı burada neredeyse bedava — ikinci replikanın sileceği satırlar zaten yok. Ölçülmeye değer olan diğer yarısıydı: **bu süpürücü hiçbir şeye karar vermiyor.**
  - **Neden önemliydi:** boşalttığı tablo erişim vekilinin duruş (posture) zorlamasını besliyor; bir cihazın duruş verisini silen bir süpürücü, o cihazı *izinli*den *reddedilmiş*e taşıyan şey olabilirdi — yani Zero Trust zorlama yolunda, replika başına bir kez koşan bir **geçiş**. Değil: `EvaluateIdentityPosture` sonucu **süresi dolmuş** bir kontrolü de, **hiç sonucu olmayan** bir kontrolü de aynı şekilde başarısız sayıyor. Dolayısıyla zaten süresi dolmuş bir satırı silmek hiçbir kararı değiştiremez.
  - **Test satır saymıyor, kararı ölçüyor** (`posture_expiry_testdb_test.go`): kontrol başına izinli/reddedilmiş haritası süpürücünün öncesi ve sonrasında birebir aynı olmak zorunda. Satır saymak, canlı sonuçları da silen bir süpürücüyü geçirirdi — ve o süpürücü, duruşu hâlâ geçerli olan her cihaza karşı sessiz bir hizmet reddi olurdu. Üç mutasyon kırmızı: süresi dolmuşlar yerine canlı satırları silmek, `WHERE`'i tamamen düşürmek, hiçbir şey silmemek. Sekiz eşzamanlı süpürücü tek süpürücüyle aynı yere iniyor ve durum oturuyor.
  - **Bekçinin kapsamı yanlıştı, bunu açığa çıkaran bu kalem oldu.** İdempotentlik bekçisi idempotentliği bozan iki şekli **dosyanın tamamında** arıyordu; süpürücüsünden başka bir şey barındırmayan 145 satırlık bir dosyada işe yaradı ve denenen ikinci kayıtta yanlış alarm verdi: `posture.go` 1054 satır ve istek yolunda beş alakasız `INSERT` içeriyor. Cevap dosyaya değil **süpürücüye** dair olduğu için, `idempotent` kaydı artık kendi fonksiyonunu adlandırıyor ve bekçi yalnızca o fonksiyonun gövdesini okuyor. Fonksiyon adlandırmayan ya da dosyada olmayan bir fonksiyonu adlandıran kayıt kırmızı. "Karar verilmedi" listesi 10'dan 9'a indi.
- [x] **Sayımdan üçüncü kalem: `sms_config_watcher.go` → "süreç-başına" (2026-09-14).** Tur tek bir `system_settings` satırını okuyor ve **hiçbir şey yazmıyor**: bu sürecin kendi SMS sağlayıcısını ve OTP ayarlarını değiştiriyor, `lastUpdatedAt` su-seviyesi de watcher'ın kendi goroutine'indeki yerel bir değişken. Lidere bağlamak **kusurun kendisi** olurdu: lider olmayan her pod, yöneticinin az önce değiştirdiği sağlayıcı üzerinden kod göndermeye ayakta kaldığı sürece devam ederdi. "Karar verilmedi" listesi 9'dan 8'e indi.
- [x] **İmza anahtarı yenileme her SAML imzasıyla yarışıyordu (2026-09-14).** `signer.go` sayımda (doğru biçimde) "süreç-başına" duruyor — yenilemeyi lidere bağlamak on iki `oauth-service` replikasının on birini bayat bir JWKS sunar hâle getirirdi. Ama o kaydı denetlerken başka bir şey çıktı: `refreshSigner` anlık görüntüyü atomik işaretçiyle takas ettikten **sonra** `s.privateKey` ve `s.publicKey` düz alanlarını da atıyordu; bu alanları SAML imzalama yolları (`signRedirectBinding`, `signAssertionEnveloped`, `samlSigningCertBase64`, step-up jetonu) **istek goroutine'lerinde**, kilitsiz okuyor. Üstelik yazan yalnızca ticker değil: `verificationKeyfunc` bilinmeyen bir `kid` gördüğünde yenilemeyi satır içi çağırıyor, yani bir istek diğeriyle yarışabiliyordu.
  - **Ölçüldü:** `go test -race` ilk denemede bildirdi — hem işaretçi alanı hem de gösterdiği `rsa.PrivateKey` yapısı için. Düzeltmeden sonra aynı test temiz (`internal/oauth/signer_race_testdb_test.go`).
  - **Düzeltme:** yenileme artık atomik işaretçiden başka bir şey yazmıyor; tüm okuyucular `activePrivateKey()` / `activePublicKey()` üzerinden geçiyor (anlık görüntü yoksa kurulum anındaki anahtara düşüyor — birim testleri `Service`'i veritabanısız kuruyor). Eski alanlar yalnızca `NewService` içinde, bir kez yazılıyor.
  - **Düzeltmenin iki yarısı birbirinin yerine geçmiyor ve bu da varsayılmadı, ölçüldü.** Yarış için hem yazma hem senkronsuz okuma gerekiyor: `-race` testi **okuma** yarısını tutuyor (imzalama yoluna alan okumasını geri koyun, kırmızıya döner); yalnızca **yazmayı** geri koymak testi yeşil bırakıyor, çünkü artık alanı eşzamanlı okuyan yok. Bu yüzden yazma yarısının kendi türetilmiş muhafızı var: paketin kendi kaynaklarını okuyup kurulum dışındaki her atamada kırmızıya dönüyor.
- [x] **Sayımdan dördüncü kalem ve yeni bir kusur: `ziti_fabric.go` → "lider" (2026-09-14).** 30 saniyelik tur tek fonksiyonda iki farklı iş yapıyor ve sayımdaki sorunun iki ayrı cevabı varmış. Sağlık kontrolü ve yeniden kimlik doğrulama **süreç-başına** ve her replikada koşmalı: her pod kendi SDK oturumunu tutuyor, lider başkası diye kendi yeniden bağlanmasını atlayan bir pod bağlantısız kalırdı. Ardından yazdığı yedi metrik ise tam tersi — çevrimiçi yönlendirici, servis/kimlik/politika sayısı **fabric'in** özellikleri, pod'un değil.
  - **Sonuç:** sekiz replika aynı olguyu sekiz kez yazıyordu ve bedeli yalnızca depolama değildi: fabric genel bakışı `ziti_metrics`'in **en son 50 satırını** okuyor; bu pencere ~3,5 dakikalık geçmişten, aynı anın sekiz kopyasıyla **26 saniyeye** düşüyordu.
  - **Düzeltme ve ölçüm:** metrik yarısı `leader.IsLeaderForTick` ile tur başına kapılandı; sağlık kontrolü ve yeniden doğrulama olduğu gibi kaldı. Gerçek Redis ve gerçek veritabanıyla aynı kovada yarışan sekiz replika **yedi** satır yazıyor (kapı sorulup sonucu yok sayıldığında **elli altı**), ve Redis'siz bir kurulum metriklerini yine kaydediyor — tek replikanın koordine olacağı bir eşi yok. "Karar verilmedi" listesi 8'den 7'ye indi.
- [x] **Sayımdan beşinci kalem ve duran olmayan bir süpürücü: `guacamole_users.go` → "idempotent" (2026-09-14).** Tek ticker iki süpürücü çalıştırıyor. Deprovision süpürücüsü önce broker hesabını sonra eşleme satırını siliyor; ikinci replikanın zaten silinmiş hesabı silmesi tolere edilen 404, satır her hâlükârda gidiyor — yakınsıyor. **Stale-grant süpürücüsü ise işini hiç işaretlemiyordu:** biten bir oturumun bıraktığı READ yetkisini iptal edip hiçbir şey yazmıyordu, dolayısıyla aynı satırlar her turda yeniden eşleşiyordu — Mart'ta biten bir oturum Haziran'da hâlâ, beş dakikada bir iptal ediliyordu. Görünmezdi, çünkü olmayan bir yetkiyi iptal etmek de tolere edilen 404: **süpürücü hiç hata vermediği için çalışıyor görünüyordu.**
  - **Asıl bedel boşa giden çağrılar değil:** sorgu ilerleme işareti olmadan `LIMIT 200` taşıyor, yani eşleşen satır sayısı ikiyüzü geçtiğinde (kurulum yaşlandıkça artar, hiç azalmaz) süpürücü rastgele ikiyüzünü tekrar geziyor, kalanlara hiç ulaşmayabiliyordu — ve en çok iptal edilmesi gereken yetkiler (tarayıcısı kapatılmış, başka hiçbir şeyin temizlemediği oturumlar) tam da o limitin arkasında kalabilenler.
  - **v193** `pam_entry_sessions.guac_revoked_at` kolonunu ve süpürücünün kendi yüklemi üzerine kısmi bir indeks ekliyor; işaret **yalnızca broker onayladığında** yazılıyor. Reddedilen bir iptal satırı işaretsiz bırakıyor ki bir sonraki tur yeniden denesin — erişim ayaktayken "iptal edildi" yazmak, bu süpürücünün kapatmak için var olduğu sessiz deliğin ta kendisi.
  - **Ölçüm:** gerçek PostgreSQL + HTTP broker ile ilk tur biten ve 13 saatlik oturumu iptal ediyor, canlı oturuma dokunmuyor; **ikinci tur broker'ı sıfır kez çağırıyor.** Üç mutasyon kırmızı: yüklemden işareti düşürmek (eski süpürücü — ikinci turda yine iptal ediyor), reddedilen iptali "yapıldı" saymak, bayatlık penceresini daraltıp canlı oturumları kesmek. "Karar verilmedi" listesi 7'den 6'ya indi.
- [ ] governance/provisioning/audit ticker'ları `cmd/<svc>-worker` binary'lerine; API pod'larında `RunPeriodic` çağrısı yok.
- [ ] APISIX upstream'leri düzlem başına; `nodeSelector: plane=issue` ayrı düğüm havuzu. *(Kubernetes Ingress yarısı yapıldı — `identityService.planeSplit`; NetworkPolicy bilerek bileşen etiketiyle her iki yarıyı kapsıyor.)*
- **Kabul:** ADMIN düzlemine 10× yük → ISSUE p99 değişmez (k6 senaryosu "admin flood"); verify-service pod'unda PG bağlantısı 0.

### 3.5 Kabul denetleyicisi ve maliyet kotası (ADR-10)

**Dosyalar:** `internal/common/middleware/admission.go`, `ratelimit.go`
- [x] `Admission(cfg)`: `MaxInflight`, `QueueTimeout`, 503 + `Retry-After`; metrik `openidx_admission_{inflight,rejected_total,queue_wait_seconds}`. **(2026-09-13)**
  - **Bu bir hız sınırı değil ve fark önemli.** Depodaki hız sınırlayıcı **varışları** sınırlıyor ve sürecin *hâlihazırda ne taşıdığını göremiyor*: saniyede 200 istek, her biri 5 ms sürerken iyi, bozulmuş bir veritabanına karşı 2 s sürerken ölümcül — dakikalık bir sayaç ikisini ayırt edemez. Sabit bir kaynağı (bağlantı havuzu, CPU, bekleyen isteğin tuttuğu bellek) koruyan şey **aynı anda uçuşta kaç istek olduğuna** konan sınırdır.
  - **Önlediği başarısızlık "yavaş" değil.** Sınır yokken aşırı yüklü servis her şeyi kabul eder: goroutine'ler birikir, her biri gövdesini ve havuz sırasındaki yerini tutar, gecikme her istemcinin zaman aşımını geçer, istemciler yeniden dener, yük artar. Hiçbir şey tamamlanmaz ve süreç, kimsenin artık beklemediği işlerle dolu bir kuyrukla ölür. Sınırlı kuyruk + hızlı ret bunu *bozulmuş ama ayakta*'ya çevirir.
  - **Neden kuyruk var:** 20 ms süren bir patlama aşırı yük değil; onu reddetmek servisi sıradan titreşimde bozuk gösterirdi. Kuyruk patlamayı emer; kuyruğun **zaman aşımı** ise bir kesintiyi emmesini engeller.
  - **Varsayılan geçişli:** `MaxInflight <= 0` iken middleware hiçbir şey yapmıyor. Ölçülmeden tahmin edilen bir sınır, kendi eliyle yaratılmış bir kesintidir.
  - `/health`, `/ready`, `/metrics` **asla** kapıdan geçmiyor: kapının yük attığını operatörün öğrendiği yer orası, ve kendi aşırı yükünü gizleyen bir kapı hiç kapı olmamasından kötüdür.
  - Kuyrukta beklerken bağlantıyı kapatan istemci yerini **anında** bırakıyor; yoksa kuyruk gerçek talebi değil terk edilmiş istekleri ölçer.
  - `queue_wait_seconds` hem kabul edilen hem reddedilen istekler için gözleniyor — yalnız başarıda ölçülen bir kuyruk, var olma sebebi olan aşırı yükü gizler.
  - **Kanıt:** altı mutasyon kırmızı — slotu bırakmamak, `Retry-After`'ı göndermemek, kuyruğu kaldırmak, istemci iptalini dinlememek, health yolunu kapıya sokmak, ve `MaxInflight=0`'ı 1 slotlu kapıya çevirmek.
  - **Bir mutasyon yeşil kaldı, testin şekli değişti:** "geçişli" testi yalnız durum kodlarını sayıyordu ve 1 slotlu kapı onu geçiyordu (30 × 2 ms tek slottan 60 ms'de akıyor, varsayılan kuyruk bütçesinin çok altında). Özellik *eşzamanlılık* olduğu için ölçülen de artık eşzamanlılık; o mutasyon şimdi kırmızı.
- [x] Rota maliyeti tablosu (`RouteCost`), kiracı bütçesi birim/pencere; bayrak `RATELIMIT_COST_MODE=off|observe|enforce`. **(2026-09-13)**
  - **Ölçüldü, tartışılmadı.** Deponun kendi Argon2id parametrelerine karşı (`pwhash.Default`, m=19456 KiB, t=2): bir parola doğrulaması **37,3 ms ve 19.926.087 bayt**, bir JWKS cevabı **6,0 µs ve 540 bayt**. CPU'da altı bin kat, bellekte otuz yedi bin kat — ve tehlikeli olan yarısı bellek: yüz eşzamanlı giriş iki gigabayt Argon2 karalama alanı tutar, istek hızı hâlâ sıradan görünürken.
  - **Bu sayılar ağırlık olmuyor.** Oranı birebir yansıtan bir tablo bütçenin tamamını tek sınıfa harcatır ve mekanizmayı "fazladan aritmetiği olan bir giriş sınırlayıcısı"na çevirir — ki auth katmanı zaten odur. Ağırlıklar **sıralı (ordinal)**: 1, 2, 5, 10. Ölçüm **sırayı** belirliyor, tam sayıları değil.
  - **Aldığımız şey bir yük atma önceliği.** Bütçesini tüketen kiracı `/oauth/token`'da 429 alırken, aynı kiracının relying party'leri JWKS'i çekmeye ve ellerindeki token'ları doğrulamaya devam ediyor. Kiracıyı tümden kesmek, bir ekibin yük testini o ekibin çalıştırdığı her uygulama için kimlik doğrulama kesintisine çevirirdi.
  - **Maliyeti 1 olan rotalar ne atılıyor ne de harcatıyor.** JWKS yolunda bir Redis gidiş-dönüşü, isteği sunmaktan pahalı olurdu; ayrıca bir panonun yoklaması bütçeyi harcayabilseydi kiracının kendi konsolu kendi girişlerini attırabilirdi. Ucuz trafiği sınırlamak istek sayacının işi ve zaten yapıyor.
  - **Redis kaybında açık başarısızlık (fail open).** Bu bir kapasite denetimi, güvenlik denetimi değil: auth katmanı kaba kuvvet için kapalı başarısız oluyor, bu ise bir Redis kesintisinde filo çapında her pahalı isteği reddetmemek için açık — o reddediş, mekanizmanın önlemek için var olduğu kesintinin ta kendisi olurdu.
  - **`observe` bir mod değil, boyutlandırma yöntemi.** `openidx_ratelimit_cost_rejected_total{mode="observe"}` neyin reddedileceğini hiçbir şeyi reddetmeden söylüyor. Tanınmayan bir mod başlangıçta reddediliyor, sessizce `off` olmuyor.
  - **Önekler eleman bazlı eşleşiyor** (3.4'te Ingress'in öğrettiği ders): `/oauth/logout` ile `/oauth/logout-all` ayrı — string önekiyle bir oturum kapatma, her oturumu iptal eden bir fan-out'un maliyetini alırdı.
  - **Kanıt:** dokuz mutasyon kırmızı — iadeyi kaldırmak, ucuz rotaları harcatmak, kiracı ayrımını kaldırmak, string önekine dönmek, kapalı başarısız olmak, `observe`'ü reddettirmek, eşiği `after`'a kaydırmak, bilinmeyen modu sessizce `off` yapmak, token uç noktasını ucuza düşürmek. İki mutasyon daha montaj bekçisi için (bir servisten `Admission`'ı ya da bütçeyi düşürmek).
- [x] **Sekiz servise montaj + türetilmiş bekçi.** Bütçe **kiracı çözücüden sonra** bağlanıyor: öncesinde her istek atıfsız `"_"` kovasına düşer ve bir kiracının seli diğer her kiracının pahalı işini attırırdı. `gateway-service` gerekçesiyle muaf — Host'tan `X-Org-Slug` türetip arka uçların çözmesine bırakıyor, kendisi kiracı çözmüyor; slug ile anahtarlamak aynı kiracı için ikinci bir anahtar uzayı açardı ve iki bütçe de yanlış olurdu. Bekçi `cmd/`'den **türetiliyor**, listelenmiyor — gateway'in bir sürüm boyunca hiçbir şeyin okumadığı bir hız sınırı yapılandırması taşıması tam olarak bu yüzden.
- **Kabul:** Token floodu (maliyet 5) kiracı bütçesini tüketir, aynı kiracının JWKS/okuma istekleri (maliyet 1) **etkilenmez**; komşu kiracı hiç etkilenmez. *(Karşılandı ve tek bir yürüyüşte ölçülüyor — üçü tek bir özelliğin parçaları olduğu için: 40 token isteği 50 birimlik bütçeye karşı 10 kabul/30 ret verirken, aynı kiracının JWKS ve discovery istekleri **her turda** 200 dönüyor ve komşu kiracının sekiz girişinin hiçbiri reddedilmiyor.)*
- **Açık kalan:** hiçbir bütçe üretimde ölçülmedi. Rakam `observe` modunda bir hafta koşturulmadan `enforce`'a alınmamalı — ve bu bir ihtiyat cümlesi değil, mekanizmanın kullanım talimatı.
- **Bilinen boşluk:** `admission.go`'daki kapı eşzamanlılığı **tek biçimli** sınırlıyor — bir slot 19,9 MB Argon2 tutuyor da olabilir 540 bayt JSON de. Ucuz duruma göre boyutlanmış bir `MaxInflight` pahalı durumda yine OOM eder. Slotu rotanın maliyeti kadar saydırmak bariz sonraki adım ve **kasıtlı olarak atılmadı**: kapının hızlı yolunu değiştiriyor ve bu mekanizmanın sayıları üzerine bir şey inşa edilmeden önce `observe` ile ölçülmesi gerekiyor.

### 3.6 KEDA

- [x] Prometheus tetikleyicileri: ISSUE kuyruk bekleme p95, VERIFY rps/pod, EVENT outbox teslim gecikmesi p95. **(2026-09-13)** — `templates/keda-scaledobject.yaml`, `keda.*` değerleri; varsayılan **kapalı**.
  - **Neden zaten bir HPA varken.** 0.5'teki HPA CPU ve belleğe bakıyor; ikisi de **gecikmeli** göstergeler. Yük altındaki bir düzlem **önce kuyruğa girer**, CPU'yu sonra yakar: istekler slot, bağlantı, kilit bekler ve pod'un CPU'su %40'ta dururken her çağıran saniyelerce gecikme görür. CPU hedefi geçtiğinde kuyruk çoktan bir dakikadır derin, ve o an gelen replikalar onlarsız başlamış bir soruna bir dakika geç kalmış olur.
  - **ISSUE → `openidx_admission_queue_wait_seconds` p95.** Bu, 3.5'teki kabul kapısının ürettiği sayının ta kendisi ve düzlem geri kaldığı **anda** yükseliyor. (`ADMISSION_MAX_INFLIGHT` ayarlı olmalı; yoksa histogramın gözlemi olmaz ve tetikleyici sonsuza kadar sıfır okur — bu tetikleyicinin yazılı ön koşulu.)
  - **VERIFY → pod başına rps.** Doğrulama CPU biçimli ve durumsuz; rps/pod replika başına yükün doğrudan vekili ve kullanımdan önce hareket ediyor.
  - **EVENT → `openidx_outbox_relay_lag_seconds` p95.** Plan NATS tüketici gecikmesi diyordu; **NATS henüz yok (3.2)** ve EVENT düzleminin bugünkü kuyruğu outbox. Aynı soruyu var olan kuyruğa soruyoruz; NATS gelince bu bir tetikleyici **kazanır**, anlamı değişmez.
  - **Bir Deployment'ta iki otomatik ölçekleyici bir yapılandırma değil, bir hata.** KEDA pod'ları kendisi ölçeklemiyor: her ScaledObject için **kendi HPA'sını yaratıyor**. Yani hem bunu hem chart'ın kendi HPA'sını taşıyan bir servis, aynı `scaleTargetRef`'e bakan iki HorizontalPodAutoscaler alır; her biri kendi metriğinden bir replika sayısı hesaplar ve yazar. Pazarlık etmezler. Deployment **en son yazanı** izler ve ikisi var olduğu sürece salınır — bu salınım yük altında flapping gibi görünür, yani otomatik ölçeklemenin önlemek için açıldığı şey gibi. Chart bunu **render etmeyi reddediyor**; üretimde keşfedilecek bir şey değil.
  - **İkinci kilit:** `keda.prometheusAddress` boşken render başarısız. Okuyacak yeri olmayan bir tetikleyici, ScaledObject'i `minReplicas`'ta bırakır ve hatayı kimsenin bakmadığı bir `status` alanına yazar.
  - **Kanıt:** dört mutasyon kırmızı — ISSUE'yu CPU'ya bağlamak, iki-ölçekleyici kilidini kaldırmak, KEDA'yı varsayılan açık yapmak, adres kilidini kaldırmak.
- **Kabul:** Faz 0.5 HPA testi tekrar; ölçekleme CPU'dan **önce** tetiklenir. *(Render tarafı karşılandı ve CI'da: her düzlem kendi adına yazılmış sinyalle ölçekleniyor, hiçbir ScaledObject bir cpu/memory sorgusu taşımıyor — taşısaydı gecikmeli gösterge geri gelirdi ve hiçbir şey yanlış görünmezdi — ve KEDA'nın ölçeklediği hiçbir Deployment ayrıca chart'ın HPA'sını taşımıyor. **Ölçülmedi:** "CPU'dan önce tetiklendi" cümlesi bir chart render'ından çıkarılamaz; 0.5'in kendi kabulü gibi **oyun günü M1'de** ölçülüp `docs/evidence/`'e yazılacak.)*

---

## Faz 4 — Hücre modeli ve ikinci bölge (8–12 hafta)

### 4.1 Kiracı dizini (küresel kontrol düzlemi, minimal)

**Dosyalar:** `cmd/tenant-directory/` (küçük, salt-okur ağır), migrasyon **v190** (`org_cells`), Terraform `modules/global-control-plane`
- [ ] `org → {cell_id, region, residency, status}`; yazma yalnız kayıt/taşıma; okuma kenar KV'ye itilir (60 s TTL).
- [ ] JWT `cell` claim'i; yanlış hücreye gelen istek `421 Misdirected Request` + `X-OpenIDX-Cell`.
- **Kabul:** Kiracı dizini 10 dk kapalı → mevcut kiracılar için sıfır etki (kenar önbelleği); yeni kayıt kuyruğa.

### 4.2 Hücre Terraform modülü

- [ ] `modules/cell`: VPC/VNet, küme, pgcat+PG (Multi-AZ), 3 Redis, NATS, ES, Ziti fabric, Helm release; girdi `cell_id, region, size=s|m|l`.
- [ ] "Küçük hücre" profili (tek AZ, min replika) ilk pazarlar için.
- **Kabul:** `terraform apply` sıfırdan hücre < 90 dk; `make k8s-chaos` canlı yeşil; `make dr-game-day` geçer.

### 4.3 İkinci bölge ve kanarya hücre

- [ ] `eu-1` (mevcut) + `us-1`; `canary-1` küçük hücre, sürüm dalgası: canary → eu-1 → us-1.
- [ ] Release workflow (`.github/workflows/release.yml`) hücre sıralı dağıtım adımı.
- **Kabul:** Bir hücrenin tamamen kapatılması (oyun günü) diğer hücrenin SLO'larını **hiç** etkilemez; ölçüm panoda.

### 4.4 Hücre başına anahtar ve KEK

- [ ] JWT imza anahtarı `kid=<cell>-<n>`; `cmd/rekey` hücre kapsamı; OpenBao/KMS hücre başına.
- **Kabul:** Bir hücrenin imza anahtarının sızması diğer hücrede token doğrulatamaz (test: çapraz hücre JWT → 401).

### 4.5 Ziti kontrol düzlemi koruması (Y4)

- [ ] Controller/router ayrı hostname + L4 LB, kenar HTTP yolundan çıkar; enrollment JWT 15 dk, tek kullanımlık, kiracı başına saatte N (`access-service`).
- **Kabul:** Enrollment floodu (k6, 10k/dk) → controller Raft sağlıklı, kurulu tüneller kesilmez, meşru enrollment < 5 s.

---

## Faz 5 — Sürekli (çeyreklik)

- [ ] DDoS oyun günü (Faz 1.5 senaryoları + yeni vektörler) her çeyrek, her hücrede.
- [ ] `make k8s-chaos` canlı aylık; sonuç `docs/evidence/` altına.
- [ ] SLO incelemesi; hata bütçesi politikası (`docs/PRODUCTION-READINESS.md`'e bölüm).
- [ ] Kenar CIDR/kural drift denetimi (Git ↔ sağlayıcı) haftalık CI.
- [ ] Bu plan ve tasarım belgesi çeyrek sonunda yeniden doğrulanır; kapanan bulgular çizilir.

---

## Bağımlılık grafiği

```mermaid
flowchart LR
  F0[Faz 0 Sızdırmazlık] --> F1[Faz 1 Kenar]
  F0 --> F2[Faz 2 Veri]
  F2 --> F3[Faz 3 Olay + Düzlem]
  F1 --> F4[Faz 4 Hücre]
  F3 --> F4
  F4 --> F5[Faz 5 Sürekli]
  F1 -. oyun günü #1 .-> F3
```

## Başarı tanımı (proje sonu)

| Ölçüt | Hedef | Nasıl ölçülür |
|---|---|---|
| Hücre kaybı blast radius | Yalnız o hücrenin kiracıları | Faz 4.3 oyun günü |
| Verify p99 saldırı altında | < 30 ms, değişmez | Faz 1.5 / 5 k6 |
| Issue meşru başarı saldırı altında | > %99 | aynı |
| PG bağlantısı vs replika | Bağımsız (pgcat) | Faz 2.2 |
| Kill-switch uçtan uca | p95 < 2 s | Faz 3.3 panosu |
| Kiracı sızıntısı | 0, iki RLS modunda | Faz 2.1 testi, `orgscope` |
| Origin'e doğrudan erişim | İmkânsız | Faz 1.2 |
