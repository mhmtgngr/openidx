# OpenIDX — Proje Analizi ve Yol Haritası Önerisi

> **Tarih:** 2026-09-23 · **İncelenen sürüm:** `main` @ `a2589aa` (v1.36.0)
>
> **Bu belge nedir:** Tarihli bir analiz ve öneri kaydıdır; bir karar belgesi değildir.
> Buradaki öneriler proje sahibi tarafından onaylandıktan sonra kök dizindeki tek
> sayfalık bir `ROADMAP.md` dosyasına ve GitHub Milestones'a taşınmalıdır. Bu belge
> daha sonra güncellenmez; zamanla eskimesi beklenir.
>
> **Nasıl hazırlandı:** Kod, CI, dağıtım ve dokümanlar incelendi. Derleme ve testler
> bu ortamda çalıştırıldı. GitHub verileri (yıldız, issue, PR, indirme, Actions
> sonuçları) 2026-09-23'te okundu. Yöntem ve kanıtlar için Ek A'ya bakın.

---

## 1. Yönetici özeti

OpenIDX, Ocak ile Eylül 2026 arasındaki sekiz ayda tek bir geliştiricinin AI kodlama
ajanlarıyla inşa ettiği bir platform. Kimlik (IAM), yönetişim (IGA), ayrıcalıklı
erişim (PAM) ve sıfır güven ağ erişimini (ZTNA) tek bir kontrol düzleminde
birleştiriyor ve teknik olarak etkileyici. Mühendislik disiplini benzer ölçekteki
projelerin çok üstünde: çok kiracılık veritabanı seviyesinde FORCE RLS ile sağlanıyor,
37 CI kontrol betiği var, sürümler imzalı ve bir tehdit modeli yazılmış.

Ancak projenin başarısını artık kod miktarı belirlemiyor. Analiz dört yapısal açık
gösteriyor:

1. **Güven açığı.** Arayüzde var görünen ama uygulanmayan güvenlik kontrolleri Eylül
   sonuna kadar bulunmaya devam etti: PKCE, scope kısıtlaması ve token introspection
   sahipliği bunlardan bazıları. Temel yetki zorlama bayrakları varsayılan olarak
   kapalı. Pentest veya OpenID conformance gibi bağımsız bir doğrulama hiç yapılmamış.
   Güvenlik bildirim adresi DNS'te var olmayan bir alan adına gidiyor.
2. **Odak açığı.** Dört ürün kategorisi, dört istemci kod tabanı ve 36 haftalık bir
   "küresel ölçek" programı tek bir kişinin omzunda. Gerçek kurulum ise tek bir sanal
   makinede çalışıyor.
3. **Tanım açığı.** Hedef müşteri, iş modeli, kapsam dışı alanlar ve tek bir yol
   haritası yazılı değil. Ürün kararları AI ajanına devredilmiş. Yaklaşık 3,3 MB
   doküman birbiriyle çelişiyor.
4. **Benimsenme açığı.** Projenin 0 yıldızı var ve son sürüm 0 kez indirilmiş. Çalışan
   bir doküman sitesi ya da topluluk kanalı yok. Hızlı başlangıç yalnızca bakımcının
   kendi ortamında çalışacak şekilde yapılandırılmış.

**Önerinin özü:**
- Yeni özellik eklemeyi bir döngü boyunca durdurun ve "Güvenilir Çekirdek" (v2.0 LTS)
  kilometre taşına odaklanın.
- Ürünü tek sayfada tanımlayın ve giriş kapısı olarak **PAM + ZTNA (+SSO)** seçin.
- Kurulumu dışarıdan gelen herkes için 15 dakikaya indirin.
- Küresel ölçek programını gerçek bir talep gelene kadar dondurun.

---

## 2. Mevcut durum — ölçülen değerler

| Alan | Değer |
|---|---|
| Proje yaşı | 8 ay (ilk commit 2026-01-16) |
| Commit | `main` üzerinde 1.978. Eylül'deki 515 birleştirme dışı commit'in 497'si AI ajanı tarafından yazılmış |
| Sürümler | v1.0.0 (2026-05-22) → v1.36.0 (2026-09-18): 4 ayda 65 sürüm, bunların 43'ü Temmuz'da |
| Kullanım sinyali | v1.36.0'ın tüm dosyaları 0 kez indirilmiş. 0 yıldız, 1 fork |
| Go backend | Testler hariç yaklaşık 222 bin satır, ayrıca yaklaşık 173 bin satır test. 41 `internal` paketi, 8 servis, 202 veritabanı göçü |
| Backend doğrulaması | `go build` ve `go vet` temiz. `go test -short` sonucu: 110 paket geçti, 0 başarısız. Toplam 3.997 testin 3.316'sı geçti, 681'i atlandı (çoğu Postgres istiyor). Postgres ile koşulan 6 çekirdek pakette 1.715 test geçti, 0 başarısız. `govulncheck` 0 erişilebilir açık buldu. Çekirdek paketlerde kapsam veritabanısız %6–23, veritabanıyla %31–49 |
| Web konsolu | React 19 ve strict TypeScript. 106 sayfa rotası, yaklaşık 94 bin satır (18,5 bini çeviri). 1.241 birim testi. 50 e2e senaryo dosyasından yalnızca 12'si CI'da koşuyor |
| İstemciler | Flutter (6,5 bin satır Dart), Go ajanı (10,5 bin satır kod + 7,7 bin satır test), Kotlin Android ajanı (3,5 bin satır, **0 test**) |
| CI | 15 workflow (8.472 satır). Go kodu değiştiren bir PR yaklaşık 82 iş çalıştırıyor. 37 kontrol betiği ve 19 Go aracı var |
| `main` üzerinde CI | Go, Frontend, Docker, Helm, CodeQL ve Security Scan yeşil. **Documentation kırmızı**: GitHub Pages kapalı olduğu için yayın adımı her push'ta başarısız oluyor |
| Güvenlik bulguları | Yaklaşık 225 açık CodeQL uyarısı (yüksek önemdeki 40'ı triaj edilmiş). Pentest, üçüncü taraf denetim ve conformance testi yok |
| Dağıtım | Hızlı başlangıç compose dosyası 39 servis çalıştırıyor ve en az 8–10 GB RAM istiyor. Helm chart'ı (35 şablon) var. Terraform (AWS/Azure) hiç uygulanmamış |
| Gerçek kurulum | Tek bir Azure VM üzerinde podman + systemd, bir kurum (`docs/architecture/system-design-review-2026-07-14.md`) |
| Dokümantasyon | 212 Markdown dosyası, toplam yaklaşık 3,3 MB. En büyükleri: `CHANGELOG.md` 712 KB, `docs/PROJECT-READINESS-GUIDE.md` 440 KB, hücre mimarisi planı 344 KB |
| Topluluk ve süreç | 0 açık issue; bugüne kadar açılmış issue sayısı 3. 23 açık PR var: 21'i dependabot'tan ve dependabot yapılandırması kaldırıldığı için sahipsiz kaldı; 1'i üç haftadır yanıt bekleyen bir dış katkı (#881). 464 uzak dal var |

---

## 3. Güçlü yönler (korunmalı)

1. **Birleşik kontrol düzlemi gerçek bir farklılaştırıcı.** Tek bir "kill switch" ile
   token'lar, oturumlar, kasa (vault) ödünç almaları, canlı PAM oturumları ve OpenZiti
   ağ devreleri birlikte kesilebiliyor. Rakip ürünlerde aynı sonuç, birden fazla ürün
   arasında bir entegrasyon projesi gerektiriyor.
2. **Çok kiracılık veritabanı seviyesinde sağlanıyor.** Bunun için üç mekanizma var:
   - FORCE RLS,
   - her bağlantıya kiracı bilgisinin damgalanması,
   - `tools/orgscope` CI denetimi.

   v200 itibarıyla kiracıya ait tüm tablolar bu kapsamda. RLS'i atlayamayan bir rolle
   gerçek Postgres üzerinde test ediliyor.
3. **Mühendislik disiplini olağanüstü.** Somut örnekler:
   - Kontrol betiklerinin kendi testleri var; her betiğin gerçekten başarısız
     olabildiği kanıtlanıyor.
   - Kontrol listeleri elle tutulmuyor, workflow dosyalarından türetiliyor.
   - Checksum dosyası ve Helm chart'ı cosign ile anahtarsız imzalanıyor.
   - Bir tehdit modeli ve uyum eşlemesi (SOC 2, ISO 27001, GDPR) var.
   - Derleme, vet ve testler temiz; `govulncheck` erişilebilir açık bulmuyor.
   - Göç zinciri geri alınıp yeniden uygulanabiliyor.
   - Üretimde zayıf sırlarla, joker CORS ile ya da TLS'siz veritabanı/Redis
     bağlantısıyla açılış reddediliyor.
4. **Ürün sahada kullanılıyor.** Canlı bir kurumsal kurulum var ve sahada bulunan
   hatalar CI kapsamına geri besleniyor. Bu kurum, "ilk müşteri" (customer zero)
   olarak son derece değerli.
5. **Türkçe ve İngilizce yerelleştirme tam.** 109 sayfanın tamamı çevrilmiş ve eksik
   bir çeviri anahtarı tip kontrolünde hata veriyor. Ürün yerel pazara hazır.
6. **PAM en güçlü sütun.** Bu, dokümanların kendi değerlendirmesi. Kasa ve şifre
   rotasyonu, Guacamole ve SSH aracılığı, şifreli oturum kaydı, dört göz onayı ve
   canlı izleme mevcut.
7. **Proje dürüst olmayı bir kültür haline getirmiş.** Örnekler:
   - "Görünen = uygulanan" ilkesi yazılı (`docs/evidence/display-equals-enforcement.md`).
   - `SUPPORT.md` gerçekçi.
   - Tehdit modeli artık (kabul edilen) riskleri açıkça yazıyor.
   - CodeQL triajı açık sözlü.

   Güvenin temeli bu kültür. Yapılması gereken, dışa dönük iddiaları (README,
   `SECURITY.md`) aynı hizaya getirmek.

---

## 4. Başlıca riskler (önem sırasına göre)

### R1 — Güvenlik bildirim kanalı çalışmıyor (Kritik, hemen düzeltilmeli)

`SECURITY.md` güvenlik bildirimlerini `security@openidx.io` adresine yönlendiriyor ve
PGP anahtarını `openidx.io` üzerinde gösteriyor. Ancak `openidx.io` alan adı DNS'te yok
(NXDOMAIN):
- Gönderilen bildirimler kimseye ulaşmıyor.
- Alan adını kaydeden herhangi biri gelecekteki güvenlik bildirimlerini teslim
  alabilir.

Aynı dosyada başka sorunlar da var:
- Gerçekte olmayan şeyler vaat ediyor: bir ödül programı (bug bounty), 24 ve 48
  saatlik yanıt süreleri ve bir "güvenlik ekibi".
- Bağlantıları yanlış GitHub hesabını gösteriyor.

### R2 — Güven açığı: görünen ≠ uygulanan (Yüksek)

- **Uzun süre "var" görünen kontroller aslında çalışmıyordu.** Eylül'de birleştirilen
  PR'lar bunu gösteriyor:
  - #902: başarı raporlayan ama hiçbir etkisi olmayan on kontrol.
  - #888: üçüncü taraf ZTNA erişimi tüm kontrolleri atlıyordu.
  - #942: back-channel logout yalnızca ilan ediliyordu, uygulanmıyordu.
  - #947–#949: scope kısıtlaması, scope'ların alt dize olarak eşleştirilmesi,
    introspection'da token sahipliği ve PKCE.
- **Temel yetki zorlama bayrakları varsayılan olarak kapalı**
  (`internal/common/config/config.go:1083-1130`):
  - `access_assignment_enforce=false`: bu durumda uygulama ataması bir yetki değil,
    yalnızca bir katalog kaydı.
  - `abac_enforce=off`
  - `enable_opa_authz=false`

  Buna ek olarak delegasyon kapsamları arayüzde gösteriliyor ama uygulanmıyor.
- **Doğrulama kayıt tabloları boş.** Bu durum hem
  `docs/evidence/display-equals-enforcement.md` hem de `docs/evidence/release-gate.md`
  için geçerli.
- **Bağımsız güvence yok.** Pentest, üçüncü taraf denetim, OpenID Foundation
  conformance testi ve SAML birlikte çalışabilirlik testi hiç yapılmamış.
- **README ise tüm özellikleri ✅ ile listeliyor.** Bir güvenlik ürününde bu, insanların
  ürünü benimsemesinin önündeki bir numaralı engeldir.

### R3 — Odak dağınıklığı ve erken ölçekleme (Yüksek)

- **Kapsam çok geniş.** Proje dört ürün kategorisinde birden oynuyor ve her birinde
  olgun rakipler var:
  - IAM: Keycloak, Authentik, Zitadel
  - IGA: midPoint
  - PAM: Teleport, JumpServer
  - ZTNA: NetBird, Pomerium

  Bunlara dört istemci kod tabanı ekleniyor (React, Flutter, Go, Kotlin). Android iki
  kez kapsanıyor: hem Flutter uygulaması hem de Kotlin ajanı cihaz kaydı, duruş
  kontrolü ve Ziti bağlantısı yapıyor.
- **Ölçek hedefleri talebin çok önünde.** `docs/plans/2026-09-13-global-scale-roadmap.md`
  tek kişiyle yürütülecek 36 haftalık bir hücre mimarisi programı tarif ediyor. Hedefler:
  bölge başına 10 bin kiracı, 50 milyon kullanıcı ve hücre başına saniyede 200 bin
  istek. Oysa gerçek kurulum tek bir VM ve dış kullanıcı yok.
- **Yön değişmiş.** Temmuz'daki tasarım incelemesi "Kubernetes, NATS ve daha fazla
  mikroservis benimsemeyin" diyordu; Eylül'de bu tersine döndü. Getirilen karmaşıklık
  kalıcı, ama gerekçesi olan talep varsayımsal.

### R4 — Ürün tanımsız ve kararlar AI'a devredilmiş (Yüksek)

- **Temel tanımlar yazılı değil:** hedef müşteri, fiyatlama ve iş modeli ("ileride
  open-core olabilir" dışında) ve kapsam dışı alanlar.
- **Ürün kararları açıkça AI ajanına devredilmiş (2026-09-20).** Ajanın bu yetkiyle
  aldığı kararlar:
  - kimlik bağlantılarının kiracı kapsamı,
  - cihaz kayıt kotası,
  - olay yolunun (event bus) zorunlu bir bağımlılık olmaması.
- **Commit'ler de AI'dan geliyor.** Eylül'deki 515 commit'in 497'si AI tarafından
  yazılmış. DCO kontrolü eklendiğinden beri atılan imzaların tamamı AI adına. Oysa DCO
  bir insanın beyanıdır; AI adına atılan imza bu beyanı karşılamaz.
- **Tek bir yol haritası yok.** Şu belgelerin her biri farklı bir "sıradaki iş" listesi
  veriyor:
  - `docs/PROJECT-STATUS.md`
  - `docs/PROJECT-READINESS-GUIDE.md`
  - küresel ölçek yol haritası
  - README
  - operatör rehberi

### R5 — Dışarıdan biri için ilk kurulum bozuk (Yüksek)

- **Konsol başka bir makinede API'ye ulaşamıyor.** Hızlı başlangıç compose dosyası
  konsolu derlerken `VITE_API_URL` değerini bakımcının kendi kurumunun alan adına
  sabitliyor. Aynı değer şu iki yerde de var:
  - `deployments/docker/Dockerfile.admin-console` içindeki varsayılanlar,
  - `web/admin-console/.env.production`.
- **Konsolun geliştirme sunucusu derleniyor.** Compose dosyasında derleme hedefi
  belirtilmediği için Docker, Dockerfile'daki son aşamayı, yani Vite **geliştirme
  sunucusunu** derliyor.
- **Dış ağa açık portlar var ve hafif bir profil yok.** 39 servisin 36 host portu
  0.0.0.0 adresine bağlı; bunların arasında Postgres, Redis, Elasticsearch, OPA ve
  APISIX yönetim portu da var. Hafif bir "lite" profil yok ve CI hiçbir zaman
  `compose up` çalıştırmıyor.
- **Kuruma özgü değerler ürün koduna da sızmış.** Örnekler:
  - `deploy/health-monitor.go:544`
  - `agent/packaging/nfpm.yaml`
  - repodaki tek nginx yapılandırması

  Yaklaşık 142 dosya kuruma özgü bir alan adı ya da yerel bir ev dizini içeriyor.

### R6 — Sürümlerin doğruluğu ve tedarik zinciri (Yüksek)

- **İmzalı bir sürüm, kümede çalışan kodu belirlemiyor.**
  - Helm chart'taki imaj etiketleri varsayılan olarak `latest` ve `IfNotPresent`;
    `appVersion` yalnızca bir etiket olarak kullanılıyor.
  - `values-prod.yaml` hiç yayımlanmamış olan `v0.1.0` sürümünü sabitliyor.
- **arm64 imajlarının içinde amd64 ikilileri var.** 14 Go Dockerfile'ı
  `GOARCH=amd64` değerini sabitliyor, ama arm64 imajları da yayımlanıyor.
- **İmza ve sabitleme eksik.**
  - İmajlar cosign ile imzalanmıyor.
  - 210 action referansının hiçbiri bir commit SHA'sına sabitlenmemiş.
  - `trivy-action@master`, yazma yetkisi olan işlerde çalışıyor.
- **Bağımlılık güncellemeleri durmuş.**
  - Dependabot yapılandırması 2026-09-01'de kaldırıldı ve yerine gelmesi planlanan
    Renovate hiç commit atmadı.
  - CI hâlâ desteği bitmiş Node 20'yi kullanıyor.
  - Sahipsiz kalan dependabot PR'larının bir kısmı artık anlamsız. Örneğin OPA
    kütüphanesi `go.mod`'dan çıkarıldığı halde onu güncelleyen #850 hâlâ açık.
- **Sızan gerçek bir API anahtarı yakalanmaz.** gitleaks istisna listesindeki
  `^oidx_[0-9a-f]{64}$` kalıbı, gerçek API anahtarlarının biçimiyle birebir eşleşiyor.

### R7 — Backend'de doğrulama boşlukları ve yapısal borç (Orta-yüksek)

- **Güvenlik testlerinin bir kısmı CI'da hiç koşmuyor.** Veritabanı gerektiren 19
  güvenlik testi, CI'daki elle yazılmış `-run` desenlerinin hiçbirine uymuyor.
  Bunlar arasında şunlar var: rol veya grup kaldırıldığında token'ların geri alınması,
  yetki yükseltmesinin süresinin dolması ve kimlik bağlantılarında kiracı izolasyonu.
  Testler yerelde geçiyor ama CI onları hiç çalıştırmıyor.
- **RLS atlatma mekanizması zayıf.** Kiracı izolasyonu, `app.bypass_rls` ayarı `on`
  olduğunda devre dışı kalıyor. Uygulama rolüyle çalışan herhangi bir SQL bu ayarı
  açabilir; dolayısıyla tek bir SQL enjeksiyonu tüm izolasyonu aşabilir. Ayrıca süper
  kullanıcı bağlantısı RLS'i sessizce devre dışı bırakıyor ve servisler açılışta bunu
  kontrol etmiyor.
- **Göç (migration) çalıştırıcısı kırılgan.**
  - Hangi göçlerin uygulanacağına kilidi almadan önce karar veriyor.
  - Göçü ve kaydını ayrı işlemlerde yapıyor.
  - Kilidi 15 dakika sonra başka bir süreç çalabiliyor.
  - SQL'i satır satır bölüyor; 53 göç bu yüzden geçici çözüm yorumları taşıyor.
  - İndeksleri eşzamanlı (`CONCURRENTLY`) kuramıyor, bu yüzden büyük tablolarda indeks
    kurulumu yazmaları bloke ediyor.
- **Ölü kod ve gösterişten ibaret yapılar.**
  - Hiçbir binary'nin içe aktarmadığı 13 paket (6.775 satır) var; mevcut
    `deadservice` denetimi bunları göremiyor.
  - Canlı paketlerin içinde ayrıca 419 erişilemeyen fonksiyon var.
  - AI ajan kaydının arkasında bir çalışma zamanı yok.
  - Outbox tablosunu okuyan bir relay var ama tabloya yazan kimse yok.
- **Kod yapısı ağırlaşıyor.**
  - Servisler aynı 222 tablolu şemayı paylaşıyor ve birbirlerinin alan paketlerini
    doğrudan içe aktarıyor; yani bu bir "dağıtık monolit".
  - Tek süreçte çalışan bir "hepsi bir arada" mod yok.
  - En büyük dosyalar: `internal/identity/service.go` 7.264 satır; `access.Service`
    tipinin 523 metodu var.
  - 169 handler dosyasının 121'inde satır içi SQL var ve tipli bir sorgu katmanı yok.
  - Yanıtlar büyük ölçüde tipsiz: 3.295 `gin.H{}` kullanımı.

### R8 — Benimsenmeyi sağlayacak altyapı yok (Orta-yüksek)

- **Doküman sitesi hiç yayımlanmadı.** GitHub Pages kapalı.
- **README'deki topluluk ve destek bağlantıları çalışmıyor.** `docs.openidx.io` yok,
  Discord daveti geçersiz ve `support@` / `hello@openidx.io` adreslerine gönderilen
  e-postalar ulaşmaz.
- **Topluluk mekanizmaları kullanılmıyor.**
  - Issue takibi yapılmıyor; bugüne kadar yalnızca 3 issue açılmış.
  - GitHub Discussions kapalı ve "good first issue" etiketi yok.
  - Tek dış katkı (#881, iOS desteği) üç haftadır yanıt bekliyor.
- **Mobil ve masaüstü istemciler dağıtılamaz durumda.**
  - Flutter uygulama kimliği hâlâ şablonun varsayılanı olan `com.example.openidx_client`
    (`client/android/app/src/main/AndroidManifest.xml`).
  - Android APK debug anahtarıyla imzalı, iOS paketi hiç imzalanmamış.
  - Windows ajanının kod imzalama sertifikası kendinden imzalı.
- **Rakip ürünlerden geçiş aracı yok.** Keycloak, Okta, Entra ya da CyberArk'tan veri
  içe aktarılamıyor.

### R9 — Bakım yükü ve tek kişiye bağımlılık (Orta)

- **Proje tek kişiye bağlı (bus factor = 1).** CODEOWNERS'ta tek bir kişi var.
  19–20 Eylül'de yalnızca iki günde 25 PR birleştirilmiş ve bunları inceleyen ikinci bir
  insan yok.
- **CI dışarıdan katkı yapacak biri için ağır.** Bir katkıcı 31 zorunlu kontrol işiyle
  karşılaşır. Bakımcının kendi ortamına özgü işler, örneğin saha skor tabloları ve
  selfheal, birleştirmeyi engelliyor.
- **Dokümanlar şişiyor.**
  - Her PR `CHANGELOG.md` dosyasına ve 440 KB'lık hazırlık rehberine bir "oturum
    günlüğü" ekliyor. Tek bir sürümün CHANGELOG girdisi 3.600 satıra kadar çıkıyor.
  - `docs/PRODUCTION-READINESS.md` Haziran'dan kalma ve ürünü hâlâ "tek kiracılı" diye
    tanımlıyor.
  - `CONTRIBUTING.md` eskimiş: Go 1.22'yi ve `dev` dalını anlatıyor.
- **Sürümler çok sık ve güvenceleri eksik.**
  - 4 ayda 65 sürüm çıkmış.
  - LTS ve tanımlı bir destek süresi yok.
  - Önceki bir sürümden yükseltme ve yedekten geri yükleme CI'da hiç denenmiyor.

---

## 5. Projeyi tanımlamak: tek sayfalık ürün tanımı (öneri)

"İyi tanımlanmış proje", aşağıdaki soruların her birinin tek cümlelik, yazılı ve bir
insan tarafından onaylanmış bir cevabı olması demektir. Taslak öneri:

| Soru | Önerilen cevap (taslak) |
|---|---|
| **Vizyon** | Kurumlar kimlik, yetki, ayrıcalıklı erişim ve ağ erişimini kendi altyapılarında tek bir kontrol düzleminden yönetsin; bir erişim kararı her katmana saniyeler içinde yansısın. |
| **Çözülen problem** | Orta ölçekli kurumlar dört beş ayrı ürün (IdP, IGA, PAM, VPN/ZTNA) satın alıp bunları birbirine entegre etmek zorunda. Kullanıcı başına lisanslar pahalı. Ürünler arasındaki boşluklar, örneğin işten ayrılan birinin VPN ya da sunucu erişiminin açık kalması, denetim bulgusuna ve güvenlik ihlaline dönüşüyor. |
| **Hedef müşteri (ICP)** | 200 ile 5.000 arası çalışanı olan, düzenlemeye tabi kurumlar: KVKK kapsamındakiler, bankacılıkta BDDK'ya bağlı olanlar, kamuda Bilgi ve İletişim Güvenliği Rehberi'ne uyması gerekenler, ayrıca sağlık, eğitim ve vakıf/STK kuruluşları. Ortak özellikleri: verilerini yurt dışındaki bir bulut IdP'ye çıkaramıyorlar ve BT ekipleri küçük. Bunlara ek olarak bu kurumlara hizmet veren MSP'ler ve entegratörler. |
| **Giriş kapısı (wedge)** | **VPN'siz, onaylı ve kayıtlı ayrıcalıklı erişim ve üçüncü taraf erişimi**, SSO ve MFA dahil. Sunuculara ve iç uygulamalara hiçbir port dışarı açılmadan erişilir; her oturum onaylanır, kaydedilir ve saniyeler içinde geri alınabilir. |
| **Farklılaştırıcı** | Tek kontrol düzlemi ve tek kill switch; veritabanı seviyesinde çok kiracılık; tamamen self-hosted ve Apache-2.0 lisanslı; Türkçe arayüz. |
| **Kapsam dışı (şimdilik)** | Çok bölgeli küresel SaaS; FedRAMP ve FIPS; bir bağlayıcı pazaryeri; WASM ile uygulama sanallaştırma; 50 milyon kullanıcı ölçeği; ayrı bir Kotlin Android ajanı. |
| **Başarı ölçütü (North Star)** | Üretimde OpenIDX çalıştıran bağımsız kurum sayısı. |

### 5.1 Giriş kapısı seçenekleri

| Seçenek | Artıları | Eksileri | Değerlendirme |
|---|---|---|---|
| **A. PAM + ZTNA (+SSO), veri egemenliği gereken orta ölçekli kurumlar** | En güçlü sütun bu. Canlı kurulum zaten bu kombinasyonu kullanıyor. Satın alma tetikleyicisi net: paylaşılan yönetici şifreleri ve tedarikçi VPN'leri gibi denetim bulguları. `docs/VENDOR-ACCESS-ROADMAP.md` hazır | Teleport, CyberArk, BeyondTrust ve yerli PAM üreticileriyle rekabet etmek gerekir | **Önerilen** |
| B. MSP'ler için çok kiracılı platform | RLS altyapısı hazır. MSP başına ücretlendirme gibi bir gelir modeli mümkün | Kiracı başına overlay ayrımı henüz yok. Kanal üzerinden satış yavaş ilerler | A'dan sonraki ikinci aşama |
| C. IdP odaklı (Keycloak veya Okta alternatifi) | Pazar geniş | Pazar çok kalabalık; Keycloak ücretsiz ve olgun. OpenIDX'in conformance eksikleri daha yeni kapandı | Tek başına önerilmez |
| D. IGA odaklı | Sözleşme değerleri yüksek | Satış döngüsü uzun. Çok sayıda bağlayıcı gerekir ve bunlar yok | Önerilmez |

### 5.2 Başarı metrikleri

| Metrik | Bugün | 90 gün hedefi | 12 ay hedefi |
|---|---|---|---|
| Üretimdeki bağımsız kurum sayısı | 1 (bakımcının kendi kurumu) | 3 tasarım ortağı pilotta | 10'dan fazla |
| Dışarıdan biri için ilk girişe kadar geçen süre | Ölçülemiyor; hızlı başlangıç bakımcının ortamına bağlı (R5) | 15 dakika ve 4 GB RAM veya daha az | 10 dakika veya daha az |
| OpenID conformance (hedef profiller) | Hiç çalıştırılmadı | Basic OP ve Config OP geçiyor | Resmî sertifika alındı |
| "Görünen = uygulanan" doğrulaması | Kayıt yok | Her sürümde tüm satırlar doğrulanıyor | Otomatik |
| Açık kritik veya yüksek önemli pentest bulgusu | Pentest yapılmadı | Pentest tamamlandı, 0 açık bulgu | Pentest yılda bir tekrarlanıyor |
| Sürüm başına indirme / GitHub yıldızı | 0 / 0 | Ölçülüyor | Büyüme eğiliminde |
| İnsan maintainer sayısı | 1 | Bir ikinci aday var | 2 |

---

## 6. Başarı için yapılması gerekenler

### 6.1 İlk iki hafta — hızlı kazanımlar (çoğu bir günden kısa sürer)

| # | İş | Neden | Efor |
|---|---|---|---|
| 1 | `SECURITY.md`'yi düzeltin. GitHub Private Vulnerability Reporting'i açın ve çalışan bir iletişim adresi koyun. Ödül programı ve yanıt süresi vaatlerini `SUPPORT.md` ile uyumlu hale getirin. `openidx.io` alan adını ya kaydedin ya da her yerden kaldırın | R1, kritik | S |
| 2 | GitHub Pages'i açın: Settings → Pages → Source: GitHub Actions | Doküman sitesi yayına çıkar ve kırmızı workflow yeşile döner | S |
| 3 | README'deki destek bağlantılarını gerçeğe uydurun. Discord yerine GitHub Discussions'ı kullanın; doküman bağlantısı `mkdocs.yml`'deki github.io adresini göstersin | Ölü bağlantılar güveni zedeler | S |
| 4 | Kuruma özgü değerleri ürün kodundan çıkarın. Konsol varsayılan olarak kendi origin'ini kullansın. Site dosyaları ayrı ve özel bir dağıtım reposuna ya da bir overlay'e taşınsın | R5 | S–M |
| 5 | Bekleyen PR'ları kapatın. Dependabot PR'larını birleştirin ya da kapatın ve Renovate'in gerçekten çalıştığını doğrulayın. #881 ile #824'e yanıt verin. Birleşmiş dalları temizleyin | Depo hijyeni ve katkıcılara saygı | S |
| 6 | Tek sayfalık ürün tanımını (bölüm 5) onaylayın. Kök dizine İngilizce, tek sayfalık bir `ROADMAP.md` koyun ve işleri GitHub Issues ile Milestones'a taşıyın. Diğer plan belgelerini "tarihli kayıt" olarak işaretleyin | R4 | M |
| 7 | Kök dizine bir `CLAUDE.md` / `AGENTS.md` dosyası olarak bir **AI çalışma anlaşması** yazın. Temel kuralları aşağıdaki listede | R2, R4, R9 | S |
| 8 | Küresel ölçek programını resmî olarak dondurun. Planın başına şu notu ekleyin: "Donduruldu; yeniden başlatma tetikleyicisi: çok bölge isteyen ilk müşteri" | R3 | S |

7. işteki AI çalışma anlaşmasının temel kuralları:
- Ürün kararlarını insan verir; ajan yalnızca seçenekleri ve önerisini sunar.
- Güvenlik açısından kritik yollardaki değişiklikler insan onayı gerektirir: oauth,
  identity, RLS ve veritabanı, vault ve kriptografi.
- Bir özellik, hem pozitif hem negatif testi olmadan "bitti" sayılmaz.
- Oturum günlükleri dokümanlara yazılmaz.
- DCO imzasını insan atar.

### 6.2 Kilometre taşı M1 — "Güvenilir Çekirdek" (hedef: v2.0 LTS, yaklaşık 12 hafta)

Bu dönemde yeni bir sütun ya da büyük bir özellik eklenmez. M1, aşağıdaki çıkış
kriterlerinin tamamı sağlandığında biter:

1. **Güvenli varsayılanlar.**
   - Yeni kurulumlarda `access_assignment_enforce` açık olmalı.
   - ABAC observe modundan enforce moduna geçirilmeli.
   - OPA zorlaması açık olmalı.
   - Erişim yakınsama (access convergence) rollout'u tamamlanmalı.
   - Delegasyon kapsamları ya gerçekten uygulanmalı ya da arayüzden kaldırılmalı.
2. **Görünen = uygulanan.** Doğrulama tablosunun her satırı, pozitif ve negatif
   yarısıyla birlikte otomatik bir testle koşar ve sürüm kanıtı olarak kaydedilir.
3. **Standartlara uyum.**
   - OpenID Conformance Suite her gece CI'da koşar ve geçer. Kapsanacak profiller:
     Basic OP, Config OP, RP-Initiated Logout ve Back-Channel Logout.
   - SAML en az iki SP ile birlikte çalışır, örneğin SimpleSAMLphp ve Shibboleth.
   - SCIM uyum testleri geçer.
4. **Bağımsız güvence.**
   - Kapsamı belirlenmiş bir pentest yapılır. Kapsam: OAuth/OIDC, çok kiracılık, PAM
     aracısı ve ajan güncelleme zinciri. Açık kritik ya da yüksek önemli bulgu kalmaz.
   - OWASP ASVS L2 öz değerlendirmesi tamamlanır.
   - OpenSSF Scorecard kurulur ve OpenSSF Best Practices rozeti alınır.
5. **Sürüm doğruluğu.**
   - Chart imajları `appVersion` değerine bağlanır.
   - Dockerfile'lar çok mimarili hale getirilir.
   - İmajlar cosign ile imzalanır ve action'lar commit SHA'sına sabitlenir.
   - Sürüm yayımlandıktan sonra çalışan bir iş, chart'ı iki mimaride çözümleyip ayağa
     kaldırır.
6. **Hafif (lite) kurulum.** Yalnızca Postgres, Redis, çekirdek servisler ve konsoldan
   oluşur:
   - Yayımlanmış imajları çeker.
   - Portları yalnızca 127.0.0.1'e bağlar.
   - 4 GB RAM veya daha azıyla çalışır.
   - CI'da `compose up` yapıp giriş yapan bir duman testi vardır.
7. **İşletim kanıtı.**
   - Yedekten geri yükleme ve önceki bir sürümden yükseltme CI'da test edilir.
   - Runbook bağlantıları olan tek bir alarm seti vardır.
   - Birkaç SLO tanımlanmıştır.
8. **Dürüst iddialar.**
   - README'deki ✅ listesinin yerini bir özellik olgunluk matrisi (GA / Beta /
     Deneysel) alır.
   - README, `SECURITY.md`, `CONTRIBUTING.md` ve `docs/PRODUCTION-READINESS.md`
     güncellenir.
9. **Backend sağlamlığı.**
   - Veritabanı gerektiren tüm testler CI'da koşar. Bunun için ilgili paketler, isim
     desenleriyle seçilmek yerine bütün olarak çalıştırılır.
   - Üretimde süper kullanıcı veya BYPASSRLS rolüyle açılış reddedilir.
   - RLS atlatma, ayarlanabilir bir değişken yerine ayrı bir role ve bağlantı havuzuna
     taşınır.
   - Göç çalıştırıcısı düzeltilir: kilit alındıktan sonra uygulanmış göçler yeniden
     okunur, göç ve kaydı tek işlemde yapılır ve Postgres advisory lock kullanılır.
   - Kullanılmayan 13 paket ve ölü kod silinir. Ölü kod denetimi `go list -deps` ya da
     x/tools `deadcode` üzerine kurulur.

### 6.3 M2 — İlk kurumlar (M1 ile kısmen paralel, 1–3 ay)

- **Tasarım ortağı programı.** 3–5 kurumla çalışın: onlar geri bildirim ve referans
  verir, siz ücretsiz kurulum desteği verirsiniz. Canlı kurulumdan, izin alınarak ve
  anonimleştirilerek bir vaka çalışması hazırlayın.
- **Üç "altın yol" rehberi.** Her biri ekran görüntüleri ve kısa bir video içersin:
  1. SSO ve MFA ile ilk uygulamanın bağlanması.
  2. VPN'siz sunucu erişimi: Ziti, PAM ve kayıtlı SSH/RDP oturumları.
  3. Tedarikçi erişimi: onay, zaman sınırı, kayıt ve erişimin geri alınması.
- **Karşılaştırma sayfaları.** "OpenIDX ile Keycloak + Teleport + NetBird yığınının
  karşılaştırması" gibi dürüst sayfalar hazırlayın; hem özellikleri hem toplam sahip
  olma maliyetini karşılaştırın.
- **Duyuru.** Projeyi M1'in çıkış kriterleri sağlandıktan sonra duyurun, öncesinde
  değil. Uygun kanallar:
  - OpenZiti topluluğu (doğal bir dağıtım kanalı),
  - r/selfhosted,
  - Show HN,
  - Türkiye'deki güvenlik toplulukları ve konferansları,
  - awesome-selfhosted gibi listeler.
- **Katkı hunisi.**
  - Issue formları ve "good first issue" etiketleri ekleyin.
  - Zorunlu kontrolleri açıklayan tek bir tablo hazırlayın.
  - Dış katkılara 72 saat içinde ilk yanıtı verme hedefi koyun.

### 6.4 Sürdürülebilirlik (3–6 ay)

- **Sürüm politikası.**
  - Her ay bir minor sürüm, gerektiğinde patch sürümleri çıkarın.
  - Yılda bir LTS sürümü çıkarın ve 12 ay boyunca güvenlik yaması verin.
  - Semver'in bu projede ne anlama geldiğini yazılı hale getirin.
  - Sürüm notları kullanıcıya dönük ve kısa olsun. Bunun için changelog parçacıkları
    kullanın: her PR tek bir küçük dosya ekler, dosyalar sürüm anında birleştirilir.
    Mevcut dev CHANGELOG ve hazırlık rehberi arşive taşınır.
- **Doküman diyeti.**
  - Oturum günlüğü tarzındaki belgeleri bir arşiv klasörüne taşıyın.
  - Her konu için tek bir güncel belge bırakın.
  - Türkçe belgeleri dil etiketiyle işaretleyin.
- **İş modeli.**
  - Çekirdek Apache-2.0 olarak kalsın. Ücretli katmanlar: kurulum ve destek, uyum
    paketleri (KVKK, BDDK ve Bilgi ve İletişim Güvenliği Rehberi raporları), bir MSP
    konsolu ve LTS.
  - Ticari bir tüzel kişilik kurun ve "OpenIDX" markasını tescil ettirin.
  - Repoyu bir GitHub organizasyonuna taşıyın. `go.mod` zaten modül yolu olarak
    `github.com/openidx/openidx` kullanıyor.
- **İkinci maintainer.**
  - Tercihen güvenlik geçmişi olan birini bulun.
  - Güvenlik açısından kritik yollarda iki kişilik incelemeyi kural haline getirin.

---

## 7. Sonraki geliştirmeler — teknik yol haritası

### Şimdi (2026'nın son çeyreği): güveni artıranlar ve giriş kapısını tamamlayanlar

1. **M1'in çıkış kriterleri** (bölüm 6.2).
2. **Tedarikçi (üçüncü taraf) erişimi, V1.** Kapsamı:
   - tedarikçi kimliği,
   - BrowZer üzerinden ajan kurmadan erişim,
   - zaman sınırlı onay,
   - oturum kaydı.

   `docs/VENDOR-ACCESS-ROADMAP.md`'ye göre yaklaşık 2–3 haftalık bir iş. Giriş kapısının
   "öldürücü özelliği" bu.
3. **SSH komut politikası.** İzin ve engel listeleri; riskli bir komutta oturumu
   durdurma ya da onay isteme. Bu kodda henüz yok ve PAM alıcılarının standart
   beklentisi.
4. **Mobil uygulamayı dağıtılabilir hale getirmek.**
   - Gerçek bir uygulama kimliği verin.
   - Her ABI için sürüm anahtarıyla imzalanmış APK üretin.
   - Flutter sürümünü sabitleyin.
   - `agent-android/` ile Flutter masaüstü kabuğunu dondurun ve Android Enterprise
     provizyonunu "deneysel" olarak işaretleyin. Böylece istemci kod tabanı sayısı
     dörtten iki ya da üçe iner.
5. **Konsol güvenliği.**
   - Giriş akışını paylaşılan HTTP istemcisine taşıyın.
   - Refresh token'ı `localStorage` yerine httpOnly bir çerezde tutun
     (`web/admin-console/src/lib/auth.tsx`).
   - Konsolun nginx yapılandırmasına bir CSP ekleyin.

### Sonra (2027'nin ilk yarısı): benimsenmeyi hızlandıranlar

6. **Geçiş araçları.** Öncelik sırası:
   - Keycloak realm içe aktarma,
   - Okta ve Entra'dan kullanıcı, grup ve uygulama içe aktarma,
   - CyberArk ve KeePass kasalarını içe aktarma.

   Geçiş maliyetini düşürmek, yeni özellik eklemekten daha çok müşteri getirir.
7. **Bağlayıcı kataloğu.**
   - Mevcut giden SCIM altyapısı üzerinde, en çok istenen 10 SaaS için hazır şablonlar
     hazırlayın: Microsoft 365/Entra, Google Workspace, GitHub, Slack, Atlassian, AWS
     IAM Identity Center ve benzerleri.
   - Bunun yanına bir bağlayıcı SDK'sı ekleyin.
8. **Konsolu eksik kalan backend'ler.** Aşağıdaki özelliklerin backend'i hazır; konsol
   ekranları GA sonrasına bırakılmıştı:
   - giden SCIM,
   - İK sisteminden tetiklenen işe giriş, pozisyon değişikliği ve işten çıkış (JML)
     akışları,
   - SSF/CAEP.
9. **Kod olarak yapılandırma.** OpenAPI'den üretilen Go ve TypeScript SDK'ları, bir
   yönetim CLI'ı ve bir Terraform provider.
10. **Uyum paketleri.** `docs/COMPLIANCE-CONTROL-MAPPING.md` üzerine kurulacak hazır
    raporlar:
    - KVKK, BDDK ve Bilgi ve İletişim Güvenliği Rehberi kontrol eşlemeleri,
    - ISO 27001:2022 Ek A kanıtlarının dışa aktarımı.
11. **Yüksek erişilebilirlik (HA) referans mimarisi.**
    - İki ya da üç düğüm: Postgres için Patroni veya CloudNativePG, Redis için Sentinel.
    - Yük devretme test edilmiş olmalı.

    Orta ölçekli bir kurum için küresel hücre mimarisinden çok daha değerli.
12. **Kod yapısının sadeleştirilmesi.**
    - Servisler için ortak bir başlangıç paketi çıkarın. Bugün her servisin
      `main.go` dosyasının yaklaşık %46'sı birbirinin aynısı.
    - gateway-service ile APISIX arasında bir seçim yapın.
    - `internal/access` paketini ZTNA/Ziti, PAM, uzaktan destek ve cihaz duruşu
      paketlerine bölün.
    - Tipli sorgular (ör. sqlc) ve tipli yanıtlar benimseyin; OpenAPI tanımlarını
      bunlardan üretin.
    - İsteğe bağlı olarak tüm servisleri tek süreçte çalıştıran bir "hepsi bir arada"
      mod ekleyin. Bu, hafif kurulumu çok kolaylaştırır.
13. **Farklılaştırıcı bahis: AI ajanları için ayrıcalıklı erişim.** Kapsamı:
    - ajanlara kimlik vermek,
    - RFC 8693 ile yetki devri,
    - JIT onay, oturum kaydı ve kill switch,
    - MCP sunucularına OAuth 2.1 tabanlı yetkilendirme.

    Bu, 2026'nın en hızlı büyüyen kimlik alanı ve OpenIDX'in birleşik kontrol düzlemi
    buna doğal olarak uyuyor. Dar bir kapsamla başlanmalı. Önce mevcut boşluk
    kapanmalı: bugünkü AI ajan kaydının arkasında çalışan bir zorlama yok (R7).

### Daha sonra: talep geldikçe

14. **Küresel hücre mimarisi ve çok bölge.** Çok bölge isteyen ilk müşteri ya da MSP ile
    başlatılır; tasarım belgeleri hazır.
15. **MSP özellikleri.** Kiracı başına overlay ayrımı, bir MSP yönetim konsolu, faturalama
    ve kotalar.
16. **Tehdit tespiti ve modern giriş.**
    - Kimlik tehdidi tespiti ve müdahalesi (ITDR),
    - EDR/MDM duruş entegrasyonları,
    - passkey öncelikli giriş,
    - cihaza bağlı oturumlar.
17. **Standartlar, müşteri çıktıkça.**
    - AB müşterisi olursa OpenID4VP ve AB dijital kimlik cüzdanı; ayrıca OpenID
      Federation.
    - Açık bankacılık müşterisi olursa FAPI 2.0.
18. **Yeni platformlar.** iOS istemcisi (#881 dış katkısı üzerinden) ve bir macOS ajan
    paketi.
19. **Sertifikasyonlar.** SOC 2, ISO 27001 ve FIPS 140-3. Bunlar ticari tüzel kişilik
    kurulduktan ve yönetilen hizmet (SaaS) kararı verildikten sonra gündeme gelir.

---

## 8. Durdurulması veya ertelenmesi önerilenler

| Bırakın veya erteleyin | Yerine |
|---|---|
| 36 haftalık küresel ölçek programı | M1 ve M2; HA referans mimarisi |
| Yeni sütunlar (WASM ile uygulama sanallaştırma, Windows uygulama dağıtımı) | Giriş kapısının derinliği (tedarikçi erişimi, SSH komut politikası) |
| Her PR'da `CHANGELOG.md`'ye, hazırlık rehberine ve plana oturum günlüğü yazmak | Changelog parçacıkları ve issue/PR açıklamaları |
| Günde birden fazla sürüm çıkarmak | Aylık ritim ve LTS |
| Dosya metnini kontrol eden yeni kontrol betikleri | Sonucu kontrol eden testler: `compose up`, yükseltme, geri yükleme, conformance |
| Ayrı Kotlin Android ajanı | Flutter mobil uygulama ve Go motoru |
| Ürün kararlarını AI ajanına devretmek | Ajan seçenekleri ve önerisini sunar; karar kaydını (ADR) insan onaylar |

---

## 9. Çalışma modeli ve yönetişim

- **Karar kaydı (ADR).** Her mimari ya da ürün kararı için tek sayfalık bir kayıt tutulur:
  bağlam, seçenekler, karar ve sonuçlar. Kaydı bir insan onaylar. Küresel ölçek
  tasarımındaki kararlar da bu kalıba taşınıp "askıda" olarak işaretlenebilir.
- **Hazır tanımı (Definition of Ready).** Bir işe başlamadan önce hedef kullanıcı, kabul
  kriterleri ve negatif senaryo yazılı olmalı.
- **Bitti tanımı (Definition of Done).** Bir iş şu koşullarla biter:
  - pozitif ve negatif testler,
  - kritik akışlarda e2e testi,
  - ilgiliyse "görünen = uygulanan" tablosunda bir satır,
  - kısa bir kullanıcı dokümanı,
  - bir changelog parçacığı,
  - güvenlik açısından kritik yollarda insan incelemesi.
- **Haftalık ritim.** Pazartesi günü işler milestone'dan seçilir. Cuma günü bir demo
  yapılır ve kısa bir sürüm notu yazılır. Yol haritası ayda bir, metriklere bakılarak
  gözden geçirilir.
- **AI ajanlarıyla verimli çalışmak.** Ajanlar paralel iş için çok iyidir, ancak:
  - iş tanımını bir insan yazmalı,
  - kabul kriterleri önceden test olarak verilmeli,
  - her PR tek bir konuya odaklanmalı,
  - ajanın "yaptım" iddiası bir testle doğrulanmadan PR birleştirilmemeli.

  Eylül'de görülen "görünen ≠ uygulanan" hata sınıfı tam olarak bu doğrulama
  eksikliğinden doğuyor.
- **Risk kaydı.** Tek kişiye bağımlılık, finansman, rekabet, olası bir güvenlik olayı ve
  OpenZiti'nin kendi yol haritasına bağımlılık izlenir. Kayıt üç ayda bir gözden
  geçirilir.

---

## 10. Proje sahibinin vermesi gereken kararlar

1. **Amaç:** Bu bir kurum içi ürün mü, topluluk odaklı bir açık kaynak projesi mi, yoksa
   ticari bir şirket mi? Başarı metrikleri bu cevaba göre değişir.
2. **Giriş kapısı:** A seçeneği (PAM + ZTNA + SSO) mi, yoksa başka bir seçenek mi?
3. **Küresel ölçek programı:** Dondurulsun mu?
4. **Canlı kurulumun sahibi kurum:** Referans ya da vaka çalışması olarak anılabilir mi?
5. **Sürüm politikası:** Aylık ritim benimsensin ve v2.0 ilk LTS olsun mu?
6. **Dil:** Ana dil İngilizce, Türkçe de çeviri olarak mı kalsın?
7. **Güvenlik iletişimi:** `openidx.io` alan adı alınacak mı, yoksa GitHub tabanlı
   kanallarla mı devam edilecek?

---

## Ek A — Yöntem ve kanıtlar

- **Web konsolu.** Çalıştırılan adımlar ve sonuçları:
  - `npm ci` başarılı.
  - Tip kontrolünde 0 hata.
  - Lint'te 0 hata ve 188 uyarı.
  - 1.241 birim testinin 4'ü yük altında zaman aşımına uğradı; tek başına yeniden
    koşulduklarında geçtiler.
  - `npm run build` başarılı.
- **Go ajanı.** `go build`, `go vet` (Windows hedefi dahil) ve testler geçti.
- **Backend (Go 1.26.8).**
  - `go build ./...` ve `go vet ./...` bulgusuz tamamlandı.
  - `go test -count=1 -short -cover ./...` sonucu: 110 paket geçti, 0 başarısız, 19
    pakette test yok.
  - Tek geçici Postgres 16 ve Redis 7 üzerinde koşulanlar:
    - governance, audit, provisioning, oauth, identity ve access paketleri:
      1.715 test geçti, 0 başarısız.
    - RLS paketi (süper kullanıcı olmayan rolle): 32 test geçti.
    - Göç zinciri v1 → v202 → 0 → v202 gidiş-dönüşü başarılı.
  - `govulncheck` 0 erişilebilir açık buldu.
  - x/tools `deadcode` 419 erişilemeyen fonksiyon buldu.
- **GitHub verileri.** 2026-09-23'te GitHub API'den okundu.
  - v1.36.0 sürümündeki dosyaların indirme sayısı 0.
  - `main` üzerindeki son Documentation çalıştırmalarının hepsi `actions/deploy-pages`
    adımında "Ensure GitHub Pages has been enabled" hatasıyla başarısız.
- **Alan adları ve topluluk kanalları.**
  - `openidx.io` ve `docs.openidx.io` için yapılan DNS sorgusu NXDOMAIN döndü.
  - README'deki Discord daveti Discord API'sinde "Unknown Invite" döndü.
- **İncelenen kod ve yapılandırmalar.**
  - Varsayılan yetki bayrakları: `internal/common/config/config.go:1083-1130`.
  - Chart imaj etiketleri: `deployments/kubernetes/helm/openidx/values.yaml` ve
    `deployments/kubernetes/helm/openidx/values-prod.yaml`.
  - Compose portları ve derleme argümanları: `deployments/docker/docker-compose.yml`.
  - Konsol derlemesi: `deployments/docker/Dockerfile.admin-console`.
  - Güvenlik politikası: `SECURITY.md`.
  - gitleaks istisnaları: `.gitleaks.toml`.
- **Doküman bulguları.** Şu belgeler temel alındı:
  - `docs/plans/2026-09-13-global-scale-roadmap.md`
  - `docs/plans/2026-09-13-global-scale-cell-architecture-plan.md`
  - `docs/PROJECT-READINESS-GUIDE.md`
  - `docs/evidence/final-audit.md`
  - `docs/THREAT-MODEL.md`
- **Bu belgede ölçülmeyenler.**
  - Canlı kurulumun gerçek kullanım verileri.
  - Mobil derlemeler (bu ortamda Flutter ve Android SDK kurulu değil).
  - Docker ile gerçek `compose up` (bu ortamda Docker servisi çalışmıyor). Compose
    bulguları dosya incelemesine ve `docker compose config` çıktısına dayanıyor.
