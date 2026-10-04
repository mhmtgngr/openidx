# Üçüncü Taraf Erişimi ve Geçici Yetkilendirme (PAM/JIT) Çerçevesi

> **Tarih:** 2026-09-28 · **İncelenen sürüm:** `main` @ `38100a6` (v1.38.0 sonrası) · **Dil:** Türkçe
>
> **Bu belge nedir:** Bir tasarım ve plan belgesidir; karar belgesi değildir. Ürün
> kararı gerektiren her nokta §12'de seçenekler ve bir öneriyle sunulur ve
> [ADR 0002](../adr/0002-third-party-access-and-temporary-privilege.md) taslağına
> taşınmıştır. Proje sahibi yazılı onay verene kadar hiçbiri alınmış sayılmaz
> ([AI çalışma anlaşması §1](../AI-WORKING-AGREEMENT.md)).
>
> **Yol haritasındaki yeri:** Uygulama işleri M3 "Wedge depth" kapsamındadır
> ([#970](https://github.com/mhmtgngr/openidx/issues/970),
> [#975](https://github.com/mhmtgngr/openidx/issues/975),
> [#976](https://github.com/mhmtgngr/openidx/issues/976)). M1 "Güvenilir Çekirdek"
> yeni özellik eklemez; bu yüzden yalnızca §9 Faz 0'daki düzeltmeler (var olan
> kontrollerin doğru çalışması) M1 içinde yapılabilir.
>
> **Neyi cevaplar:** (1) Kurum dışından destek verecek kişi ve firmalara, güvenlik
> açığı oluşturmadan, kontrollü erişim nasıl verilir? (2) Kurum içi geçici
> yetkilendirmeler (PAM, JIT yükseltme, kasa alımı, acil durum erişimi) hangi ortak
> çerçeveye oturur?
>
> **Konunun sahibi belgeler:** [VENDOR-ACCESS-ROADMAP.md](../VENDOR-ACCESS-ROADMAP.md)
> (bugünkü durum ve tamamlanan V0), [remote-access-lifecycle-scenarios.md](../remote-access-lifecycle-scenarios.md)
> (roller ve senaryolar), [THREAT-MODEL.md](../THREAT-MODEL.md). Bu belge onları tekrar
> etmez; üzerine kurar ve her öneriyi bugünkü koda bağlar (Ek B).

---

## 1. Yönetici özeti

**Kısa cevap.** Kurum dışı bir destekçiye verilecek güvenli erişim bir *bağlantı*
değil, bir *kimliktir*: sponsorlu, süresi belli, hiçbir varsayılan yetkisi olmayan,
MFA'sı zorunlu, yalnızca adlandırılmış hedeflere, onaylı ve süreli yetkiyle, ağa
değil aracıya (broker) bağlanan, her oturumu kaydedilen ve süresi dolduğunda ya da
sponsoru ayrıldığında kendiliğinden kapanan bir kullanıcı. Kurum içi geçici
yetkilendirme de aynı omurgadan geçer; fark yalnızca kimliğin türü ve
politikanın sıkılığıdır. **Tek çerçeve, iki profil.**

Ürün bu omurganın parçalarının çoğuna sahip (§1.2). Eksik olan, onları dış
kullanıcı için *zorunlu* kılan kimlik türü, iki ayrı onay motorunu birleştiren
tek talep akışı ve "süresi dolunca hiçbir şey ardında kalmasın" kuralının
kapsamındaki boşluklardır (kill switch'in dokunmadığı PAM yetkileri, geçici
bağlantılar, SSH sertifikaları).

### 1.1 Beş ilke

| # | İlke | Ne demek |
|---|---|---|
| P1 | **Bağlantı değil, kimlik** | Her erişim bir kullanıcıya atfedilir. Anonim bir URL, paylaşılan bir "destek" hesabı ya da VPN hesabı erişim yolu değildir. |
| P2 | **Sıfır kalıcı ayrıcalık** | Kalıcı olan yalnızca *uygunluktur* (kim isteyebilir). Fiili ayrıcalık talep edilir, onaylanır, süreli verilir ve süresi dolunca kendiliğinden geri alınır. |
| P3 | **Ağ değil, hedef** | Verilen şey bir sunucu, bir uygulama ya da bir kimlik bilgisi için erişimdir; bir ağ segmenti değil. Hedefe hiçbir port dışarı açılmadan, overlay üzerinden ve aracı aracılığıyla ulaşılır. |
| P4 | **Aracılı, kayıtlı, izlenebilir oturum** | Kimlik bilgisi kullanıcıya hiç gösterilmez; oturum kaydedilir; sponsor izleyebilir ve sonlandırabilir; her karar tek denetim zincirine düşer. |
| P5 | **Sona erme garantisi** | Süre dolar, sponsor ayrılır, inceleme "geri al" der veya kill switch basılır: token, oturum, kasa alımı, PAM yetkisi, canlı oturum ve ağ devresi birlikte kesilir. Bunun her parçası iki yönlü testle kanıtlanır. |

### 1.2 Bugün ne var, ne eksik

| Yapı taşı | Durum | Nerede |
|---|---|---|
| PAM kayıtları (SSH/RDP/VNC), süreli ACL, onay bayrağı, kayıt bayrağı, kasadan kimlik bilgisi enjeksiyonu | Var (Beta) | `internal/access/pam_entries.go`, `internal/access/pam_launch.go` |
| Aracının hedefe overlay üzerinden ulaşması (`PAM_REQUIRE_ZTNA`) | Var, varsayılan `off` | `internal/access/pam_ztna.go` |
| Tarayıcıdan istemcisiz overlay erişimi (BrowZer) | Var; operatör akışı eksik | `internal/access/ziti_browzer.go`, `internal/access/browzer_targets.go` |
| Taze MFA kapısı (`STEPUP_GATE`) | Var, varsayılan `off` | `internal/stepup/stepup.go`, `internal/access/stepup_gate.go` |
| Erişim talebi, onay politikası, otomatik onay, SoD, süreli (JIT) yetki, süre sonu süpürmesi | Var (Beta) | `internal/governance/workflows.go`, `internal/jitgrant/jitgrant.go`, `internal/governance/jit_expiry.go` |
| Kill switch (token, oturum, kasa alımı, JIT, Guacamole oturumu, Ziti) | Var; PAM yetkisi, geçici bağlantı, SSH sertifikası kapsam dışı | `internal/access/kill_switch.go` |
| Oturum kaydı, saklama, yasal tutma; izleme ve sonlandırma | Var; moderasyon yalnızca rota tabanlı Guacamole bağlantılarında | `internal/access/moderated_sessions.go`, `internal/access/guacamole_sessions.go` |
| Davet akışı (e-posta, tek kullanımlık token, 7 gün) | Var; rol/grup verebiliyor, kimlik türü yok | `internal/identity/service.go` (`user_invitations`) |
| Erişim incelemeleri ve zamanlanmış kampanyalar | Var; PAM yetkilerini ve kullanıcı türünü kapsamıyor | `internal/governance/service.go` |
| Geçici erişim bağlantısı (anonim URL) | Var; V0 ile dürüst hâle getirildi, kimliksiz ve MFA'sız kalıyor | `internal/access/temp_access.go` |
| **Dış kullanıcı kimlik türü, sponsor, hesap süresi, tedarikçi kuruluş kaydı** | **Yok** | — |
| **Dış kullanıcı için zorunlu kılınan kontroller (rol tavanı, zorunlu onay/kayıt/overlay, reveal yasağı)** | **Yok** | — |
| **PAM kaydı onayının yönetişim onay motoruna bağlanması** | **Yok** (iki ayrı motor) | `pam_entry_access_requests` ile `access_requests` ayrı |
| **Talep, onay, süre sonu bildirimleri** | **Yok** | yalnızca PAM yetkisi verildiğinde ve geçici bağlantı kullanıldığında bildirim var |

### 1.3 Neyi yapmayacağız

Dış tarafa VPN hesabı; paylaşılan tedarikçi hesabı; parolanın "dışarıdan
söylenmesi"; dış kullanıcıya operatör ya da yönetici rolü; IP izin listesini
tek başına kontrol saymak; aracıyı (Guacamole) genele açmak; süresiz yetki;
kayıtsız ayrıcalıklı oturum; kalıcı yerel yönetici hesabı. Tam liste Ek A'da.

---

## 2. Kapsam ve terimler

| Terim | Tanım |
|---|---|
| **Dış kullanıcı** (external user) | Kuruma ait olmayan, bir tedarikçi kuruluş adına çalışan gerçek kişi. `users` tablosunda `user_type = external`. Konsoldaki karşılığı "Dış kullanıcı". |
| **Tedarikçi kuruluş** (vendor organization) | Dış kullanıcıların bağlı olduğu firma kaydı. Ayrı bir kiracı (tenant) **değildir**; kuruma ait bir kayıttır ve o kurumun RLS sınırı içinde yaşar. |
| **Sponsor** | Dış kullanıcıdan sorumlu kurum içi çalışan. Daveti başlatır, yetki taleplerini onaylar, oturumları izleyebilir, ayrılınca dış kullanıcı askıya alınır. |
| **Hedef** | Bir PAM kaydı (sunucu, veritabanı, uygulama penceresi), yayımlanmış bir uygulama, bir kasa kimlik bilgisi ya da bir Ziti servisi. |
| **Uygunluk** (eligibility) | Bir kişinin bir hedef için *talepte bulunabilmesi*. Kalıcıdır, erişim vermez. |
| **Yetki** (grant) | Bir hedefe belirli eylemlerle (bağlan, göster, düzenle) ve bir bitiş zamanıyla verilmiş erişim. |
| **Yükseltme** (elevation, JIT) | Onaylı bir talebin sonucu olarak süreli verilen rol, grup, uygulama, ağ servisi ya da kasa kimlik bilgisi yetkisi. |
| **Oturum** | Aracı üzerinden açılan tek bir SSH/RDP/VNC/uygulama bağlantısı; kaydedilir, sonlandırılabilir. |
| **Acil durum erişimi** (break-glass) | Onay beklemeden, yüksek sesle denetlenen ve sonradan incelenen ayrıcalıklı erişim. |
| **Dört göz** (four-eyes) | Talep eden ile onaylayanın ayrı kişiler olması; gerekiyorsa ikinci bir onaylayan. |

**Kapsam dışı:** SSH komut politikası ([#976](https://github.com/mhmtgngr/openidx/issues/976);
bu çerçeve ona bir kanca bırakır, tasarımını yapmaz), AI ajanları için
ayrıcalıklı erişim, çok kiracılı MSP konsolu, tedarikçinin kendi IdP'siyle SAML
federasyonu (IdP tarafı bugün yok; §5.7).

---

## 3. Tehdit modeli: dış erişim ve geçici yetki

[THREAT-MODEL.md](../THREAT-MODEL.md) platformun genel tehdit modelidir. Aşağıdaki
tablo yalnızca bu iki soruya özgü tehditleri, bugünkü kontrolü ve kalan açığı
listeler. "Hedef kontrol" sütunu bu belgenin önerdiği şeydir.

| # | Tehdit | Bugünkü kontrol | Açık | Hedef kontrol |
|---|---|---|---|---|
| T1 | Anonim ya da atfedilemeyen erişim: bir URL ya da paylaşılan hesap üzerinden kim ne yaptı bilinmez | Geçici bağlantı V0 ile PAM çekirdeğinden geçiyor, kullanım kaydı tutuluyor | Bağlantının kullanıcısı yok (`pam_entry_sessions.user_id` NULL), MFA yok, denetim olayları yalnızca log satırı | Dış kullanıcı gerçek kimlik olur (§5.1); geçici bağlantı sınırlandırılır ve sonra emekliye ayrılır (§5.8, karar D2) |
| T2 | Yönetilmeyen cihaz: tedarikçinin dizüstüne ajan kurulamaz, duruş bilinmez | BrowZer ile tarayıcı overlay'e katılır; aracı overlay adresinde yayımlanır | Operatör akışı yok; `POSTURE_DEVICE_TRUST_GATE` dış cihaz için anlamsız | Dış kullanıcı için istemci = BrowZer; cihaz güveni yerine oturum sertleştirme ve kayıt (§5.4, §5.6) |
| T3 | Süresi dolmayan erişim: iş bitti, hesap kaldı | JIT süre sonu süpürmesi; `pam_entry_grants.expires_at`; `user_roles.expires_at` | Hesabın kendisinin süresi yok; PAM yetkisi kill switch ve deprovision kapsamında değil | Dış kimlikte zorunlu `account_expires_at`; her yetki ≤ kimlik süresi; süpürme ve kill switch PAM yetkilerini de kapsar (§5.2 I1, I8; §6.8) |
| T4 | Sponsor ayrılır, dış kullanıcı sahipsiz kalır | — | Sponsor kavramı yok | Sponsor zorunlu; sponsorun ayrılışı dış kullanıcıyı askıya alır (§5.3, karar D5) |
| T5 | Tedarikçi tarafında personel değişir; hesap devredilir | — | Tedarikçi kuruluş kaydı yok; e-posta tekilliği dışında kısıt yok | Kişi başı hesap, tedarikçi kuruluşa bağlı; kuruluş kapatılınca tüm hesaplar kapanır (§5.1, §5.3) |
| T6 | Yatay hareket: verilen sunucudan ağa sıçrama | `reach_mode=ziti` ve `PAM_REQUIRE_ZTNA=enforce` ile hedef yalnızca aracıdan ulaşılır | Kapı varsayılan `off`; dış kullanıcı için zorunlu değil | Dış kullanıcı için overlay ve aracı zorunlu; kullanıcı tarayıcısı hiçbir zaman ağda bir adres almaz (§5.2 I5) |
| T7 | Kimlik bilgisinin öğrenilmesi | Kasadan sunucu tarafında enjeksiyon; `allow_reveal` bayrağı | Dış kullanıcı için reveal yasak değil | Dış kullanıcıya reveal hiçbir zaman verilmez (§5.2 I5) |
| T8 | Oturum içinden veri sızdırma: pano, dosya aktarımı, sürücü yönlendirme, yazıcı | Kayıt var | Guacamole parametreleri `disable-copy`, `disable-paste`, `enable-drive`, `enable-sftp`, `disable-download`, `disable-upload`, `enable-printing` hiçbir yerde sabitlenmiyor | Dış kullanıcı için varsayılan kapalı; kayıt başına gerekçeli istisna (§5.6, karar D7) |
| T9 | MFA zayıflığı: tedarikçinin SMS'i ya da hiç MFA'sı yok | Kuruluş MFA politikası ve ek süre (grace) var | Dış kullanıcıya özel politika yok; ilk giriş öncesi kayıt zorunlu değil | Dış kullanıcıda MFA kaydı tamamlanmadan hiçbir yetki etkinleşmez; SMS/e-posta kodu dış kullanıcıya kapalı (§5.5, karar D4) |
| T10 | Onay yorgunluğu, kendi kendine onay, tek kişilik onay | Talep eden onaylayamaz (403); rol/grup adımında talep eden dışlanır | `MinApprovals`, adım sırası ve zaman aşımı saklanır ama uygulanmaz; bildirim yok | Onaylayan ≠ talep eden ≠ sponsor kuralı; N-of-M gerçekten uygulanır ya da alandan kaldırılır (§6.7) |
| T11 | Ayrıcalığın token'da kalması: rol düşürüldü, token hâlâ rolü taşıyor | Süre sonunda `killUserSessions`; erişim token'ı ≤ 1 saat | Rota tabanlı Guacamole bağlantısı ACL'siz | PAM/kasa kararları her zaman anlık yetkiye bakar, token'a değil; rota tabanlı bağlantı PAM kaydına katlanır (§4.2, §9 Faz 0) |
| T12 | SSH sertifikası ve bulut STS kimlik bilgisi geri alınamaz | TTL 10 dk (SSH), 15–720 dk (bulut) | Hedef başına ACL yok, KRL yok, onay yok | Kısa TTL korunur; hedef/principal ACL'si ve onay politikası eklenir (§6.2 T7, T8) |
| T13 | Acil durum erişiminin normalleşmesi | `break_glass_enabled`, taze MFA, `pam.break_glass` olayı | Sonradan inceleme, rotasyon ve sayaç yok | Tanımlı break-glass akışı: gerekçe, otomatik rotasyon, 24 saat içinde inceleme görevi, uyarı (§6.6) |
| T14 | Denetçiye "kim, ne zaman, neye, kimin onayıyla" sorusuna cevap verilememesi | HMAC zincirli birleşik denetim | Geçici bağlantı olayları denetime düşmüyor; yetki-talep bağı yok; dış kullanıcı için kapanış raporu yok | Her yetki `request_id` taşır; dış kullanıcı için kapanış raporu; yeni denetim olayları (§5.9, §7) |

**Değişmeyen varsayımlar.** Aracı (guacd, wasm-ssh) yalnızca access-service'in
ulaşabildiği bir segmentte çalışır (THREAT-MODEL R3); tedarikçiye açılan tek
adres BrowZer/aracı adresidir; hedef sunucularda dış kullanıcıya verilen hesap
en az yetkili yerel hesaptır (komut politikası bir korkuluktur, sandbox değil;
[#976](https://github.com/mhmtgngr/openidx/issues/976)).

---

## 4. Ortak omurga: her erişimin geçtiği zincir

İç ve dış her ayrıcalıklı erişim aynı dokuz halkadan geçer. Bir halkanın
atlanması, bu belgede "açık" olarak listelenen şeydir.

```
kimlik ──► uygunluk ──► talep ──► onay ──► süreli yetki ──► uygulama noktaları
  │                                                              │
  │  (MFA, tür, süre)     (politika)   (dört göz)   (≤ tavan)    │ (OAuth, API, PAM,
  │                                                              │  kasa, Ziti, proxy)
  └────────────── kanıt ◄── sona erme ◄── oturum kontrolü ◄──────┘
                 (denetim,     (süpürme,      (kayıt, izleme,
                  rapor,        kill switch,   sonlandırma,
                  inceleme)     sponsor)       risk kapısı)
```

### 4.1 Halkalar

| Halka | İç kullanıcı | Dış kullanıcı (ek kısıt) |
|---|---|---|
| **Kimlik** | Dizin/SCIM/İK ile gelir; MFA politikası kuruluşa göre | Davetle gelir; sponsor ve süre zorunlu; MFA kaydı etkinleşme ön şartı; rol tavanı `user` |
| **Uygunluk** | Rol/grup üzerinden; onay politikasının `AllowedRoles`/`AllowedGroups` alanları | Yalnızca `external_allowed` işaretli gruplar; varsayılan atama yok |
| **Talep** | Gerekçe zorunlu; süre `Nh`/`Nd`; tavan `ACCESS_REQUEST_MAX_DURATION_HOURS` | Süre ≤ hesap süresi; talep yalnızca kendi tedarikçi kuruluşuna açılmış hedeflere |
| **Onay** | Onay politikası; talep eden onaylayamaz | Sponsor her zaman onay zincirinde; dört göz istenirse ikinci onaylayan |
| **Süreli yetki** | `access_requests.expires_at`; rol/grup/uygulama/ağ/kasa; PAM kaydı yetkisi `expires_at` | Aynı; ayrıca `require_approval`, `record_session`, `reach_mode=ziti` dış kullanıcı için kod tarafından zorlanır |
| **Uygulama noktaları** | §4.2 | §4.2; ayrıca reveal her zaman reddedilir |
| **Oturum kontrolü** | Kayıt bayrağı; izleme/sonlandırma; risk kapısı | Kayıt zorunlu; sponsor bildirimi ve izleme; pano/dosya aktarımı kapalı; boşta zaman aşımı |
| **Sona erme** | Süpürme (5 dk), kill switch, inceleme geri alması, deprovision | Aynı; ayrıca hesap süresi, sponsor ayrılışı, tedarikçi kuruluşun kapanışı |
| **Kanıt** | Birleşik denetim, display = enforcement satırı | Aynı; ayrıca kapanış raporu ve dış erişim inceleme kampanyası |

### 4.2 Uygulama noktaları

"Uygulama noktası", bir erişim kararının fiilen verildiği kod yeridir. Her satır
için bugünkü kapı ve bu çerçevenin eklediği kısıt:

| Nokta | Bugün | Hedef |
|---|---|---|
| Parola/pasaparola ile giriş (`internal/identity`) | Etkin hesap, MFA politikası, risk | Askıdaki ya da süresi dolmuş dış hesap girişte reddedilir; MFA kaydı yoksa yalnızca kayıt sayfası |
| `/oauth/authorize` | Uygulama ataması (`internal/appaccess`), ABAC | ABAC öznesine `user.type`, `user.vendor_org`, `user.sponsor` eklenir |
| API rol kapısı (`internal/access/role_tiers.go`) | Konsol katmanları user…super_admin | Dış kullanıcı için tavan `user`; rol atama API'si dış kullanıcıya üst rol vermeyi reddeder |
| PAM bağlan (`internal/access/pam_launch.go`) | ACL → onay → ZTNA → taze MFA → başlat | Dış kullanıcı için onay, kayıt ve overlay bayrakları kod tarafından `true` kabul edilir; yetkinin `expires_at` değeri hesap süresini aşamaz |
| Kasa reveal (`internal/access/pam_entries.go`) | `allow_reveal` + yetki + taze MFA | Dış kullanıcıya her zaman 403 |
| Rota tabanlı Guacamole bağlan (`internal/access/guacamole.go`) | Onay ve moderatör kapısı; **ACL, taze MFA ve ZTNA yok** | Faz 0'da PAM kaydı yoluna katlanır ya da aynı kapılar eklenir |
| SSH CA (`internal/access/ssh_ca.go`) | Taze MFA; **hedef/principal ACL'si yok** | Sertifika yalnızca yetkili kayıt ve principal için imzalanır |
| Bulut JIT (`internal/access/cloud_jit.go`) | Taze MFA; **onay yok** | `cloud_role` bir talep türü olur; onay politikası uygulanır |
| Ziti dial (`internal/access/ziti_reconciler.go`) | Atamadan üretilen dial politikası | Dış kullanıcı için yalnızca yetkiden üretilen `jit-<request>` niteliği; BrowZer yolu |
| Erişim proxy'si (`internal/access/service.go`) | Atama + bağlam değerlendirici | Aynı; dış kullanıcı için bağlam kuralı (ülke, saat) isteğe bağlı |

---

## 5. Dış (üçüncü taraf) erişim modeli

### 5.1 Kimlik modeli

Dış kullanıcı, kurumun kendi `users` tablosunda yaşayan, `user_type = external`
olan bir kullanıcıdır ve bir **tedarikçi kuruluş** kaydına bağlıdır.

```
organizations (kiracı)
  └── vendor_organizations (tedarikçi kuruluş; kurumun RLS sınırı içinde)
        ├── users (user_type = external, sponsor_user_id, account_expires_at)
        │     ├── group_memberships   (yalnızca external_allowed gruplar)
        │     ├── access_requests     (süreli; onay zincirinde sponsor)
        │     └── pam_entry_grants    (expires_at ≤ account_expires_at; request_id)
        └── pam_entries / applications (bu kuruluşa "açılmış" hedefler; isteğe bağlı liste)
```

**Neden ayrı kiracı değil.** Tedarikçinin ulaşacağı hedefler kurumun kendi
kayıtlarıdır. Tedarikçiyi ayrı bir kiracıya koymak, RLS'nin tam olarak
yasakladığı şeyi (kiracılar arası yetki) gerektirir. v200 göçünün kaydettiği ilke
geçerlidir: iki kuruma hizmet veren bir danışman iki kullanıcı ve iki bağlantıdır.

**Neden `users` üzerinde sütun, ayrı profil tablosu değil.** Dış kullanıcıyı
kısıtlayan her yüklem (rol tavanı, ACL, inceleme doldurma, ABAC öznesi, giriş
reddi) zaten `users` satırını okur. Ayrı bir tabloya taşımak her yüklemde bir
`JOIN` ister ve bu depoda dört kez görülen "join'i unutan sorgu" hata sınıfını
davet eder. Seçenekler ve öneri: karar D1.

**Tedarikçi kuruluş kaydı** (`vendor_organizations`): ad, durum
(`active`/`suspended`/`closed`), iletişim, sözleşme başlangıç/bitiş, izinli
e-posta alan adları, varsayılan hesap süresi (gün), varsayılan sponsor
(isteğe bağlı), not. Kuruluş `closed` olduğunda tüm dış kullanıcıları kapatılır
ve her biri için kill switch çalışır.

### 5.2 Değişmezler

Aşağıdakiler kod tarafından zorlanır, veritabanı kısıtı ya da uygulama yüklemi
olarak; hiçbiri konsol ayarı değildir. Her biri için negatif test şarttır (§10).

| # | Değişmez | Zorlandığı yer |
|---|---|---|
| I1 | Dış kullanıcıda `sponsor_user_id` ve `account_expires_at` NULL olamaz; `account_expires_at` tedarikçi kuruluşun sözleşme bitişini ve kuruluş politikasındaki tavanı aşamaz | CHECK kısıtı + kullanıcı oluşturma/güncelleme + davet kabulü |
| I2 | Dış kullanıcı `user` dışında konsol rolü taşıyamaz; `auditor`, `operator`, `admin`, `super_admin`, `compliance_reader` ve delegasyon alamaz; onay zincirinde onaylayan olamaz | Rol atama API'si, delegasyon API'si, `createApprovalRows`, `requireTier` |
| I3 | Dış kullanıcıya varsayılan atama yoktur: davetle verilen rol/grup listesi yalnızca `external_allowed` gruplar içerebilir; `SHOW_ALL_APPS_WHEN_UNASSIGNED` dış kullanıcıya uygulanmaz | Davet kabulü, grup üyeliği API'si, portal kataloğu |
| I4 | MFA kaydı tamamlanmadan hiçbir yetki *etkin* olmaz: talep açılabilir, onaylanabilir, ama `fulfillRequest` ve PAM bağlan MFA'sız dış kullanıcıyı reddeder | Yönetişim fulfil, PAM bağlan, `/oauth/authorize` |
| I5 | Dış kullanıcının PAM bağlantısında `require_approval`, `record_session` ve `reach_mode=ziti` **kayıt ne derse desin** etkin kabul edilir; `PAM_REQUIRE_ZTNA` küresel kapıdan bağımsız olarak dış kullanıcı için `enforce`; reveal her zaman reddedilir; SSH CA ve bulut JIT yolları dış kullanıcıya kapalıdır | `handlePamConnect`, reveal, `checkPamZTNA`, SSH CA, bulut JIT |
| I6 | Dış kullanıcının her PAM oturumu başlarken sponsora bildirim gider; sponsor oturumu izleyebilir ve sonlandırabilir | Başlatma sonrası bildirim; moderasyon PAM kayıtlarına genişletilir (§6.10) |
| I7 | Dış kullanıcının oturumunda pano, dosya aktarımı, sürücü yönlendirme ve yazdırma kapalıdır; boşta zaman aşımı ve azami oturum süresi kuruluş politikasından gelir; kayıt ayarları bunları açamaz | `pam_launch.go` parametre katmanı (korunan anahtar listesi) |
| I8 | Her yetkinin `expires_at` değeri dış kullanıcının `account_expires_at` değerini aşamaz; hesap süresi dolduğunda kullanıcı `expired` olur ve kill switch çalışır | Talep oluşturma, yetki verme, süpürme |
| I9 | Sponsor devre dışı kalır, silinir ya da tedarikçi kuruluş kapanırsa dış kullanıcı askıya alınır ve kill switch çalışır | Deprovision, kill switch, yaşam döngüsü süpürmesi |
| I10 | Dış kullanıcılar üç ayda bir `external_access` türünde bir inceleme kampanyasına girer; karar verilmeyen kalem `auto_revoke` ile kapanır (kuruluş politikası) | Kampanya çalıştırıcı |
| I11 | Dış kullanıcı yalnızca kendi tedarikçi kuruluşuna açılmış hedefler için talep açabilir (kuruluş "kapalı liste" modunu seçtiyse) | Talep oluşturma |
| I12 | Dış kullanıcı başka bir kullanıcıyı davet edemez, grup oluşturamaz, kendi hesap süresini uzatamaz; uzatma sponsorun açtığı bir taleptir ve onay politikasından geçer | İlgili API'ler |

### 5.3 Yaşam döngüsü

```
            davet         MFA kaydı tamam           süre uzatma (onaylı)
[invited] ───────► [pending_mfa] ───────► [active] ◄──────────────┐
    │ 7 gün               │                  │                    │
    ▼                     ▼                  ├─ sponsor ayrıldı ──► [suspended] ── yeni sponsor (≤7 gün) ─┘
 [expired]            [expired]              ├─ inceleme: geri al ─► [suspended]
                                             ├─ account_expires_at ─► [expired]
                                             └─ tedarikçi kapandı / kill switch ─► [disabled]
```

- Her geçişte `[active]` dışına çıkış = kill switch (token, oturum, kasa alımı,
  JIT, PAM yetkisi, canlı oturum, Ziti). Geri dönüş yalnızca `[suspended] → [active]`
  ve yalnızca yeni bir sponsorla, onaylı bir taleple.
- `[expired]` ve `[disabled]` kalıcıdır; yeniden erişim yeni bir davettir. Denetim
  zinciri eski kimliğe bağlı kalır.
- Süre uzatma bir *talep*tir (`resource_type = account_extension`), sponsor açar,
  onay politikasından geçer, uzatılan süre yine tavanı aşamaz.

### 5.4 Erişim yolu

Dış kullanıcının cihazı yönetilmez; bu yüzden istemci **tarayıcıdır**.

```
Tedarikçi tarayıcısı ──HTTPS──► OpenIDX (giriş + MFA + adım yükseltme)
        │
        │  BrowZer: tarayıcı, OpenIDX'in verdiği JWT ile Ziti denetleyicisine
        │  kimlik doğrular ve yalnızca kendisine açılmış servisi dial eder
        ▼
   PAM aracısı (Guacamole / wasm-ssh), yalnızca overlay adresinde yayımlı
        │  kasadan kimlik bilgisi enjeksiyonu · kayıt · sponsor izleme
        ▼
   Hedef (reach_mode = ziti; hiçbir gelen port yok)
```

| Protokol | Yol | Not |
|---|---|---|
| SSH | PAM kaydı, `wasm-ssh` renderer, `reach_mode=ziti` | Terminal tarayıcıda; komut politikası ([#976](https://github.com/mhmtgngr/openidx/issues/976)) bu yola takılır |
| RDP / VNC | PAM kaydı, Guacamole, `reach_mode=ziti`, `record_session=true` | Pano/dosya/sürücü/yazıcı kapalı (I7) |
| İç web uygulaması | Proxy rotası ya da BrowZer ile erişilen Ziti servisi | `website` türü PAM kaydı **kullanılmaz**; overlay'den geçmez ve kaydedilmez |
| Veritabanı | PAM kaydı üzerinden SSH/RDP atlama sunucusu ya da `internal/access/dbproxy` | Doğrudan istemci bağlantısı dış kullanıcıya açılmaz |

Dağıtımın sorumluluğu değişmez: aracının genel adresi olmadığı, istemcisiz bir
makineden `curl` ile bağlantı hatası alınarak doğrulanır
([CLIENT-ACCESS-DESIGN.md §4b](../CLIENT-ACCESS-DESIGN.md)).

### 5.5 Davet ve ilk giriş

1. **Sponsor** (ya da yönetici, sponsor adına) konsolda "Dış kullanıcı davet et"
   der: tedarikçi kuruluş, e-posta, ad, gerekçe, süre (varsayılan kuruluş
   politikasından, tavanı aşamaz), izinli gruplar (yalnızca `external_allowed`).
   Var olan `user_invitations` yolu kullanılır; davete `user_type`,
   `vendor_org_id`, `sponsor_user_id`, `account_expires_at` eklenir.
2. E-posta alan adı tedarikçi kuruluşun izinli listesindeyse davet gider; değilse
   reddedilir (kuruluş politikası "izinli alan adı zorunlu" ise).
3. Kullanıcı daveti kabul eder, parola/pasaparola belirler ve **MFA kaydı yapmadan
   hiçbir sayfaya geçemez**. Dış kullanıcıya SMS ve e-posta kodu sunulmaz; TOTP,
   WebAuthn/pasaparola ve push sunulur (karar D4).
4. MFA tamamlanınca hesap `[active]` olur; sponsor bilgilendirilir. Bu ana kadar
   onaylanmış yetkiler varsa şimdi etkinleşir (I4).
5. Kullanıcı portalda yalnızca "Ayrıcalıklı Erişimim" ve "Erişim Taleplerim"
   görür; yönetici yüzeyleri görünmez ve API'de reddedilir (I2).

### 5.6 Talep, onay ve kullanım

1. Dış kullanıcı "Ayrıcalıklı Erişimim" içinden hedef ve süre seçer, gerekçe
   yazar (bilet numarası politika gerektiriyorsa zorunlu;
   `internal/governance/ticket` doğrulayıcıları).
2. Talep `resource_type = pam_entry` ile yönetişim onay motoruna düşer (§6.9).
   Onay zincirine sponsor **her zaman** eklenir; kuruluş politikası dört göz
   istiyorsa PAM yöneticisi ya da hedef sahibi ikinci adımdır. Talep eden ve
   sponsor aynı kişi olamaz (dış kullanıcı zaten sponsor olamaz, I2).
3. Onay → `fulfillRequest` bir `pam_entry_grants` satırı yazar: `actions =
   {connect}`, `expires_at = min(talep süresi, account_expires_at)`,
   `request_id` ile talebe bağlı.
4. Kullanım: "Bağlan" → taze MFA → başlatma onayı (mevcut tek kullanımlık
   `pam_entry_access_requests` onayı, sponsorun onayıyla) → oturum. Sponsora
   "oturum başladı" bildirimi; sponsor canlı izleyebilir ve sonlandırabilir.
5. Oturum kaydedilir; risk kapısı (`PAM_SESSION_RISK_GATE`) dış kullanıcı için
   `enforce` önerilir (mesai dışı ve uzun oturum sinyalleri).
6. Süre dolunca yetki süpürülür, canlı oturum sonlandırılır, Ziti devresi kesilir.

"Başlatma onayı" ile "yetki onayı" ayrı iki karardır ve ikisi de kalır: yetki
onayı *bu pencerede bu hedefe erişebilir* der; başlatma onayı *şu an bağlanıyor,
haberim var* der. Düşük riskli hedeflerde kuruluş politikası başlatma onayını
sponsor bildirimiyle değiştirebilir (otomatik onay koşulu).

### 5.7 Tedarikçinin kendi IdP'si (federasyon)

Bugün kuruluş başına OIDC sağlayıcı, e-posta alan adı kuralı ve JIT
provizyon var (`internal/admin/federation.go`, `internal/oauth/social_login.go`);
yukarı akış SAML IdP girişi yok. V1 için öneri: **yerel hesap + davet**.
Federasyon V2'de, şu kısıtlarla: sağlayıcı bir tedarikçi kuruluşa bağlanır,
JIT provizyonla gelen kullanıcı `external` olur ve aynı I1–I12'ye tabidir,
**OpenIDX'in kendi MFA'sı yine zorunludur** ("kapıda MFA": tedarikçinin IdP'sinin
MFA iddiasına güvenilmez), tedarikçi kuruluş kapanınca sağlayıcı devre dışı kalır.
Karar D8.

### 5.8 Geçici erişim bağlantısının kaderi

V0 sonrası bağlantı dürüst: PAM çekirdeğinden geçer, kayıt ve enjeksiyon
uygular, IP listesi CIDR bilir, 7 günle sınırlıdır. Ama kimliksiz ve MFA'sızdır
ve bu, ürünün kendi ilkesiyle (P1) çelişir. Öneri: V1 yayına girene kadar §9
Faz 0 düzeltmeleriyle kalır (denetim olayları, kill switch, oluşturanın
ayrılışında iptal); V1 yayına girince konsolda oluşturma gizlenir ve bir sonraki
minor sürümde uç nokta kaldırılır. Karar D2.

### 5.9 Kapanış raporu ve kanıt

Dış kullanıcı `[expired]`/`[disabled]` olduğunda ya da tedarikçi kuruluş
kapandığında bir kapanış raporu üretilir: kimlik, sponsor, süre, verilen her
yetki (talep, onaylayan, pencere), her oturum (hedef, başlangıç/bitiş, kaynak
adres, kayıt bağlantısı), reddedilen girişimler, break-glass (dış kullanıcı
için hiç olmamalı). Bu yeni bir depo değildir; birleşik denetim üzerinde bir
sorgu ve bir sayfadır ve denetçiye verilen "tedarikçi erişim kanıtı"dır.

---

## 6. Kurum içi geçici yetkilendirme (PAM/JIT) çerçevesi

### 6.1 İlke: kalıcı olan uygunluktur, ayrıcalık değil

Bir yöneticinin sürekli `admin` rolü taşıması, bir DBA'nın sürekli üretim
veritabanı kaydına bağlanabilmesi, bir operatörün kasadan parola görebilmesi
*kalıcı ayrıcalıktır*. Hedef, bunların her birini "isteyebilir" (uygunluk) ile
"şu an, şu süreyle, şu onayla yapabilir" (yetki) olarak ikiye ayırmaktır. Ürün
bunun altyapısını taşıyor; çerçeve, hangi yetki türünün hangi politikayla ve
hangi uygulama noktasında süreli hâle geldiğini tek tabloya indirir.

### 6.2 Yetki türleri

| Tür | Bugün | Süreli mi? | Onay | Süre sonunda | Açık |
|---|---|---|---|---|---|
| T1 Rol (`role`, `privileged_role`, `role_assignment`) | Talep → `user_roles`; doğrudan süreli atama da var (`user_roles.expires_at`) | Evet | Onay politikası | Rol silinir, token'lar iptal | — |
| T2 Grup (`group`) | Talep → `group_memberships` | Evet (talep üzerinde) | Onay politikası | Üyelik silinir, token'lar iptal | Üyelik satırında süre yok; yalnızca talep bilir |
| T3 Uygulama (`application`) | Talep → `user_application_assignments` | Evet | Onay politikası | Atama silinir, Ziti devresi kesilir | — |
| T4 Ağ servisi (`network_service`) | Talep → Ziti niteliği `jit-<request>` | Evet | Onay politikası | Nitelik kaldırılır | — |
| T5 Kasa kimlik bilgisi (`vault_credential`) | Talep → süreli reveal; iade; rotasyon | Evet (zorunlu) | Onay politikası | Rotasyon tetiklenir | — |
| T6 PAM kaydı bağlantısı | `pam_entry_grants` (yönetici verir) + `pam_entry_access_requests` (1 saatlik başlatma onayı) | ACL'de isteğe bağlı | **Ayrı motor**, yalnızca yönetici onaylar | Yetki süresi dolar; **kill switch ve deprovision dokunmaz** | Yönetişimle birleşmeli (§6.9); kill switch kapsamı (§6.8) |
| T7 SSH sertifikası | `POST /pam/connect/ssh`, 10 dk TTL | TTL ile | Yok | TTL | Hedef/principal ACL'si yok, KRL yok |
| T8 Bulut rolü (AWS STS) | `POST /pam/connect/cloud`, 15–720 dk | TTL ile | Yok | TTL (geri alınamaz) | Onay yok; `vault.Use` yetki kontrolü yapmaz |
| T9 Acil durum (break-glass) | Kayıt bayrağı + taze MFA + olay | Oturum süresince | Yok (tanım gereği) | — | Sonradan inceleme, rotasyon, sayaç yok (§6.6) |
| T10 Delegasyon (`admin_delegations`) | Yönetici izinleri, `expires_at`, yalnızca kuruluş kapsamı | Evet | Yönetici verir | Süre dolar | Talep/onay akışı yok; ayrı bir "yükseltme" sayılmalı |

Hedef: T6, T7, T8 ve T10'un da bir *talep* olması (`resource_type` sırasıyla
`pam_entry`, `ssh_principal`, `cloud_role`, `delegation`), aynı onay
politikasından geçmesi, aynı süpürmeyle bitmesi ve `internal/jitgrant` içinde
tek bir `Revoke` dalı olması. Bu paketin var olma nedeni tam olarak bu:
"bir tür burada bağlandıysa her yerde bağlıdır".

### 6.3 Yükseltme politikası

Bugün onay davranışı dört yere dağılmış: `approval_policies` (adımlar, otomatik
onay koşulları), PAM kaydı bayrakları (`require_approval`,
`dual_control_required`, `exclusive_checkout`, `break_glass_enabled`),
`ACCESS_REQUEST_MAX_DURATION_HOURS` (tek küresel tavan) ve kasa sırrının
`require_step_up` alanı. Çerçeve bunları *tek bir politika nesnesinde* toplar;
depolama olarak var olan `approval_policies` genişletilir (yeni tablo değil).

| Alan | Anlamı | Bugün |
|---|---|---|
| `resource_type`, `resource_id` | Hangi hedef(ler) | Var |
| `eligible` (roller/gruplar) | Kim talep edebilir | `auto_approve_conditions.AllowedRoles/Groups` yalnızca otomatik onay için okunuyor; uygunluk kapısı olarak da okunmalı |
| `approval_steps` + `min_approvals` + sıra | Kim onaylar, kaç kişi, hangi sırayla | Adımlar var; `MinApprovals` ve sıra saklanıyor, **uygulanmıyor** (display ≠ enforcement) |
| `four_eyes` | Talep eden ≠ onaylayan (var) ve onaylayan ≠ sponsor/sahip | Kısmen |
| `max_duration`, `default_duration` | Politika başına tavan | Yalnızca küresel tavan |
| `extension` | Uzatma izni, kaç kez, kim onaylar | Yok |
| `cooldown` | Aynı hedefe ardışık talepler arası bekleme | Yok |
| `require_step_up_at_request`, `at_launch` | Taze MFA nerede | Başlatmada `STEPUP_GATE` var; talepte yok |
| `require_ticket` (+ sağlayıcı) | Bilet zorunlu mu, doğrulansın mı | `internal/governance/ticket` var, politikaya bağlı değil |
| `require_recording` | Kayıt zorunlu | Kayıt bayrağı var, politikada yok |
| `schedule` | İzinli saat/gün penceresi | Yok (proxy rotalarında DSL var, taleplerde yok) |
| `max_risk_score` | Risk tavanı | Otomatik onayı engelliyor, talebi değil |
| `on_expiry` | Rolü sil / oturumu bitir / kimlik bilgisini döndür | Türe göre sabit; politikaya taşınır |
| `notify` | Talep eden, onaylayan, sponsor, SIEM | **Yok** |

Bu alanların her biri için kural aynıdır: **ya uygulanır ya alandan kalkar**.
`tools/inertswitch` bunu CI'da yakalar.

### 6.4 Durum makinesi

```
[pending] ─onay(N-of-M)─► [approved] ─fulfil─► [active] ─T-15dk─► [expiring] ─► [expired]
    │                         │                    │                                 
    ├─ red ──► [denied]       ├─ SoD/hata ──► [approved, blocked]                    
    ├─ iptal ─► [cancelled]   │  (tekrar denenir / raporlanır)                       
    └─ zaman aşımı ─► [expired]│                   ├─ kill switch / inceleme / manuel ─► [revoked]
                              └─ planlı başlangıç ─┘   └─ iade (kasa) ─► [returned]
```

- `[approved, blocked]` bugün var: SoD ihlali fulfil'i durdurur ve talep
  `approved` kalır. Bu durum konsolda ayrı gösterilmeli.
- `[expiring]`: süre dolmadan 15 dakika önce talep edene ve sponsora bildirim;
  uzatma politika izin veriyorsa buradan açılır.
- `[revoked]` ile `[expired]` denetimde ayrı olaylardır (`jit_access_expired`
  bugün var; `jit_access_revoked` eklenir, nedeni ve aktörüyle).

### 6.5 Uygulama noktaları ve token sorunu

Rol ve grup yükseltmeleri token'a yazılır (`jitgrant.TokenCarries`). Bu yüzden
süre sonunda `killUserSessions` çağrılır; erişim token'ı en fazla 1 saattir
(THREAT-MODEL R2). Çerçeve iki kural ekler:

1. **Ayrıcalıklı kararlar token'a değil anlık yetkiye bakar.** PAM bağlan, reveal,
   SSH CA ve bulut JIT, karar anında `pam_entry_grants` / `access_requests`
   satırını okur. Token'daki rol bu yollarda yeterli değildir.
2. **Yükseltme süresi token ömründen kısaysa token da kısalır.** 30 dakikalık bir
   yükseltme için verilen erişim token'ı 30 dakikada dolar (`exp = min(token
   ömrü, yükseltme sonu)`); böylece R2 penceresi yükseltmeyi aşmaz.

### 6.6 Acil durum erişimi (break-glass)

Tanımlı bir yol olmalı, "onayı atlamanın adı" değil:

| Kural | Uygulama |
|---|---|
| Yalnızca `break_glass_enabled` kayıtlar ve önceden tanımlı bir uygunluk grubu | Politika `eligible` alanı; dış kullanıcı hiçbir zaman |
| Gerekçe zorunlu, taze MFA zorunlu | Var |
| Oturum kaydı zorunlu; bayrak kapalıysa bile kayıt açılır | Başlatma parametre katmanı |
| Anında uyarı: güvenlik kanalı (bildirim + webhook + SSF olayı) | `internal/webhooks/catalogue.go` içine `pam.break_glass` eklenir |
| Oturum bitince kimlik bilgisi rotasyonu tetiklenir | Rotasyon politikasına "break-glass sonrası" tetikleyicisi |
| 24 saat içinde inceleme görevi: otomatik açılan tek kalemlik `privileged_access` incelemesi | Kampanya çalıştırıcı |
| Sayaç ve eşik: kuruluş başına ayda N break-glass aşılırsa kapı kapanır ve yönetici açar | Kuruluş ayarı |

Karar D9: kuruluşun break-glass'ı tamamen kapatabilmesi.

### 6.7 Dört göz ve görev ayrılığı

- Talep eden onaylayamaz (var, 403). Ek kural: **sponsor ve hedef sahibi de talep
  eden olamaz**; bir kişi hem PAM kaydını düzenleyip hem kendine yetki
  onaylayamaz (`edit` eylemi taşıyan kişi o kayıt için onaylayan olamaz).
- `min_approvals` ve adım sırası uygulanır; uygulanmayacaksa alanlar kaldırılır.
- SoD bugün yalnızca rol yolunda (`checkSoDForRoleGrant`). Grup ve PAM kaydı
  için SoD kuralı tanımlanabilmeli ("ödeme sistemine bağlanan, ödeme onaylayan
  rolü taşıyamaz"); `internal/governance/sod_detective.go` süpürmesi bunları da
  kapsar.
- Yönetici bypass'ı: yönetici, PAM ACL'sini ve başlatma onayını atlar. Bu
  bilinçli bir karardır ama görünür olmalı: yönetici bypass'ıyla açılan her
  oturum `pam.entry_connected` olayında `admin_bypass: true` taşır ve
  incelemede ayrı sayılır. Kuruluş politikası bypass'ı kapatabilir (yönetici
  de talep açar).

### 6.8 Kill switch ve sona erme kapsamı

Bugün kill switch şunları keser: oturum ve token, API anahtarı, kasa alımı ve
kasa yetkisi, JIT yükseltmeleri, Guacamole oturumu, Ziti oturum ve kimliği.
**Dokunmadıkları**: `pam_entry_grants`, `temp_access_links`, `brokered_sessions`
(SSH ve bulut), SSH sertifikaları. Deprovision ve yaşam döngüsü süpürmesi de aynı
boşluğu taşır. Çerçeve kuralı: **kill switch, deprovision, hesap süresi, sponsor
ayrılışı ve tedarikçi kapanışı aynı tek fonksiyonu çağırır** ve o fonksiyon her
yetki türünü keser. SSH sertifikası için kısa TTL (≤ 10 dk) yeterli kabul edilir
ve KRL yayımı isteğe bağlıdır; bulut STS kimlik bilgisi geri alınamaz, bu yüzden
tavan 60 dakikaya indirilir (karar D6).

### 6.9 İki onay motorunun birleştirilmesi

Bugün PAM kaydı için yönetici yetki verir (`/pam/entries/:id/grants`), kullanıcı
başlatma onayı ister (`/pam/entries/:id/request`, 1 saat, yalnızca yönetici
onaylar) ve bu akış yönetişimin onay politikalarından, otomatik onaydan, SoD'den
ve denetim olaylarından habersizdir. Öneri (karar D3): `pam_entry` bir yönetişim
talep türü olur; `fulfillRequest` yetkiyi `pam_entry_grants` içine yazar
(`request_id` ile); PAM tarafındaki başlatma onayı kalır ama onaylayanı
politika belirler (sponsor, hedef sahibi ya da PAM yöneticisi) ve süresi
politikadan gelir. `pam_entry_access_requests` tablosu başlatma onayı olarak
kalır; yetki onayı taşınır. Böylece tek onay ekranı, tek bildirim, tek
display = enforcement satırı olur.

### 6.10 İzleme, moderasyon ve bildirim

- Moderasyon (`guacamole_moderation_sessions`) yalnızca rota tabanlı Guacamole
  bağlantılarında. PAM kayıtlarına genişletilir: `pam_entries.require_moderator`
  ve dış kullanıcı için sponsorun "izle/sonlandır" hakkı.
- Bildirim olayları (talep açıldı, onay bekliyor, onaylandı/reddedildi, yetki
  etkin, süre dolmak üzere, süre doldu, oturum başladı/bitti, break-glass)
  `internal/notifications` üzerinden kullanıcıya ve `internal/webhooks` üzerinden
  SIEM'e gider. Bugün yalnızca "PAM yetkisi verildi" ve "geçici bağlantı
  kullanıldı" var.
- SSF/CAEP: yükseltme başlangıç/bitişinde `token-claims-change`, askıya almada
  `session-revoked` (var olan `internal/common/ssfsignal` üzerinden).

### 6.11 Gözden geçirme

- `privileged_access` inceleme türü bugün yalnızca `admin`/`manager`/`auditor`
  rollerini doldurur. `pam_entry_grants`, süreli olmayan `user_roles` ve aktif
  yükseltmeler de kalem olur.
- Yeni tür `external_access`: her dış kullanıcı için tek kalem (sponsor
  inceler): sürdür / süre kısalt / kapat.
- Her iki kampanyada `auto_revoke` önerilir; karar verilmeyen kalem *kapanır*.

---

## 7. Veri modeli değişiklikleri (öneri)

Göç numaralandırması v206'dan devam eder; her yeni kiracı tablosu `org_id NOT
NULL`, `pol_<tablo>_org_scope` politikası ve FORCE RLS ile gelir (şablon
`internal/migrations/sql_v148.go`; `tools/orgscope` CI'da zorlar). Aşağıdaki
sütun ve tablo adları öneridir; adlandırma kararı D10.

| Nesne | Değişiklik | Neden |
|---|---|---|
| `users` | `user_type VARCHAR(16) NOT NULL DEFAULT 'internal'` (`internal`/`external`/`service`); `vendor_org_id UUID NULL REFERENCES vendor_organizations`; `sponsor_user_id UUID NULL REFERENCES users`; `account_expires_at TIMESTAMPTZ NULL`; `account_status` (`invited`/`pending_mfa`/`active`/`suspended`/`expired`/`disabled`); CHECK: `user_type <> 'external' OR (vendor_org_id IS NOT NULL AND sponsor_user_id IS NOT NULL AND account_expires_at IS NOT NULL)` | I1; yüklemler tek satırdan okunur |
| `vendor_organizations` (yeni) | `id, org_id, name, status, contact_name, contact_email, contract_start, contract_end, allowed_email_domains TEXT[], default_expiry_days INT, closed_list BOOLEAN, notes` | §5.1 |
| `vendor_org_targets` (yeni, isteğe bağlı) | `vendor_org_id, target_type (pam_entry/application/network_service), target_id` | I11 kapalı liste modu |
| `groups` | `external_allowed BOOLEAN NOT NULL DEFAULT false` | I3 |
| `user_invitations` | `user_type, vendor_org_id, sponsor_user_id, account_expires_at` | §5.5 |
| `access_requests` | `resource_type` değerlerine `pam_entry`, `cloud_role`, `ssh_principal`, `delegation`, `account_extension`; `sponsor_user_id` (dış kullanıcı talebinde kopya); `scheduled_start_at` (isteğe bağlı) | §6.2, §5.3 |
| `pam_entry_grants` | `request_id UUID NULL REFERENCES access_requests`; `reason TEXT`; `session_policy JSONB` (pano/dosya/boşta/azami süre; dış kullanıcıda politikadan gelen değer sabitlenir) | §6.9, I7 |
| `pam_entries` | `require_moderator BOOLEAN`; `owner_user_id UUID` (hedef sahibi = onaylayan adayı) | §6.10, §6.7 |
| `approval_policies` | `eligible JSONB`, `min_approvals INT`, `max_duration_hours INT`, `default_duration_hours INT`, `extension JSONB`, `cooldown_minutes INT`, `require_step_up_at_request BOOLEAN`, `require_ticket JSONB`, `require_recording BOOLEAN`, `schedule JSONB`, `max_risk_score INT`, `on_expiry JSONB`, `notify JSONB` | §6.3; her alan uygulanır ya da eklenmez |
| `pam_entry_sessions` | `admin_bypass BOOLEAN`, `sponsor_notified_at`, `moderator_user_id` | §6.7, I6 |
| `temp_access_links` | `require_mfa` ve `notify_email` ölü sütunları düşürülür; `revoked_reason` | §5.8 |
| `org_settings` / kuruluş politikası | `external_access` bloğu: `max_expiry_days`, `default_expiry_days`, `mfa_methods_allowed`, `require_allowed_domain`, `session_policy` varsayılanları, `sponsor_grace_days`, `review_interval_days`, `break_glass_enabled`, `admin_bypass_enabled`, `launch_approval_mode` (`approve`/`notify`) | §5, §6 |
| Denetim olayları (yeni) | `external.invited`, `external.activated`, `external.suspended`, `external.expired`, `external.extended`, `vendor_org.closed`, `jit_access_revoked`, `pam.grant_created` (`request_id` ile), `pam.session_moderated`, `temp_access.*` (bugün yalnızca log satırı) | §5.9, T14 |

---

## 8. API ve konsol değişiklikleri (özet)

| Yüzey | Ekleme | Kısıt |
|---|---|---|
| `POST /api/v1/identity/invitations` | `user_type=external`, `vendor_org_id`, `sponsor_user_id`, `expires_in_days` | Davet eden: yönetici ya da sponsor adayı; gruplar `external_allowed` |
| `GET/POST/PUT /api/v1/identity/vendor-orgs`, `POST …/:id/close` | Tedarikçi kuruluş CRUD ve kapatma | Yönetici; kapatma kill switch'i tetikler ve geri alınamaz |
| `POST /api/v1/identity/users/:id/roles` | Dış kullanıcıya `user` dışı rol → 403 `external_role_cap` | I2 |
| `POST /api/v1/governance/requests` | `resource_type` değerleri `pam_entry`, `cloud_role`, `ssh_principal`, `delegation`, `account_extension`; süre ≤ politika tavanı ve ≤ hesap süresi | §6.2, I8 |
| `GET /api/v1/governance/requests/:id` | `state` alanına `blocked`, `expiring`, `revoked` | §6.4 |
| `POST /api/v1/governance/requests/:id/extend` | Uzatma talebi (politika izin veriyorsa) | §6.3 |
| `POST /api/v1/access/pam/entries/:id/connect` | Dış kullanıcıda zorlanan bayraklar; yanıt `session_policy` ile | I5, I7 |
| `POST /api/v1/access/pam/entries/:id/reveal` | Dış kullanıcıya 403 `external_reveal_forbidden` | I5 |
| `POST /api/v1/access/pam/moderation/*` | PAM kaydı oturumları için de; sponsor izleme/sonlandırma | §6.10 |
| `POST /api/v1/access/users/:id/kill-switch` | `pam_entry_grants`, `temp_access_links`, `brokered_sessions` de kesilir; yanıt sayaçları | §6.8 |
| `GET /api/v1/access/external/:id/closing-report` | Kapanış raporu (JSON ve yazdırılabilir) | §5.9 |
| `POST /api/v1/governance/reviews` | `type=external_access`; `privileged_access` PAM yetkilerini kapsar | §6.11 |
| Konsol: **Dış Kullanıcılar** sayfası | Tedarikçi kuruluşlar, dış kullanıcı kaydı (aktif/süresi dolmak üzere/askıda), sponsor, son kullanım, kapanış raporu | Yönetici; sponsor kendi dış kullanıcılarını görür |
| Konsol: **Erişim Talepleri** | PAM kaydı talepleri aynı kuyrukta; `blocked`/`expiring` rozetleri | Tek onay ekranı |
| Konsol: **PAM Bağlantıları** | Kayıt formunda `owner`, `require_moderator`, oturum politikası; dış kullanıcı için kilitli alanlar gri ve "politika tarafından zorlanır" notlu | display = enforcement |
| Portal: **Ayrıcalıklı Erişimim** | Dış kullanıcı için yalnızca açık hedefler; talep, süre, durum; sponsor adı | I11 |
| Konsol: **Onay Politikaları** | §6.3 alanları; uygulanmayan alan yok | `tools/inertswitch` |

---

## 9. Uygulama planı

Her faz bağımsız olarak yayınlanabilir ve kendi iki yönlü testleri,
display = enforcement satırları ve belge güncellemesiyle "bitmiş" sayılır
([AI çalışma anlaşması §3](../AI-WORKING-AGREEMENT.md)). Efor tahminleri tek
geliştirici + ajan içindir ve onaylandığında GitHub issue'larına taşınır.

### Faz 0 — Var olan kontrollerin doğru çalışması (M1 içinde yapılabilir; düzeltme, özellik değil)

| # | İş | Neden M1'e uyar | Efor |
|---|---|---|---|
| 0.1 | Kill switch, deprovision ve yaşam döngüsü süpürmesi `pam_entry_grants`, `temp_access_links` (oluşturan) ve `brokered_sessions` satırlarını da keser; yanıt sayaçları ve `TestKillSwitchEndsPamGrants` iki yönlü | "Görünen = uygulanan": konsol kill switch'in her şeyi kestiğini söylüyor | 2–3 gün |
| 0.2 | `temp_access.*` olayları birleşik denetime düşer (bugün yalnızca zap satırı) | Denetim zinciri iddiası | 1 gün |
| 0.3 | Onay politikasında `MinApprovals`, adım sırası ve `max_wait_hours` ya uygulanır ya alandan kalkar; `tools/inertswitch` yeşil | Uygulanmayan alan | 2–3 gün |
| 0.4 | Rota tabanlı Guacamole bağlan (`/guacamole/connections/:routeId/connect`) ACL, taze MFA ve ZTNA kapılarından geçer ya da PAM kaydı yoluna yönlendirilir | Ayrıcalıklı yol kapısız | 2–3 gün |
| 0.5 | SSH CA imzalama, principal'ı kullanıcının bir PAM kaydı yetkisiyle eşler; eşleşme yoksa 403 | Kapısız sertifika | 2 gün |
| 0.6 | Bulut JIT tavanı ve `vault.Use` için yetki kontrolü | Kapısız kimlik bilgisi | 1–2 gün |
| 0.7 | `pam.entry_connected` olayına `admin_bypass` alanı | Görünürlük | 0.5 gün |

### Faz 1 — Dış kimlik (M3, #975 V1'in ilk yarısı)

- v206+: `users` sütunları ve CHECK, `vendor_organizations`, `groups.external_allowed`,
  `user_invitations` alanları; RLS belt'leri.
- Değişmezler I1, I2, I3, I4, I8, I9, I12 kodda; her biri için negatif test.
- Davet ve ilk giriş akışı (§5.5); MFA kaydı kapısı; dış kullanıcıya SMS/e-posta
  faktörü sunulmaz.
- Hesap süresi ve sponsor süpürmesi (`internal/governance/jit_expiry.go` içinde
  yeni bir adım ya da yaşam döngüsü süpürmesinde).
- Konsol: Dış Kullanıcılar sayfası (liste, davet, askıya al, süre uzat), Kullanıcı
  formunda tür ve sponsor alanları.
- Kanıt: display = enforcement satırları "dış kullanıcı rol tavanı", "dış kullanıcı
  hesap süresi", "sponsor ayrılışı".
- Efor: 1,5–2 hafta.

### Faz 2 — Tek talep akışı ve zorlanan PAM kontrolleri (M3, #975 V1'in ikinci yarısı)

- `resource_type=pam_entry`; `fulfillRequest` → `pam_entry_grants` (`request_id`);
  `jitgrant.Revoke` dalı; süpürme.
- I5, I6, I7, I11: dış kullanıcı için zorlanan bayraklar, reveal yasağı, oturum
  politikası parametreleri (korunan anahtar listesi), sponsor bildirimi.
- Sponsor onay zincirine otomatik eklenir; `four_eyes` genişletmesi (§6.7).
- Moderasyonun PAM kayıtlarına genişletilmesi; sponsor izleme/sonlandırma.
- Bildirim olayları (§6.10) ve webhook kataloğu.
- Konsol: Erişim Talepleri tek kuyruk; PAM kaydı formunda kilitli alanlar.
- Kanıt: "onaylı pencerede dış kullanıcı yalnızca onaylı hedefe ulaşır; süresi
  dolmuş, onaysız ya da kapsam dışı girişim OAuth, proxy, Ziti dial ve PAM'de
  reddedilir" (#975 kabul ölçütü) kabul testi. Test göç edilmiş Postgres
  üzerinde, birim işinde koşar: governance, OAuth ve proxy kendi route'larıyla
  süreç içinde çalışır; Ziti denetleyicisi ve PAM aracısı yerine taklit
  kullanılır (§10).
- Efor: 2 hafta.

### Faz 3 — İşletilebilirlik (M3, #975 V2)

- BrowZer operatör akışı: "bu PAM kaydını bu tedarikçi kuruluşa bu pencerede
  aç" tek adımı (servis + dial politikası + `#browzer-enabled` niteliği).
- `external_access` inceleme türü ve üç aylık kampanya şablonu; `privileged_access`
  incelemesinin PAM yetkilerini kapsaması.
- Kapanış raporu uç noktası ve sayfası.
- Geçici bağlantı için karar D2'nin uygulanması.
- Üçüncü altın yol rehberi ([#972](https://github.com/mhmtgngr/openidx/issues/972))
  bu akışa karşı yazılır.
- Efor: 1–1,5 hafta.

### Faz 4 — Kurum içi JIT derinliği (M3 sonrası; ayrı bir tracking issue gerekir)

- Yükseltme politikası alanları (§6.3): uygunluk kapısı, politika başına tavan,
  uzatma, cooldown, talepte taze MFA, bilet zorunluluğu, zaman penceresi,
  bildirim.
- Break-glass akışı (§6.6): rotasyon tetikleyicisi, otomatik inceleme kalemi,
  sayaç.
- T7/T8/T10 talep türleri (`ssh_principal`, `cloud_role`, `delegation`).
- Token ömrü = min(token, yükseltme) (§6.5).
- ABAC öznesine `user.type`, `user.vendor_org`; talep değerlendirmesine zaman
  penceresi.
- SoD'nin grup ve PAM kaydına genişlemesi.
- Efor: 3–4 hafta, parçalanabilir.

### Faz 5 — SSH komut politikası ([#976](https://github.com/mhmtgngr/openidx/issues/976))

Bu çerçevenin bıraktığı kanca: politika `pam_entries` ve yetki üzerinden
çözülür; dış kullanıcı için kuruluş varsayılanı `alert` + tehlikeli komutlarda
`require-approval`; onay canlı moderasyon akışını kullanır.

### Bağımlılıklar ve sıra

```
Faz 0 (M1) ──► Faz 1 ──► Faz 2 ──► Faz 3 ──► Faz 5
                              └──► Faz 4 (bağımsız parçalar Faz 2 ile paralel)
```

M1 çıkış ölçütleri #956, #957, #964 ve #965 birleşmeden Faz 1 başlamaz
([#970](https://github.com/mhmtgngr/openidx/issues/970)). Faz 0 kalemleri M1
issue'larına ("display = enforcement", "backend robustness") bağlanabilir;
bunun kararı bakımcınındır.

### Başarı ölçütleri

| Ölçüt | Hedef |
|---|---|
| Dış kullanıcının davetten ilk oturuma süresi (MFA dâhil) | ≤ 15 dakika, VPN ve istemci kurulumu olmadan |
| Kapsam dışı girişimlerin reddedildiği uygulama noktası sayısı | 4/4 (OAuth, proxy, Ziti dial, PAM), CI'da |
| Süre dolduğunda ardında kalan yetki/oturum/devre | 0, süpürme sonrası ölçülür |
| Sponsor ayrılışından dış kullanıcının askıya alınmasına süre | ≤ 5 dakika (süpürme aralığı) |
| Kalıcı `admin`/`operator` rolü taşıyan kullanıcı oranı (pilot kurum) | Düşüş; hedef "eligibility"ye taşınmış |
| Denetçi sorusu "kim, ne zaman, neye, kimin onayıyla" | Tek sorguyla cevaplanır (kapanış raporu) |

---

## 10. Test ve kanıt matrisi

Her satırın bir pozitif (izinli durum çalışır) ve bir negatif (reddedilen durum
reddedilir) testi vardır. "Yer" sütunu, testin koştuğu iş (birim / göç edilmiş
Postgres / servislere karşı entegrasyon).

| Kontrol | Pozitif | Negatif | Yer |
|---|---|---|---|
| I1 zorunlu sponsor ve süre | Sponsorlu, süreli dış kullanıcı oluşur | Sponsorsuz ya da süresiz dış kullanıcı CHECK'e takılır; süre tavanı aşarsa 400 | DB |
| I2 rol tavanı | Dış kullanıcı `user` ile portala girer | `operator` atama 403; delegasyon 403; onay zincirinde yer almaz; `requireTier` reddeder | DB + birim |
| I3 varsayılan atama yok | `external_allowed` gruba eklenir | Sıradan gruba eklenmek 403; davetteki sıradan grup reddedilir | DB |
| I4 MFA ön şartı | MFA kayıtlı dış kullanıcının yetkisi etkinleşir | MFA'sız dış kullanıcıda fulfil bekler, PAM bağlan 403 | Entegrasyon |
| I5 zorlanan bayraklar | Dış kullanıcı `reach_mode=ziti` kayda onayla bağlanır, kayıt açılır | `reach_mode=direct` kayda dış kullanıcı 403 (küresel kapı `off` olsa da); reveal 403; SSH CA 403; bulut JIT 403 | DB |
| I7 oturum politikası | Parametrelerde pano/dosya kapalı | Kayıt ayarı `enable-drive=true` dese de dış kullanıcıda kapalı kalır | Birim |
| I8 yetki ≤ hesap süresi | Hesap süresi içinde yetki verilir | Hesap süresini aşan talep 400; süre dolunca yetki, oturum ve devre gider | DB + entegrasyon |
| I9 sponsor ayrılışı | Yeni sponsorla yeniden etkinleşir | Sponsor devre dışı → dış kullanıcı askıda, girişte 401, canlı oturum sonlanır | Entegrasyon |
| I10 inceleme | Sponsor "sürdür" der, hesap kalır | Karar verilmeyen kalem `auto_revoke` ile kapanır | DB |
| I11 kapalı liste | Açık hedefe talep açılır | Açılmamış hedefe talep 403 | DB |
| §6.9 tek talep akışı | `pam_entry` talebi onaylanır, yetki `request_id` ile yazılır | Onaysız talep yetki yazmaz; SoD ihlali `blocked` | DB |
| §6.7 dört göz | İkinci onaylayan onaylar | Talep eden, sponsor ya da `edit` sahibi onaylayamaz (403); `min_approvals=2` tek onayla açılmaz | DB |
| §6.8 kill switch kapsamı | Yetkili kullanıcı bağlanır | Kill switch sonrası PAM yetkisi, geçici bağlantı, SSH oturumu yok; başka kullanıcı etkilenmez | DB |
| §6.6 break-glass | Uygun kullanıcı gerekçe ve taze MFA ile açar; olay, webhook, inceleme kalemi, rotasyon | Uygun olmayan ya da dış kullanıcı 403; eşik aşımında kapı kapalı | DB + birim |
| §6.5 token ömrü | 30 dk yükseltmede token 30 dk | Süre sonrası token ile PAM bağlan 401/403 | Birim + entegrasyon |
| §5.9 kapanış raporu | Rapor her yetki ve oturumu listeler | Başka kuruluşun dış kullanıcısı için 404 | DB |
| #975 kabul ölçütü | Onaylı pencerede onaylı hedef ulaşılır | Süresi dolmuş/onaysız/kapsam dışı girişim OAuth, proxy, Ziti dial ve PAM'de reddedilir | DB (birim işi `internal/access`: servislerin kendi route'ları süreç içinde; Ziti denetleyicisi ve PAM aracısı taklit) |

Her satır tamamlandığında [display-equals-enforcement.md](../evidence/display-equals-enforcement.md)
tablosuna bir satır eklenir.

---

## 11. Uyum eşlemesi

Bu çerçevenin kontrolleri hangi denetim ölçütlerine kanıt üretir. Ayrıntılı
eşleme, özellik yayına girdiğinde [COMPLIANCE-CONTROL-MAPPING.md](../COMPLIANCE-CONTROL-MAPPING.md)
içine taşınır; burada yalnızca başlıklar.

| Çerçeve | Kontrol | Bu belgedeki karşılığı |
|---|---|---|
| ISO/IEC 27001:2022 | A.5.19–A.5.22 tedarikçi ilişkileri ve izlenmesi | Tedarikçi kuruluş kaydı, sözleşme süresi, `external_access` incelemesi, kapanış raporu |
| | A.5.16 kimlik yönetimi, A.5.18 erişim hakları, A.6.5 ayrılış | Kişi başı dış kimlik, sponsor, hesap süresi, kill switch kapsamı |
| | A.8.2 ayrıcalıklı erişim hakları | Sıfır kalıcı ayrıcalık, yükseltme politikası, dört göz, break-glass incelemesi |
| | A.8.3 bilgi erişim kısıtı, A.8.5 güvenli kimlik doğrulama | Kapalı hedef listesi, MFA ön şartı, taze MFA |
| | A.8.15 loglama, A.8.16 izleme | Birleşik denetim olayları, oturum kaydı, sponsor izleme |
| | A.8.20–A.8.22 ağ güvenliği ve ayrımı | Overlay zorunluluğu, aracı, gelen port yok |
| SOC 2 | CC6.1, CC6.2, CC6.3 | Kimlik ve MFA; davet/askıya alma/kapatma; en az ayrıcalık ve SoD |
| | CC6.6, CC6.7 | Dış sınırdan erişim yalnızca BrowZer/aracı; kimlik bilgisi kullanıcıya geçmez |
| | CC7.2 | Break-glass ve risk kapısı uyarıları |
| KVKK teknik ve idari tedbirler | Erişim yetki matrisi, erişim logları, yetkilerin düzenli kontrolü, sözleşmede güvenlik hükümleri | Yetki = talep + onay kaydı; kapanış raporu; inceleme kampanyası; tedarikçi kuruluş sözleşme alanları |
| BDDK bilgi sistemleri yönetmeliği | Dış hizmet alımında erişim kontrolü ve iz kaydı; ayrıcalıklı erişimin izlenmesi | Aynı kontroller; oturum kaydı ve yasal tutma |
| Bilgi ve İletişim Güvenliği Rehberi | Uzaktan erişim, ayrıcalıklı hesap yönetimi, üçüncü taraf erişimi başlıkları | Aynı kontroller |

Bu tablo bir sertifika iddiası değildir; ürünün ürettiği kanıtı denetçinin
sorusuna bağlar.

---

## 12. Karar gerektiren konular

Her biri için seçenekler, öneri ve gerekçe. Bakımcı onaylayınca
[ADR 0002](../adr/0002-third-party-access-and-temporary-privilege.md) "Accepted"
olur; reddedilen ya da değiştirilen madde ADR'de kaydedilir.

| # | Karar | Seçenekler | Öneri | Gerekçe |
|---|---|---|---|---|
| D1 | Dış kimlik nasıl temsil edilir | (a) `users` üzerinde sütunlar + `vendor_organizations`; (b) ayrı `external_profiles` tablosu; (c) tedarikçi başına ayrı kiracı | **(a)** | Her yüklem `users` okuyor; join'i unutan sorgu hata sınıfı; (c) RLS ile çelişir |
| D2 | Geçici erişim bağlantısının kaderi | (a) Faz 0 düzeltmeleriyle kalır; (b) V1 sonrası oluşturma gizlenir, bir minor sonra uç nokta kalkar; (c) şimdi kaldırılır | **(b)**, V1'e kadar (a) | Kimliksiz yol P1 ile çelişir; ama V1 gelmeden tek düşük frekanslı seçenek |
| D3 | PAM kaydı onayı yönetişim motoruna taşınır mı | (a) iki motor kalır; (b) `pam_entry` talep türü, başlatma onayı PAM'de kalır; (c) yeni birleşik motor | **(b)** | Tek onay ekranı, tek bildirim, tek kanıt satırı; en az yeni kod |
| D4 | Dış kullanıcı MFA politikası | (a) kuruluşun genel politikası; (b) yalnızca WebAuthn/pasaparola; (c) SMS ve e-posta hariç her faktör, WebAuthn önerilir, kuruluş sıkılaştırabilir | **(c)** | (b) tedarikçilerde benimsenmeyi düşürür; SMS/e-posta kimlik avına açık |
| D5 | Sponsor ayrılınca | (a) anında devre dışı; (b) askıya al, 7 gün içinde yeni sponsor atanabilir; (c) sponsorun yöneticisine otomatik devir | **(b)** | Güvenlik duruşu (a) ile aynı (askıda giriş yok), iş sürekliliği daha iyi; (c) sessiz devir yaratır |
| D6 | Süre tavanları | Dış hesap: varsayılan 90 gün, tavan 365; PAM/kasa/rol yükseltmesi: varsayılan 4 saat, politika tavanı; bulut STS: tavan 60 dk | Bu değerler | Sözleşme dönemleriyle uyumlu; geri alınamayan kimlik bilgisi kısa tutulur |
| D7 | Dış oturum sertleştirme varsayılanları | (a) açık, kayıt başına kapatılır; (b) kapalı, kayıt başına gerekçeli açılır | **(b)** | Veri sızdırma yolu varsayılan kapalı olmalı |
| D8 | Tedarikçi IdP federasyonu | (a) V1'de; (b) V2'de, "kapıda MFA" ile | **(b)** | Yukarı akış SAML yok; V1 kapsamını büyütür |
| D9 | Break-glass kuruluş düzeyinde kapatılabilir mi | (a) her zaman açık; (b) kuruluş ayarı, varsayılan açık; (c) varsayılan kapalı | **(b)** | Düzenlemeye tabi kurumlar kapatmak isteyebilir |
| D10 | Adlandırma (konsol, Türkçe ve İngilizce) | "Dış kullanıcı / External user", "Tedarikçi kuruluş / Vendor organization", "Sponsor / Sponsor", "Yükseltme / Elevation", "Acil durum erişimi / Break-glass" | Bu terimler | Konsolun mevcut sözlüğüyle uyumlu ("Ayrıcalıklı Erişim", "JIT Yükseltmeleri") |
| D11 | Yönetici bypass'ı | (a) kalır, görünür; (b) kuruluş ayarıyla kapatılabilir | **(b)**, varsayılan açık | Dört göz isteyen kurumlar kapatır |
| D12 | Faz 0'ın M1 issue'larına bağlanması | (a) #957/#964 altında; (b) M3'e bırakılır | **(a)** | Hepsi "görünen = uygulanan" düzeltmesi |

---

## 13. Riskler ve açık sorular

| Risk | Etki | Azaltım |
|---|---|---|
| Dış kullanıcı için zorlanan bayraklar, var olan kayıtlarda `reach_mode=direct` ise tedarikçi bağlanamaz | İlk pilotta "neden bağlanmıyor" | Konsol Connect'i kapatır ve nedenini söyler (`require_ztna` deseni); kayıt sihirbazı dış kullanıcıya açılan kaydı `ziti` yapar |
| BrowZer OpenZiti'nin bileşeni; burada test edilmiyor | Tedarikçi yolu CI'da uçtan uca kanıtlanamaz | Faz 3'te kind üzerinde BrowZer'lı bir duman testi; olmazsa maturity "Beta" kalır ve belge bunu söyler |
| Onay motoru birleşmesi var olan PAM talep akışını değiştirir | Mevcut kurulumda kırılma | Eski uç noktalar bir sürüm boyunca yeni motora yönlendirir; CHANGELOG'da yükseltme notu |
| Sponsor kavramı İK verisiyle (`manager_id`) karışabilir | Yanlış onaylayan | Sponsor ayrı sütun; İK senkronu dış kullanıcıya dokunmaz (`source` kontrolü) |
| E-posta tekilliği: aynı tedarikçi çalışanı iki kuruma hizmet veriyorsa | İkinci davet çakışır | v200 ilkesi: kurum başına ayrı kullanıcı; global tekillik kiracı başına tekilliğe dönüştürülür mü, ayrı karar |
| Uzun süreli kayıtlar depolama maliyeti | Operatör | Var olan saklama politikası; dış kullanıcı kayıtları için ayrı saklama sınıfı isteğe bağlı |

Açık sorular: (1) Dış kullanıcıya `auditor` benzeri salt okunur bir rol (dış
denetçi) gerekecek mi? Bu çerçeve hayır der; gerekirse ayrı bir tür (`external_auditor`)
ve ayrı ADR. (2) MSP senaryosunda "tedarikçi" MSP'nin kendisi olduğunda sponsor
kim olur? MSP konsolu kararına bağlı, kapsam dışı. (3) SSH komut politikası
canlı onayı moderasyon akışını mı, yönetişim onayını mı kullanır? #976 tasarımına
bırakılır.

---

## Ek A. Yapılmayacaklar

| Yapılmayacak | Neden | Yerine |
|---|---|---|
| Tedarikçiye VPN hesabı | Ağ verir, hedef değil; kayıtsız; ayrılışta unutulur | PAM kaydı + overlay + BrowZer |
| Paylaşılan "destek" hesabı | Atfedilemez; MFA paylaşılır; kişi ayrılınca hesap kalır | Kişi başı dış kimlik |
| Parolanın tedarikçiye söylenmesi | Kasa varken sızdırılmış kimlik bilgisi | Sunucu tarafı enjeksiyon |
| Dış kullanıcıya `operator`/`admin` | Rol tavanı ihlali; kill switch ve inceleme dışı kalır | Süreli, hedefe özel yetki |
| IP izin listesini tek kontrol saymak | NAT, ev ofisi, mobil; kimlik değil konum | Ek kısıt olarak, tek başına değil |
| Aracıyı (Guacamole) genele açmak | TB5 ihlali; R3 | Yalnızca overlay adresi; `curl` doğrulaması |
| Süresiz yetki, süresiz hesap | P2, P5 ihlali | Zorunlu süre ve süpürme |
| Kayıtsız ayrıcalıklı oturum | Repudiation | Dış kullanıcıda zorlanan kayıt |
| Kalıcı yerel yönetici hesabı hedefte | Yatay hareket | En az yetkili hedef hesabı + rotasyon |
| Anonim URL'yi kalıcı çözüm saymak | P1 ihlali | Kimlik (V1) |
| Uygulanmayan bir anahtar ya da alan göstermek | Bu deponun yinelenen hata sınıfı | Ya uygulanır ya kaldırılır; `tools/inertswitch` |

## Ek B. Kod haritası (2026-09-28)

Bu belgenin dayandığı yerler; satır numaraları bu commit içindir.

| Konu | Yer |
|---|---|
| Geçici erişim bağlantısı: model, kapı, kullanım | `internal/access/temp_access.go` (kapı `tempLinkGate`, kullanım `handleUseTempAccess`); anonim rota kaydı `internal/access/public_surface_test.go`; göçler `internal/migrations/sql_v54.go`, `internal/migrations/sql_v148.go`, `internal/migrations/sql_v188.go` |
| JIT yükseltme: tek tanım, iptal, kimin token'ında | `internal/jitgrant/jitgrant.go` (`Revoke`, `TokenCarries`, `EndAllForUser`, `EndAllForDisabledUsers`) |
| Süre sonu süpürmesi (5 dk, lider) | `internal/governance/jit_expiry.go`; doğrudan süreli rol `internal/identity/role_expiry.go` |
| Erişim talebi, onay satırları, fulfil, SoD | `internal/governance/workflows.go` (`createApprovalRows`, `fulfillRequest`, `checkSoDForRoleGrant`); tipler `internal/governance/approval_chain.go`; otomatik onay `internal/governance/auto_approve.go`; süre tavanı `internal/common/config/config.go` |
| Ağ servisi JIT ve devre kesme kuyruğu | `internal/governance/network_revocation.go`, `internal/access/network_revocation_worker.go` |
| PAM kaydı, ACL, yetki, başlatma onayı | `internal/access/pam_entries.go` (`pamEntryAllowed`), `internal/access/pam_launch.go` (`handlePamConnect`, `checkAndConsumePamApproval`, `launchPamSession`, parametre katmanı), şema `internal/migrations/sql_v81.go` |
| Alım kontrolleri, dual control, break-glass, reveal | `internal/access/pam_checkout_control.go`, `internal/migrations/sql_v105.go` |
| Overlay zorunluluğu | `internal/access/pam_ztna.go` |
| Oturum riski | `internal/access/pam_session_risk.go` |
| Moderasyon, izleme, sonlandırma, kayıt, yasal tutma | `internal/access/moderated_sessions.go`, `internal/access/guacamole_sessions.go`, `internal/access/guacamole_legal_hold.go` |
| Rota tabanlı Guacamole bağlantısı (kapısız yol) | `internal/access/guacamole.go` |
| SSH CA ve bulut JIT | `internal/access/ssh_ca.go`, `internal/access/cloud_jit.go`; kasa `Use` `internal/vault/store.go` |
| Taze MFA | `internal/stepup/stepup.go`, `internal/stepup/window.go`, `internal/access/stepup_gate.go` |
| Kill switch ve yaşam döngüsü | `internal/access/kill_switch.go`, `internal/access/lifecycle_sweep.go`, deprovision `internal/identity/service.go` |
| Kullanıcı modeli, davet | `internal/migrations/sql.go` (`users`, `user_invitations`), `internal/identity/models.go`, `internal/identity/service.go` |
| Kuruluş, üyelik, delegasyon | `internal/organization/service.go`, `internal/migrations/sql_v54.go` (`admin_delegations`), `internal/common/middleware/middleware.go` (`resolveDelegations`) |
| Federasyon ve sosyal giriş | `internal/admin/federation.go`, `internal/oauth/social_login.go`, `internal/oauth/social_policy.go`, `internal/migrations/sql_v200.go` |
| ABAC öznesi ve karar | `internal/abac/vocabulary.go`, `internal/abac/subject.go`, `internal/abac/decide.go`; bağlam kuralları `internal/access/context_evaluator.go`, `internal/access/policy_dsl.go` |
| Denetim, bildirim, webhook, SSF | `internal/access/unified_audit.go`, `internal/access/grant_notify.go`, `internal/webhooks/catalogue.go`, `internal/oauth/ssf_transmitter.go`, `internal/common/ssfsignal` |
| İncelemeler ve kampanyalar | `internal/governance/service.go` (`populateReviewItems`, `RunCampaign`), `internal/admin/attestation.go` |
| Bilet doğrulama | `internal/governance/ticket` |
| Rol katmanları | `internal/access/role_tiers.go`, `web/admin-console/src/lib/roles.ts` |
| Konsol | `web/admin-console/src/App.tsx`, `web/admin-console/src/pages/ziti-network.tsx` (geçici bağlantı bölümü), `web/admin-console/src/pages/my-network.tsx`, `web/admin-console/src/components/my-privileged-access-section.tsx`, `web/admin-console/src/lib/api.ts` |
| Uygulama kapıları | [configuration.md](../docs/deployment/configuration.md#enforcement-gates) |
| Göç kaydı ve şablon | `internal/migrations/loader.go`, `internal/migrations/sql_v205.go` (son), `internal/migrations/sql_v148.go` (RLS şablonu) |
| Kanıt tablosu | [display-equals-enforcement.md](../evidence/display-equals-enforcement.md) |
