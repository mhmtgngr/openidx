# OpenIDX İstemci Ekosistemi: Analiz ve Yol Haritası

> **Tarih:** 2026-10-15 · **İncelenen sürüm:** `main` @ `f3ee7c2` (v1.46.0)
>
> **Bu belge nedir:** İstemci tarafının (uç ajanları, telefon uygulaması, tarayıcı,
> komut satırı) ve onları taşıyan ağ ve güvenlik katmanının tarihli bir analizi ve
> yol haritası önerisidir. Üç gözle yazıldı: sistem mimarı, ağ uzmanı ve güvenlik
> uzmanı. Bir karar belgesi değildir. Kararlar proje sahibinindir (§11). Kabul
> edilenler `ROADMAP.md`'ye (§14'teki öneri) ve bir ADR'ye taşınır; taslağı
> [ADR 0003](../adr/0003-client-ecosystem-one-engine-three-shells.md)'tür.
>
> **Nasıl hazırlandı:** `agent/`, `client/`, `agent-android/`, `cmd/openidx-connect/`,
> `internal/access/`, `web/admin-console/`, `deployments/`, `.github/workflows/`
> ve `docs/` okundu. Her bulgu bir dosyaya ve satıra işaret eder. En kritik
> güvenlik bulguları kodda ikinci kez doğrulandı; hangileri doğrulandı Ek A'da
> yazılıdır. Bu ortamda Flutter, Android SDK, Windows ve canlı bir OpenZiti
> denetleyicisi yoktur; derleme ve canlı testler yapılmadı.
>
> **Önceki belgelerle ilişkisi:** [2026-09-23 proje analizi](./2026-09-23-proje-analizi-ve-yol-haritasi.md)
> ürünün bütününü, [2026-10-05 bitirme planı](./2026-10-05-finalize-plan.md) M1'in
> kapanışını ele alır. Bu belge ikisini değiştirmez; istemci ve ağ katmanını
> derinleştirir ve M1 sonrası için bir sıra önerir. M1'in "yeni özellik yok"
> kuralı geçerlidir; §9'da her iş "düzeltme" ya da "özellik" olarak işaretlidir.

---

## İçindekiler

1. [Yönetici özeti](#1-yönetici-özeti)
2. [Sözlük: önce bunu okuyun](#2-sözlük-önce-bunu-okuyun)
3. [Bugünkü ekosistem: harita ve envanter](#3-bugünkü-ekosistem-harita-ve-envanter)
4. [Sistem mimarı gözüyle](#4-sistem-mimarı-gözüyle)
5. [Ağ uzmanı gözüyle](#5-ağ-uzmanı-gözüyle)
6. [Güvenlik uzmanı gözüyle](#6-güvenlik-uzmanı-gözüyle)
7. [Kullanılabilirlik: "kolay anlaşılır" ilkesi](#7-kullanılabilirlik-kolay-anlaşılır-ilkesi)
8. [Hedef ekosistem: 12 ay sonrası](#8-hedef-ekosistem-12-ay-sonrası)
9. [Kesin yol haritası](#9-kesin-yol-haritası)
10. [Durdurulacaklar ve dondurulacaklar](#10-durdurulacaklar-ve-dondurulacaklar)
11. [Proje sahibinin kararları](#11-proje-sahibinin-kararları)
12. [Ölçütler](#12-ölçütler)
13. [Bu haritayı nasıl yürütürsünüz](#13-bu-haritayı-nasıl-yürütürsünüz)
14. [ROADMAP.md için önerilen değişiklik](#14-roadmapmd-için-önerilen-değişiklik)
- [Ek A: Yöntem ve kanıtlar](#ek-a-yöntem-ve-kanıtlar)
- [Ek B: Belge ile kod arasındaki çelişkiler](#ek-b-belge-ile-kod-arasındaki-çelişkiler)

---

## 1. Yönetici özeti

### 1.1 Eylül analizinden bu yana istemcide ne değişti

Üç haftada (v1.37.0 → v1.46.0) istemci tarafı, ürünün en hızlı değişen parçası oldu:

- **Windows ajanının duruş döngüsü ilk kez çalışıyor** (v1.41, #1110/#1114). Sunucu
  ve ajan aynı dili konuşmuyordu: her kontrol "bilinmeyen tür" olarak koşuyor, her
  rapor boş kaydediliyordu. Düzeltmeyle birlikte Windows cihazları için uygulama
  (grace period, askıya alma, `device-trusted`) ilk kez devreye girdi.
- **Cihaz anahtarı ve imzalı raporlar** (v1.41): TPM'de (ya da yazılım anahtar
  deposunda) bir ECDSA anahtarı; anahtarı olan cihazın raporu imzasız kabul
  edilmiyor. İmzalı eklentiler, sertleştirilmiş güncelleyici, `agent.json` ACL'i,
  iptal edilen cihazın her rotada 403 alması aynı sürümde geldi.
- **VPN'siz tünel** (v1.43 → v1.46): Windows MSI ve Linux deb/rpm paketleri
  `ziti-edge-tunnel` v1.18.7'yi SHA-256 pinli taşıyor. Kuruluş ağ politikası
  (always-on, split tunnel, doğrudan erişimi engelle) sürümlü olarak cihaza iniyor
  ve cihaz neyi uygulayabildiğini, neyi uygulayamadığını geri bildiriyor.
- **Cihaz artık overlay'de kendi kimliğiyle var** (v1.42): `dev-<agent_id>`,
  kullanıcının grupları ve uygulamalarıyla; `#device-trusted` yalnız o cihazın
  kendi uyumundan geliyor.
- **Ağ kaynakları** (v1.43): CIDR, host ve DNS adlarıyla tanımlanan, kullanıcılara
  atanan "network" türü uygulamalar; GlobalProtect'ten geçiş rehberi.
- **Tedarikçi çerçevesi** (v1.40 → v1.45): dış kullanıcı, sponsor, engagement,
  vendor portalı, tarayıcıdan uzaktan destek, broker tarafında kayıt ve oynatma.
  Geçici erişim bağlantıları kaldırıldı.
- **Telefon**: push onayı artık telefona ulaşıyor (uygulama açıkken 3 saniyede bir
  sorgu), numara eşleştirme düzeltildi, biyometrik kilit, sırların Keystore ve
  Keychain ile mühürlenmesi.
- **Konsol**: Cihaz ekleme sihirbazı, Agent Fleet'te tünel ve politika rozetleri,
  "Device agent checks" kartı, "Bu kişi şuna neden erişebiliyor?" açıklaması.

### 1.2 Beş ana bulgu

1. **Ürün üç istemciyle üç farklı hikâye anlatıyor.** Windows'ta tam bir ajan var
   (tray, tünel, TPM anahtarı). Linux'ta tray'siz ve paketi imzasız bir ajan var.
   macOS'ta hiçbir şey yok. Telefonda tünelsiz bir yardımcı uygulama, bir de
   askıdaki Kotlin ajanı var. Konsol bile iki kayıt yolunu iki farklı uygulamaya
   yönlendiriyor: "Cihaz ekle" sihirbazı Flutter uygulamasına, Agent Fleet'teki
   Android Enterprise QR'ı Kotlin ajanına.
2. **"İki uç aynı dili konuşmuyor" hata sınıfı tekrar ediyor.** Üç haftada beş
   örnek bulundu: duruş kontrolünün `check_type`/`type` alanı, `tunnel_status`
   biçimi, push onay alanları, mobil `zitiDial` yanıtı, bildirim okundu gövdesi.
   Hepsi tek tek yakalandı; hiçbiri bir sözleşme testiyle önlenmedi. Ajan
   API'sinin OpenAPI tanımı yok ve CI hiçbir ajanı canlı sunucuya kaydetmiyor.
3. **Cihaz kimliği güçlendi, ama kayıt hâlâ en zayıf halka.** Kayıt sırasında cihaz
   hiçbir şey kanıtlamıyor (donanım tanıklığı yok). Parmak iziyle yeniden kayıt,
   satırın sahibini kontrol etmiyor (G1, kodda doğrulandı). Windows'ta cihazın
   overlay özel anahtarı tüm yerel kullanıcılarca okunabiliyor (G2). Derin
   bağlantıdaki sunucu adresi doğrulanmıyor (G6).
4. **Ağ katmanı "split tunnel, Linux root'ta engelleme" seviyesinde.** Tam tünel
   yok, Windows'ta engelleme yok, macOS ve mobilde tünel yok, DNS tasarımı yok,
   denetleyici yüksek erişilebilirliği yalnız Helm'de, filo alarmları tanımlı ama
   yüklü değil. Bunlar bir VPN'in yerine geçecek üründe ilk sorulan şeyler.
5. **Kullanılabilirlik düzeltmelerle ilerliyor, tasarımla değil.** Ajan ve telefon
   uygulaması yalnızca İngilizce (konsol iki dilli). Mağazada uygulama yok, MSI
   kendinden imzalı (SmartScreen uyarısı), Linux paketi imzasız, macOS kurulumu
   yok. Push onayı yalnız uygulama açıkken geliyor. İptal edilen cihaz geri
   alınamıyor; kullanıcı kendi cihazını iptal edemiyor.

### 1.3 Önerinin özü

- **Önce gönderilen doğru olsun (Faz 0).** Kritik güvenlik düzeltmeleri, bir
  sözleşme testi ve dürüst belgeler. Hepsi düzeltme niteliğinde; M1 ile uyumlu.
- **Sonra "tek motor, üç kabuk".** Go motoru (`openidx-agent`) her platformda aynı
  işi yapar. Kabuklar: masaüstünde Go tray (Windows, macOS, Linux), telefonda
  Flutter, komut satırında CLI. Flutter masaüstü kabuğu ve Kotlin ajanı
  dondurulur; ROADMAP bunu zaten söylüyor, bu belge "nasıl"ını ekliyor.
- **Ağ: her adım önce observe.** macOS ajanı ve Windows'ta engelleme, sonra tam
  tünel ve DNS, sonra denetleyici yüksek erişilebilirliği ve tanılama.
- **Mobil: mağaza, sonra arka plan push, en sonda mobil tünel.** Mobil tünel en
  pahalı iş; kararı talebe bağlanır.
- **Her faz için çıkış kriteri, her iş için kanıt tanımı.**

| Faz | Ne zaman | Amaç | Çıkış kriteri (özet) |
|---|---|---|---|
| **0. Gönderilen doğru olsun** | 2026-10-20 → 2026-11-07 | Kritik güvenlik ve sözleşme | G1, G2, G3, G5, G7 kapalı; sözleşme testi CI'da; Ek B'deki çelişkiler giderildi |
| **1. Güven tabanı** | 2026-11-10 → 2026-12-19 (v2.0 LTS ile) | İmza, mağaza, iptal bütünlüğü, dil | #966 kapalı; MSI güvenilir sertifikayla; deb/rpm imzalı; tek iptal yolu; TR/EN istemciler |
| **2. Ağ tamamlama** | 2027 Q1 | macOS, engelleme, tam tünel, HA, tanılama | macOS pkg (notarize); Windows WFP; egress; compose HA; `openidx-agent doctor` |
| **3. Mobil ve ekosistem** | 2027 Q2 | Arka plan push, integrity, MDM/EDR, SDK | iOS/Android arka plan onayı; attested cihaz oranı ölçülüyor; `openidx` CLI |
| **4. Talep geldikçe** | 2027 H2+ | iOS yerel ajan, Windows oturum MFA'sı, kiosk | Her biri bir müşteri talebiyle açılır |

---

## 2. Sözlük: önce bunu okuyun

Belgenin geri kalanı bu terimleri açıklamadan kullanır.

| Terim | Tek cümlede |
|---|---|
| **Ajan (agent)** | Cihazda çalışan OpenIDX programı (`openidx-agent`): cihazı kaydeder, sağlığını raporlar, tüneli çalıştırır. |
| **Kayıt (enrolment)** | Cihazın sunucuya "ben buyum" deyip karşılığında bir kimlik alması; kod, QR, bağlantı ya da kullanıcı girişiyle olur. |
| **Duruş (posture)** | Cihazın sağlık kontrolleri: disk şifreli mi, güvenlik duvarı açık mı, ekran kilidi var mı, yamalar güncel mi. |
| **Katman (Tier)** | Tier 0 yalnız kayıt kapısı; Tier 1 kayıtlı cihaz; Tier 2 duruşu geçen, güvenilir cihaz. |
| **Overlay (üst ağ), OpenZiti** | Uygulamaları internete açmadan, yalnız kayıtlı kimliklerin ulaşabildiği özel ağ. Controller karar verir, router taşır. |
| **Tunneler (`ziti-edge-tunnel`)** | Cihazdaki tüm programların overlay'e çıkmasını sağlayan OpenZiti aracı; VPN istemcisine benzer ama VPN değildir. |
| **Split tunnel / full tunnel** | Yalnız kurum adreslerini tünele almak / tüm trafiği tünele almak. |
| **Block direct** | Kurum ağına tünel dışından gidilmesini cihazda engellemek. |
| **BrowZer** | Hiçbir şey kurmadan, tarayıcının kendisinin overlay'e girmesi ("istemcisiz" erişim). |
| **PAM broker (Guacamole)** | SSH/RDP/VNC oturumlarını tarayıcıda açan, kaydeden ve parolayı kullanıcıdan saklayan aracı. |
| **Kill switch** | Bir kullanıcının token, oturum, kasa, ayrıcalıklı oturum ve ağ erişimini aynı anda kesme. |
| **Cihaz anahtarı (TPM)** | Cihazın donanımında saklanan, dışarı çıkmayan anahtar; raporları imzalar. |
| **Tanıklık (attestation)** | Donanımın "bu anahtar gerçekten bende ve cihaz şu durumda" diye imzalı tanıklık etmesi. Bugün yok. |
| **DPAPI / Keystore / Keychain** | Windows, Android ve iOS'un sır saklama kasaları. |
| **ntfy** | Kendi sunucunuzda çalışan push bildirim servisi; telefon uygulaması push onaylarını buradan alır. |
| **Step-up** | Önemli bir işlemden önce ikinci faktörü yeniden isteme. |
| **observe / enforce** | Bir kontrolün önce yalnız kaydetmesi, sonra gerçekten uygulaması. |
| **Görünen = uygulanan** | Ekranda görünen her şeyin gerçekten uygulanması ilkesi (`docs/evidence/display-equals-enforcement.md`). |

---

## 3. Bugünkü ekosistem: harita ve envanter

### 3.1 Harita

```
 KULLANICI TARAFI                          GİRİŞ KAPILARI                     KONTROL DÜZLEMİ
 ┌──────────────────────────┐             ┌────────────────────┐             ┌──────────────────────┐
 │ Windows PC               │─HTTPS 30 sn─▶│ APISIX / nginx 443 │────────────▶│ access-service       │
 │  ajan (servis) + tray    │             └────────────────────┘             │  kayıt, duruş, tünel │
 │  ziti-edge-tunnel (wintun)│─mTLS 1280──▶┌────────────────────┐◀─reconciler─│  politikası, PAM,    │
 │ Linux PC                 │─TLS 3022───▶│ Ziti controller    │             │  uzaktan destek      │
 │  ajan (servis, tray yok) │             │ + edge router(lar) │             ├──────────────────────┤
 │  ziti-edge-tunnel (nft)  │             └────────────────────┘             │ identity, oauth,     │
 │ macOS: istemci yok       │                                                │ governance, audit    │
 │ Android / iOS            │─HTTPS──────▶ (API)                             └──────────┬───────────┘
 │  Flutter: TOTP, push,    │◀─ntfy sorgu─ (push)                                       │
 │  erişim; tünel yok       │                                                ┌──────────▼───────────┐
 │ Tarayıcı                 │─WSS 3023───▶┌────────────────────┐             │ PostgreSQL (RLS)     │
 │  konsol, portal, vendor  │             │ BrowZer bootstrap  │             │ Redis · Ziti DB      │
 │  portalı, BrowZer        │             └────────────────────┘             └──────────────────────┘
 │ Komut satırı             │─HTTPS──────▶ /pam/connect/ssh (kısa ömürlü SSH sertifikası)
 │  openidx-connect         │
 └──────────────────────────┘
   HEDEFLER: iç web uygulamaları (router `host.v1`), sunucular (Guacamole broker → overlay),
             Windows uygulama sunucuları (app host ajanı)
```

### 3.2 İstemci envanteri

| İstemci | Kimin için | Platform | Olgunluk (README) | Kod ve test | İmza ve dağıtım | Bugün gerçekten çalışıyor mu |
|---|---|---|---|---|---|---|
| **Go uç ajanı** `agent/` | Yönetilen cihaz (çalışan bilgisayarı) | Windows (servis + tray), Linux (servis) | Beta | 16,7 bin satır Go, 13,2 bin satır test, yaklaşık 424 test fonksiyonu; Windows runner'da da koşuyor | MSI: kendinden imzalı Authenticode. deb/rpm: imzasız. winget: Temmuz'da kalmış. macOS: paket yok | Windows: evet, v1.41'den beri (öncesinde raporlar boş kaydediliyordu). Linux: evet, tray'siz. macOS: hayır |
| **Flutter telefon uygulaması** `client/` | Çalışanın telefonu | Android, iOS | Beta | 7,2 bin satır Dart + 0,6 bin satır Kotlin/Swift; 1,9 bin satır test, ekran testi az | APK: yükleme anahtarı secret'ı varsa imzalı, yoksa debug. IPA: imzasız. Mağazada yok. Uygulama kimliği `com.example.openidx_client` | Kayıt, giriş, TOTP, push onayı (uygulama açıkken), QR ile giriş, "Erişimim": evet. Duruş ve tünel: hayır |
| **Flutter masaüstü kabuğu** `client/` | Çalışan bilgisayarı (tray'e alternatif) | Windows, macOS, Linux | Deneysel | Aynı kod tabanı | CI ham derleme çıktısı yükler; motor paketlenmiyor (TODO); MSIX/dmg/AppImage yok | Kısmen: motoru bulur; dağıtılmıyor; tray menüsü çalışmıyor |
| **Kotlin Android ajanı** `agent-android/` | Kurumun sahip olduğu Android (kiosk, device owner) | Android 11+ | Deneysel, askıda | 3,5 bin satır Kotlin, **0 test** | Debug APK; `deployments/android/` boş, bu yüzden Android Enterprise QR'ı 503 döner | Tasarım var, saha kanıtı yok; Play Integrity hatası "geçti" sayılıyor |
| **Tarayıcı: konsol, portal, vendor portalı** `web/admin-console/` | Yönetici, çalışan, tedarikçi | Her tarayıcı | Beta | 101 bin satır TS; 1,4 bin birim testi; 50 e2e'nin 12'si CI'da | nginx + CSP; token'lar `localStorage`'da (#965) | Evet |
| **BrowZer (istemcisiz)** | Tedarikçi, kurulum yapılamayan cihaz | Tarayıcı | Beta (GA adayı) | OpenZiti bileşeni; hedef üretimi test edilmiş | Compose'da var; Helm'de yok | Canlı kurulumda evet; CI'da uçtan uca yok |
| **`openidx-connect` CLI** `cmd/openidx-connect/` | Operatör (SSH) | Her işletim sistemi | Belirtilmemiş | 345 satır, 2 test | Dağıtım yok; bearer token elle verilir | Evet, token elle verilirse |
| **Ziti Desktop Edge** (OpenZiti'nin istemcisi) | Geçici çözüm (özellikle macOS) | Windows, macOS | Dış ürün | - | OpenZiti dağıtır | Evet, ama OpenIDX politikaları (duruş, always-on, engelleme) uygulanmaz |

### 3.3 Yetenek matrisi

✅ var ve test edilmiş · 🟡 var ama kısmi ya da doğrulanmamış · ❌ yok · ⛔ tasarım gereği yok · 🔒 askıdaki Kotlin ajanında

| Yetenek | Windows | Linux | macOS | Android (Flutter) | iOS (Flutter) | Tarayıcı | Kotlin ajanı |
|---|---|---|---|---|---|---|---|
| Kayıt: kod, QR, bağlantı | ✅ (bağlantı UAC ister) | ✅ komut satırı | ❌ | ✅ | ✅ (URL şeması CI'da eklenir) | ⛔ | 🔒 OAuth, AE QR |
| Kayıt: kullanıcı girişiyle | ✅ | ✅ | ❌ | ✅ | ✅ | ⛔ | 🔒 |
| Cihazın overlay kimliği | ✅ | ✅ | ❌ | 🟡 yalnız uygulama içi köprü | 🟡 | BrowZer JWT | 🔒 seamless |
| Cihaz anahtarı | ✅ TPM / yazılım deposu | 🟡 dosya | ❌ | ❌ | ❌ | ⛔ | ❌ |
| Duruş kontrolleri | ✅ 8/10 | ✅ 10/10 | 🟡 kod var (8/10), paket yok | ❌ | ❌ | ⛔ | 🔒 10 kontrol |
| Tünel: always-on, split | ✅ | ✅ (root ya da systemd) | ❌ | ❌ | ❌ | ⛔ | ❌ |
| Tünel: doğrudan erişimi engelle | ❌ (WFP gerekir) | ✅ root, nftables | ❌ | ❌ | ❌ | ⛔ | ❌ |
| Tünel: full tunnel | ❌ | ❌ | ❌ | ❌ | ❌ | ⛔ | ❌ |
| TOTP (çevrimdışı) | ⛔ | ⛔ | ⛔ | ✅ | ✅ | ⛔ | ❌ |
| Push onayı | ⛔ | ⛔ | ⛔ | 🟡 yalnız uygulama açıkken | 🟡 yalnız uygulama açıkken | ⛔ | ❌ |
| Passkey / Windows Hello | ✅ (tarayıcıda) | ✅ (tarayıcıda) | ✅ (tarayıcıda) | tarayıcıda | tarayıcıda | ✅ | - |
| Ayrıcalıklı oturum (tarayıcıda) | ✅ tray'den | 🟡 konsoldan | 🟡 konsoldan | ✅ | ✅ | ✅ | ❌ |
| Ayrıcalıklı oturum (yerel mstsc/ssh) | ❌ tasarlandı (#1119) | 🟡 `openidx-connect` | 🟡 `openidx-connect` | ❌ | ❌ | ⛔ | ❌ |
| Uzaktan destek (ekran) | ✅ görüntü, klavye, onay istemi | 🟡 görüntü yok (stub) | ❌ | ❌ | ❌ | izleyici ✅ | 🔒 |
| Kullanıcı arayüzü | ✅ tray (İngilizce) | ❌ | ❌ | ✅ (İngilizce) | ✅ (İngilizce) | ✅ TR / EN | 🔒 |
| Kendini güncelleme | ✅ 6 saatte bir, imzalı | 🟡 yalnız elle | ❌ | mağaza yok | mağaza yok | - | ❌ |
| İmzalı eklenti | ✅ | ✅ | - | ⛔ | ⛔ | - | - |
| İptalin cihaza ulaşması | 30 sn (sorgu) | 30 sn | - | uygulama açıkken | uygulama açıkken | anında | 60 sn |
| Cihaz durumu (beş durum) | tray | ❌ | ❌ | ❌ (yalnız masaüstü ekranı) | ❌ | My Devices | - |

Kaynaklar: `agent/internal/checks/registry.go`, `agent/internal/tunnel/`, `agent/internal/tray/tray_other.go`,
`agent/internal/remotesupport/capture_stub.go`, `client/lib/`, `docs/AGENT-TUNNEL.md`.

### 3.4 Sunucu tarafındaki istemci yüzeyi

| Parça | Ne var | Ne eksik |
|---|---|---|
| Ajan API'si (`internal/access/agent_api.go`) | `/agent/enroll`, `/agent/report`, `/agent/config` (aktif cihazda 30 sn, uzaktan destekte 5 sn), `/agent/device-key`, uzaktan destek sinyali, Windows uygulama keşfi | OpenAPI tanımı; sözleşme testi; `/agent/config`'in imzalı olması |
| Kayıt yolları | Yönetici token'ı (tek kullanımlık, 24 saat; "reusable" 10 yıl), sihirbaz kodu (12 karakter, 15 dk), Android Enterprise QR, OAuth (`agent.enroll` kapsamı) | Token'ların konsol arayüzü yok; cihaz artık doğrudan `active` yazılıyor, tasarım belgesi hâlâ "pending" diyor |
| Agent Fleet (`agent-fleet.tsx`) | Platform filtresi, uyum yüzdesi, Tünel ve Politika rozetleri, duruş detayı, iptal, Device agent checks kartı, AE QR | İptal, Access 360'taki iptalden daha az iş yapıyor (G7); "iptali geri al" yok |
| Network Resources ve Network policy kartı | Kaynak listesi, hedef düzenleme, erişim diyaloğu; üç anahtar (always-on, split, block) ve "N cihazda uygulandı" sayacı | CSV içe aktarma yalnız API; `policy_gaps` yalnız rozette |
| Cihaz ekleme sihirbazı (`add-device.tsx`) | QR, bağlantı, kod, işletim sistemine göre indirme, durum sorgusu | macOS satırı "kurulum yok"; iOS dağıtılmıyor |
| My Devices (`my-devices.tsx`) | Bilinen cihazlar (ekle, adlandır, sil), ajanlar salt okunur, Ziti kimliği | Kullanıcı ajanını iptal edemez; "güven iste" yalnız log satırı yazar (`internal/portal/service.go:893-904`) |
| Karar açıklaması | `GET /access/decisions/explain` ve User Access 360'ta "neden erişebiliyor?" | Tray ve telefonda yok |
| Gözlemlenebilirlik | `openidx_tunnel_agents_down`, `openidx_tunnel_dial_failures_total`, `openidx_ziti_network_orphans_total` | `openidx_agent_*` metriği yok; iki tünel alarmı compose ve Helm kural dosyalarına yüklenmiyor |

---

## 4. Sistem mimarı gözüyle

### 4.1 İyi olan, korunmalı

1. **Tek Go motoru.** Aynı kod masaüstünde bir süreç (`openidx-agent serve`),
   telefonda bir kütüphane (gomobile `agent/mobile`). JSON şekilleri birebir aynı;
   Dart modelleri her iki taşıyıcıyı aynı `fromJson` ile çözüyor. Doğru temel.
2. **Küçük ve net bir yerel sözleşme.** Kontrol API'si 13 rota
   (`agent/internal/control/server.go:119-133`); Windows'ta loopback + rastgele
   bearer, Unix'te 0600 soket.
3. **Cihaz sunucuda birinci sınıf bir kimlik.** `dev-<agent_id>` kimliği, sürümlü
   ağ politikası, cihazın "uyguladım / uygulayamadım" geri bildirimi
   (`internal/access/tunnel_policy.go`, migration 237).
4. **Red kanıtı kültürü istemciye de taşınmış.** `tools/inertswitch`,
   `tools/posturevocab`, `scripts/check-mobile-keystore.sh`,
   `scripts/check-mobile-secrets-at-rest.sh`, Windows runner'da koşan Windows
   testleri.
5. **Dürüst belgeler.** `docs/AGENT-TUNNEL.md`'nin "doğrulanmadı" listesi, #1119'un
   "yapılmadı ve neden" bölümü.

### 4.2 Yapısal sorunlar

| # | Sorun | Kanıt | Sonuç |
|---|---|---|---|
| **M1** | **Dört istemci kod tabanı, iki Android.** ROADMAP Kotlin ajanını ve Flutter masaüstü kabuğunu askıya alıyor, ama kod, CI ve konsol ikisine de hâlâ yol veriyor: Cihaz ekleme sihirbazı `openidx://enroll` ile Flutter'a, Agent Fleet'teki AE QR Kotlin'e gidiyor | `internal/access/enroll_session.go:88-101`, `web/admin-console/src/pages/agent-fleet.tsx:118`, `.github/workflows/ci-android.yml` (test kaynağı olmayan test işi) | Bakım yükü; kullanıcı için iki farklı "Android" |
| **M2** | **Sözleşme yok.** Ajan API'si OpenAPI'de tanımlı değil; sunucu ve ajan aynı yapıları ayrı ayrı yazıyor. Üç haftada beş uyumsuzluk: `check_type`/`type` (#1110), `tunnel_status` biçimi (v1.45), push onay alanları (#1112), mobil `zitiDial` yanıtı, bildirim okundu gövdesi (`client/lib/api/notifications.dart:25-31` ↔ `internal/notifications/service.go:397-405`). CI hiçbir ajanı canlı sunucuya kaydetmiyor; tunneler canlı controller'a karşı hiç koşmadı | `api/` altında ajan şeması yok; `ci.yml`'de ajan işi yok | Aynı hata sınıfı her sürümde yeniden |
| **M3** | **Platform farkları plan değil, rastlantı.** Tray yalnız Windows (`agent/internal/tray/tray_other.go`); uzaktan destek görüntüsü yalnız Windows derlemesinde; iki ayrı uyum özeti aynı sonuca farklı karar veriyor (`agent/internal/agent/posture.go:55-95` desteklenmeyeni atlar, `agent/internal/control/engine.go:572` uyumsuz sayar); masaüstü arayüzünün `/posture`'ı yalnız 3 varsayılan kontrolü koşuyor (`engine.go:503-526`) | | Linux kullanıcısı kör; macOS kullanıcısı yok; telefon ve bilgisayar aynı kelimeyi farklı anlıyor |
| **M4** | **İki iptal yolu, iki sonuç.** Agent Fleet'teki iptal yalnız durumu yazıp Ziti kimliğini siliyor; Access 360'taki iptal oturumları kesiyor, bilinen cihazı güvensiz yapıyor, token ailelerini iptal ediyor | `internal/access/agent_api.go:2259-2320` ↔ `internal/access/user_devices.go:369-426` (kodda doğrulandı) | Yönetici hangi düğmeye bastığına göre farklı güvenlik sonucu alıyor |
| **M5** | **Sürüm uyumluluk politikası yok.** "Her iki şekli de kabul et" türünden geçici uyumluluklar var (v1.41, v1.45) ama hangi ajan sürümünün hangi sunucuyla çalışmak zorunda olduğu yazılı değil; kontrol API'sinin sürümü yok | `CHANGELOG.md` 1.41.0 ve 1.45.0 "Fixed" | Her yükseltme bir risk |
| **M6** | **Konfigürasyon dağınık ve tutarsız.** Ajanın varsayılan dizini `/etc/openidx-agent`, systemd birimi `/var/lib/openidx-agent` bekliyor; `install.sh` servis kurmuyor; deb/rpm sertleştirilmiş birimi ve `openidx-agent` kullanıcısını paketlemiyor; `latest.json` yalnız MSI'yi ilan ediyor | `agent/cmd/openidx-agent/main.go:44-53`, `agent/deploy/openidx-agent.service`, `agent/packaging/install.sh`, `agent/packaging/nfpm.yaml` | Linux kurulumu elle ve kırılgan |
| **M7** | **`internal/access` 69 bin satır.** İstemci API'si, PAM, uzaktan destek, Ziti ve ağ politikası tek pakette | `find internal/access -name '*.go'` | Her istemci değişikliği en kalabalık paketi değiştiriyor (ROADMAP'te "Later") |
| **M8** | **Belgeler kodun gerisinde.** Ek B'de 9 çelişki | | Yeni gelen yanlış şeyi öğreniyor |

### 4.3 Hedef mimari: "tek motor, üç kabuk"

```
                  ┌───────────────────────────────────────────────────────┐
                  │  openidx-agent  (Go motoru, her platformda aynı)      │
                  │  kayıt · cihaz anahtarı · duruş · tünel · oturum      │
                  │  ayrıcalıklı erişim · uzaktan destek · güncelleme     │
                  │  yerel karar: "bu cihaz şu anda şunu yapamaz, çünkü…" │
                  └──────────┬─────────────────┬─────────────────┬────────┘
                   kontrol API (soket/pipe)   gomobile bağı     komut satırı
                              │                 │                 │
                  ┌───────────▼──────┐  ┌───────▼────────┐  ┌─────▼──────────┐
                  │ Masaüstü kabuğu  │  │ Telefon kabuğu │  │ openidx CLI    │
                  │ = Go tray        │  │ = Flutter      │  │ (openidx-agent │
                  │ Windows·macOS·   │  │ Android · iOS  │  │  + openidx-    │
                  │ Linux            │  │                │  │  connect)      │
                  └──────────────────┘  └────────────────┘  └────────────────┘
```

Kurallar:

1. **Yetenek motora yazılır, kabuğa değil.** Bugün "kritik kontrol başarısızsa
   ayrıcalıklı oturum açma" kararı tray'de (`agent/internal/tray/health.go`); bu
   karar motora taşınırsa Linux ve macOS'ta da geçerli olur.
2. **Masaüstü kabuğu Go tray'dir.** Kullanılan `getlantern/systray` kütüphanesi üç
   işletim sistemini destekler; bugün yalnız Windows derlemesine bağlı. Flutter
   masaüstü kabuğu dondurulur (#966 zaten bunu söylüyor) ve Go tray mac/Linux'u
   kapsadığında silinir.
3. **Telefon kabuğu Flutter'dır.** Kotlin ajanı dondurulur. Onun iki eşsiz
   yeteneği (device owner / kiosk, Play Integrity) talep gelirse Flutter'a ve
   motora taşınır (Faz 4).
4. **Sözleşme tek yerden üretilir.** `api/agent-v1.yaml` (OpenAPI) → sunucu
   tipleri, ajan tipleri, Dart modelleri. CI'da "sözleşme testi": sunucu bir
   sahte cihazı kaydeder, config verir, rapor alır (eski ve yeni şekil), tünel
   durumunu alır, iptal eder, 403'ü görür.
5. **Yazılı sürüm politikası.** Ajan, kendisinden en çok iki minor sürüm yeni
   sunucuyla çalışmak zorundadır (N-2). Sunucu eski biçimi bir sürüm boyunca
   kabul eder. Kontrol API'si `/v1/...` ile sürümlenir.
6. **Beş cihaz durumu her yerde aynı kelimeyle:** kayıtsız, onay bekliyor,
   kayıtlı, güvenilir, iptal edildi. Tray, telefon, My Devices ve Agent Fleet aynı
   sözcük listesini kullanır (`docs/CLIENT-ACCESS-DESIGN.md` §1 bunu tanımlıyor;
   bugün yalnız masaüstü ekranında var).

---

## 5. Ağ uzmanı gözüyle

### 5.1 Dört veri yolu

| Yol | Kim kullanır | İstemci | Giriş | Karar noktası | Zayıf halka |
|---|---|---|---|---|---|
| **A. Ters vekil (proxy)** | Herkes, web uygulamaları | Tarayıcı | APISIX / nginx 443 → access-proxy | forward-auth `/auth/decide`, `internal/accessdecision` | Hedef hâlâ ağda görünür; "karanlık" değil |
| **B. İstemcisiz (BrowZer)** | Tedarikçi, kurulum yapılamayan cihaz | Tarayıcı (WASM) | bootstrapper 8445 → router WSS 3023 | Giriş kapısı (uygulama ataması) + Dial politikası | Forward-auth'u atlar; `ACCESS_ASSIGNMENT_ENFORCE` kapalıysa herkes girer; Helm'de yok |
| **C. Yerel overlay (ajan + tünel)** | Yönetilen cihaz | ajan + `ziti-edge-tunnel` | controller 1280, router 3022 | Dial politikası (`#app-<id>` ve `#device-trusted`) | macOS ve mobilde yok; full tunnel yok; DNS tasarımı yok |
| **D. Ayrıcalıklı oturum (PAM broker)** | SSH/RDP/VNC | Tarayıcı (+ CLI) | Guacamole (doğrudan ya da overlay brokerı) | `PAM_REQUIRE_ZTNA`, grant, onay, kayıt | Kullanıcı→broker bacağı dağıtımın sorumluluğunda; bağlama değişince `pam-ziti-tunnel` yeniden başlatılmalı (`deployments/docker/README.pam-broker.md:93-95`) |

**Portlar** (`docs/ziti-nat-firewall-requirements.md`, `docs/host-firewall-baseline.md`):
içeri yalnız 443, 1280 (controller, mTLS), 3022 (router), 3023 (router WSS,
yalnız BrowZer). İstemciler yalnız dışarı bağlanır. Veritabanı, Redis, etcd ve
APISIX yönetim portları loopback'te kalır. **NAT**: yalnız hedef NAT; kaynak NAT
ve TLS inceleme yok (mTLS ve pinli Ziti PKI bozulur).

### 5.2 Tünel politikasının bugünkü durumu

| Anahtar | Windows | Linux (root) | Linux (yetkisiz, systemd) | macOS | Telefon |
|---|---|---|---|---|---|
| Always on | Uygulanır | Uygulanır | Uygulanır | Tünel yok | Tünel yok |
| Split tunnel | Her zaman split | Her zaman split | Her zaman split | - | - |
| Full tunnel | Boşluk `full_tunnel` | Boşluk | Boşluk | - | - |
| Doğrudan erişimi engelle | Boşluk `block_direct` (WFP gerekir) | nftables ile uygulanır | Boşluk | Boşluk (pf gerekir) | - |

Kaynak: `docs/AGENT-TUNNEL.md` §"The organization's network policy",
`agent/internal/tunnel/directblock_other.go:13`.

### 5.3 Bulgular

| # | Bulgu | Kanıt | Neden önemli |
|---|---|---|---|
| **N1** | **macOS'ta istemci yok.** Ajan derlenir (`_darwin` dosyası yok, `runtime.GOOS` dallanması var) ama paket, notarization ve tunneler yok; yalnız bir LaunchDaemon plist'i var. `packaging/DEEPLINK.md:45` CI'da `pkgbuild` olduğunu söylüyor; yok | `agent/deploy/com.openidx.agent.plist`, `docs/AGENT-TUNNEL.md:51`, `add-device.tsx:25-32` | Tasarımcı, yönetici ve yöneticilerin bilgisayarı sıklıkla Mac |
| **N2** | **Telefonda cihaz çapında tünel yok.** `VpnService` / `NetworkExtension` hiçbir ağaçta yok. Flutter'daki `zitiDial` yalnız `127.0.0.1:<port>` açar ve adresi bir snackbar'da gösterir | `agent/internal/ziti/dialer.go:51`, `agent/internal/control/engine.go:630-665`, `docs/mobile-openziti-integration-guide.md` (silinmiş uygulama için yazılmış) | Telefondan iç uygulamaya erişim yalnız BrowZer ile |
| **N3** | **Full tunnel yok; egress tasarımı yok.** "A full tunnel would need an overlay service that carries all traffic to an egress router, which OpenIDX does not configure" | `docs/AGENT-TUNNEL.md:209-213` | GlobalProtect/AnyConnect'ten geçen kurumlar "tüm trafik" ister |
| **N4** | **Engelleme yalnız Linux root'ta.** Windows'ta WFP, macOS'ta pf yazılmamış | `agent/internal/tunnel/directblock.go:40-45`, `directblock_other.go:13` | Politika "açık" görünür, Windows'ta hiçbir şey engellenmez (konsol bunu söylüyor, iyi) |
| **N5** | **DNS tasarımı yok.** Tunneler intercept adlarını kendisi çözüyor; Windows kurulum betiği hosts dosyasına satır yazıyor; kurum iç DNS'iyle ilişki (split DNS, NRPT) tanımsız; `*.localtest.me` adları compose'da | `agent/scripts/install-openidx-agent.ps1:34-38`, `docs/AGENT-TUNNEL.md:307` | "Adı çözülmeyen kaynak" en sık destek talebi olur |
| **N6** | **Controller HA yalnız Helm'de (Raft 3).** Compose'da tek controller, `restart: unless-stopped`. Controller düşerse mevcut devreler akar; yeni dial, kayıt, sync ve kill-switch kesmesi durur. Bir controller yeniden başlatması imzalayıcı anahtarı döndürüp router'ları düşürdü | `docs/ZITI_HA_DEPLOYMENT.md:48-54`, `deployments/apisix-edge/ziti-router/EXTERNAL-INGRESS.md:33-60` | Tek VM kurulumunda ağ tek noktaya bağlı |
| **N7** | **Router yerleşimi anlatılmıyor.** Bir ağ kaynağını taşıyan router o ağa erişebilmeli ("her ağa bir router"); konsol bunu söylemiyor, "Needs setup" dışında rehber yok | `docs/migration-from-globalprotect.md:28-30`, `docs/how-network-access-works.md:61-64` | Kaynak "Synced" görünür, erişilemez |
| **N8** | **`policy_gaps` yalnız rozette.** Metrik, alarm ve uyum etkisi yok; boşluklu cihaz "applied" sayılıyor | `tunnel-status-badge.tsx:59-64`, `internal/access/tunnel_status.go` | Yönetici "%100 uygulandı" sanır |
| **N9** | **Filo gözlemlenebilirliği eksik.** `openidx_agent_*` metriği yok; `OpenIDXAgentTunnelDown` ve `OpenIDXTunnelDialFailures` yalnız `deployments/monitoring/alerts.yml`'de; compose ve Helm kural dosyaları yüklemiyor | `deployments/docker/prometheus/alert_rules.yml`, Helm `prometheus-rules.yaml` | Tünel çökünce kimse uyanmaz |
| **N10** | **CI hiçbir zaman canlı controller'a karşı ajan kaydetmiyor.** `lite-profiles --with ziti` yalnız `/ziti/status` okuyor; tunneler sahte bir ikiliyle test ediliyor | `.github/workflows/ci.yml`, `docs/AGENT-TUNNEL.md:297-311` | En kritik yol hiç otomatik koşmadı |
| **N11** | **Helm'de BrowZer bootstrapper ve ortak Guacamole yok** ("operator step"); APISIX edge "elle çalıştırılan konteyner" | `deployments/kubernetes/helm/openidx/values.yaml:545`, `docs/OPENIDX_CLIENTLESS_EDGE_ARCHITECTURE.md:187-188` | Kubernetes kurulumunda tedarikçi yolu çalışmaz |
| **N12** | **Uyum kapıları varsayılan kapalı.** `ACCESS_ASSIGNMENT_ENFORCE` kapalıyken Dial politikası `#openidx-agent` VEYA `#app-<id>`; yani her kayıtlı cihaz her ağ kaynağını çevirebilir (çıkarım). Üretim v1.42'den beri açık kapıyla başlamayı reddediyor, ama `ENFORCEMENT_OBSERVE_UNTIL` 30 güne kadar erteleyebiliyor | `internal/access/ziti_reconciler.go:617-634`, `internal/common/config/config.go` `ReportModeGates` | Pilot kurulumlar "ağ kaynağı = herkese açık" durumunda başlayabilir |

### 5.4 Hedef ağ resmi

- **Her cihazda aynı tünel davranışı:** always-on; split ya da full (egress router
  üzerinden); doğrudan erişimi engelleme her işletim sisteminde (Windows WFP,
  macOS pf, Linux nftables). Uygulayamayan cihaz "applied" sayılmaz.
- **DNS bir politika alanıdır:** overlay adlarını tunneler çözer; kurum DNS'i bir
  ağ kaynağı olarak overlay'e alınır; Windows'ta NRPT, macOS'ta resolver, Linux'ta
  systemd-resolved ile split DNS; hosts dosyası hack'i kalkar.
- **Controller:** Helm'de 3 düğüm Raft; compose'da 3 controller + 2 router
  seçeneği; imzalayıcı anahtar rotasyonu için runbook.
- **Router:** ağ başına en az bir router; konsol "bu kaynağa ulaşan router yok"
  uyarısı verir.
- **Tanılama:** `openidx-agent doctor` (controller ve router erişimi, DNS, saat,
  sertifika, tünel durumu, politika sürümü, hangi servisler çevriliyor) ve
  konsolda cihaz → router → kaynak yol izi (topology sayfası bugün var, filo ile
  bağlı değil).
- **Ölçüm:** `openidx_agents_by_state`, `openidx_agent_reports_total`,
  `openidx_tunnel_policy_pending`, `openidx_tunnel_policy_gaps`; alarmlar her
  kurulum şeklinde yüklü.

---

## 6. Güvenlik uzmanı gözüyle

### 6.1 Sağlam olan

- Cihaz anahtarı TPM'de (ya da yazılım deposunda), raporlar imzalı, 5 dakikalık
  zaman penceresi (`internal/access/agent_device_key.go`).
- Eklentiler yayıncı sertifikasıyla imzalı; çalıştırmadan önce özet yeniden
  kontrol ediliyor; yerleşik kontrol adları gölgelenemiyor.
- Tunneler ikilisi SHA-256 ile pinli; Linux'ta `/proc/self/fd/N` üzerinden,
  Windows'ta tutulan handle ile çalıştırılıyor; PATH asla aranmıyor.
- `agent.json` yalnız SYSTEM ve yöneticilerce yazılabilir; servis-tray pipe'ı
  kullanıcıya salt okunur; token karşılaştırmaları sabit zamanlı.
- `user-tokens.json` Windows'ta DPAPI + dosya DACL'i; telefonda Keystore ve
  Keychain mührü, kendi kendini test eden mühür, yedekleme dışı.
- Cihaz iptali bağlı refresh token ailelerini ve oturumları da iptal ediyor;
  yerel çıkış `/oauth/revoke` çağırıyor; native istemcilerde aile tavanı (14/30
  gün, en çok 90).
- Uzaktan destekte onay istemi "Hayır" varsayılanlı; tedarikçi oturumları her
  zaman onaylı, relay ve broker kaydıyla.
- Kayıt token'ları tek kullanımlık ve atomik; iptal edilen cihazın parmak iziyle
  yeniden kaydı reddediliyor; `agent-v0.3.0`'a sızan kayıt token'ı bulundu ve
  kapatıldı.

### 6.2 Bulgular

Önem: **Yüksek** = bugün bir saldırganın işine yarar; **Orta** = bir ön koşulla
yarar ya da savunma derinliğini azaltır; **Düşük** = hijyen. "Doğrulandı" =
bu belge için kod ikinci kez okundu (Ek A).

| # | Önem | Bulgu | Kanıt | Düzeltme |
|---|---|---|---|---|
| **G1** | Yüksek, doğrulandı | **Parmak iziyle yeniden kayıt sahipliği kontrol etmiyor.** Sunucu `device_fingerprint` ile kuruluştaki mevcut satırı bulur, token'ı döndürür, durumu `active` yapar ve isteğe göre cihaz anahtarını değiştirir ya da siler ("the enrolment is the authority on the device"). Kayıt oturumu kuruluştaki her kullanıcıya açık. Parmak izi `sha256(MachineGuid \| hostname)`; hedef makinede yerel hesabı olan herkes hesaplayabilir. Sonuç: gerçek ajanın token'ı geçersizleşir (hizmet kesintisi), askı kalkar, cihaz anahtarı silinir, saldırgan o cihaz adına duruş raporlar | `internal/access/agent_api.go:170-174, 350-398`, `agent_device_key.go:149-178`, `agent/internal/transport/fingerprint_windows.go:19-31` | Yeniden kayıt yalnız (a) aynı `enrolled_by` kullanıcı ya da operatör token'ıyla, ya da (b) mevcut cihaz anahtarıyla imzalı istekle; aksi hâlde yeni satır. Anahtar yalnız imzalı istekle değişir. Red kanıtı: başka kullanıcının parmak iziyle kayıt → 409 ve `agent.enroll_denied` |
| **G2** | Yüksek, doğrulandı | **Windows'ta overlay özel anahtarı ve kayıt JWT'si tüm yerel kullanıcılarca okunabilir.** İkisi de `os.WriteFile(…, 0600)` ile yazılıyor; Windows modu yok sayar; dosya `%ProgramData%` ACL'ini alır. Cihaz kimliği artık kullanıcının grup, uygulama ve `#device-trusted` özniteliklerini taşıdığı için kopyalanan dosya cihazın erişimini başka makineye taşır. #1119 madde 4 bunu biliyor ve bir karar bekliyor | `agent/internal/enrollment/enroll.go:116,189`, `agent/internal/secretfile/secretfile.go:11-17`, `internal/access/device_identity.go:16-34` | Dosya DACL'i SYSTEM + Administrators; JWT kullanıldıktan sonra silinir. Tray'in overlay sinyali için karar gerekir (§11 K2): servis üzerinden pipe ile köprü, ya da tray için ayrı ve dar bir kimlik |
| **G3** | Yüksek, doğrulandı | **Personel uzaktan destek oturumunda onay isteğe bağlı ve varsayılan kapalı.** `consent_required` istek gövdesinde; varsayılan `false`; mod varsayılanı interaktif; kayıt isteğe bağlı ve operatörün tarayıcısında; kayıt şifreleme anahtarı üretimde zorunlu değil. `STEPUP_GATE` varsayılan kapalı | `internal/access/remote_support_api.go:320, 373-376, 525`, `remote_support_recording.go:70-72` | Kuruluş politikasında `remote_support.consent_required` (varsayılan açık); "onaysız" oturum ayrı izin + gerekçe + taze ikinci faktör; kayıt broker'da ve zorunlu (tedarikçi yolundaki gibi); üretim kapısı: kayıt anahtarı yoksa başlatma. Görünen = uygulanan satırı |
| **G4** | Yüksek | **Kayıtta cihaz hiçbir şey kanıtlamıyor.** Anahtar türü (`tpm`, `software`, `file`) cihazın beyanı; EK sertifikası, anahtar tanıklığı, TPM quote, Windows DHA, App Attest yok. Play Integrity yalnız Kotlin'de: nonce cihazda üretiliyor, sunucu karşılaştırmıyor ("future replay detection"), boş politika her şeyi geçiriyor, hata PASS sayılıyor. Flutter ve Kotlin raporları imzasız | `internal/access/agent_device_key.go:64-85`, `internal/access/play_integrity.go:39-41,69-72`, `agent-android/.../IntegrityCheck.kt:28,37,64` | Faz 1'de "tanıklık hazırlığı" (observe): Windows'ta EK sertifikası ve anahtar tanıklığı toplanır, "attested" alanı gösterilir, karar verilmez. Faz 3'te Play Integrity ve App Attest Flutter'a, nonce sunucudan |
| **G5** | Yüksek, doğrulandı | **Tier-0 kayıt kapısı her geçerli access token'ı kabul ediyor.** `/api/v1/access/enroll` `agent.enroll` kapsamı istemiyor, iptal kesme noktasını kontrol etmiyor; kullanıcının kimliği için 7 günlük Ziti kayıt JWT'si üretiyor. Konsol token'ı `localStorage`'da (#965) olduğundan çalınan 1 saatlik token kalıcı bir overlay kimliğine dönüşebilir | `internal/access/enroll_handler.go:81-112`, `internal/access/ziti.go:1419-1444` | `agent.enroll` kapsamı; iptal kesme noktası; taze ikinci faktör; JWT ömrü 15 dakika; denetim olayı |
| **G6** | Orta | **Derin bağlantıdaki sunucu adresi doğrulanmıyor.** CLI ve bağlantı yolu `server`'ı olduğu gibi geçiriyor; mobil `SetServer` `http://` kabul ediyor; Flutter bağlantı gelince otomatik kaydoluyor; Windows'ta UAC istemi sunucu adını göstermiyor. Sahte sunucu cihazı kendine kaydeder, "onaysız" uzaktan destek ve klavye girişi başlatabilir | `agent/cmd/openidx-agent/main.go:118-134`, `agent/internal/control/engine.go:373-379`, `client/lib/ui/screens/enroll_screen.dart:49-54`, `agent/internal/agent/config.go:216-219` | https zorunlu; ilk kayıtta sunucu adı ve kuruluş adı gösterilip onay istenir; yönetilen cihazda `server_url` allowlist (MSI özelliği); UAC istemi sunucuyu söyler |
| **G7** | Orta, doğrulandı | **İki iptal yolu, iki sonuç; kill switch cihaz kimliklerini bırakıyor.** Agent Fleet iptali yalnız durum + Ziti kimliği; Access 360 iptali oturum, bilinen cihaz, token aileleri. Kill switch cihaz oturumlarını kesiyor ama kimliği bırakıyor ("a device may be re-assigned"); kullanıcı devre dışı bırakılmadıysa cihaz hemen yeniden bağlanır. İptal edilen cihazı geri alacak yönetici işlemi yok | `agent_api.go:2259-2320`, `user_devices.go:369-426`, `kill_switch.go:387-390`, CHANGELOG 1.41.0 yükseltme notu | Tek `RevokeDevice`; kill switch'e "cihazları karantinaya al" seçeneği; "iptali geri al" işlemi (gerekçeli, denetimli) |
| **G8** | Orta, doğrulandı | **Tek kendinden imzalı sertifika üç şeyi imzalıyor** (Authenticode, güncelleme manifesti, eklenti); iptal yolu yok; 2031'e kadar geçerli. PFX secret'ı `pull_request` tetikli iş akışında job env'de: aynı depodaki her PR derlemesi yayın anahtarıyla imzalanır. Manifestte son kullanma yok (güncelleme dondurma saldırısı) | `.github/workflows/windows-client-build.yml:21-33, 254-260`, `agent/internal/updater/trust.go` | İmzalama yalnız tag ve dispatch'te, `environment: release-signing` korumasıyla; ayrı anahtarlar (Authenticode: güvenilir CA; manifest/eklenti: çevrimdışı anahtar, rotasyon planı); manifeste `expires` |
| **G9** | Orta | **İstemci artefaktlarının tedarik zinciri eksik.** deb/rpm imzasız, depo yok; `install.sh` ve `install-openidx-agent.ps1` hash ve imza kontrolsüz indiriyor; `nfpm` checksum'suz; SBOM ve provenance yalnız Docker imajlarında; cosign yalnız sunucu `SHA256SUMS` ve chart'ta | `agent/packaging/install.sh`, `agent/scripts/install-openidx-agent.ps1:96-104`, `windows-client-build.yml:150-159`, `release.yml:83-107` | GPG ile apt/yum deposu; betiklerde `SHA256SUMS` + cosign doğrulama; her istemci artefaktı için provenance |
| **G10** | Orta | **Telefon uygulamasında savunma derinliği az.** TLS pinning yok; biyometrik kilit kapalı ve açık olsa da "Devam et" ile geçiliyor (fail-open); root/jailbreak tespiti yok; ekran görüntüsü koruması yok; `ziti-identity.json` mühürsüz; TOTP sırları iOS'ta varsayılan erişilebilirlikte | `client/lib/mobile/app_lock.dart:36-38,150-165`, `agent/mobile/mobile.go:131-133`, `client/lib/state/api_providers.dart:22-29` | Sıra: Ziti kimliğini bellekten yükleyen SDK değişikliği; SPKI pinning (yedek pinli); kilit fail-closed ve yöneticinin zorlayabildiği bir ayar; integrity (G4) |
| **G11** | Orta, doğrulandı | **İstemci denetim olayları hash zincirinde değil.** `agent.*` ve `remote_support.*` olayları `unified_audit_events`'e yazılıyor; HMAC zinciri yalnız `audit_events` tablosunu mühürlüyor. THREAT-MODEL A5 aksini söylüyor | `internal/audit/chain.go:235`, `internal/access/agent_api.go:101-131`, `docs/THREAT-MODEL.md:110` | Zinciri unified tabloya genişlet ya da istemci olaylarını zincirli tabloya yönlendir; belgeyi düzelt |
| **G12** | Orta | **Rapor yeniden oynatılabilir; imza yalnız iki rotada.** ±5 dakika pencere, nonce ve tekrar önbelleği yok; `/agent/config`, uzaktan destek WebSocket'i ve onay rotası, Windows uygulama raporu yalnız bearer ile. Yerel yönetici TPM anahtarıyla istediği duruşu imzalayabilir (quote yok) | `agent_device_key.go:45-51, 251-281` | Sunucu nonce'u (config yanıtında), tüm ajan rotalarında imza, tekrar önbelleği; quote Faz 3/4 |
| **G13** | Düşük | **Yerel sınırda küçük boşluklar.** Unix soketinde eş kimlik (peer credential) kontrolü yok, `XDG_RUNTIME_DIR` yokken `/tmp/openidx-agent.sock`; Ziti köprüleri kimliksiz loopback dinleyici (her yerel süreç kullanabilir); `insecure_skip_verify` `ConfigTrusted` kapsamında değil; tray pipe sunucusunun kimliğini doğrulamıyor; yönetici token'ının `created_by`'ı gövdeden; kontrol API'sinde istek boyutu sınırı yok; masaüstü arayüzü `/posture` için uyum özeti servisten farklı | `agent/internal/control/listener_unix.go:46-78`, `agent/internal/ziti/dialer.go:51-60`, `agent/internal/agent/config.go:209-222`, `agent/internal/ipc/pipe_windows.go:51-65`, `agent_api.go:2400-2441` | Faz 0'da toplu, küçük PR'lar |
| **G14** | Düşük | **Tehdit modeli istemciyi tek paragrafta ele alıyor** (§4.9); uç noktada oturan saldırgan, yerel yönetici, çalınan cihaz (öznitelik taşıyan kimlikle), sahte sunucu, tedarik zinciri yok. Pentest kapsamı Flutter ve Kotlin'i dışarıda bırakıyor; manifest imzalama için yanlış iş akışını gösteriyor | `docs/THREAT-MODEL.md` §3-§4.9, `docs/security/pentest-scope.md` madde 6 | Faz 1'de istemci bölümü; pentest kapsamına ajan güncelleme zinciri ve Flutter |

### 6.3 Tehdit modelinin istemci boşlukları

| Tehdit | Modellenmiş mi | Not |
|---|---|---|
| Çalınan cihaz | Evet (§4.9), ama eski | "Yalnız kendi Ziti kimliğini taşır" diyor; v1.42'den beri kullanıcının uygulama özniteliklerini de taşıyor |
| İptal edilen ajanın geri dönmesi | Kısmen | Parmak iziyle yeniden kayıt iptal için reddediliyor; iptal edilmemiş satırın ele geçirilmesi (G1) yok |
| Kötü niyetli yerel yönetici | Yok | |
| Yeniden oynatılan duruş | Yok | |
| Sahte kayıt ya da sahte sunucu | Yok | |
| Ajan kanalında araya girme | Yok | |
| Ajan ikilisinin tedarik zinciri | Modelde yok, kodda var | İmzalı manifest; pentest madde 6 |
| Tunneler ikilisinin değiştirilmesi | Yok | Kodda pin ve tutulan handle ile karşılanmış; macOS'ta pencere açık ama tunneler de yok |
| Uzaktan destek onayının kötüye kullanımı | Yok | Yalnız rol katmanı §4.4'te |

### 6.4 Tedarik zinciri: artefakt başına durum

| Artefakt | İmza | Provenance / SBOM | Dağıtım kanalı |
|---|---|---|---|
| MSI ve `openidx-agent.exe` | Kendinden imzalı Authenticode (secret yoksa imzasız) | Yok | GitHub release `agent-latest`; winget manifesti Temmuz'da kalmış |
| `latest.json` | RSA, pinli sertifika | - | GitHub release |
| deb / rpm | **Yok** | Yok | GitHub release; depo yok |
| APK (Flutter) | Yükleme anahtarı secret'ı varsa; yoksa debug | Yok | GitHub release (AAB yok, mağaza yok) |
| IPA | **Yok** (`--no-codesign`) | Yok | GitHub release; TestFlight yok |
| macOS ajanı | Derlenmiyor, paketlenmiyor | - | - |
| Flutter masaüstü | İmzasız ham çıktı | - | 7 günlük CI artefaktı |
| Sunucu ikilileri ve chart | cosign (keyless) | Docker imajlarında SBOM + provenance | GHCR |

---

## 7. Kullanılabilirlik: "kolay anlaşılır" ilkesi

### 7.1 Dört yolculuk bugün

**A. Yönetici bir Windows bilgisayarı ekler.** Konsol → Cihaz ekle → QR, bağlantı
ya da kod → kullanıcı MSI'yi indirir (SmartScreen uyarır: kendinden imzalı) →
`openidx://enroll` bağlantısı UAC ister (sunucu adı görünmez) → servis kaydolur →
tray 15 saniye içinde çıkar → "Sign in" → tarayıcı → Windows Hello kurulumu
tray'den. **Takılma noktaları:** SmartScreen; İngilizce tray; iptal sonrası geri
dönüş yok; kayıt token'ları yalnız API'den.

**B. Çalışan telefonunu kurar.** Mağaza yok → Android'de APK yan yükleme, iOS'ta
dağıtım yok → sunucu adresi elle → tarayıcıda giriş → push kaydı (ikinci faktörü
olanlara parola sorulur) → push onayı yalnız uygulama açıkken; işletim sistemi
bildirimi yok → TOTP çevrimdışı çalışır. **Takılma:** iOS; bildirim yok;
İngilizce; biyometrik kilit kapalı ve geçilebilir; "Notifications" ekranına giden
yol yok; cihaz durumu ve duruş telefonda gösterilmiyor.

**C. Tedarikçi destek verir.** Davet → `/accept-invite` + TOTP → `/vendor` "My
Work" → engagement → "Start support" (tarayıcı, relay, kayıt) → sponsor izler ve
bitirir. **Takılma:** BrowZer için genel DNS gerekiyor ("Needs setup"); e-posta
yoksa bağlantı elle iletiliyor. Bu yolculuk dördünün en olgunu.

**D. Linux ve macOS çalışanı.** Linux: deb/rpm + terminalden `openidx-agent
enroll --code …`; tray yok; durumunu görmenin yolu yok; güncelleme elle. macOS:
hiçbir şey; geçici çözüm Ziti Desktop Edge, politikasız.

### 7.2 Bulgular

| # | Bulgu | Kanıt |
|---|---|---|
| **K1** | **Dil.** Tray ve Flutter yalnızca İngilizce; konsol TR/EN. Hedef müşteri Türkiye'de | `agent/internal/tray/` (katalog yok), `client/pubspec.yaml` (`flutter_localizations` yok) |
| **K2** | **Dağıtım.** Mağaza yok; MSI SmartScreen uyarısı; Linux paketi imzasız; macOS yok; winget eski; `latest.json` yalnız MSI | §6.4 |
| **K3** | **Geri bildirim eşitsiz.** Windows'ta cihaz sağlığı ve nedenler tray'de (iyi); Linux'ta hiçbir arayüz yok; telefonda cihaz durumu ve duruş yok | `agent/internal/tray/health.go`, `client/lib/ui/widgets/device_state_banner.dart` (yalnız masaüstü ekranında) |
| **K4** | **Push onayı yalnız uygulama açıkken.** Bildirim eklentisi yok; arka planda ve kapalıyken hiçbir şey gelmiyor; iOS'ta APNs ve arka plan modu yok; kullanıcı "push gelmiyor" der | `client/lib/mobile/ntfy_inbox.dart:22-27`, `docs/mobile/push-mfa-delivery.md` |
| **K5** | **İptal tek yönlü.** İptal edilen cihaz geri alınamıyor; kullanıcı kendi ajanını iptal edemiyor (My Devices'taki "Remove" yalnız bilinen cihaz satırını siler); "güven iste" log satırı yazıyor | CHANGELOG 1.41.0, `internal/portal/service.go:880-904` |
| **K6** | **Kayıt token'larının konsol arayüzü yok** (yalnız API) | `web/` altında `/agent/tokens` çağrısı yok |
| **K7** | **İki kayıt yolu iki uygulamaya gidiyor.** Cihaz ekle → Flutter; Agent Fleet QR → Kotlin; `deployments/android/` boş olduğu için QR 503 döner | `agent_api.go:2466, 2584-2606` |
| **K8** | **Masaüstü kabuğu yanıltıcı.** Tray menüsü çalışmıyor, "Windows Hello" kartı macOS ve Linux'ta da görünüyor, sunucu ayarı sessizce yok sayılıyor | `client/lib/ui/tray.dart:8-10,37-45`, `home_screen.dart:72-94`, `desktop_engine_client.dart:349-351` |
| **K9** | **"Neden erişemiyorum?" yalnız konsolda.** Tray step-up ve onay nedenlerini söylüyor (iyi); telefon ve Linux hiçbir şey söylemiyor | `agent/internal/tray/refusal.go` |
| **K10** | **Belgeler istemciyi anlatmıyor.** Belge sitesinin menüsünde istemci bölümü yok; `AGENT-TUNNEL.md`, `windows/mfa-without-a-phone.md` ve `mobile/` sitede yok; `NTFY_PUSH_NOTIFICATIONS.md` silinmiş React Native uygulamasını anlatıyor | `docs/mkdocs.yml` nav |
| **K11** | **Erişilebilirlik.** Flutter'da `Semantics` yok; TOTP sayacının etiketi yok; tek `semanticLabel` | `client/lib/ui/screens/mobile/authenticator_screen.dart` |
| **K12** | **Yükseltme.** Windows 6 saatte bir otomatik; Linux ve macOS elle; "güncelleme var" bildirimi yalnız elle kontrolde | `agent/internal/winservice/service_windows.go:161-196`, `agent/internal/updater/apply_other.go:66` |

### 7.3 İlkeler

1. **Aynı beş durum, aynı kelimeler, her yerde:** kayıtsız · onay bekliyor ·
   kayıtlı · güvenilir · iptal edildi.
2. **Her reddin bir nedeni ve bir sonraki adımı var.** "Bağlanamadı" yasak;
   "ikinci faktörünüz 20 dakikadan eski, yeniden giriş yapın" serbest.
3. **Kurulum üç adım, beş dakika, uyarısız.** İndir → tıkla → giriş yap.
   SmartScreen ya da "bilinmeyen geliştirici" uyarısı bir hata sayılır.
4. **Kullanıcının dili.** Konsolun TR/EN kuralı istemcilere de uygulanır.
5. **Sessiz başarısızlık yok.** Push gelmiyorsa uygulama nedenini söyler; tünel
   kopuksa tray söyler; politika uygulanamıyorsa konsol "uygulandı" demez.

---

## 8. Hedef ekosistem: 12 ay sonrası

### 8.1 Resim

```
                         ┌──────────────── KONTROL DÜZLEMİ ────────────────┐
                         │ Agent Fleet · Network policy (tünel + DNS)      │
                         │ Enrollment tokens · Decision explain · Metrics  │
                         │ api/agent-v1.yaml (tek sözleşme)                │
                         └───────┬───────────────┬───────────────┬─────────┘
                                 │               │               │
        ┌────────────────────────▼──┐  ┌─────────▼─────────┐  ┌──▼──────────────────────┐
        │ MASAÜSTÜ: openidx-agent   │  │ TELEFON: Flutter  │  │ TARAYICI ve CLI         │
        │ Windows · macOS · Linux   │  │ Android · iOS     │  │ konsol/portal (TR/EN)   │
        │ tray (TR/EN) · tünel      │  │ mağazada          │  │ vendor portalı · BrowZer│
        │ always-on/split/full      │  │ TOTP · push (arka │  │ openidx CLI: login,     │
        │ block-direct her OS       │  │ planda) · integrity│  │ ssh/rdp, doctor         │
        │ TPM tanıklığı · doctor    │  │ (karar) VPN tüneli│  │                         │
        └───────────────────────────┘  └───────────────────┘  └─────────────────────────┘
                 │ MSI (CA imzalı, winget) · pkg (notarize, brew) · deb/rpm (imzalı depo)
                 │ MDM: Intune / Jamf / Android Enterprise şablonları
                 ▼
        ┌───────────────────────── AĞ ─────────────────────────┐
        │ controller HA (Raft 3) · ağ başına router · egress   │
        │ split DNS · metrik + alarm · canlı CI                │
        └──────────────────────────────────────────────────────┘
```

### 8.2 Katman katman: bugün ve 12 ay sonra

| Katman | Bugün | 12 ay sonra |
|---|---|---|
| Masaüstü | Windows ajan + tray; Linux ajan; macOS yok | Tek ajan, üç işletim sisteminde tray; MSI (güvenilir CA, winget), deb/rpm (imzalı depo), pkg (notarize, Homebrew) |
| Telefon | Flutter (Android yan yükleme, iOS yok) | Play ve App Store (TestFlight); arka planda push; integrity; mobil tünel kararı verilmiş |
| Tarayıcı | Konsol TR/EN, portal, vendor portalı, BrowZer (compose) | Aynı + Helm'de BrowZer; httpOnly refresh çerezi (#965) |
| Komut satırı | `openidx-connect` (token elle) | `openidx` CLI: PKCE giriş, ssh/rdp, doctor, yönetim |
| Ağ | split; Linux root'ta engelleme; tek controller (compose) | always-on + split/full + engelleme her OS'ta; egress router; controller HA; DNS politikası; metrik ve alarm |
| Kimlik ve güven | Token + TPM anahtarı (beyan) | TPM / Play Integrity / App Attest tanıklığı; nonce'lu rapor; tek iptal yolu; karantina |
| Yönetim | Agent Fleet, Network policy | Kayıt token'ı arayüzü, MDM şablonları, EDR duruşu (Wazuh / Defender) |
| Entegrasyon | ntfy; SIEM webhook'ları | ntfy + FCM/APNs; SCIM dışa; (ROADMAP "Later") Okta/Entra içe aktarma |
| Geliştirici | Yok | `api/agent-v1.yaml`, üretilmiş Go/TS/Dart istemciler, sözleşme testi |

### 8.3 Platform kapsamı ve dağıtım kanalı

| Platform | Kabuk | Kanal | Kayıt yolu | Faz |
|---|---|---|---|---|
| Windows 10/11 | Go tray | MSI (CA imzalı), winget, Intune | `openidx://enroll`, MSI özelliği, GPO | 1 |
| macOS 13+ | Go tray | pkg (notarize), Homebrew cask, Jamf | `openidx://enroll`, pkg özelliği | 2 |
| Linux (Ubuntu/Debian, RHEL/Fedora) | Go tray (AppIndicator) | apt/yum deposu (GPG) | komut satırı, `.desktop` bağlantısı | 1 (paket), 2 (tray) |
| Android 11+ | Flutter | Play (iç test → üretim), AE şablonu | QR, bağlantı, giriş | 1 (mağaza), 3 (push, integrity) |
| iOS 16+ | Flutter | TestFlight → App Store | bağlantı, giriş | 1 (TestFlight), 3 |
| Tarayıcı | Konsol, portal, BrowZer | - | - | var |
| Sunucu/CLI | `openidx` CLI | GitHub release, cosign | PKCE giriş | 3 |

---

## 9. Kesin yol haritası

### 9.0 Kurallar

1. **M1 bitene kadar yalnız "düzeltme" türü işler.** Her satırda tür yazılıdır:
   *düzeltme* (yanlış ya da eksik uygulanan bir şeyi doğru yapar; M1 ile
   uyumludur) ya da *özellik* (yeni yetenek; M1 sonrası ya da proje sahibinin
   yazılı onayıyla).
2. **Sıra:** önce yanlış olanı doğru yap (Faz 0), sonra eksik olanı tamamla
   (Faz 1), sonra yeni platform ekle (Faz 2-3).
3. **Her iş** bir issue, bir PR, iki yönlü test (izin verilen çalışır, yasak
   reddedilir), gerekiyorsa bir "görünen = uygulanan" satırı ve bir changelog
   parçası ister. Güvenlik yollarına dokunan PR insan onayı bekler
   (`docs/AI-WORKING-AGREEMENT.md` §2).
4. **Her ağ ve güvenlik kapısı önce observe, sonra enforce.**
5. **Bir faz, çıkış kriterleri kanıtla kapanmadan sonraki faz "başladı" sayılmaz.**
   Paralel iş olur; "bitti" demek olmaz.

Büyüklük: S = bir gün, M = bir hafta, L = iki ila dört hafta, XL = daha uzun.

### 9.1 Faz 0: Gönderilen doğru olsun (2026-10-20 → 2026-11-07)

Hepsi *düzeltme*; M1 ile uyumlu.

| ID | İş | Çözdüğü | Bitti kanıtı | Büyüklük | Kim |
|---|---|---|---|---|---|
| F0-1 | Yeniden kayıtta sahiplik: aynı `enrolled_by` kullanıcı ya da operatör token'ı, ya da mevcut cihaz anahtarıyla imzalı istek; aksi hâlde yeni satır. Cihaz anahtarı yalnız imzalı istekle değişir | G1 | Red testi: başka kullanıcının parmak iziyle kayıt → 409, `agent.enroll_denied` | S | AI yazar, sahip inceler |
| F0-2 | Tier-0 kapı: `agent.enroll` kapsamı, iptal kesme noktası, taze ikinci faktör, 15 dakikalık JWT | G5 | İki yönlü test; denetim olayı | S | AI, sahip inceler |
| F0-3 | Tek `RevokeDevice`: Agent Fleet, Access 360 ve kill switch aynı fonksiyonu çağırır; kill switch'e "cihazları karantinaya al" | G7, M4 | Test: Fleet iptali → token ailesi iptal, bilinen cihaz güvensiz, Ziti oturumları kesik | M | AI, sahip inceler |
| F0-4 | Uzaktan destek varsayılanları: kuruluş politikasında onay zorunlu (varsayılan açık), "onaysız" ayrı izin + gerekçe + taze ikinci faktör; kayıt broker'da ve zorunlu; üretimde kayıt anahtarı yoksa başlatma | G3 | Görünen = uygulanan satırı; red testleri | M | AI, sahip inceler |
| F0-5 | Windows'ta `ziti-identity.json` ve `ziti-enrollment.jwt` için DACL; JWT kullanıldıktan sonra silinir | G2 | Windows runner testi | S-M | Karar K2 sonra AI |
| F0-6 | **Sözleşme testi** CI'da: sunucu + sahte ajan: enroll → config → report (eski ve yeni biçim) → tunnel_status → revoke → 403 | M2 | `ci.yml`'de `agent-contract` işi yeşil | M | AI |
| F0-7 | `api/agent-v1.yaml`: mevcut ajan rotalarının OpenAPI şeması; sunucu ve ajan tiplerinin şemayla uyumunu doğrulayan test | M2, M5 | Guard yeşil; CONTRIBUTING'de sürüm kuralı | M | AI |
| F0-8 | Belge diyeti (Ek B'nin tamamı) ve belge sitesine "Clients" bölümü (`AGENT-TUNNEL.md`, `windows/mfa-without-a-phone.md`, `mobile/push-mfa-delivery.md`) | M8, K10 | Bağlantılar yeşil; `docs.yml` yeşil | S | AI |
| F0-9 | Telefon küçükleri: Notifications ekranını bağla ya da kaldır; okundu gövdesi; `zitiDial` yanıtı; push gelmiyorsa ekranda nedeni; kilit için fail-closed seçeneği | K4 (kısmen), G10 (kısmen) | Widget testleri | S | AI |
| F0-10 | Yerel sınır küçükleri: Unix soketinde eş kimlik kontrolü, `XDG_RUNTIME_DIR` zorunlu, Ziti köprüsü yalnız açan sürece, `insecure_skip_verify` `ConfigTrusted`'a, `created_by` token'dan, istek boyutu sınırı, tek uyum özeti | G13, M3 | Testler | S | AI |
| F0-11 | İmzalama yalnız tag ve dispatch'te, `environment: release-signing` ile; manifeste `expires` | G8 | Workflow + guard; PR derlemesi imzasız | S | AI; sahip environment'ı açar |
| F0-12 | Filo alarmları compose ve Helm kural dosyalarına; `openidx_agents_by_state`, `openidx_tunnel_policy_gaps` metrikleri; boşluklu cihaz "applied" sayılmaz | N8, N9 | `promtool` testi; rozet testi | S | AI |
| F0-13 | Dondurma işlemleri (#966): Kotlin ajanının ve masaüstü kabuğunun test kaynağı olmayan CI işleri kaldırılır; README matrisi "Experimental, on hold"; Agent Fleet'teki AE QR, APK yokken açıklama gösterir | M1, K7 | Matris güncel; CI dakikaları düşer | S | AI |

**Çıkış kriteri:** G1, G2, G3, G5, G7 kapalı ve her biri bir red testiyle
kanıtlı; `agent-contract` işi yeşil; Ek B'de açık madde yok; alarmlar yüklü.

### 9.2 Faz 1: Güven tabanı (2026-11-10 → 2026-12-19, v2.0 LTS ile)

| ID | İş | Çözdüğü | Tür | Bitti kanıtı | Büyüklük | Kim |
|---|---|---|---|---|---|---|
| F1-1 | Mağaza hazırlığı (#966): uygulama kimliği (K1), yükleme anahtarı + Play App Signing, Apple Developer hesabı, TestFlight; `Info.plist` kullanım açıklamaları (kamera, Face ID); ikonlar; artefakt adları; Gradle dosyaları depoya | K2 | düzeltme (M1 #966) | Play iç test ve TestFlight'ta imzalı derleme | M | Sahip (hesaplar, kimlik) + AI |
| F1-2 | Yerelleştirme: Flutter (`flutter_localizations` + ARB) ve tray (basit katalog) TR/EN; dil = işletim sistemi dili | K1 | düzeltme (görünen = uygulanan: "TR arayüz" iddiası) | Her ekran iki dilde; eksik anahtar testi | M | AI |
| F1-3 | Windows MSI güvenilir sertifika (OV/EV ya da Azure Trusted Signing); SmartScreen itibarı | K2, G8 | düzeltme | Temiz Windows'ta uyarısız kurulum (video) | S + satın alma | Sahip satın alır, AI bağlar |
| F1-4 | deb/rpm GPG imzası ve apt/yum deposu; `install.sh` ve `.ps1` için `SHA256SUMS` + cosign doğrulama; `nfpm` checksum; her istemci artefaktı için provenance | G9 | düzeltme (#960/#967) | Doğrulama adımları `docs/RELEASING.md`'de; test | M | AI |
| F1-5 | Linux paketi: sertleştirilmiş birim + `openidx-agent` kullanıcısı paketlenir; config dizini tek; `latest.json`'da Linux girdileri; `update --apply` paket yöneticisiyle | M6, K12 | düzeltme | Temiz Ubuntu ve RHEL'de kurulum ve güncelleme (CI) | M | AI |
| F1-6 | Tanıklık hazırlığı: Windows'ta TPM EK sertifikası ve anahtar tanıklığı toplanır, saklanır, Agent Fleet'te "attested" gösterilir; karar verilmez (observe) | G4 | özellik (sahip onayı; M1 sonrası da olabilir) | Alan dolu; testler | M | AI, sahip onayı |
| F1-7 | Rapor nonce'u (config yanıtında), tüm ajan rotalarında imza, tekrar önbelleği | G12 | düzeltme | Red testi: tekrar → 401 | S | AI, sahip inceler |
| F1-8 | Tehdit modeli istemci bölümü; pentest kapsamına ajan güncelleme zinciri ve Flutter | G14 | düzeltme (#959) | Belge; kapsam dosyası | S | AI |
| F1-9 | Denetim zinciri `unified_audit_events`'i kapsar ya da istemci olayları zincirli tabloya yönlenir; THREAT-MODEL A5 düzeltilir | G11 | düzeltme | Zincir doğrulama testi istemci olayı içeriyor | M | AI, sahip inceler |
| F1-10 | Kayıt token'ı konsol sayfası; "iptali geri al" yönetici işlemi (gerekçeli); kullanıcı kendi ajanını iptal edebilir; "güven iste" ya gerçek bir istek açar ya kaldırılır | K5, K6 | özellik (küçük; sahip onayı) | İki yönlü testler; görünen = uygulanan | M | AI |
| F1-11 | Uçtan uca kullanıcı yolculuğu CI'da: Windows runner'da MSI kur → sahte sunucuya kaydol → tray çıkar → iptal → tray "iptal edildi" | M2, K3 | düzeltme | `windows-client-build.yml`'de e2e işi | M | AI |
| F1-12 | Beş cihaz durumu her kabukta aynı sözcüklerle (telefon ekranına banner) | K3 | düzeltme | Ekran testleri | S | AI |

**Çıkış kriteri:** #966 kapalı; MSI uyarısız kuruluyor; deb/rpm imzalı depodan
kuruluyor; tray ve telefon TR/EN; tek iptal yolu; tehdit modeli istemci bölümü
yayında; e2e Windows yolculuğu CI'da yeşil.

### 9.3 Faz 2: Ağ tamamlama (2027 Q1)

| ID | İş | Çözdüğü | Tür | Bitti kanıtı | Büyüklük |
|---|---|---|---|---|---|
| F2-1 | macOS ajanı: tray (NSStatusBar), tunneler paketleme (TUN izni ve sistem uzantısı kararı), pkg + notarization, Homebrew cask | N1, K2 | özellik | Temiz macOS'ta kurulum → tünel (video, CI macOS işi) | L |
| F2-2 | Windows'ta doğrudan erişimi engelleme: WFP filtresi, tunneler süreci muaf | N4 | özellik | Windows runner'da red testi; `block_direct` boşluğu kalkar | L |
| F2-3 | macOS'ta engelleme: pf anchor | N4 | özellik | Aynı | M |
| F2-4 | Full tunnel: router'da `openidx-egress` (`host.v1`, 0.0.0.0/0) + politika anahtarı; önce observe; DNS ile birlikte | N3 | özellik | `full_tunnel` boşluğu kalkar; çıkış IP'si testi | L |
| F2-5 | DNS politikası: kuruluş politikasında `dns` alanı; kurum DNS'i overlay üzerinden; Windows NRPT, macOS resolver, Linux systemd-resolved; hosts hack'i kalkar | N5 | özellik | Ad çözümleme testi üç OS'ta | L |
| F2-6 | Controller HA compose (3 controller + 2 router) ve imzalayıcı rotasyon runbook'u; "ağ başına router" rehberi; konsolda "bu kaynağa ulaşan router yok" uyarısı | N6, N7 | düzeltme + özellik | Compose'da controller düşürme testi; uyarı testi | L |
| F2-7 | `openidx-agent doctor` ve konsolda yol izi (topology ↔ fleet) | tanılama | özellik | Çıktı belgede; test | M |
| F2-8 | Canlı controller CI işi: controller + router + Linux sahte cihaz tunneler → servis dial | N10 | düzeltme | `ci.yml` işi yeşil | L |
| F2-9 | Helm'de BrowZer ve PAM broker; APISIX'i ürünleştir ya da ingress-nginx'e karar | N11 | özellik | kind'da BrowZer smoke | L |
| F2-10 | Yerel RDP/SSH başlatma (#1119 madde 1) | #1119 | özellik (sahip onayı) | Tasarım #1119'da | L |

**Çıkış kriteri:** macOS kurulumu var; `block_direct` ve `full_tunnel` boşlukları
Windows ve macOS'ta kapalı; DNS politikası uygulanıyor; compose'da controller
düşünce ağ devam ediyor; canlı CI işi yeşil.

### 9.4 Faz 3: Mobil ve ekosistem (2027 Q2)

| ID | İş | Çözdüğü | Tür | Bitti kanıtı | Büyüklük |
|---|---|---|---|---|---|
| F3-1 | Arka planda push: Android ön plan servisi ya da FCM; iOS APNs (+ ntfy yedek); bildirime dokunuş → onay ekranı | K4 | özellik | Kilitli telefonda onay (video); gecikme ölçümü | L |
| F3-2 | Mobil integrity: Play Integrity (Flutter) ve App Attest; nonce sunucudan; politika boşsa geçmez | G4, G10 | özellik | Red testleri; "attested" oranı | L |
| F3-3 | SPKI pinning (yedekli), ekran görüntüsü koruması, Ziti kimliği bellekten (SDK değişikliği), TOTP sırlarında erişilebilirlik sınıfı | G10 | düzeltme | Testler | M |
| F3-4 | **Mobil tünel kararı (K4):** Android `VpnService` + `ziti-tunnel-sdk-c`, iOS `NetworkExtension`; ya da "telefonda yalnız uygulama içi ve BrowZer" | N2 | karar + özellik | Karar ADR'de; seçilirse pilot | XL |
| F3-5 | MDM şablonları (Intune, Jamf) ve Android Enterprise QR'ının Flutter'a taşınması | K7 | özellik | Şablonlar belgede; QR testi | M |
| F3-6 | EDR duruşu: Wazuh ve Defender sinyali cihaz uyumuna (belge var, çalışma kanıtı yok) | - | özellik | Canlı kanıt satırı | M |
| F3-7 | `openidx` CLI: PKCE giriş, ssh/rdp (`openidx-connect` birleşir), doctor, yönetim komutları | - | özellik | Belge; testler | L |
| F3-8 | OpenAPI'den Go/TS/Dart istemci üretimi; Terraform sağlayıcısı (ROADMAP "Later") | M2 | özellik | Üretilmiş kod CI'da | L |

**Çıkış kriteri:** Kilitli telefonda push onayı çalışıyor; attested cihaz oranı
ölçülüyor; mobil tünel kararı ADR'de; CLI ile giriş ve SSH.

### 9.5 Faz 4: Talep geldikçe (2027 H2 ve sonrası)

Her biri bir müşteri talebiyle ve bir ADR ile açılır:

- iOS yerel ajanı (duruş; Tier 2 iPhone).
- Windows oturum açma MFA'sı (credential provider; #1119 madde 3'ün ön koşulları:
  cihaz kimlikli faktör uç noktaları, çevrimdışı cevap, kurtarma yolu).
- Kiosk ve device owner (Kotlin ajanından Flutter'a).
- AI ajanları için kimlik ve ayrıcalıklı erişim (ROADMAP "Later").
- OpenID4VP ve AB dijital kimlik cüzdanı (müşteri çıkarsa).

### 9.6 Bağımlılıklar

```
F0-6 sözleşme testi ──▶ F0-7 OpenAPI ──▶ F3-8 SDK üretimi
F0-1 / F0-2 / F0-3 / F0-5 ──▶ F1-7 nonce ve imza ──▶ F1-6 tanıklık (observe) ──▶ F3-2 mobil integrity
F0-11 imzalama ortamı ──▶ F1-3 MSI sertifikası ──▶ F2-1 macOS notarization
F0-13 dondurma ──▶ F1-1 mağaza ──▶ F3-1 arka plan push ──▶ F3-4 mobil tünel kararı
F0-12 metrikler ──▶ F2-7 doctor ──▶ F2-8 canlı CI
F1-5 Linux paketi ──▶ F2-1 macOS (aynı tray ve paketleme deseni)
F2-5 DNS ──▶ F2-4 full tunnel
```

---

## 10. Durdurulacaklar ve dondurulacaklar

| Ne | Karar | Yerine | Ne zaman silinir |
|---|---|---|---|
| Kotlin Android ajanı (`agent-android/`) | Dondur (ROADMAP'te var); CI test işini kaldır | Flutter + Go motoru; kiosk ve AE talep gelirse Faz 4 | Altı ay talep gelmezse (2027-04) |
| Flutter masaüstü kabuğu (`client/` masaüstü hedefleri) | Dondur; CI'dan kaldır | Go tray (üç OS) | F2-1 bittiğinde |
| Ziti Desktop Edge rehberi (`docs/OPENIDX_ZITI_ARCHITECTURE.md` §12.3) | Geçici çözüm olarak işaretle | macOS ajanı | F2-1 bittiğinde |
| Windows kurulum betiğindeki hosts dosyası satırları | Kaldır | DNS politikası (F2-5) | F2-5 bittiğinde |
| Serbest "Add service" Ziti formu (zaten deprecated) | Kaldır | Ağ kaynakları | v2.1 |
| `allow_unsigned_plugins`, `--insecure`, `insecure_skip_verify` | Belgede "yalnız laboratuvar"; üretim uyarısı | - | - |
| Her istemci için ayrı "uyum özeti" hesabı | Tek fonksiyon (F0-10) | - | Faz 0 |

---

## 11. Proje sahibinin kararları

| # | Karar | Seçenekler | Öneri | Neden | Son tarih |
|---|---|---|---|---|---|
| K1 | Uygulama kimliği ve bundle ID | Sahip olunan ters DNS adı | `org.openidx.client` gibi, Kotlin'in `com.openidx.agent`'inden farklı; alan adı kararıyla birlikte | #966 başlayamıyor | Faz 0 içinde |
| K2 | Windows'ta Ziti kimliği ACL'i (G2): tray'in overlay sinyali ne olacak? | (a) kimlik SYSTEM'e kilitli, tray sinyali servis üzerinden pipe'la; (b) tray için ayrı dar kimlik; (c) bugünkü gibi | **(a)**; tek kimlik, tek sorumlu | Özel anahtar sızıntısı | Faz 0 başı |
| K3 | Kod imzalama bütçesi | OV/EV sertifika ya da Azure Trusted Signing; Apple Developer; Play Console | Hepsi; yıllık ~1.000 USD civarı (fiyatlar değişir, kontrol edin) | SmartScreen ve mağaza | Faz 1 başı |
| K4 | Mobil tünel | VPN (Android VpnService, iOS NetworkExtension) ya da "telefonda yalnız uygulama içi ve BrowZer" | Talep gelene kadar BrowZer; Faz 3'te pilotla karar | En pahalı iş | Faz 3 |
| K5 | macOS önceliği | Faz 2 (Q1) ya da talep | Faz 2; tasarım ortaklarında Mac oranı yüksek olur | N1 | Faz 1 sonu |
| K6 | Uzaktan destek varsayılanı | Onay zorunlu + "onaysız" ayrı izin; ya da bugünkü | Onay zorunlu; onaysız yalnız `super_admin` ve gerekçeyle | G3 | Faz 0 |
| K7 | Kotlin ajanı: silme tarihi | 2027-04 ya da talep | 2027-04 | M1 | Faz 1 |
| K8 | Yerel RDP/SSH (#1119 madde 1) | Faz 2'de yap / bekle | Faz 2 sonunda, Windows engelleme (F2-2) ile birlikte | Tasarım hazır | Faz 2 başı |
| K9 | Ajan sürüm uyumluluğu | N-1 / N-2 / sınırsız | N-2 | M5 | Faz 0 (F0-7 ile) |
| K10 | Dil politikası | Her istemci TR/EN; ya da yalnız konsol | Her istemci TR/EN | K1 | Faz 1 |
| K11 | GitHub `release-signing` environment'ı ve gerekli onaylayıcı | Oluştur | Oluştur; onaylayıcı siz | G8 | Faz 0 |
| K12 | Pentest kapsamına istemciler | Ajan güncelleme zinciri + Flutter / yalnız sunucu | İkisi de | G14, #959 | Faz 1 |

---

## 12. Ölçütler

| Ölçüt | Bugün | Faz 1 sonu | 12 ay |
|---|---|---|---|
| Temiz cihazda kurulumdan ilk overlay bağlantısına süre | Ölçülmüyor | ≤ 10 dk (Windows) | ≤ 5 dk (üç OS) |
| Filoda "politika uygulandı" oranı (boşluksuz) | Ölçülmüyor (boşluklu cihaz "applied" sayılıyor) | Ölçülüyor | ≥ %95 |
| Duruş raporu gecikmesi (p95) | Ölçülmüyor | ≤ 60 sn | ≤ 60 sn |
| Yüksek önemli açık güvenlik bulgusu (G1-G5) | 5 | 0 | 0 |
| Tanıklığı olan (attested) cihaz oranı | %0 (yok) | Ölçülüyor | ≥ %80 (Windows) |
| İmzalı istemci artefaktı oranı | MSI (kendinden imzalı) | %100, güvenilir anahtarlarla | %100 + provenance |
| "İki uç uyumsuz" hata sınıfı (sürüm başına) | 5 / 3 hafta | 0 (sözleşme testi) | 0 |
| Push onayının telefona ulaşma süresi (p95) | Yalnız uygulama açıkken | Ölçülüyor | ≤ 5 sn, kilitli telefonda |
| Platform kapsamı (tray + tünel) | Windows (tam), Linux (yarım) | Windows, Linux | Windows, macOS, Linux |
| İstemci dili | EN | TR/EN | TR/EN |
| Ajan sürüm dağılımı | Ölçülmüyor | Ölçülüyor | ≥ %90 N-2 içinde |

---

## 13. Bu haritayı nasıl yürütürsünüz

**Issue şablonu** (her F-satırı bir issue):

```text
Başlık: F0-1 Yeniden kayıtta sahiplik kontrolü
Çözdüğü: G1 (docs/plans/2026-10-15-istemci-ekosistemi-analizi-ve-yol-haritasi.md §6.2)
Tür: düzeltme (M1 ile uyumlu) | özellik (onay: ...)
Bitti kanıtı: red testi "başka kullanıcının parmak iziyle kayıt → 409"; audit olayı; changelog parçası
Güvenlik yolu: evet (internal/access) → insan onayı
```

**AI oturumu için başlangıç talimatı:**

```text
docs/plans/2026-10-15-istemci-ekosistemi-analizi-ve-yol-haritasi.md §9'u,
ROADMAP.md'yi ve docs/AI-WORKING-AGREEMENT.md'yi oku. main yeşil değilse önce
onu düzelt. Sonra açık fazın "Kim" sütunu seni gösteren ilk bitmemiş satırını
al ve yalnız o PR'ı yap. Türü "özellik" olan bir satıra onay yazılı değilse
başlama; sahibin kararını (§11) gerektiren bir satıra gelirsen issue'ya tam
soruyu yaz ve dur. Bitince bu belgedeki satırı işaretle.
```

**Haftalık ritim:** Pazartesi fazın tablosundan en çok üç satır seçilir; Cuma
her satır için kanıt (test adı, ekran görüntüsü ya da video) issue'ya eklenir.
Faz sonunda çıkış kriterleri tek tek kontrol edilir ve bu belgenin ilgili
bölümüne "kapandı: tarih" yazılır.

**Bitti tanımı** (`docs/AI-WORKING-AGREEMENT.md` §3 ile aynı): iki yönlü test;
görünen = uygulanan satırı; kısa kullanıcı belgesi; changelog parçası; güvenlik
yolunda insan incelemesi; PR'da "doğrulandı / doğrulanmadı" bölümü.

---

## 14. ROADMAP.md için önerilen değişiklik

`ROADMAP.md` proje sahibinindir; bu belge onu değiştirmez. Kabul edilirse aşağıdaki
bölüm M3'ün altına eklenir ve "Later" listesindeki istemci maddeleri buraya taşınır
(İngilizce, dosyanın diliyle):

```markdown
### M4 — Client ecosystem: one engine, three shells (after M1; network and
mobile phases run in 2027) · [analysis](docs/plans/2026-10-15-istemci-ekosistemi-analizi-ve-yol-haritasi.md), ADR 0003 (proposed)

Phase 0 (fixes, inside M1): re-enrolment proves ownership; the Tier-0 door
requires the `agent.enroll` scope; one device revoke; remote-support consent on
by default; the device's overlay key readable only by SYSTEM; an agent API
contract test in CI; fleet alerts loaded.

Phase 1 (with v2.0 LTS): store-ready mobile client (#966); trusted code-signing
certificate; signed deb/rpm repository; Turkish and English in the tray and the
phone app; TPM attestation collected (observe); client section of the threat
model.

Phase 2 (2027 Q1): macOS agent and package; block-direct on Windows (WFP) and
macOS (pf); full tunnel through an egress router; DNS policy; controller HA on
Compose; `openidx-agent doctor`; a live-controller CI job.

Phase 3 (2027 Q2): background push on Android and iOS; Play Integrity and App
Attest; the mobile tunnel decision; MDM templates; `openidx` CLI; generated SDKs.

Frozen: the Kotlin Android agent and the Flutter desktop shell (deleted when the
Go tray covers macOS and Linux).
```

---

## Ek A: Yöntem ve kanıtlar

**Okunanlar.** `agent/` (18 iç paket, komutlar, paketleme, iş akışları),
`client/` (ekranlar, API istemcileri, eklenti köprüsü, testler), `agent-android/`
(üç modül), `cmd/openidx-connect/`, `internal/access/` (ajan API'si, cihaz
kimliği, tünel politikası, kill switch, uzaktan destek, kayıt), `web/admin-console/src/pages/`
(cihaz, filo, ağ, portal sayfaları), `deployments/` (compose, Helm, APISIX,
Terraform, systemd), `.github/workflows/` (19 iş akışı), `docs/` (tasarım,
tehdit modeli, tünel, ağ, HA, pentest kapsamı), `CHANGELOG.md` v1.37.0 → v1.46.0,
GitHub issue'ları #954 ve alt issue'ları, #966, #1094, #1119.

**Kodda ikinci kez doğrulananlar** (dosya ve satır belgenin içinde):

1. G1: `/agent/enroll/session` operatör kapısı olmadan JWT grubunda; parmak
   iziyle yeniden kayıt sahiplik kontrolsüz; `setAgentDeviceKey` anahtarı
   isteğe göre değiştiriyor ya da siliyor.
2. G2: `ziti-identity.json` ve `ziti-enrollment.jwt` `os.WriteFile(…, 0600)` ile.
3. G3: `consent_required` istek alanı, varsayılan `false`.
4. G5: `resolveEnrollSubject` kapsam istemiyor; `ReEnrollIdentity` 7 günlük
   süre veriyor.
5. G7: kill switch yorumu "device identities are left in place"; Fleet iptali ile
   Access 360 iptali farklı işler yapıyor.
6. G8: `windows-client-build.yml` `pull_request` tetiklemesi ve job env'de PFX.
7. G11: `internal/audit/chain.go` yalnız `audit_events` tablosunu güncelliyor;
   `unified_audit_events` için zincir kodu yok.
8. Ajan config aralığı: aktif cihazda 30 sn, uzaktan destekte 5 sn, askıda 24 saat.
9. Telefon: bildirim eklentisi yok (`pubspec.yaml`); kilit `canBypass` fail-open.
10. Yerelleştirme: tray'de katalog yok; `client/pubspec.yaml`'da
    `flutter_localizations` yok.

**Ölçülmeyenler.** Derleme ve testler bu ortamda koşmadı (Flutter, Android SDK,
Windows, canlı OpenZiti yok). Canlı kurulumun kullanım verileri. GitHub
Actions'ın güncel durumu. Fiyatlar (K3) tahmindir.

**Satır sayıları** (`wc -l`, 2026-10-15): Go ajanı 16.693 kod + 13.213 test;
Flutter 7.197 Dart + 609 Kotlin/Swift, 1.908 test; Kotlin ajanı 3.540, 0 test;
`openidx-connect` 345; konsol 100.988 TS; `internal/access` 69.218.

## Ek B: Belge ile kod arasındaki çelişkiler

Her satır F0-8'in bir parçasıdır.

| Belge | Ne diyor | Kod ne yapıyor |
|---|---|---|
| `docs/CLIENT-ACCESS-DESIGN.md` §1 | Kayıt "pending" ile başlar | Her kayıt doğrudan `active` (`agent_api.go:312`) |
| `docs/THREAT-MODEL.md` A5 (satır 110) | `unified_audit_events` HMAC zincirli | Zincir yalnız `audit_events` (`internal/audit/chain.go`) |
| `docs/THREAT-MODEL.md` §4.9 | Uzaktan destek oturumları §4.7 kriptosuyla kaydedilir | Yalnız tedarikçi oturumları broker'da; personel oturumları isteğe bağlı ve tarayıcıda |
| `docs/THREAT-MODEL.md` §4.9 | Çalınan cihaz "yalnız kendi Ziti kimliğini taşır" | Cihaz kimliği kullanıcının uygulama özniteliklerini taşıyor (v1.42) |
| `docs/THREAT-MODEL.md` R6, `README.md` 47-49 | RLS bypass açık | v1.42'de rol oldu (`DATABASE_BYPASS_URL`); #964 hâlâ açık ama bu madde kapandı |
| `docs/NTFY_PUSH_NOTIFICATIONS.md` "Mobile app subscription" | WebSocket, expo-notifications, `/api/v1/notifications/push-config` | Flutter 3 saniyede bir `/{topic}/json?poll=1` sorguluyor; eski React Native uygulaması silinmiş |
| `docs/mobile/push-mfa-delivery.md` "Verifying delivery" | "Dokunulabilir" bildirim | Uygulama hiç bildirim göstermiyor |
| `agent/packaging/DEEPLINK.md:45` | CI'da macOS `pkgbuild` adımı | Hiçbir iş akışında yok |
| `cmd/openidx-connect/README.md` | Varsayılan sunucu kuruma özgü bir alan adı | Kodda varsayılan yok; site değeri (#977) |
| `docs/mobile-openziti-integration-guide.md` | Silinmiş uygulama için tasarım | Flutter'da yalnız loopback köprü; cihaz çapında tünel tasarımı yok |
| `docs/security/pentest-scope.md` madde 6 | Manifest `release.yml`'de imzalanır | `windows-client-build.yml:768-845`'te |
| `docs/ZITI_HA_DEPLOYMENT.md:136-145`, `docs/OPENIDX_ZITI_ARCHITECTURE.md:521-523` | IAM cihaz güveni `#device-trusted` verir | v1.42'den beri yalnız ajan uyumundan, kapı `enforce` iken |
| `docs/openidx-trafik-mimarisi.md:169,177` | "Azure modülü eksik" | `deployments/terraform/azure/` var |
