# OpenIDX kullanıcı rehberi

Bu sayfa, OpenIDX'i ilk kez kullanacak bir çalışan içindir. Dört şey anlatır:
giriş, ikinci doğrulama (MFA), bilgisayarınıza ajan kurma ve uygulamalara
erişim. BT ekibi için sıra ve ayarlar `docs/runbooks/go-live-windows.md`
dosyasındadır.

Aşağıda `https://<sunucu>` yazan yerde kurumunuzun OpenIDX adresi vardır;
BT size bildirir.

## 1. Giriş

1. Tarayıcıda `https://<sunucu>` adresini açın.
2. Şirket kullanıcı adınız ve parolanızla girin (bilgisayara girdiğiniz
   hesap).
3. İlk girişte ikinci doğrulama istenir; bir sonraki bölüm bunu anlatır.

Girişten sonra **My Apps & Network** sayfası açılır. Size tanımlı
uygulamalar burada listelenir; çoğu tek tıkla tarayıcıda açılır, bilgisayara
bir şey kurmak gerekmez.

## 2. İkinci doğrulama (MFA)

Parolanın yanında bir ikinci kanıt gerekir. İki seçenek var; biri yeterlidir.

**Telefonda doğrulama uygulaması (önerilen):** Google Authenticator,
Microsoft Authenticator veya benzeri bir uygulama.

1. Telefonunuza uygulamayı kurun.
2. OpenIDX'te sağ üstten **Profile → Security** bölümüne gidin ve
   **Authenticator app** altında QR kodunu gösterin.
3. Telefondaki uygulamada "hesap ekle" deyip QR'ı okutun. Microsoft
   Authenticator'da "diğer hesap (Google, Facebook vb.)" seçeneğini kullanın.
4. Uygulamanın gösterdiği 6 haneli kodu OpenIDX'e girerek kaydı bitirin.
5. Ekrana gelen **yedek kodları** kaydedin. Telefonunuz yanınızda değilken
   giriş için bunlardan biri kullanılır; her kod bir kez geçerlidir.

**Windows Hello veya güvenlik anahtarı (passkey):** Aynı sayfada **Security
key / Windows Hello** ile bilgisayarınızın parmak izi, yüz tanıma ya da PIN'ini
kaydedebilirsiniz. Bu yalnızca kaydettiğiniz bilgisayarda çalışır; başka bir
yerden giriş için doğrulama uygulaması da kurmanız önerilir.

**Süre:** BT bir geçiş süresi tanımlar (genellikle 7 gün). Bu süre boyunca
giriş ekranı size kalan süreyi gösterir ve "Set up now" ile sizi kayıt
sayfasına götürür. Süre dolunca ikinci doğrulama olmadan giriş yapılamaz.

**Telefonu kaybettiyseniz veya değiştirdiyseniz:** BT'ye yazın. Ya ikinci
doğrulamanızı sıfırlarlar, siz yeniden kaydolursunuz; ya da tek kullanımlık
bir geçiş kodu verirler.

## 3. Bilgisayarınıza OpenIDX ajanını kurma (Windows)

Ajan, bilgisayarınızın güvenli olduğunu (güvenlik duvarı açık, disk şifreli,
ekran kilidi var, Windows güncel) OpenIDX'e bildirir ve ağ kaynaklarına
VPN'siz erişimi sağlar. Yalnızca BT size "ajanı kurun" dediyse kurun; web
uygulamaları için gerekmez.

Kurulum için bilgisayarda **yönetici** yetkisi gerekir.

1. OpenIDX'te **My Devices → Add a device** sayfasını açın, **Windows**
   seçin.
2. Adım 2'deki **Download the script** düğmesiyle betiği indirin
   (`trust-and-install-openidx-agent.ps1`).
3. Betiği indirdiğiniz klasörde Başlat menüsünden **Windows PowerShell →
   Yönetici olarak çalıştır** deyin ve sayfadaki komutu yapıştırıp çalıştırın
   (komutun yanındaki kopyala düğmesi vardır):

   ```
   powershell -ExecutionPolicy Bypass -File .\trust-and-install-openidx-agent.ps1 -Server https://<sunucu>
   ```

   Betik imza sertifikasını bilgisayarınıza tanıtır, kurulum dosyasını indirir,
   imzasını denetler ve kurar. 1-2 dakika sürer. "Unknown publisher" uyarısı
   çıkmaz; çıkarsa betik yerine MSI'ı doğrudan çalıştırmışsınızdır.
4. Aynı sayfada adım 3'te **Generate connect code** deyin ve **Open in app**
   düğmesine tıklayın. Ajan kodu alır ve sayfa birkaç saniye içinde "Device
   connected" der.
5. Görev çubuğunda OpenIDX simgesi belirir. **Network: Connected** yazıyorsa
   ağ erişimi hazırdır.

Kurulum bir kez yapılır. Ajan arka planda çalışır ve kendini günceller.

## 4. Uygulamalara ve ağa erişim

- **Web uygulamaları:** My Apps & Network'te uygulamanın kartına tıklayın.
  Tarayıcıda açılır. Bir uygulamayı görmüyorsanız size atanmamıştır;
  **Request access** ile isteyebilirsiniz.
- **Uzak masaüstü ve SSH:** Yine tarayıcıda açılır; bilgisayara bir program
  kurmak gerekmez. Bazı sistemler onay ister; onay gelince oturum başlar.
- **Dosya sunucuları, iç ağ adresleri, kalın istemciler:** Ajan kuruluysa bu
  adreslere eskisi gibi, VPN bağlamadan ulaşırsınız. Henüz OpenIDX'e taşınmamış
  bir adres için VPN'i kullanmaya devam edin; BT geçişi adım adım yapar.

**My Devices** sayfası cihazınızın durumunu gösterir. **Offline** yazıyorsa
ajan bir süredir rapor vermemiştir (bilgisayar kapalıydı, uykudaydı ya da
ajan durmuş); ajan tekrar rapor verince erişim kendiliğinden geri gelir.
**Non-compliant** yazıyorsa hangi kontrolün başarısız olduğu yanında yazar
(örneğin güvenlik duvarı kapalı); düzeltince bir sonraki raporla erişim
döner.

## 5. Sorun olursa

| Durum | Ne yapmalı |
| --- | --- |
| Giriş ekranı "expired" diyor | Sekmeyi kapatıp `https://<sunucu>` adresini yeniden açın. |
| Doğrulama kodu kabul edilmiyor | Telefonun saati otomatik ayarlı mı bakın; kod 30 saniyede bir değişir, yenisini bekleyin. |
| Telefon yanınızda değil | Kayıt sırasında aldığınız yedek kodlardan birini girin. |
| Telefon kayıp / değişti | BT'ye yazın: ikinci doğrulamanızı sıfırlar ya da geçiş kodu verir. |
| "Device connected" hiç gelmedi | Betiği yönetici PowerShell'de mi çalıştırdınız? Görev çubuğunda OpenIDX simgesi var mı? Yoksa betiği yeniden çalıştırın. |
| My Devices'ta Offline | Bilgisayar açık ve internete bağlıysa birkaç dakika bekleyin; geçmezse BT'ye cihaz adınızı yazın. |
| Bir adrese ulaşamıyorum | VPN'i bağlayıp deneyin; çalışıyorsa adres henüz taşınmamıştır, BT'ye bildirin. |
