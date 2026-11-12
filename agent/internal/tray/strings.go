package tray

// strs is every user-facing string the tray shows: menu labels, tooltips,
// status lines and notifications. One table per language, so a new item
// cannot be added in English only without a test noticing (see strings_test).
type strs struct {
	Lang string

	AppName, Quit, QuitTip string

	NotSignedIn, SignedIn, SignIn, SignInTip, SignOut, SignOutTip string
	SessionExpired, SignInFailed                                  string

	ClaimSignIn, ClaimNow, ClaimTip string

	ReEnroll, ReEnrollTip, ReEnrollMessage string
	Hello, HelloTip                        string
	OpenApps, OpenAppsTip                  string
	Connections, ConnectionsTip            string

	Health, HealthTip, HealthOK, HealthPrefix string

	Network, NetworkTip                           string
	NetConnected, NetConnecting, NetOff, NetError string
	NetServiceOne, NetServicesN, NetMore          string
	NetOffHint, NetNotInstalled                   string

	Settings, Autostart, AutostartTip, Updates, UpdatesTip, About, AboutTip string

	AdminSees, AdminControls string

	NotEnrolled, NotEnrolledStatus, BrowserFailed, PrefNotSaved       string
	FreshMFAAsk, SignedInAgain, AccessAsk, AccessSendFail, AccessSent string
}

var enStrings = strs{
	Lang:    "en",
	AppName: "OpenIDX", Quit: "Quit", QuitTip: "Quit OpenIDX",

	NotSignedIn: "Not signed in", SignedIn: "Signed in",
	SignIn: "Sign in", SignInTip: "Sign in to OpenIDX",
	SignOut: "Sign out", SignOutTip: "Sign out",
	SessionExpired: "Session expired · sign in again", SignInFailed: "Sign-in failed",

	ClaimSignIn: "Sign in to claim this device", ClaimNow: "Claim this device",
	ClaimTip: "Nobody owns this device yet; sign in to make it yours",

	ReEnroll:        "Enroll this device again",
	ReEnrollTip:     "The server no longer accepts this device's credential; enroll it again from the console",
	ReEnrollMessage: reEnrollMessage,
	Hello:           "Set up Windows Hello sign-in",
	HelloTip:        "Register Windows Hello or a security key as your passkey; no phone needed",
	OpenApps:        "Open my apps",
	OpenAppsTip:     "Open your OpenIDX apps in the browser",
	Connections:     "My Connections", ConnectionsTip: "Launch a privileged session",

	Health: "Device health", HealthTip: "Security checks on this device",
	HealthOK: "Device health: all checks pass", HealthPrefix: "Device health: ",

	Network: "Network", NetworkTip: "The OpenIDX network tunnel",
	NetConnected: "Connected", NetConnecting: "Connecting", NetOff: "Off", NetError: "Error",
	NetServiceOne: "1 service", NetServicesN: "%d services", NetMore: "…and %d more",
	NetOffHint:      "Off by policy. Your IT team turns it on for this device.",
	NetNotInstalled: "tunnel not installed",

	Settings: "Settings", Autostart: "Start when I sign in", AutostartTip: "Start the OpenIDX tray at Windows sign-in",
	Updates: "Check for updates", UpdatesTip: "Ask the update server whether a newer OpenIDX is published",
	About: "About OpenIDX", AboutTip: "Version, server and device",

	AdminSees:     "🔴 An OpenIDX admin can see this device",
	AdminControls: "🔴 An OpenIDX admin can see and CONTROL this device",

	NotEnrolled:       notEnrolledMessage,
	NotEnrolledStatus: "Not enrolled · open your enrollment link",
	BrowserFailed:     "The browser could not be opened.\n\nOpen this page yourself:\n",
	PrefNotSaved:      "The preference could not be saved.\n\n",
	FreshMFAAsk: "This connection needs a recently verified second factor.\n\n" +
		"Sign in again now? Your browser will ask for your second factor; " +
		"the connection is then one click away.",
	SignedInAgain: "Signed in. Click the connection again to open it.",
	AccessAsk: "This connection needs an approved access request.\n\n" +
		"Send a request now? An approver is notified; you can connect once they approve.",
	AccessSendFail: "The request could not be sent.\n\n",
	AccessSent:     "Your request was sent. You can connect once it is approved.",
}

var trStrings = strs{
	Lang:    "tr",
	AppName: "OpenIDX", Quit: "Çıkış", QuitTip: "OpenIDX'ten çık",

	NotSignedIn: "Oturum açılmadı", SignedIn: "Oturum açık",
	SignIn: "Oturum aç", SignInTip: "OpenIDX'te oturum aç",
	SignOut: "Oturumu kapat", SignOutTip: "Oturumu kapat",
	SessionExpired: "Oturum süresi doldu · yeniden oturum açın", SignInFailed: "Oturum açılamadı",

	ClaimSignIn: "Bu cihazı sahiplenmek için oturum açın", ClaimNow: "Bu cihazı sahiplen",
	ClaimTip: "Bu cihazın henüz sahibi yok; sizin olması için oturum açın",

	ReEnroll:        "Bu cihazı yeniden kaydet",
	ReEnrollTip:     "Sunucu bu cihazın kimlik bilgisini artık kabul etmiyor; konsoldan yeniden kaydedin",
	ReEnrollMessage: "Sunucu bu cihazı artık kabul etmiyor.\n\nMenüden \"Bu cihazı yeniden kaydet\" seçeneğini kullanın; tarayıcıda konsol açılır.",
	Hello:           "Windows Hello ile oturum açmayı kur",
	HelloTip:        "Windows Hello'yu veya bir güvenlik anahtarını geçiş anahtarı olarak kaydedin; telefon gerekmez",
	OpenApps:        "Uygulamalarımı aç",
	OpenAppsTip:     "OpenIDX uygulamalarınızı tarayıcıda açın",
	Connections:     "Bağlantılarım", ConnectionsTip: "Ayrıcalıklı oturum başlat",

	Health: "Cihaz sağlığı", HealthTip: "Bu cihazdaki güvenlik denetimleri",
	HealthOK: "Cihaz sağlığı: tüm denetimler geçti", HealthPrefix: "Cihaz sağlığı: ",

	Network: "Ağ", NetworkTip: "OpenIDX ağ tüneli",
	NetConnected: "Bağlı", NetConnecting: "Bağlanıyor", NetOff: "Kapalı", NetError: "Hata",
	NetServiceOne: "1 hizmet", NetServicesN: "%d hizmet", NetMore: "…ve %d tane daha",
	NetOffHint:      "İlke gereği kapalı. Bu cihaz için BT ekibiniz açar.",
	NetNotInstalled: "tünel kurulu değil",

	Settings: "Ayarlar", Autostart: "Oturum açtığımda başlat", AutostartTip: "OpenIDX tepsisini Windows oturum açılışında başlat",
	Updates: "Güncellemeleri denetle", UpdatesTip: "Güncelleme sunucusuna daha yeni bir OpenIDX olup olmadığını sor",
	About: "OpenIDX hakkında", AboutTip: "Sürüm, sunucu ve cihaz",

	AdminSees:     "🔴 Bir OpenIDX yöneticisi bu cihazı görebiliyor",
	AdminControls: "🔴 Bir OpenIDX yöneticisi bu cihazı görebiliyor ve DENETLEYEBİLİYOR",

	NotEnrolled: "Bu cihaz henüz kayıtlı değil, bu yüzden oturum açılacak bir yer yok.\n\n" +
		"Bu bilgisayarda OpenIDX konsolundaki kayıt bağlantısını açın veya yönetici komut isteminden\n" +
		"openidx-agent enroll --code <kod> --server <url> komutunu çalıştırın.",
	NotEnrolledStatus: "Kayıtlı değil · kayıt bağlantınızı açın",
	BrowserFailed:     "Tarayıcı açılamadı.\n\nBu sayfayı kendiniz açın:\n",
	PrefNotSaved:      "Tercih kaydedilemedi.\n\n",
	FreshMFAAsk: "Bu bağlantı yakın zamanda doğrulanmış bir ikinci faktör gerektiriyor.\n\n" +
		"Şimdi yeniden oturum açılsın mı? Tarayıcınız ikinci faktörünüzü isteyecek; " +
		"ardından bağlantı tek tık uzağınızda.",
	SignedInAgain: "Oturum açıldı. Açmak için bağlantıya yeniden tıklayın.",
	AccessAsk: "Bu bağlantı onaylanmış bir erişim isteği gerektiriyor.\n\n" +
		"Şimdi istek gönderilsin mi? Bir onaylayıcıya bildirilir; onaylandığında bağlanabilirsiniz.",
	AccessSendFail: "İstek gönderilemedi.\n\n",
	AccessSent:     "İsteğiniz gönderildi. Onaylandığında bağlanabilirsiniz.",
}

// langTurkish is the primary language id of Turkish (LANG_TURKISH).
const langTurkish = 0x1f

// stringsFor picks the table for a Windows LANGID: Turkish for any Turkish
// locale, English otherwise (including 0, "unknown").
func stringsFor(langID uint16) *strs {
	if langID&0x3ff == langTurkish {
		return &trStrings
	}
	return &enStrings
}

// T is the table for this session's UI language.
var T = stringsFor(uiLanguage())
