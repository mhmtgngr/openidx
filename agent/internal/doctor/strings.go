package doctor

import "fmt"

// Lang is an output language.
type Lang string

const (
	LangEN Lang = "en"
	LangTR Lang = "tr"
)

// ParseLang reads a --lang value; empty means the user's own language.
func ParseLang(s string) (Lang, error) {
	switch s {
	case "":
		return DetectLang(), nil
	case "en":
		return LangEN, nil
	case "tr":
		return LangTR, nil
	}
	return "", fmt.Errorf("unknown language %q (use en or tr)", s)
}

// Message says what is wrong and the one thing to do about it.
type Message struct {
	Title  string
	Action string
}

type ui struct {
	heading, healthy, problem, action, note, repair, skipped string
	checks                                                   map[string]string
	outcomes                                                 map[string]string
	repairs                                                  map[string]string
	codes                                                    map[string]Message
}

const fixHint = "openidx-agent doctor --fix"

var tables = map[Lang]*ui{
	LangEN: {
		heading: "OpenIDX connection check",
		healthy: "No problems found.",
		problem: "Problem",
		action:  "What to do",
		note:    "Note",
		repair:  "Repair",
		skipped: "skipped",
		checks: map[string]string{
			CheckConfig: "Agent setup", CheckCredentials: "Device sign-in", CheckDNS: "Name lookup",
			CheckTCP: "Connection to server", CheckTLS: "Secure connection", CheckHTTP: "Server answer",
			CheckClock: "Clock", CheckIdentity: "Network identity", CheckService: "Agent service",
			CheckTunnel: "Secure tunnel",
		},
		outcomes: map[string]string{
			OutcomePlanned: "would be tried with --fix", OutcomeApplied: "done",
			OutcomeFailed: "did not work", OutcomeNeedsElevation: "needs administrator rights",
		},
		repairs: map[string]string{
			RepairFlushDNS: "Clear the name lookup cache", RepairRestartService: "Restart the agent service",
		},
		codes: map[string]Message{
			CodeConfigUnreadable:   {"The agent's settings cannot be read with your account.", "Run this command as administrator (root on Linux)."},
			CodeNotEnrolled:        {"This device is not registered with OpenIDX yet.", "Open the OpenIDX portal, choose \"Add a device\" and follow the steps."},
			CodeAuthInvalid:        {"The server no longer accepts this device's sign-in.", "Register the device again from the portal (\"Add a device\")."},
			CodeDeviceRevoked:      {"An administrator has removed this device's access.", "Contact IT to have the device reinstated."},
			CodeDNSFail:            {"The server's name cannot be found on this network.", "Check that you are online. If other sites work, run `" + fixHint + "`, then contact IT."},
			CodeDNSTimeout:         {"Looking up the server's name takes too long.", "Check your internet connection and try again; if it persists, run `" + fixHint + "`."},
			CodeTCPBlocked:         {"This network refuses the connection to the server.", "Try another network (for example a phone hotspot). If that works, this network blocks OpenIDX; tell IT."},
			CodeTCPTimeout:         {"The server does not answer from this network.", "Try another network. If that works, a firewall here drops the traffic; tell IT."},
			CodeTLSUntrusted:       {"The secure connection is being intercepted or the network wants you to sign in first.", "Open a browser and complete any Wi-Fi sign-in page. On a company network, ask IT about TLS inspection."},
			CodeTLSFail:            {"A secure connection to the server could not be set up.", "Try again in a minute; if it keeps failing, send this output to IT."},
			CodeProxyAuthRequired:  {"The network's proxy asks for a user name and password.", "Ask IT for the proxy settings the agent should use."},
			CodeServerHTTPError:    {"The OpenIDX server is reachable but reports an error.", "Nothing is wrong with your device. Wait a few minutes; tell IT if it continues."},
			CodeHTTPTimeout:        {"The server takes too long to answer.", "Check your connection and try again."},
			CodeHTTPFail:           {"The server could not be reached.", "Check your internet connection, then try another network."},
			CodeClockSkew:          {"This computer's clock is wrong by more than five minutes.", "Turn on automatic date and time in the system settings."},
			CodeIdentityMissing:    {"The device's network identity file is missing.", "Register the device again from the portal (\"Add a device\")."},
			CodeIdentityExpired:    {"The device's network identity has expired.", "Register the device again from the portal (\"Add a device\")."},
			CodeIdentityExpiring:   {"The device's network identity expires soon.", "Nothing to do now; the agent renews it. Tell IT if this note stays for days."},
			CodeIdentityInvalid:    {"The device's network identity file is damaged.", "Register the device again from the portal (\"Add a device\")."},
			CodeServiceNotRunning:  {"The OpenIDX agent service is not running.", "Run `" + fixHint + "` as administrator, or restart the computer."},
			CodeTunnelDown:         {"The secure tunnel is not working.", "Run `" + fixHint + "` as administrator. If it does not recover, send this output to IT."},
			CodeTunnelNotInstalled: {"The secure tunnel component is not installed on this device.", "Reinstall the OpenIDX agent, or ask IT for the full installer."},
			CodeTunnelOff:          {"The secure tunnel is turned off for this device.", "This is normal if your organization does not use it. Otherwise ask IT to enable it."},
			CodeInternal:           {"One of the checks could not be completed.", "Send this output to IT."},
		},
	},
	LangTR: {
		heading: "OpenIDX bağlantı teşhisi",
		healthy: "Sorun bulunmadı.",
		problem: "Sorun",
		action:  "Ne yapmalı",
		note:    "Not",
		repair:  "Onarım",
		skipped: "atlandı",
		checks: map[string]string{
			CheckConfig: "Ajan kurulumu", CheckCredentials: "Cihaz oturumu", CheckDNS: "Ad çözümleme",
			CheckTCP: "Sunucuya bağlantı", CheckTLS: "Güvenli bağlantı", CheckHTTP: "Sunucu yanıtı",
			CheckClock: "Saat", CheckIdentity: "Ağ kimliği", CheckService: "Ajan servisi",
			CheckTunnel: "Güvenli tünel",
		},
		outcomes: map[string]string{
			OutcomePlanned: "--fix ile denenir", OutcomeApplied: "yapıldı",
			OutcomeFailed: "işe yaramadı", OutcomeNeedsElevation: "yönetici yetkisi gerekiyor",
		},
		repairs: map[string]string{
			RepairFlushDNS: "Ad çözümleme önbelleğini temizle", RepairRestartService: "Ajan servisini yeniden başlat",
		},
		codes: map[string]Message{
			CodeConfigUnreadable:   {"Ajanın ayarları sizin hesabınızla okunamıyor.", "Bu komutu yönetici olarak (Linux'ta root ile) çalıştırın."},
			CodeNotEnrolled:        {"Bu cihaz henüz OpenIDX'e kaydedilmemiş.", "OpenIDX portalını açın, \"Cihaz ekle\"yi seçin ve adımları izleyin."},
			CodeAuthInvalid:        {"Sunucu bu cihazın oturumunu artık kabul etmiyor.", "Cihazı portaldan yeniden kaydedin (\"Cihaz ekle\")."},
			CodeDeviceRevoked:      {"Bir yönetici bu cihazın erişimini kaldırmış.", "Cihazın yeniden etkinleştirilmesi için BT ile görüşün."},
			CodeDNSFail:            {"Sunucunun adı bu ağda bulunamıyor.", "İnternete bağlı olduğunuzu kontrol edin. Başka siteler açılıyorsa `" + fixHint + "` çalıştırın, sonra BT'ye bildirin."},
			CodeDNSTimeout:         {"Sunucunun adını bulmak çok uzun sürüyor.", "İnternet bağlantınızı kontrol edip tekrar deneyin; sürerse `" + fixHint + "` çalıştırın."},
			CodeTCPBlocked:         {"Bu ağ sunucuya bağlantıyı reddediyor.", "Başka bir ağ deneyin (örneğin telefon hotspot'u). Orada çalışıyorsa bu ağ OpenIDX'i engelliyor; BT'ye bildirin."},
			CodeTCPTimeout:         {"Sunucu bu ağdan yanıt vermiyor.", "Başka bir ağ deneyin. Orada çalışıyorsa buradaki güvenlik duvarı trafiği düşürüyor; BT'ye bildirin."},
			CodeTLSUntrusted:       {"Güvenli bağlantı araya girilerek kesiliyor ya da ağ önce oturum açmanızı istiyor.", "Bir tarayıcı açıp varsa Wi-Fi giriş sayfasını tamamlayın. Şirket ağındaysanız BT'ye TLS denetimini sorun."},
			CodeTLSFail:            {"Sunucuyla güvenli bağlantı kurulamadı.", "Bir dakika sonra tekrar deneyin; sürerse bu çıktıyı BT'ye gönderin."},
			CodeProxyAuthRequired:  {"Ağdaki vekil sunucu (proxy) kullanıcı adı ve parola istiyor.", "Ajanın kullanacağı proxy ayarlarını BT'den isteyin."},
			CodeServerHTTPError:    {"OpenIDX sunucusuna ulaşılıyor ama sunucu hata veriyor.", "Cihazınızda bir sorun yok. Birkaç dakika bekleyin; sürerse BT'ye bildirin."},
			CodeHTTPTimeout:        {"Sunucunun yanıt vermesi çok uzun sürüyor.", "Bağlantınızı kontrol edip tekrar deneyin."},
			CodeHTTPFail:           {"Sunucuya ulaşılamadı.", "İnternet bağlantınızı kontrol edin, sonra başka bir ağ deneyin."},
			CodeClockSkew:          {"Bu bilgisayarın saati beş dakikadan fazla yanlış.", "Sistem ayarlarından otomatik tarih ve saati açın."},
			CodeIdentityMissing:    {"Cihazın ağ kimliği dosyası yok.", "Cihazı portaldan yeniden kaydedin (\"Cihaz ekle\")."},
			CodeIdentityExpired:    {"Cihazın ağ kimliğinin süresi dolmuş.", "Cihazı portaldan yeniden kaydedin (\"Cihaz ekle\")."},
			CodeIdentityExpiring:   {"Cihazın ağ kimliğinin süresi yakında doluyor.", "Şimdilik bir şey yapmanız gerekmez; ajan yeniler. Bu not günlerce kalırsa BT'ye bildirin."},
			CodeIdentityInvalid:    {"Cihazın ağ kimliği dosyası bozuk.", "Cihazı portaldan yeniden kaydedin (\"Cihaz ekle\")."},
			CodeServiceNotRunning:  {"OpenIDX ajan servisi çalışmıyor.", "`" + fixHint + "` komutunu yönetici olarak çalıştırın ya da bilgisayarı yeniden başlatın."},
			CodeTunnelDown:         {"Güvenli tünel çalışmıyor.", "`" + fixHint + "` komutunu yönetici olarak çalıştırın. Düzelmezse bu çıktıyı BT'ye gönderin."},
			CodeTunnelNotInstalled: {"Güvenli tünel bileşeni bu cihazda kurulu değil.", "OpenIDX ajanını yeniden kurun ya da BT'den tam kurulum paketini isteyin."},
			CodeTunnelOff:          {"Güvenli tünel bu cihaz için kapalı.", "Kurumunuz tünel kullanmıyorsa bu normaldir. Kullanıyorsa BT'den açmasını isteyin."},
			CodeInternal:           {"Kontrollerden biri tamamlanamadı.", "Bu çıktıyı BT'ye gönderin."},
		},
	},
}

func table(l Lang) *ui {
	if t, ok := tables[l]; ok {
		return t
	}
	return tables[LangEN]
}

// MessageFor is the plain-language text for a cause code.
func MessageFor(code string, l Lang) Message {
	if m, ok := table(l).codes[code]; ok {
		return m
	}
	return table(l).codes[CodeInternal]
}
