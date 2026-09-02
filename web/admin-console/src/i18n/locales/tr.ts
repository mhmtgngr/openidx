import type en from './en'

// Turkish catalog. Typed against the English catalog: adding a key to en.ts
// without translating it here (or leaving a stale key behind) fails
// `npm run type-check`.
const tr: typeof en = {
  switcher: {
    label: 'Dil',
  },
  landing: {
    nav: {
      features: 'Özellikler',
      integrations: 'Entegrasyonlar',
      documentation: 'Belgeler',
      signIn: 'Oturum Aç',
      getStarted: 'Başlayın',
    },
    hero: {
      badge: 'Açık kaynak · Kendi sunucunuzda · Apache-2.0',
      titleLead: 'Modern kurumlar için',
      titleHighlight: 'Sıfır Güven Erişim Platformu',
      subtitle:
        'OpenIDX; SSO, MFA, erişim yönetişimi, ayrıcalıklı erişim ve Sıfır Güven ağını, bunları kanıtlayan denetim ve uyumluluk raporlamasıyla birlikte sunan eksiksiz bir kimlik ve erişim yönetimi platformudur. Açık kaynak, kendi sunucunuzda, kuruma hazır.',
      viewDocs: 'Belgeleri Görüntüle',
      point1: '%100 açık kaynak (Apache-2.0)',
      point2: 'Kendi sunucunuzda — verileriniz kendi altyapınızda kalır',
      point3: 'Docker Compose ile hızlı kurulum',
    },
    stats: {
      pillars: 'Sütun: IAM · IGA · PAM · ZTNA',
      services: 'Go Servisi',
      openSource: 'Açık Kaynak',
      darkPorts: 'Karanlık Servisler İçin Gelen Port',
    },
    features: {
      title: 'Eksiksiz Güvenlik Platformu',
      subtitle:
        'Uygulamalarınıza, verilerinize ve altyapınıza erişimi güvence altına almak için gereken her şey',
      zeroTrust: {
        title: 'Sıfır Güven Mimarisi',
        description:
          'Asla güvenme, her zaman doğrula. Her erişim isteği; erişim verilmeden önce eksiksiz olarak kimliği doğrulanır, yetkilendirilir ve şifrelenir.',
      },
      iam: {
        title: 'Kimlik ve Erişim Yönetimi',
        description:
          'Tüm uygulamalarınız için merkezî kullanıcı sağlama, rol tabanlı erişim denetimi ve yaşam döngüsü yönetimi.',
      },
      mfa: {
        title: 'Çok Faktörlü Kimlik Doğrulama',
        description:
          'TOTP, WebAuthn (geçiş anahtarları ve güvenlik anahtarları), anlık bildirim onayları ile SMS veya e-posta tek kullanımlık kodları.',
      },
      sso: {
        title: 'Tek Oturum Açma (SSO)',
        description:
          'SAML, OIDC ve sosyal kimlik sağlayıcı desteğiyle tüm uygulamalarınıza tek oturumla erişin.',
      },
      monitoring: {
        title: 'Gerçek Zamanlı İzleme',
        description:
          'Kapsamlı denetim kaydı, oturum izleme ve anlık uyarılarla güvenlik analitiği.',
      },
      governance: {
        title: 'Uyumluluk ve Yönetişim',
        description:
          'Otomatik erişim incelemeleri, sertifikasyon kampanyaları ve SOC 2 ile ISO 27001 için uyumluluk raporlaması.',
      },
      gateway: {
        title: 'API Ağ Geçidi ve Güvenliği',
        description:
          'Hız sınırlama, IP izin listeleri ve OAuth 2.0 belirteç doğrulaması sunan güçlü API ağ geçidi.',
      },
      performance: {
        title: 'Yüksek Performans',
        description:
          'Yatay ölçeklenmek üzere tasarlanmış durumsuz Go servisleri; sağlık denetimleri, kontrollü kapanış ve yüksek erişilebilirliğe hazır dağıtım profilleri.',
      },
    },
    integrations: {
      title: 'Altyapınızla Bütünleşir',
      subtitle:
        'Açık standartlar üzerinden federasyon ve kullanıcı sağlama — SAML 2.0, OIDC, SCIM 2.0 ve LDAP',
    },
    cta: {
      title: 'Erişiminizi Güvence Altına Almaya Hazır mısınız?',
      subtitle:
        'IAM · IGA · PAM · ZTNA yığınının tamamını kendi altyapınızda çalıştırın — tek kimlik, tek politika düzlemi, tek denetim izi.',
      viewOnGitHub: "GitHub'da Görüntüle",
    },
    footer: {
      tagline: 'Modern kurumlar için açık kaynaklı Sıfır Güven Erişim Platformu.',
      product: 'Ürün',
      project: 'Proje',
      securityLegal: 'Güvenlik ve Lisans',
      apiReference: 'API Referansı',
      issues: 'Sorun Takibi',
      contributing: 'Katkıda Bulunma',
      changelog: 'Değişiklik Günlüğü',
      license: 'Lisans (Apache-2.0)',
      securityPolicy: 'Güvenlik Politikası',
      threatModel: 'Tehdit Modeli',
      complianceMapping: 'Uyumluluk Eşlemesi',
      copyright: '© {{year}} OpenIDX katkıcıları. Apache-2.0 ile lisanslanmıştır.',
      sourceOnGitHub: "Kaynak kodu GitHub'da",
    },
  },
}

export default tr
