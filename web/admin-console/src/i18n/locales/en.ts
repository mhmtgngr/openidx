// English catalog — the source of truth for translation keys. Other locales
// are typed against this object, so a missing or extra key fails type-check.
const en = {
  switcher: {
    label: 'Language',
  },
  common: {
    cancel: 'Cancel',
  },
  chrome: {
    views: {
      admin: 'Admin',
      manage: 'Manage',
      report: 'Report',
      groupLabel: 'Console view',
    },
    toggleSidebar: 'Toggle sidebar',
    searchMenuPlaceholder: 'Search menu...',
    searchMenu: 'Search menu',
    clearSearch: 'Clear menu search',
    noMenuMatches: 'No menu items match.',
    openNavigation: 'Open navigation',
    zitiStatus: 'Ziti Network Status',
    account: {
      myAccount: 'My Account',
      myProfile: 'My Profile',
      settings: 'Settings',
      logout: 'Logout',
    },
  },
  login: {
    errors: {
      authFailed: 'Authentication failed. Please try again.',
      loginFailed: 'Login failed. Please try again.',
      network: 'Unable to connect to the server. Please try again.',
      otpSendFailed: 'Failed to send verification code.',
      otpSendNetwork: 'Unable to send verification code. Please try again.',
      webauthnStart: 'Failed to start WebAuthn authentication',
      webauthnCancelled: 'Authentication was cancelled',
      webauthnVerify: 'WebAuthn verification failed',
      webauthnFailed: 'WebAuthn authentication failed',
      pushStart: 'Failed to send push notification',
      pushVerify: 'Push verification failed',
      pushDenied: 'Push notification was denied.',
      pushExpired: 'Push challenge has expired. Please try again.',
      pushInit: 'Failed to initiate push challenge',
      pushCancelled: 'Push challenge cancelled.',
      invalidCode: 'Invalid verification code. Please try again.',
      forceLogin: 'Failed to force login',
      passkeyNone: 'No passkeys available',
      passkeyCancelled: 'Passkey authentication was cancelled',
      passkeyVerify: 'Passkey verification failed',
      passkeyFailed: 'Passkey authentication failed',
      phoneNeedsUsername: 'Enter your username to sign in with your phone.',
      phoneUnavailable: 'Passwordless phone sign-in is unavailable.',
      passwordlessFailed: 'Passwordless sign-in failed',
      magicLinkFailed: 'Failed to send sign-in link. Please try again.',
      qrCreateFailed: 'Failed to create QR login session.',
      qrExpired: 'QR session expired. Please try again.',
    },
    mfa: {
      chooseTitle: 'Choose Verification Method',
      chooseSubtitle: 'Select how you want to verify your identity',
      totp: {
        label: 'Authenticator App',
        hint: 'Enter code from your authenticator app',
        prompt: 'Enter the 6-digit code from your authenticator app',
      },
      sms: {
        label: 'SMS Code',
        hint: 'Receive a code via text message',
        promptSent: 'Enter the code sent to your phone',
        promptSending: 'Sending code to your phone...',
      },
      email: {
        label: 'Email Code',
        hint: 'Receive a code via email',
        promptSent: 'Enter the code sent to your email',
        promptSending: 'Sending code to your email...',
      },
      webauthn: {
        label: 'Security Key',
        hint: 'Use your security key or biometrics',
        prompt: 'Touch your security key or use biometrics to verify',
        waiting: 'Waiting for your security key...',
        waitingHint: 'Touch your security key or use biometrics when prompted by your browser.',
        retry: 'Try Again',
      },
      push: {
        label: 'Push Notification',
        hint: 'Approve on your mobile device',
        prompt: 'Approve the notification on your registered device',
        verifyNumber: 'Verify this number on your device:',
        waiting: 'Waiting for approval...',
        waitingHint: 'Open the notification on your device and approve the sign-in request.',
        send: 'Send Push Notification',
      },
      trustBrowser: 'Trust this browser',
      trustBrowserHint: 'Skip verification on this device for the next 30 days.',
      codeLabel: 'Verification Code',
      resend: 'Resend Code',
      verify: 'Verify',
      verifying: 'Verifying...',
      differentMethod: 'Use a different method',
      backToLogin: 'Back to login',
    },
    form: {
      signInWithCredentials: 'Sign in with your credentials',
      passkey: 'Sign in with a passkey',
      phone: 'Sign in with your phone',
      orPassword: 'Or continue with password',
      usernameLabel: 'Username or Email',
      usernamePlaceholder: 'Enter your username or email',
      passwordLabel: 'Password',
      passwordPlaceholder: 'Enter your password',
      signIn: 'Sign In',
      signingIn: 'Signing in...',
      forgotPassword: 'Forgot your password?',
      backToOptions: 'Back to login options',
    },
    magicLink: {
      request: 'Email me a sign-in link',
      emailLabel: 'Email address',
      send: 'Send',
      sent: 'Check your email for a sign-in link.',
    },
    qr: {
      signIn: 'Sign in with QR code',
      scanHint: 'Scan with the OpenIDX mobile app',
      waiting: 'Waiting for approval...',
    },
    options: {
      platformSubtitle: 'Identity & Access Management Platform',
      accessHint: 'Sign in to access your OpenIDX admin console',
      ssoWith: 'Sign in with {{name}}',
      orContinueWith: 'Or continue with',
      signInOpenidx: 'Sign in with OpenIDX',
      securedBy: 'Secured by OpenIDX authentication',
    },
    concurrent: {
      title: 'Session Limit Reached',
      description: 'You have reached the maximum number of active sessions. Please sign out of an existing session to continue.',
      lastActive: 'Last active: {{time}}',
      signOut: 'Sign Out',
    },
    footer: {
      security: 'Security',
      poweredBy: 'Powered by',
    },
  },
  landing: {
    nav: {
      features: 'Features',
      integrations: 'Integrations',
      documentation: 'Documentation',
      signIn: 'Sign In',
      getStarted: 'Get Started',
    },
    hero: {
      badge: 'Open source · Self-hosted · Apache-2.0',
      titleLead: 'Zero Trust Access Platform for',
      titleHighlight: 'Modern Enterprises',
      subtitle:
        'OpenIDX provides complete Identity and Access Management with SSO, MFA, access governance, privileged access, and Zero Trust networking — plus the audit and compliance reporting to prove it. Open source, self-hosted, enterprise-ready.',
      viewDocs: 'View Documentation',
      point1: '100% open source (Apache-2.0)',
      point2: 'Self-hosted — your data stays on your infrastructure',
      point3: 'Docker Compose quick start',
    },
    stats: {
      pillars: 'Pillars: IAM · IGA · PAM · ZTNA',
      services: 'Go Services',
      openSource: 'Open Source',
      darkPorts: 'Inbound Ports for Dark Services',
    },
    features: {
      title: 'Complete Security Platform',
      subtitle:
        'Everything you need to secure access to your applications, data, and infrastructure',
      zeroTrust: {
        title: 'Zero Trust Architecture',
        description:
          'Never trust, always verify. Every access request is fully authenticated, authorized, and encrypted before granting access.',
      },
      iam: {
        title: 'Identity & Access Management',
        description:
          'Centralized user provisioning, role-based access control, and lifecycle management for all your applications.',
      },
      mfa: {
        title: 'Multi-Factor Authentication',
        description:
          'TOTP, WebAuthn (passkeys and security keys), push approvals, and SMS or email one-time codes.',
      },
      sso: {
        title: 'Single Sign-On (SSO)',
        description:
          'One login to access all your applications with support for SAML, OIDC, and social identity providers.',
      },
      monitoring: {
        title: 'Real-time Monitoring',
        description:
          'Comprehensive audit logging, session monitoring, and security analytics with instant alerts.',
      },
      governance: {
        title: 'Compliance & Governance',
        description:
          'Automated access reviews, certification campaigns, and compliance reporting for SOC 2 and ISO 27001.',
      },
      gateway: {
        title: 'API Gateway & Security',
        description:
          'Powerful API gateway with rate limiting, IP allowlists, and OAuth 2.0 token validation.',
      },
      performance: {
        title: 'High Performance',
        description:
          'Stateless Go services built to scale horizontally, with health probes, graceful drains, and HA-ready deployment profiles.',
      },
    },
    integrations: {
      title: 'Integrates with Your Stack',
      subtitle:
        'Federate and provision over open standards — SAML 2.0, OIDC, SCIM 2.0, and LDAP',
    },
    cta: {
      title: 'Ready to Secure Your Access?',
      subtitle:
        'Run the complete IAM · IGA · PAM · ZTNA stack on your own infrastructure — one identity, one policy plane, one audit trail.',
      viewOnGitHub: 'View on GitHub',
    },
    footer: {
      tagline: 'Open source Zero Trust Access Platform for modern enterprises.',
      product: 'Product',
      project: 'Project',
      securityLegal: 'Security & License',
      apiReference: 'API Reference',
      issues: 'Issue Tracker',
      contributing: 'Contributing',
      changelog: 'Changelog',
      license: 'License (Apache-2.0)',
      securityPolicy: 'Security Policy',
      threatModel: 'Threat Model',
      complianceMapping: 'Compliance Mapping',
      copyright: '© {{year}} OpenIDX contributors. Apache-2.0 licensed.',
      sourceOnGitHub: 'Source on GitHub',
    },
  },
}

export default en
