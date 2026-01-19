<#macro registrationLayout bodyClass="" displayInfo=false displayMessage=true displayRequiredFields=false>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <meta name="robots" content="noindex, nofollow">
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <#if properties.meta?has_content>
        <#list properties.meta?split(' ') as meta>
            <meta name="${meta?split('==')[0]}" content="${meta?split('==')[1]}"/>
        </#list>
    </#if>
    <title>${msg("loginTitle",(realm.displayName!''))}</title>
    <link rel="icon" href="${url.resourcesPath}/img/favicon.ico" />

    <#if properties.stylesCommon?has_content>
        <#list properties.stylesCommon?split(' ') as style>
            <#if style?has_content>
                <link href="${url.resourcesCommonPath}/${style}" rel="stylesheet" />
            </#if>
        </#list>
    </#if>
    <#if properties.styles?has_content>
        <#list properties.styles?split(' ') as style>
            <link href="${url.resourcesPath}/${style}" rel="stylesheet" />
        </#list>
    </#if>

    <style>
    /* OpenIDX Keycloak Theme - Embedded Styles */
    :root {
      --openidx-blue: #3b82f6;
      --openidx-blue-dark: #1d4ed8;
      --openidx-blue-light: #dbeafe;
      --openidx-gray-50: #f9fafb;
      --openidx-gray-100: #f3f4f6;
      --openidx-gray-200: #e5e7eb;
      --openidx-gray-300: #d1d5db;
      --openidx-gray-400: #9ca3af;
      --openidx-gray-500: #6b7280;
      --openidx-gray-600: #4b5563;
      --openidx-gray-700: #374151;
      --openidx-gray-800: #1f2937;
      --openidx-gray-900: #111827;
      --openidx-white: #ffffff;
      --openidx-red: #ef4444;
      --openidx-red-dark: #dc2626;
      --openidx-green: #10b981;
      --openidx-radius: 0.5rem;
      --openidx-shadow: 0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1);
      --openidx-shadow-lg: 0 20px 25px -5px rgb(0 0 0 / 0.1), 0 8px 10px -6px rgb(0 0 0 / 0.1);
    }

    * { box-sizing: border-box; }
    html, body { margin: 0; padding: 0; min-height: 100vh; }

    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen', 'Ubuntu', sans-serif;
      background: linear-gradient(135deg, var(--openidx-gray-100) 0%, var(--openidx-blue-light) 100%);
      display: flex;
      align-items: center;
      justify-content: center;
      -webkit-font-smoothing: antialiased;
    }

    .login-container {
      width: 100%;
      max-width: 420px;
      padding: 2rem;
      display: flex;
      flex-direction: column;
      align-items: center;
      min-height: 100vh;
      justify-content: center;
    }

    .login-card {
      background: var(--openidx-white);
      border-radius: 1rem;
      box-shadow: var(--openidx-shadow-lg);
      border: 1px solid var(--openidx-gray-200);
      width: 100%;
      padding: 2.5rem;
    }

    .login-header { text-align: center; margin-bottom: 2rem; }
    .login-logo { margin-bottom: 1.5rem; }
    .login-logo svg { display: block; margin: 0 auto; filter: drop-shadow(0 4px 6px rgb(0 0 0 / 0.1)); }

    .login-title {
      font-size: 1.75rem;
      font-weight: 700;
      margin: 0 0 0.5rem 0;
      color: var(--openidx-gray-900);
    }

    .login-subtitle {
      font-size: 0.875rem;
      color: var(--openidx-gray-500);
      margin: 0;
    }

    .form-group { margin-bottom: 1.25rem; }

    .form-label {
      display: block;
      font-size: 0.875rem;
      font-weight: 500;
      color: var(--openidx-gray-700);
      margin-bottom: 0.5rem;
    }

    .form-input {
      width: 100%;
      padding: 0.75rem 1rem;
      border: 1px solid var(--openidx-gray-300);
      border-radius: var(--openidx-radius);
      font-size: 1rem;
      background: var(--openidx-white);
      transition: all 0.2s ease-in-out;
      color: var(--openidx-gray-900);
    }

    .form-input:focus {
      outline: none;
      border-color: var(--openidx-blue);
      box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.15);
    }

    .form-input.input-error { border-color: var(--openidx-red); }

    .error-message {
      display: block;
      font-size: 0.8125rem;
      color: var(--openidx-red-dark);
      margin-top: 0.5rem;
    }

    .form-options {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1.5rem;
      flex-wrap: wrap;
      gap: 0.5rem;
    }

    .remember-me { display: flex; align-items: center; gap: 0.5rem; }
    .remember-me input[type="checkbox"] { width: 1rem; height: 1rem; accent-color: var(--openidx-blue); cursor: pointer; }
    .remember-me label { font-size: 0.875rem; color: var(--openidx-gray-600); cursor: pointer; }

    .forgot-password {
      font-size: 0.875rem;
      color: var(--openidx-blue);
      text-decoration: none;
      font-weight: 500;
    }
    .forgot-password:hover { text-decoration: underline; }

    .form-actions { margin-top: 1.5rem; }

    .btn-primary {
      display: block;
      width: 100%;
      padding: 0.875rem 1.5rem;
      background: linear-gradient(135deg, var(--openidx-blue) 0%, var(--openidx-blue-dark) 100%);
      color: var(--openidx-white);
      border: none;
      border-radius: var(--openidx-radius);
      font-size: 1rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s ease-in-out;
      box-shadow: var(--openidx-shadow);
      text-align: center;
      text-decoration: none;
    }

    .btn-primary:hover {
      background: linear-gradient(135deg, var(--openidx-blue-dark) 0%, #1e3a8a 100%);
      transform: translateY(-1px);
      box-shadow: var(--openidx-shadow-lg);
    }

    .alert {
      padding: 1rem;
      border-radius: var(--openidx-radius);
      margin-bottom: 1.5rem;
      display: flex;
      align-items: flex-start;
      gap: 0.75rem;
    }

    .alert-icon { flex-shrink: 0; font-size: 1rem; }
    .alert-text { font-size: 0.875rem; line-height: 1.5; }
    .alert-error { background: #fef2f2; border: 1px solid #fecaca; color: var(--openidx-red-dark); }
    .alert-success { background: #f0fdf4; border: 1px solid #bbf7d0; color: #166534; }
    .alert-warning { background: #fffbeb; border: 1px solid #fde68a; color: #92400e; }
    .alert-info { background: var(--openidx-blue-light); border: 1px solid #bfdbfe; color: var(--openidx-blue-dark); }

    .social-providers { margin-top: 1.5rem; }

    .social-divider {
      display: flex;
      align-items: center;
      margin-bottom: 1.5rem;
    }

    .social-divider::before,
    .social-divider::after {
      content: '';
      flex: 1;
      height: 1px;
      background: var(--openidx-gray-200);
    }

    .social-divider span {
      padding: 0 1rem;
      font-size: 0.8125rem;
      color: var(--openidx-gray-500);
    }

    .social-buttons { display: flex; flex-direction: column; gap: 0.75rem; }

    .btn-social {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 0.75rem;
      padding: 0.75rem 1rem;
      background: var(--openidx-white);
      border: 1px solid var(--openidx-gray-300);
      border-radius: var(--openidx-radius);
      color: var(--openidx-gray-700);
      text-decoration: none;
      font-size: 0.9375rem;
      font-weight: 500;
      transition: all 0.2s ease-in-out;
    }

    .btn-social:hover {
      background: var(--openidx-gray-50);
      border-color: var(--openidx-gray-400);
    }

    .registration-link { text-align: center; font-size: 0.875rem; color: var(--openidx-gray-600); }
    .registration-link a { color: var(--openidx-blue); text-decoration: none; font-weight: 500; margin-left: 0.25rem; }
    .registration-link a:hover { text-decoration: underline; }

    .login-footer { margin-top: 2rem; text-align: center; font-size: 0.8125rem; color: var(--openidx-gray-400); }
    .login-footer strong { color: var(--openidx-gray-600); }

    .error-content { text-align: center; }
    .error-message-text { font-size: 0.9375rem; color: var(--openidx-gray-600); margin-bottom: 1.5rem; line-height: 1.6; }

    .try-another-way { text-align: center; margin-top: 1rem; }
    .try-another-way a { color: var(--openidx-blue); text-decoration: none; font-size: 0.875rem; }
    .try-another-way a:hover { text-decoration: underline; }

    .login-info { margin-top: 1.5rem; padding-top: 1.5rem; border-top: 1px solid var(--openidx-gray-100); }

    @media (max-width: 480px) {
      .login-container { padding: 1rem; }
      .login-card { padding: 1.5rem; border-radius: 0.75rem; }
      .login-title { font-size: 1.5rem; }
      .form-options { flex-direction: column; align-items: flex-start; }
    }

    #kc-current-locale-link, #kc-locale-dropdown, #kc-locale-wrapper { display: none !important; }
    </style>
</head>

<body class="openidx-login ${bodyClass}">
    <div class="login-container">
        <div class="login-card">
            <#nested "header">

            <#if displayMessage && message?has_content && (message.type != 'warning' || !isAppInitiatedAction??)>
                <div class="alert alert-${message.type}">
                    <#if message.type = 'success'><span class="alert-icon">&#10003;</span></#if>
                    <#if message.type = 'warning'><span class="alert-icon">&#9888;</span></#if>
                    <#if message.type = 'error'><span class="alert-icon">&#10007;</span></#if>
                    <#if message.type = 'info'><span class="alert-icon">&#8505;</span></#if>
                    <span class="alert-text">${kcSanitize(message.summary)?no_esc}</span>
                </div>
            </#if>

            <#nested "form">

            <#if auth?has_content && auth.showTryAnotherWayLink()>
                <form id="kc-select-try-another-way-form" action="${url.loginAction}" method="post">
                    <div class="try-another-way">
                        <input type="hidden" name="tryAnotherWay" value="on"/>
                        <a href="#" id="try-another-way" onclick="document.forms['kc-select-try-another-way-form'].submit();return false;">${msg("doTryAnotherWay")}</a>
                    </div>
                </form>
            </#if>

            <#nested "socialProviders">

            <#if displayInfo>
                <div class="login-info">
                    <#nested "info">
                </div>
            </#if>
        </div>

        <div class="login-footer">
            <span>Powered by <strong>OpenIDX</strong></span>
        </div>
    </div>
</body>
</html>
</#macro>
