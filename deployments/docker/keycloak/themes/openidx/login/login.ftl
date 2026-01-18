<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=!messagesPerField.existsError('username','password') displayInfo=realm.password && realm.registrationAllowed && !registrationDisabled??; body>
<div class="login-pf">
  <div class="login-pf-page">
    <div class="card-pf">
      <!-- Header Section -->
      <header class="login-pf-header">
        <div class="login-pf-brand">
          <div style="height: 4rem; width: 4rem; border-radius: 50%; background: linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%); display: flex; align-items: center; justify-content: center; margin: 0 auto; box-shadow: 0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1);">
            <span style="font-size: 2rem;">🛡️</span>
          </div>
        </div>
        <h1 id="kc-page-title">
          Sign In
          <span style="display: block; font-size: 1.125rem; font-weight: 600; color: #4b5563; margin-top: 0.25rem; letter-spacing: 0.05em;">OpenIDX</span>
        </h1>
        <p id="kc-page-subtitle">Identity & Access Management Platform</p>
      </header>

      <!-- Body Section -->
      <main class="login-pf-body">
        <#if displayMessage && message?has_content && (message.type != 'warning' || !isAppInitiatedAction??)>
          <div class="alert alert-${message.type}">
            <#if message.type = 'success'><span class="pficon pficon-ok"></span></#if>
            <#if message.type = 'warning'><span class="pficon pficon-warning-triangle-o"></span></#if>
            <#if message.type = 'error'><span class="pficon pficon-error-circle-o"></span></#if>
            <#if message.type = 'info'><span class="pficon pficon-info"></span></#if>
            <span class="kc-feedback-text">${kcSanitize(message.summary)?no_esc}</span>
          </div>
        </#if>

        <#if realm.password>
          <form id="kc-form-login" onsubmit="login.disabled = true; return true;" action="${url.loginAction}" method="post">
            <div class="login-pf-fields">
              <div class="form-group">
                <label for="username" class="form-label">
                  <#if !realm.loginWithEmailAllowed>${msg("username")}<#elseif !realm.registrationEmailAsUsername>${msg("usernameOrEmail")}<#else>${msg("email")}</#if>
                </label>
                <input
                  tabindex="1"
                  id="username"
                  class="form-control"
                  name="username"
                  value="${(login.username!'')?html}"
                  type="text"
                  autofocus
                  autocomplete="username"
                  aria-invalid="<#if messagesPerField.existsError('username','password')>true</#if>"
                  required
                />

                <#if messagesPerField.existsError('username','password')>
                  <div class="alert alert-error">
                    ${kcSanitize(messagesPerField.getFirstError('username','password'))?no_esc}
                  </div>
                </#if>
              </div>

              <div class="form-group">
                <label for="password" class="form-label">${msg("password")}</label>
                <input
                  tabindex="2"
                  id="password"
                  class="form-control"
                  name="password"
                  type="password"
                  autocomplete="current-password"
                  aria-invalid="<#if messagesPerField.existsError('username','password')>true</#if>"
                  required
                />
              </div>

              <#if realm.rememberMe && !usernameHidden??>
                <div class="login-pf-remember">
                  <input tabindex="3" id="rememberMe" name="rememberMe" type="checkbox" <#if login.rememberMe??>checked</#if>>
                  <label for="rememberMe">${msg("rememberMe")}</label>
                </div>
              </#if>
            </div>

            <div class="login-pf-actions">
              <input type="hidden" id="id-hidden-input" name="credentialId" <#if auth.selectedCredential?has_content>value="${auth.selectedCredential}"</#if>/>
              <button tabindex="4" class="btn btn-primary" name="login" id="kc-login" type="submit">
                ${msg("doLogIn")}
              </button>
            </div>
          </form>
        </#if>

        <#if realm.password && social.providers??>
          <div class="login-pf-social">
            <div class="login-pf-social-providers">
              <#list social.providers as p>
                <a href="${p.loginUrl}" class="btn btn-secondary">
                  <#if p.iconClasses?has_content>
                    <i class="${p.iconClasses}" aria-hidden="true"></i>
                    <span class="sr-only">${msg("socialLogin")} ${p.displayName}</span>
                  <#else>
                    <span>${p.displayName}</span>
                  </#if>
                </a>
              </#list>
            </div>
          </div>
        </#if>

        <#if realm.password && realm.registrationAllowed && !registrationDisabled??>
          <div class="login-pf-links">
            <a tabindex="6" href="${url.registrationUrl}">${msg("doRegister")}</a>
          </div>
        </#if>

        <#if realm.password && realm.resetPasswordAllowed>
          <div class="login-pf-links">
            <a tabindex="5" href="${url.loginResetCredentialsUrl}">${msg("doForgotPassword")}</a>
          </div>
        </#if>
      </main>

      <!-- Footer Section -->
      <footer class="login-pf-footer">
        <div class="footer-links">
          <a href="#">Privacy</a>
          <span>•</span>
          <a href="#">Terms</a>
          <span>•</span>
          <a href="#">Help</a>
        </div>
        <div class="footer-branding">
          Powered by <strong>OpenIDX</strong>
        </div>
      </footer>
    </div>
  </div>
</div>
</@layout.registrationLayout>
