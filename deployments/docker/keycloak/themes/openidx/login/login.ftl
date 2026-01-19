<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=!messagesPerField.existsError('username','password') displayInfo=realm.password && realm.registrationAllowed && !registrationDisabled??; section>
    <#if section = "header">
        <div class="login-header">
            <div class="login-logo">
                <svg width="48" height="48" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <circle cx="24" cy="24" r="24" fill="url(#gradient)"/>
                    <path d="M24 12L32 18V30L24 36L16 30V18L24 12Z" fill="white" fill-opacity="0.9"/>
                    <path d="M24 18L28 21V27L24 30L20 27V21L24 18Z" fill="#3b82f6"/>
                    <defs>
                        <linearGradient id="gradient" x1="0" y1="0" x2="48" y2="48" gradientUnits="userSpaceOnUse">
                            <stop stop-color="#3b82f6"/>
                            <stop offset="1" stop-color="#1d4ed8"/>
                        </linearGradient>
                    </defs>
                </svg>
            </div>
            <h1 class="login-title">Sign In</h1>
            <p class="login-subtitle">OpenIDX Identity Platform</p>
        </div>
    <#elseif section = "form">
        <#if realm.password>
            <form id="kc-form-login" onsubmit="login.disabled = true; return true;" action="${url.loginAction}" method="post">
                <div class="form-group">
                    <label for="username" class="form-label">
                        <#if !realm.loginWithEmailAllowed>${msg("username")}<#elseif !realm.registrationEmailAsUsername>${msg("usernameOrEmail")}<#else>${msg("email")}</#if>
                    </label>
                    <input
                        tabindex="1"
                        id="username"
                        class="form-input<#if messagesPerField.existsError('username','password')> input-error</#if>"
                        name="username"
                        value="${(login.username!'')}"
                        type="text"
                        autofocus
                        autocomplete="username"
                        aria-invalid="<#if messagesPerField.existsError('username','password')>true</#if>"
                    />
                    <#if messagesPerField.existsError('username','password')>
                        <span class="error-message">${kcSanitize(messagesPerField.getFirstError('username','password'))?no_esc}</span>
                    </#if>
                </div>

                <div class="form-group">
                    <label for="password" class="form-label">${msg("password")}</label>
                    <input
                        tabindex="2"
                        id="password"
                        class="form-input<#if messagesPerField.existsError('username','password')> input-error</#if>"
                        name="password"
                        type="password"
                        autocomplete="current-password"
                        aria-invalid="<#if messagesPerField.existsError('username','password')>true</#if>"
                    />
                </div>

                <div class="form-options">
                    <#if realm.rememberMe && !usernameHidden??>
                        <div class="remember-me">
                            <input tabindex="3" id="rememberMe" name="rememberMe" type="checkbox" <#if login.rememberMe??>checked</#if>>
                            <label for="rememberMe">${msg("rememberMe")}</label>
                        </div>
                    </#if>
                    <#if realm.resetPasswordAllowed>
                        <a tabindex="5" href="${url.loginResetCredentialsUrl}" class="forgot-password">${msg("doForgotPassword")}</a>
                    </#if>
                </div>

                <div class="form-actions">
                    <input type="hidden" id="id-hidden-input" name="credentialId" <#if auth.selectedCredential?has_content>value="${auth.selectedCredential}"</#if>/>
                    <button tabindex="4" class="btn-primary" name="login" id="kc-login" type="submit">
                        ${msg("doLogIn")}
                    </button>
                </div>
            </form>
        </#if>
    <#elseif section = "socialProviders">
        <#if realm.password && social.providers??>
            <div class="social-providers">
                <div class="social-divider">
                    <span>or continue with</span>
                </div>
                <div class="social-buttons">
                    <#list social.providers as p>
                        <a id="social-${p.alias}" href="${p.loginUrl}" class="btn-social">
                            <#if p.iconClasses?has_content>
                                <i class="${p.iconClasses}" aria-hidden="true"></i>
                            </#if>
                            <span>${p.displayName}</span>
                        </a>
                    </#list>
                </div>
            </div>
        </#if>
    <#elseif section = "info">
        <#if realm.password && realm.registrationAllowed && !registrationDisabled??>
            <div class="registration-link">
                <span>${msg("noAccount")}</span>
                <a tabindex="6" href="${url.registrationUrl}">${msg("doRegister")}</a>
            </div>
        </#if>
    </#if>
</@layout.registrationLayout>
