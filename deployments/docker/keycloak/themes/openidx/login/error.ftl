<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=false; section>
    <#if section = "header">
        <div class="login-header">
            <div class="login-logo error-logo">
                <svg width="48" height="48" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <circle cx="24" cy="24" r="24" fill="#ef4444"/>
                    <path d="M24 14L24 28" stroke="white" stroke-width="3" stroke-linecap="round"/>
                    <circle cx="24" cy="34" r="2" fill="white"/>
                </svg>
            </div>
            <h1 class="login-title">Error</h1>
            <p class="login-subtitle">Something went wrong</p>
        </div>
    <#elseif section = "form">
        <div class="error-content">
            <#if message?has_content>
                <p class="error-message-text">${kcSanitize(message.summary)?no_esc}</p>
            <#else>
                <p class="error-message-text">An unexpected error occurred. Please try again.</p>
            </#if>

            <#if skipLink??>
            <#else>
                <#if client?? && client.baseUrl?has_content>
                    <a href="${client.baseUrl}" class="btn-primary">Back to Application</a>
                </#if>
            </#if>
        </div>
    </#if>
</@layout.registrationLayout>
