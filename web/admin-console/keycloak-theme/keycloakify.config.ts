import { createKeycloakifyConfig } from "keycloakify";

export default createKeycloakifyConfig({
    themeName: "openidx",
    accountThemeName: "openidx",
    loginThemeName: "openidx",
    emailThemeName: "openidx",
    adminConsoleThemeName: "openidx",
    securityAdminConsoleThemeName: "openidx",
    welcomeThemeName: "openidx",
    loginThemeResourcesFromKeycloakVersion: "23.0.7",
    extraPages: [],
    keycloakVersion: "23.0.7",
});
