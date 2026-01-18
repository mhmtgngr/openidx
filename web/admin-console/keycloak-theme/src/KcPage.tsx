import { lazy, Suspense } from "react";
import type { KcContextBase } from "keycloakify";
import { KcApp as KcAppBase } from "keycloakify";
import { Login } from "./login/Login";

const KcApp = lazy(() => import("keycloakify/KcApp"));

export type { KcContextBase };

export const KcPage = ({ kcContext }: { kcContext: KcContextBase }) => {
    return (
        <Suspense>
            <KcApp
                kcContext={kcContext}
                getKcAppClassName={({ pageId }) => `kc-app-${pageId}`}
            >
                {(() => {
                    switch (kcContext.pageId) {
                        case "login.ftl":
                            return <Login kcContext={kcContext} />;
                        default:
                            return <KcAppBase kcContext={kcContext} />;
                    }
                })()}
            </KcApp>
        </Suspense>
    );
};
