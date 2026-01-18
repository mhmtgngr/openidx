import { useState, useEffect } from "react";
import type { KcContextBase } from "keycloakify";
import { clsx } from "keycloakify/lib/tools/clsx";

export const Login = ({ kcContext }: { kcContext: KcContextBase.Login }) => {
    const { social, realm, url, usernameHidden, login, auth, registrationDisabled, messagesPerField, message } = kcContext;

    const [isLoginButtonDisabled, setIsLoginButtonDisabled] = useState(false);

    const onSubmit = (e: React.FormEvent<HTMLFormElement>) => {
        e.preventDefault();
        setIsLoginButtonDisabled(true);

        const formElement = e.target as HTMLFormElement;
        formElement.submit();
    };

    return (
        <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 via-indigo-50 to-purple-50">
            <div className="w-full max-w-md shadow-xl bg-white rounded-lg overflow-hidden border border-gray-200">
                {/* Header Section */}
                <header className="text-center p-8 pb-6 border-b border-gray-100 bg-gradient-to-br from-white to-gray-50">
                    <div className="mb-4">
                        <div className="h-16 w-16 rounded-full bg-gradient-to-br from-blue-600 to-indigo-700 flex items-center justify-center mx-auto shadow-lg">
                            <span className="text-2xl">🛡️</span>
                        </div>
                    </div>
                    <h1 className="text-3xl font-bold bg-gradient-to-r from-blue-600 to-indigo-600 bg-clip-text text-transparent mb-1">
                        Sign In
                        <span className="block text-lg font-semibold text-gray-600 mt-1">OpenIDX</span>
                    </h1>
                    <p className="text-sm text-gray-500">Identity & Access Management Platform</p>
                </header>

                {/* Body Section */}
                <main className="p-8">
                    {/* Error Messages */}
                    {message !== undefined && (message.type !== "warning" || !auth?.showTryAgain) && (
                        <div
                            className={clsx(
                                "mb-6 p-3 rounded-md border",
                                message.type === "success" && "bg-green-50 border-green-200 text-green-800",
                                message.type === "warning" && "bg-yellow-50 border-yellow-200 text-yellow-800",
                                message.type === "error" && "bg-red-50 border-red-200 text-red-800",
                                message.type === "info" && "bg-blue-50 border-blue-200 text-blue-800"
                            )}
                        >
                            <span dangerouslySetInnerHTML={{ __html: message.summary }} />
                        </div>
                    )}

                    {/* Login Form */}
                    {realm.password && (
                        <form id="kc-form-login" onSubmit={onSubmit} action={url.loginAction} method="post" className="space-y-6">
                            {/* Username Field */}
                            {!usernameHidden && (
                                <div>
                                    <label htmlFor="username" className="block text-sm font-medium text-gray-700 mb-2">
                                        {!realm.loginWithEmailAllowed
                                            ? "Username"
                                            : !realm.registrationEmailAsUsername
                                            ? "Username or email"
                                            : "Email"}
                                    </label>
                                    <input
                                        tabIndex={1}
                                        id="username"
                                        className={clsx(
                                            "w-full px-3 py-2 border rounded-md shadow-sm focus:outline-none focus:ring-2 focus:border-transparent transition-colors",
                                            messagesPerField?.existsError?.("username", "password")
                                                ? "border-red-300 focus:ring-red-500"
                                                : "border-gray-300 focus:ring-blue-500 focus:border-blue-500"
                                        )}
                                        name="username"
                                        defaultValue={login.username ?? ""}
                                        type="text"
                                        autoFocus
                                        autoComplete="username"
                                        aria-invalid={messagesPerField?.existsError?.("username", "password")}
                                        required
                                    />
                                    {messagesPerField?.existsError?.("username", "password") && (
                                        <div className="mt-1 text-sm text-red-600">
                                            {messagesPerField.getFirstError("username", "password")}
                                        </div>
                                    )}
                                </div>
                            )}

                            {/* Password Field */}
                            <div>
                                <label htmlFor="password" className="block text-sm font-medium text-gray-700 mb-2">
                                    Password
                                </label>
                                <input
                                    tabIndex={2}
                                    id="password"
                                    className={clsx(
                                        "w-full px-3 py-2 border rounded-md shadow-sm focus:outline-none focus:ring-2 focus:border-transparent transition-colors",
                                        messagesPerField?.existsError?.("username", "password")
                                            ? "border-red-300 focus:ring-red-500"
                                            : "border-gray-300 focus:ring-blue-500 focus:border-blue-500"
                                    )}
                                    name="password"
                                    type="password"
                                    autoComplete="current-password"
                                    aria-invalid={messagesPerField?.existsError?.("username", "password")}
                                    required
                                />
                            </div>

                            {/* Remember Me */}
                            {realm.rememberMe && !usernameHidden && (
                                <div className="flex items-center">
                                    <input
                                        tabIndex={3}
                                        id="rememberMe"
                                        name="rememberMe"
                                        type="checkbox"
                                        defaultChecked={login.rememberMe ?? false}
                                        className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                                    />
                                    <label htmlFor="rememberMe" className="ml-2 block text-sm text-gray-600">
                                        Remember me
                                    </label>
                                </div>
                            )}

                            {/* Hidden Inputs */}
                            <input type="hidden" id="id-hidden-input" name="credentialId" value={auth?.selectedCredential} />

                            {/* Submit Button */}
                            <button
                                tabIndex={4}
                                className={clsx(
                                    "w-full py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white transition-colors focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500",
                                    isLoginButtonDisabled
                                        ? "bg-gray-400 cursor-not-allowed"
                                        : "bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700"
                                )}
                                name="login"
                                id="kc-login"
                                type="submit"
                                disabled={isLoginButtonDisabled}
                            >
                                Sign In
                            </button>
                        </form>
                    )}

                    {/* Social Providers */}
                    {realm.password && social?.providers && (
                        <div className="mt-6">
                            <div className="relative">
                                <div className="absolute inset-0 flex items-center">
                                    <div className="w-full border-t border-gray-300" />
                                </div>
                                <div className="relative flex justify-center text-sm">
                                    <span className="px-2 bg-white text-gray-500">Or continue with</span>
                                </div>
                            </div>

                            <div className="mt-6 grid grid-cols-1 gap-3">
                                {social.providers.map((p) => (
                                    <a
                                        key={p.alias}
                                        href={p.loginUrl}
                                        className="w-full inline-flex justify-center py-2 px-4 border border-gray-300 rounded-md shadow-sm bg-white text-sm font-medium text-gray-500 hover:bg-gray-50 transition-colors"
                                    >
                                        {p.iconClasses && <i className={`${p.iconClasses} mr-2`} aria-hidden="true"></i>}
                                        <span>{p.displayName}</span>
                                    </a>
                                ))}
                            </div>
                        </div>
                    )}

                    {/* Links */}
                    <div className="mt-6 space-y-2 text-center">
                        {realm.resetPasswordAllowed && (
                            <div>
                                <a
                                    tabIndex={5}
                                    href={url.loginResetCredentialsUrl}
                                    className="text-sm text-blue-600 hover:text-blue-500 transition-colors"
                                >
                                    Forgot your password?
                                </a>
                            </div>
                        )}

                        {realm.password && realm.registrationAllowed && !registrationDisabled && (
                            <div>
                                <a
                                    tabIndex={6}
                                    href={url.registrationUrl}
                                    className="text-sm text-blue-600 hover:text-blue-500 transition-colors"
                                >
                                    Create an account
                                </a>
                            </div>
                        )}
                    </div>
                </main>

                {/* Footer */}
                <footer className="px-8 py-4 bg-gray-50 border-t border-gray-100">
                    <div className="flex justify-center space-x-4 text-xs text-gray-500">
                        <a href="#" className="hover:text-gray-700 transition-colors">Privacy</a>
                        <span>•</span>
                        <a href="#" className="hover:text-gray-700 transition-colors">Terms</a>
                        <span>•</span>
                        <a href="#" className="hover:text-gray-700 transition-colors">Help</a>
                    </div>
                    <div className="mt-2 text-center text-xs text-gray-400">
                        Powered by <strong className="text-gray-600">OpenIDX</strong>
                    </div>
                </footer>
            </div>
        </div>
    );
};
