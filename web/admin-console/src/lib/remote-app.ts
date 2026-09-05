/**
 * Client-side mirror of the backend's RemoteApp argument guard
 * (internal/access/pam_launch.go `validateRemoteAppArgs`). It exists purely to
 * warn the admin *as they type* — the server is the real enforcement point and
 * rejects the same patterns on save. Keep the two regexes in sync.
 *
 * Why: RDP passes `remote-app-args` verbatim and they show up in the target's
 * process list, so a password there leaks to anyone who can see processes on
 * the host. The correct pattern is integrated auth (e.g. SSMS `-E`), which
 * signs in as the vault-injected Windows identity with no secret in the args.
 */
import i18n from '../i18n'

const SECRET_ARG_RE =
  /(^|\s)(-{1,2}p(ass(word)?)?|\/pass(word)?)([\s:=]|$)|(^|\s|;|&)(password|passwd|pwd)\s*=/i

/** True when RemoteApp args look like they contain a password. */
export function remoteAppArgsLookSecret(args: string | undefined | null): boolean {
  if (!args || !args.trim()) return false
  return SECRET_ARG_RE.test(args)
}

/**
 * The warning shown next to the args field. A function rather than a constant
 * so it re-resolves when the console language changes.
 */
export function remoteAppSecretHint(): string {
  return i18n.t('pam.remoteAppSecretHint')
}
